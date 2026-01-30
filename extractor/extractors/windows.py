"""
Windows-specific extractor for evasion artifacts.

Extracts artifacts that Windows malware checks for:
- VM files (VMware, VirtualBox, Hyper-V)
- VM registry keys
- VM/sandbox processes
- WMI queries
- Mutexes
- Analysis tools

Data sources (in order of preference):
1. Kernel logs (onemon.json) - detailed syscall traces
2. Signatures with IOCs - behavioral detection results
3. Process list - for process enumeration
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from extractor.models.artifact import (
    Artifact,
    ArtifactType,
    EvasionPurpose,
    MatchType,
    OSType,
)
from extractor.extractors.base import (
    BaseExtractor,
    ExtractionContext,
    extract_iocs_from_signature,
    is_evasion_signature,
    categorize_evasion_purpose,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Windows-specific patterns
# =============================================================================

# VM file patterns
WINDOWS_VM_FILE_PATTERNS = {
    "vmware": [
        r"C:\\Windows\\System32\\drivers\\vmhgfs\.sys",
        r"C:\\Windows\\System32\\drivers\\vmmouse\.sys",
        r"C:\\Windows\\System32\\drivers\\vmci\.sys",
        r"C:\\Program Files\\VMware.*",
        r".*vmware.*\.dll",
        r".*vmware.*\.sys",
    ],
    "virtualbox": [
        r"C:\\Windows\\System32\\drivers\\VBoxMouse\.sys",
        r"C:\\Windows\\System32\\drivers\\VBoxGuest\.sys",
        r"C:\\Windows\\System32\\drivers\\VBoxSF\.sys",
        r"C:\\Program Files\\Oracle\\VirtualBox.*",
        r".*vbox.*\.dll",
        r".*vbox.*\.sys",
    ],
    "hyperv": [
        r"C:\\Windows\\System32\\drivers\\vmbus\.sys",
    ],
}

WINDOWS_SANDBOX_FILE_PATTERNS = [
    r".*\\agent\\.*",
    r".*\\cuckoo\\.*",
    r".*\\sandbox\\.*",
    r".*\\sample\\.*",
    r"C:\\Users\\(cuckoo|sandbox|malware|analyst)\\.*",
]

WINDOWS_ANALYSIS_TOOL_FILE_PATTERNS = [
    r".*\\wireshark\\.*",
    r".*\\ida\\.*",
    r".*\\x64dbg\\.*",
    r".*\\ollydbg\\.*",
    r".*\\procmon\\.*",
]

# VM registry keys
WINDOWS_VM_REGISTRY_PATTERNS = {
    "vmware": [
        r"HKLM\\SOFTWARE\\VMware.*",
        r"HKLM\\HARDWARE\\.*vmware.*",
    ],
    "virtualbox": [
        r"HKLM\\SOFTWARE\\Oracle\\VirtualBox.*",
        r"HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX.*",
    ],
}

# VM processes
WINDOWS_VM_PROCESSES = {
    "vmware": ["vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "vmacthlp.exe"],
    "virtualbox": ["VBoxService.exe", "VBoxTray.exe"],
}

WINDOWS_SANDBOX_PROCESSES = [
    "python.exe", "pythonw.exe", "agent.exe", "analyzer.exe",
    "cuckoo.exe", "sandbox.exe",
]

WINDOWS_ANALYSIS_PROCESSES = [
    "wireshark.exe", "fiddler.exe", "procmon.exe", "procexp.exe",
    "tcpview.exe", "autoruns.exe", "idaq.exe", "idaq64.exe",
    "x32dbg.exe", "x64dbg.exe", "ollydbg.exe", "immunitydebugger.exe",
    "windbg.exe", "devenv.exe", "petools.exe", "lordpe.exe", "regshot.exe",
]

# =============================================================================
# WMI Query Patterns
# =============================================================================

# WMI queries used for VM/sandbox detection
WINDOWS_WMI_VM_QUERIES = {
    # Computer system checks
    "Win32_ComputerSystem": {
        "fields": ["Manufacturer", "Model"],
        "vm_values": ["vmware", "virtualbox", "microsoft corporation", "xen", "qemu", "parallels"],
    },
    # BIOS checks
    "Win32_BIOS": {
        "fields": ["SerialNumber", "Version", "Manufacturer"],
        "vm_values": ["vbox", "vmware", "virtual", "qemu", "xen"],
    },
    # Baseboard checks
    "Win32_BaseBoard": {
        "fields": ["Product", "Manufacturer"],
        "vm_values": ["virtualbox", "vmware", "virtual machine"],
    },
    # Disk drive checks
    "Win32_DiskDrive": {
        "fields": ["Model", "Caption"],
        "vm_values": ["vbox", "vmware", "virtual", "qemu"],
    },
    # Network adapter checks
    "Win32_NetworkAdapter": {
        "fields": ["Name", "Description", "MACAddress"],
        "vm_values": ["vmware", "virtualbox", "08:00:27", "00:0c:29", "00:50:56"],
    },
    # Process checks
    "Win32_Process": {
        "fields": ["Name", "CommandLine"],
        "vm_values": [],  # Used for process enumeration
    },
    # Fan check (VMs often have no fans)
    "Win32_Fan": {
        "fields": [],
        "vm_values": [],  # Empty result = likely VM
    },
    # Temperature sensors
    "MSAcpi_ThermalZoneTemperature": {
        "fields": [],
        "vm_values": [],  # Empty or error = likely VM
    },
}

# WMI query patterns from signatures
WINDOWS_WMI_QUERY_PATTERNS = [
    r"SELECT\s+\*\s+FROM\s+Win32_ComputerSystem",
    r"SELECT\s+\*\s+FROM\s+Win32_BIOS",
    r"SELECT\s+\*\s+FROM\s+Win32_BaseBoard",
    r"SELECT\s+\*\s+FROM\s+Win32_DiskDrive",
    r"SELECT\s+\*\s+FROM\s+Win32_NetworkAdapter",
    r"SELECT\s+\*\s+FROM\s+Win32_Process",
    r"SELECT\s+\*\s+FROM\s+Win32_Fan",
    r"SELECT\s+\*\s+FROM\s+MSAcpi_ThermalZoneTemperature",
    r"SELECT\s+Model\s+FROM\s+Win32_ComputerSystem",
    r"SELECT\s+Manufacturer\s+FROM\s+Win32_ComputerSystem",
    r"Win32_ComputerSystem",
    r"Win32_BIOS",
    r"Win32_DiskDrive",
    r"Win32_NetworkAdapter",
]


def categorize_wmi_query(query: str) -> tuple[str, str, EvasionPurpose] | None:
    """
    Categorize a WMI query for evasion detection.
    
    Returns:
        Tuple of (category, wmi_class, evasion_purpose) or None
    """
    query_upper = query.upper()
    
    # Check for known VM detection WMI classes
    for wmi_class, info in WINDOWS_WMI_VM_QUERIES.items():
        if wmi_class.upper() in query_upper:
            return ("vm_wmi", wmi_class, EvasionPurpose.VM)
    
    # Check for generic WMI query patterns
    for pattern in WINDOWS_WMI_QUERY_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            # Extract the WMI class name
            match = re.search(r"Win32_(\w+)|MSAcpi_(\w+)", query, re.IGNORECASE)
            wmi_class = match.group(0) if match else "Unknown"
            return ("vm_wmi", wmi_class, EvasionPurpose.VM)
    
    return None


def matches_any_pattern(value: str, patterns: list[str]) -> bool:
    """Check if value matches any regex pattern (case-insensitive)."""
    for pattern in patterns:
        if re.match(pattern, value, re.IGNORECASE):
            return True
    return False


def categorize_windows_file(path: str) -> tuple[str, EvasionPurpose] | None:
    """Categorize a Windows file path."""
    path_lower = path.lower()
    
    # Check VM patterns
    for vm_type, patterns in WINDOWS_VM_FILE_PATTERNS.items():
        if matches_any_pattern(path, patterns):
            return ("vm_files", EvasionPurpose.VM)
    
    # Check sandbox patterns
    if matches_any_pattern(path, WINDOWS_SANDBOX_FILE_PATTERNS):
        return ("sandbox_files", EvasionPurpose.SANDBOX)
    
    # Check analysis tool patterns
    if matches_any_pattern(path, WINDOWS_ANALYSIS_TOOL_FILE_PATTERNS):
        return ("analysis_tools", EvasionPurpose.RESEARCHER_TOOLS)
    
    return None


def categorize_windows_process(process_name: str) -> tuple[str, EvasionPurpose] | None:
    """Categorize a Windows process name."""
    proc_lower = process_name.lower()
    
    # Check VM processes
    for vm_type, processes in WINDOWS_VM_PROCESSES.items():
        if proc_lower in [p.lower() for p in processes]:
            return ("vm_processes", EvasionPurpose.VM)
    
    # Check sandbox processes
    if proc_lower in [p.lower() for p in WINDOWS_SANDBOX_PROCESSES]:
        return ("sandbox_processes", EvasionPurpose.SANDBOX)
    
    # Check analysis processes
    if proc_lower in [p.lower() for p in WINDOWS_ANALYSIS_PROCESSES]:
        return ("analysis_tools", EvasionPurpose.RESEARCHER_TOOLS)
    
    return None


class WindowsExtractor(BaseExtractor):
    """
    Extractor for Windows evasion artifacts.
    
    Handles:
    - File existence checks
    - Registry key checks
    - Process enumeration
    - WMI queries
    - Mutex checks
    """
    
    os_type = OSType.WINDOWS
    
    categories = [
        "vm_files",
        "vm_registry",
        "vm_processes",
        "vm_services",
        "vm_wmi",
        "sandbox_files",
        "sandbox_registry",
        "sandbox_processes",
        "sandbox_mutexes",
        "analysis_tools",
        "debugger_indicators",
        "hardware_checks",
    ]
    
    def extract(self, context: ExtractionContext) -> list[Artifact]:
        """
        Extract Windows evasion artifacts from the context.
        """
        self.logger.info(f"Extracting Windows artifacts from {context.sample_hash[:16]}...")
        
        artifacts: list[Artifact] = []
        seen_values: set[str] = set()
        
        # 1. Extract from kernel logs if available
        if context.has_kernel_logs:
            self.logger.debug("Using kernel logs for extraction")
            artifacts.extend(self._extract_from_kernel_logs(context, seen_values))
        
        # 2. Extract from signatures
        self.logger.debug("Extracting from signatures")
        artifacts.extend(self._extract_from_signatures(context, seen_values))
        
        # 3. Extract from process list
        self.logger.debug("Extracting from process list")
        artifacts.extend(self._extract_from_processes(context, seen_values))
        
        # 4. Extract WMI queries
        self.logger.debug("Extracting WMI queries")
        artifacts.extend(self._extract_wmi_queries(context, seen_values))
        
        self.logger.info(f"Extracted {len(artifacts)} Windows artifacts")
        return artifacts
    
    def _extract_from_kernel_logs(
        self,
        context: ExtractionContext,
        seen: set[str]
    ) -> list[Artifact]:
        """Extract artifacts from onemon.json kernel logs."""
        artifacts = []
        
        if not context.kernel_logs:
            return artifacts
        
        for entry in context.kernel_logs:
            kind = entry.get("kind", "")

            # Legacy kernel logs
            if kind in ("file_open", "file_stat"):
                artifact = self._process_file_operation(entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)

            elif kind in ("reg_open", "reg_query"):
                artifact = self._process_registry_operation(entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)

            elif kind in ("mutex_open", "mutex_create"):
                artifact = self._process_mutex_operation(entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)

            # OneMon (onemon.json) kernel logs
            elif kind == "onemon.File":
                event = entry.get("event", {})
                for path in [event.get("srcpath"), event.get("dstpath")]:
                    if not path:
                        continue
                    artifact = self._process_file_operation({"path": path}, context.sample_hash, seen)
                    if artifact:
                        artifacts.append(artifact)

            elif kind == "onemon.Registry":
                event = entry.get("event", {})
                reg_path = event.get("path") or event.get("key")
                if reg_path:
                    normalized = self._normalize_registry_path(reg_path)
                    artifact = self._process_registry_operation(
                        {"key": normalized, "value": event.get("value") or event.get("values", "")},
                        context.sample_hash,
                        seen,
                    )
                    if artifact:
                        artifacts.append(artifact)

            elif kind == "onemon.Mutant":
                event = entry.get("event", {})
                name = event.get("path") or event.get("name")
                if name:
                    artifact = self._process_mutex_operation({"name": name}, context.sample_hash, seen)
                    if artifact:
                        artifacts.append(artifact)

            elif kind == "onemon.Process":
                event = entry.get("event", {})
                image = event.get("image") or event.get("command")
                if image:
                    proc_name = Path(str(image)).name
                    categorization = categorize_windows_process(proc_name)
                    if categorization and proc_name not in seen:
                        category, purpose = categorization
                        seen.add(proc_name)
                        artifacts.append(
                            self.create_artifact(
                                artifact_type=ArtifactType.PROCESS,
                                category=category,
                                match_value=proc_name,
                                evasion_purpose=purpose,
                                description=f"Process check: {proc_name}",
                                sample_hash=context.sample_hash,
                                case_sensitive=False,
                            )
                        )
        
        return artifacts

    def _normalize_registry_path(self, path: str) -> str:
        """Normalize native registry paths to HKLM/HKU format."""
        if not path:
            return path
        upper = path.upper()
        if upper.startswith("\\REGISTRY\\MACHINE\\"):
            return "HKLM\\" + path[len("\\REGISTRY\\MACHINE\\"):]
        if upper.startswith("\\REGISTRY\\USER\\"):
            return "HKU\\" + path[len("\\REGISTRY\\USER\\"):]
        if upper.startswith("\\REGISTRY\\CURRENT_USER\\"):
            return "HKCU\\" + path[len("\\REGISTRY\\CURRENT_USER\\"):]
        return path
    
    def _process_file_operation(
        self,
        entry: dict[str, Any],
        sample_hash: str,
        seen: set[str]
    ) -> Artifact | None:
        """Process a file operation from kernel logs."""
        path = entry.get("path", "")
        if not path or path in seen:
            return None
        
        categorization = categorize_windows_file(path)
        if not categorization:
            return None
        
        category, evasion_purpose = categorization
        seen.add(path)
        
        self.logger.debug(f"Found file check: {path} -> {category}")
        
        return self.create_artifact(
            artifact_type=ArtifactType.FILE,
            category=category,
            match_value=path,
            evasion_purpose=evasion_purpose,
            description=f"File existence check: {path}",
            sample_hash=sample_hash,
            case_sensitive=False,  # Windows is case-insensitive
        )
    
    def _process_registry_operation(
        self,
        entry: dict[str, Any],
        sample_hash: str,
        seen: set[str]
    ) -> Artifact | None:
        """Process a registry operation from kernel logs."""
        key = entry.get("key") or entry.get("path", "")
        key = self._normalize_registry_path(key)
        value_name = entry.get("value", "")
        
        if not key:
            return None
        
        # Build match value
        match_value = f"{key}\\{value_name}" if value_name else key
        
        if match_value in seen:
            return None
        
        # Check if this is a VM-related registry key
        is_vm_registry = False
        for vm_type, patterns in WINDOWS_VM_REGISTRY_PATTERNS.items():
            if matches_any_pattern(key, patterns):
                is_vm_registry = True
                break
        
        if not is_vm_registry:
            # Check for sandbox indicators
            if not any(kw in key.lower() for kw in ["sandbox", "cuckoo", "analysis"]):
                return None
        
        seen.add(match_value)
        
        self.logger.debug(f"Found registry check: {match_value}")
        
        return self.create_artifact(
            artifact_type=ArtifactType.REGISTRY,
            category="vm_registry" if is_vm_registry else "sandbox_registry",
            match_value=match_value,
            evasion_purpose=EvasionPurpose.VM if is_vm_registry else EvasionPurpose.SANDBOX,
            description=f"Registry check: {match_value}",
            sample_hash=sample_hash,
            case_sensitive=False,
        )
    
    def _process_mutex_operation(
        self,
        entry: dict[str, Any],
        sample_hash: str,
        seen: set[str]
    ) -> Artifact | None:
        """Process a mutex operation from kernel logs."""
        name = entry.get("name", "")
        if not name or name in seen:
            return None
        
        # Check for known sandbox mutexes
        sandbox_mutex_keywords = ["cuckoo", "sandbox", "joe", "any.run", "wireshark", "fiddler"]
        
        if not any(kw in name.lower() for kw in sandbox_mutex_keywords):
            return None
        
        seen.add(name)
        
        self.logger.debug(f"Found mutex check: {name}")
        
        return self.create_artifact(
            artifact_type=ArtifactType.MUTEX,
            category="sandbox_mutexes",
            match_value=name,
            evasion_purpose=EvasionPurpose.SANDBOX,
            description=f"Mutex check: {name}",
            sample_hash=sample_hash,
            deception_notes="Create mutex with this name on startup",
        )
    
    def _extract_from_signatures(
        self,
        context: ExtractionContext,
        seen: set[str]
    ) -> list[Artifact]:
        """Extract artifacts from behavioral signatures."""
        artifacts = []
        
        for signature in context.signatures:
            if not is_evasion_signature(signature):
                continue
            
            sig_name = signature.get("name", "unknown")
            self.logger.debug(f"Processing evasion signature: {sig_name}")
            
            iocs = extract_iocs_from_signature(signature)
            evasion_purpose = categorize_evasion_purpose(signature)
            
            for ioc in iocs:
                if ioc in seen:
                    continue
                
                artifact = self._categorize_ioc(ioc, signature, context.sample_hash, evasion_purpose)
                if artifact:
                    seen.add(ioc)
                    artifacts.append(artifact)
        
        return artifacts
    
    def _categorize_ioc(
        self,
        ioc: str,
        signature: dict[str, Any],
        sample_hash: str,
        evasion_purpose: EvasionPurpose | None
    ) -> Artifact | None:
        """Categorize an IOC and create an appropriate artifact."""
        
        # Check if it looks like a file path
        if ioc.startswith("C:") or ioc.startswith("\\"):
            categorization = categorize_windows_file(ioc)
            if categorization:
                category, purpose = categorization
                return self.create_artifact(
                    artifact_type=ArtifactType.FILE,
                    category=category,
                    match_value=ioc,
                    evasion_purpose=purpose,
                    description=f"From signature: {signature.get('name', '')}",
                    sample_hash=sample_hash,
                    case_sensitive=False,
                )
        
        # Check if it looks like a registry key
        if ioc.startswith("HKLM") or ioc.startswith("HKEY") or ioc.startswith("HKU"):
            return self.create_artifact(
                artifact_type=ArtifactType.REGISTRY,
                category="vm_registry",
                match_value=ioc,
                evasion_purpose=evasion_purpose or EvasionPurpose.VM,
                description=f"From signature: {signature.get('name', '')}",
                sample_hash=sample_hash,
                case_sensitive=False,
            )
        
        # Check if it looks like a process name
        if ioc.endswith(".exe"):
            categorization = categorize_windows_process(ioc)
            if categorization:
                category, purpose = categorization
                return self.create_artifact(
                    artifact_type=ArtifactType.PROCESS,
                    category=category,
                    match_value=ioc,
                    evasion_purpose=purpose,
                    description=f"From signature: {signature.get('name', '')}",
                    sample_hash=sample_hash,
                    case_sensitive=False,
                )
        
        return None
    
    def _extract_from_processes(
        self,
        context: ExtractionContext,
        seen: set[str]
    ) -> list[Artifact]:
        """
        Extract from the process list.
        
        The presence of certain processes in the behavioral report
        indicates the malware was checking for them.
        """
        artifacts = []
        
        # Note: The process list in behavioral reports is what ran,
        # not necessarily what the malware checked for.
        # We mainly use this to augment kernel log data.
        
        # For now, we don't extract from the process list directly
        # as it's more likely to produce false positives.
        
        return artifacts
    
    def _extract_wmi_queries(
        self,
        context: ExtractionContext,
        seen: set[str]
    ) -> list[Artifact]:
        """
        Extract WMI queries used for VM/sandbox detection.
        
        WMI is commonly used to query hardware info and detect VMs.
        Data sources:
        1. Kernel logs (wmi_query entries)
        2. Behavioral report (wmi section)
        3. Signatures with WMI-related IOCs
        """
        artifacts = []
        
        # 1. Check kernel logs for WMI queries
        if context.kernel_logs:
            for entry in context.kernel_logs:
                kind = entry.get("kind", "")
                if kind in ("wmi_query", "wmi"):
                    artifact = self._process_wmi_entry(entry, context.sample_hash, seen)
                    if artifact:
                        artifacts.append(artifact)
        
        # 2. Check behavioral report for WMI section
        wmi_data = context.behavioral_report.get("wmi", [])
        if isinstance(wmi_data, list):
            for wmi_entry in wmi_data:
                artifact = self._process_wmi_entry(wmi_entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
        
        # 3. Check signatures for WMI-related IOCs
        for signature in context.signatures:
            if not is_evasion_signature(signature):
                continue
            
            sig_name = signature.get("name", "").lower()
            
            # Look for WMI-related signatures
            if "wmi" in sig_name or "win32_" in sig_name.lower():
                iocs = extract_iocs_from_signature(signature)
                for ioc in iocs:
                    artifact = self._process_wmi_ioc(ioc, signature, context.sample_hash, seen)
                    if artifact:
                        artifacts.append(artifact)
        
        return artifacts
    
    def _process_wmi_entry(
        self,
        entry: dict[str, Any],
        sample_hash: str,
        seen: set[str]
    ) -> Artifact | None:
        """Process a WMI query entry from kernel logs or behavioral report."""
        # Get the query string
        query = entry.get("query", "") or entry.get("wql", "") or entry.get("text", "")
        if not query:
            return None
        
        # Skip if already seen
        if query in seen:
            return None
        
        # Categorize the query
        result = categorize_wmi_query(query)
        if not result:
            return None
        
        category, wmi_class, evasion_purpose = result
        seen.add(query)
        
        # Create a normalized match value
        # Use the WMI class for deduplication, but store full query in description
        match_value = wmi_class
        
        return self.create_artifact(
            artifact_type=ArtifactType.WMI,
            category=category,
            match_value=match_value,
            evasion_purpose=evasion_purpose,
            description=f"WMI query: {query[:100]}",
            sample_hash=sample_hash,
            case_sensitive=False,
        )
    
    def _process_wmi_ioc(
        self,
        ioc: str,
        signature: dict[str, Any],
        sample_hash: str,
        seen: set[str]
    ) -> Artifact | None:
        """Process a WMI-related IOC from a signature."""
        if not ioc or ioc in seen:
            return None
        
        # Check if this looks like a WMI class or query
        result = categorize_wmi_query(ioc)
        if not result:
            return None
        
        category, wmi_class, evasion_purpose = result
        seen.add(ioc)
        
        sig_name = signature.get("name", "Unknown signature")
        
        return self.create_artifact(
            artifact_type=ArtifactType.WMI,
            category=category,
            match_value=wmi_class,
            evasion_purpose=evasion_purpose,
            description=f"From signature: {sig_name}",
            sample_hash=sample_hash,
            case_sensitive=False,
        )