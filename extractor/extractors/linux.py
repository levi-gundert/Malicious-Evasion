"""
Linux-specific artifact extractor.

Extracts evasion artifacts from Linux behavioral reports:
- Filesystem checks (VM files, container indicators, analysis tools)
- Process enumeration
- Environment variable checks

Note: Triage's Linux kernel logs (stahp.json) use Base64 encoding for paths
and have a nested event structure with 'kind' field indicating entry type.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Any

from extractor.extractors.base import (
    BaseExtractor,
    ExtractionContext,
    extract_iocs_from_signature,
    is_evasion_signature,
    categorize_evasion_purpose,
    is_loopback_address,
)
from extractor.models.artifact import (
    Artifact,
    ArtifactType,
    EvasionPurpose,
    MatchType,
    OSType,
)

logger = logging.getLogger(__name__)


def decode_base64_safe(value: Any) -> str:
    """Safely decode a Base64 string, returning empty string on failure."""
    if not value:
        return ""
    # Handle non-string values (e.g., integers in kernel logs)
    if not isinstance(value, str):
        return str(value)
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except Exception:
        return value  # Return as-is if not valid Base64


# =============================================================================
# Linux-specific patterns
# =============================================================================

# VM detection file patterns
LINUX_VM_FILE_PATTERNS = [
    # VMware
    r"/usr/bin/vmware-toolbox-cmd",
    r"/usr/bin/vmtoolsd",
    r"/etc/vmware-tools",
    r".*vmware.*",
    # VirtualBox
    r"/usr/bin/VBoxClient",
    r"/usr/bin/VBoxControl",
    r"/usr/sbin/VBoxService",
    r".*vbox.*",
    # QEMU/KVM
    r"/usr/bin/qemu-.*",
    r"/dev/kvm",
    r".*qemu.*",
    # Xen
    r"/proc/xen",
    r".*xen.*",
    # Hyper-V
    r"/usr/bin/hv_.*",
    r".*hyper-v.*",
    # Generic VM indicators
    r"/sys/class/dmi/id/product_name",
    r"/sys/class/dmi/id/sys_vendor",
    r"/sys/hypervisor/type",
]

# Container detection patterns
LINUX_CONTAINER_PATTERNS = [
    r"/.dockerenv",
    r"/run/.containerenv",
    r"/proc/1/cgroup",
    r"/proc/self/cgroup",
    r"/sys/fs/cgroup",
    r".*docker.*",
    r".*container.*",
    r".*lxc.*",
    r".*kubernetes.*",
    r".*k8s.*",
]

# Sandbox/analysis file patterns
LINUX_SANDBOX_FILE_PATTERNS = [
    r"/usr/bin/strace",
    r"/usr/bin/ltrace",
    r"/usr/bin/gdb",
    r"/usr/bin/radare2",
    r"/usr/bin/r2",
    r"/usr/bin/objdump",
    r"/usr/bin/tcpdump",
    r"/usr/sbin/tcpdump",
    r"/usr/bin/wireshark",
    r".*cuckoo.*",
    r".*sandbox.*",
    r".*malware.*",
    r".*analysis.*",
]

# Debugger indicators
LINUX_DEBUGGER_PATTERNS = [
    r"/proc/self/status",  # TracerPid check
    r"/proc/self/exe",
    r"/proc/self/cmdline",
    r"/proc/self/maps",
    r"/proc/self/fd",
    r".*ptrace.*",
    r".*debugger.*",
]

# System discovery patterns (often used for evasion fingerprinting)
LINUX_SYSTEM_DISCOVERY_PATTERNS = [
    # CPU/Hardware info
    r"/proc/cpuinfo",
    r"/proc/meminfo",
    r"/proc/version",
    r"/proc/uptime",
    r"/proc/stat",
    r"/proc/loadavg",
    # Disk/Device info
    r"/proc/scsi/scsi",
    r"/proc/ide/.*",
    r"/proc/diskstats",
    r"/sys/block/.*",
    r"/sys/devices/.*",
    # DMI/SMBIOS
    r"/sys/class/dmi/id/.*",
    r"/sys/firmware/dmi/.*",
    # Network info
    r"/proc/net/.*",
    r"/sys/class/net/.*",
    # System locale/timezone
    r"/etc/timezone",
    r"/etc/localtime",
    r"/etc/locale.*",
    r"/etc/default/locale",
    # Hostname/machine-id
    r"/etc/hostname",
    r"/etc/machine-id",
    r"/var/lib/dbus/machine-id",
    # User enumeration
    r"/etc/passwd",
    r"/etc/shadow",
    r"/etc/group",
    # Boot info
    r"/proc/cmdline",
    r"/boot/.*",
]

# Analysis tool process patterns
LINUX_ANALYSIS_PROCESS_PATTERNS = [
    r"gdb",
    r"strace",
    r"ltrace",
    r"radare2",
    r"r2",
    r"ida.*",
    r"ghidra.*",
    r"tcpdump",
    r"wireshark",
    r"tshark",
    r"burpsuite",
    r"mitmproxy",
]

# VM process patterns
LINUX_VM_PROCESS_PATTERNS = [
    r"vmtoolsd",
    r"vmware.*",
    r"VBoxClient",
    r"VBoxService",
    r"qemu-ga",
    r"qemu.*",
    r"xen.*",
    r"hv_.*",
]

# Environment variables checked for evasion
LINUX_ENV_PATTERNS = [
    r"LD_PRELOAD",
    r"LD_DEBUG",
    r"DISPLAY",
    r"USER",
    r"HOME",
    r"SHELL",
    r"TERM",
    r"SSH_.*",
    r"container",
    r"KUBERNETES.*",
]


def categorize_linux_file(path: Any) -> tuple[str, EvasionPurpose | None]:
    """
    Categorize a Linux file path for evasion detection.
    
    Returns:
        Tuple of (category, evasion_purpose)
    """
    # Handle non-string values safely
    if not isinstance(path, str):
        return "", None
    path_lower = path.lower()
    
    # VM files
    for pattern in LINUX_VM_FILE_PATTERNS:
        if re.match(pattern, path_lower):
            return "vm_files", EvasionPurpose.VM
    
    # Container indicators
    for pattern in LINUX_CONTAINER_PATTERNS:
        if re.match(pattern, path_lower):
            return "container_indicators", EvasionPurpose.CONTAINER
    
    # Sandbox/analysis files
    for pattern in LINUX_SANDBOX_FILE_PATTERNS:
        if re.match(pattern, path_lower):
            return "analysis_tools", EvasionPurpose.SANDBOX
    
    # Debugger indicators
    for pattern in LINUX_DEBUGGER_PATTERNS:
        if re.match(pattern, path_lower):
            return "debugger_indicators", EvasionPurpose.DEBUGGER
    
    # System discovery (fingerprinting for evasion)
    for pattern in LINUX_SYSTEM_DISCOVERY_PATTERNS:
        if re.match(pattern, path_lower):
            return "system_discovery", EvasionPurpose.SANDBOX
    
    return "", None


def categorize_linux_process(name: Any) -> tuple[str, EvasionPurpose | None]:
    """
    Categorize a Linux process name for evasion detection.
    
    Returns:
        Tuple of (category, evasion_purpose)
    """
    # Handle non-string values safely
    if not isinstance(name, str):
        return "", None
    name_lower = name.lower()
    
    # Analysis tools
    for pattern in LINUX_ANALYSIS_PROCESS_PATTERNS:
        if re.match(pattern, name_lower):
            return "analysis_tools", EvasionPurpose.SANDBOX
    
    # VM processes
    for pattern in LINUX_VM_PROCESS_PATTERNS:
        if re.match(pattern, name_lower):
            return "vm_processes", EvasionPurpose.VM
    
    return "", None


class LinuxExtractor(BaseExtractor):
    """
    Extractor for Linux evasion artifacts.
    
    Handles:
    - Filesystem checks (VM, container, sandbox detection)
    - Process enumeration
    - Environment variable checks
    - /proc filesystem queries
    """
    
    os_type = OSType.LINUX
    categories = [
        "vm_files",
        "container_indicators",
        "analysis_tools",
        "debugger_indicators",
        "vm_processes",
        "environment_vars",
    ]
    
    def extract(self, context: ExtractionContext) -> list[Artifact]:
        """Extract Linux evasion artifacts."""
        artifacts: list[Artifact] = []
        seen: set[str] = set()
        
        self.logger.info(f"Extracting Linux artifacts for {context.sample_hash[:8]}...")
        
        # Extract from kernel logs if available
        if context.has_kernel_logs:
            artifacts.extend(self._extract_from_kernel_logs(context, seen))
        
        # Extract from signatures
        artifacts.extend(self._extract_from_signatures(context, seen))
        
        # Extract from process list
        artifacts.extend(self._extract_from_processes(context, seen))
        
        self.logger.info(f"Extracted {len(artifacts)} Linux artifacts")
        return artifacts
    
    def _extract_from_kernel_logs(
        self,
        context: ExtractionContext,
        seen: set[str],
    ) -> list[Artifact]:
        """
        Extract artifacts from stahp.json kernel logs.
        
        Triage's stahp.json format uses:
        - kind: "stahp.File", "stahp.Process", "stahp.Syscall*", etc.
        - event: nested dict with actual data, paths are Base64 encoded
        """
        artifacts = []
        
        if not context.kernel_logs:
            return artifacts
        
        # Limit processing to avoid hanging on massive kernel logs (some samples have millions of entries)
        MAX_KERNEL_LOG_ENTRIES = 50000
        MAX_ARTIFACTS_PER_SOURCE = 500
        
        log_count = len(context.kernel_logs)
        if log_count > MAX_KERNEL_LOG_ENTRIES:
            self.logger.warning(
                f"Kernel logs too large ({log_count} entries), limiting to first {MAX_KERNEL_LOG_ENTRIES}"
            )
        
        for i, entry in enumerate(context.kernel_logs):
            # Stop if we've processed enough entries
            if i >= MAX_KERNEL_LOG_ENTRIES:
                self.logger.debug(f"Reached kernel log entry limit ({MAX_KERNEL_LOG_ENTRIES})")
                break
            
            # Stop if we've found enough artifacts from this source
            if len(artifacts) >= MAX_ARTIFACTS_PER_SOURCE:
                self.logger.debug(f"Reached artifact limit ({MAX_ARTIFACTS_PER_SOURCE}) from kernel logs")
                break
            kind = entry.get("kind", "")
            event = entry.get("event", {})
            
            # Handle Triage stahp.json format (kind starts with "stahp.")
            if kind == "stahp.File":
                artifact = self._process_stahp_file(event, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
            
            elif kind == "stahp.Process":
                artifact = self._process_stahp_process(event, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
            
            elif kind.startswith("stahp.Syscall"):
                artifact = self._process_stahp_syscall(event, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
            
            # Also handle legacy format (kind is file_stat, file_open, etc.)
            elif kind in ("file_stat", "file_open", "file_access"):
                artifact = self._process_file_operation(entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
            
            elif kind == "env_read":
                artifact = self._process_env_read(entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
        
        return artifacts
    
    def _process_stahp_file(
        self,
        event: dict[str, Any],
        sample_hash: str,
        seen: set[str],
    ) -> Artifact | None:
        """Process a stahp.File event from kernel logs."""
        # Get path from srcpath (Base64 encoded)
        srcpath_b64 = event.get("srcpath", "")
        path = decode_base64_safe(srcpath_b64)
        
        if not path:
            return None
        
        # Skip if already seen
        if path in seen:
            return None
        
        # Categorize the path
        category, evasion_purpose = categorize_linux_file(path)
        if not category:
            return None
        
        seen.add(path)
        file_kind = event.get("kind", "access")  # OpenRead, OpenWrite, etc.
        
        return self.create_artifact(
            artifact_type=ArtifactType.FILE,
            category=category,
            match_value=path,
            evasion_purpose=evasion_purpose,
            description=f"File {file_kind}: {path}",
            sample_hash=sample_hash,
        )
    
    def _process_stahp_process(
        self,
        event: dict[str, Any],
        sample_hash: str,
        seen: set[str],
    ) -> Artifact | None:
        """Process a stahp.Process event from kernel logs."""
        image = event.get("Image", "")
        if not image:
            return None
        
        # Get just the process name from the path
        if "/" in image:
            name = image.split("/")[-1]
        else:
            name = image
        
        if name in seen:
            return None
        
        # Check for evasion-related processes
        category, purpose = categorize_linux_process(name)
        if category:
            seen.add(name)
            return self.create_artifact(
                artifact_type=ArtifactType.PROCESS,
                category=category,
                match_value=name,
                evasion_purpose=purpose,
                description=f"Process: {image}",
                sample_hash=sample_hash,
            )
        
        # Also check the full path for VM/container indicators
        category, purpose = categorize_linux_file(image)
        if category:
            seen.add(image)
            return self.create_artifact(
                artifact_type=ArtifactType.FILE,
                category=category,
                match_value=image,
                evasion_purpose=purpose,
                description=f"Process image: {image}",
                sample_hash=sample_hash,
            )
        
        return None
    
    def _process_stahp_syscall(
        self,
        event: dict[str, Any],
        sample_hash: str,
        seen: set[str],
    ) -> Artifact | None:
        """Process a stahp.Syscall* event from kernel logs."""
        syscall_kind = event.get("kind", "")
        
        # Look for file-related syscalls with path arguments
        if syscall_kind in ("stat", "lstat", "access", "open", "openat", "readlink", "chdir"):
            # arg0 is usually the path (Base64 encoded)
            path_b64 = event.get("arg0", "")
            path = decode_base64_safe(path_b64)
            
            if path and path not in seen:
                category, purpose = categorize_linux_file(path)
                if category:
                    seen.add(path)
                    return self.create_artifact(
                        artifact_type=ArtifactType.FILE,
                        category=category,
                        match_value=path,
                        evasion_purpose=purpose,
                        description=f"Syscall {syscall_kind}: {path}",
                        sample_hash=sample_hash,
                    )
        
        return None
    
    def _process_file_operation(
        self,
        entry: dict[str, Any],
        sample_hash: str,
        seen: set[str],
    ) -> Artifact | None:
        """Process a file operation from kernel logs."""
        path = entry.get("path", "") or entry.get("filename", "")
        if not path:
            return None
        
        # Skip if already seen
        if path in seen:
            return None
        
        # Categorize the path
        category, evasion_purpose = categorize_linux_file(path)
        if not category:
            return None
        
        seen.add(path)
        
        return self.create_artifact(
            artifact_type=ArtifactType.FILE,
            category=category,
            match_value=path,
            evasion_purpose=evasion_purpose,
            description=f"File access: {path}",
            sample_hash=sample_hash,
        )
    
    def _process_env_read(
        self,
        entry: dict[str, Any],
        sample_hash: str,
        seen: set[str],
    ) -> Artifact | None:
        """Process an environment variable read from kernel logs."""
        env_name = entry.get("name", "") or entry.get("key", "")
        if not env_name:
            return None
        
        # Skip if already seen
        key = f"env:{env_name}"
        if key in seen:
            return None
        
        # Check if this is an evasion-related env var
        is_evasion = False
        for pattern in LINUX_ENV_PATTERNS:
            if re.match(pattern, env_name, re.IGNORECASE):
                is_evasion = True
                break
        
        if not is_evasion:
            return None
        
        seen.add(key)
        
        # Determine evasion purpose
        if env_name.upper() in ("LD_PRELOAD", "LD_DEBUG"):
            purpose = EvasionPurpose.DEBUGGER
        elif env_name.upper() in ("container", "KUBERNETES_SERVICE_HOST"):
            purpose = EvasionPurpose.CONTAINER
        else:
            purpose = EvasionPurpose.SANDBOX
        
        return self.create_artifact(
            artifact_type=ArtifactType.ENVIRONMENT_VAR,
            category="environment_vars",
            match_value=env_name,
            evasion_purpose=purpose,
            description=f"Environment variable check: {env_name}",
            sample_hash=sample_hash,
        )
    
    def _extract_from_signatures(
        self,
        context: ExtractionContext,
        seen: set[str],
    ) -> list[Artifact]:
        """Extract artifacts from behavioral signatures."""
        artifacts = []
        
        for signature in context.signatures:
            if not is_evasion_signature(signature):
                continue
            
            # Get evasion purpose from signature
            sig_name = signature.get("name", "")
            evasion_purpose = categorize_evasion_purpose(signature)
            
            # Extract IOCs
            iocs = extract_iocs_from_signature(signature)
            
            for ioc in iocs:
                artifact = self._categorize_ioc(ioc, signature, context.sample_hash, evasion_purpose, seen)
                if artifact:
                    artifacts.append(artifact)
        
        return artifacts
    
    def _categorize_ioc(
        self,
        ioc: str,
        signature: dict[str, Any],
        sample_hash: str,
        evasion_purpose: EvasionPurpose | None,
        seen: set[str],
    ) -> Artifact | None:
        """Categorize an IOC from a signature."""
        if not ioc or ioc in seen:
            return None
        
        sig_name = signature.get("name", "Unknown signature")
        
        # Check if it's a file path
        if ioc.startswith("/"):
            category, purpose = categorize_linux_file(ioc)
            if category:
                seen.add(ioc)
                return self.create_artifact(
                    artifact_type=ArtifactType.FILE,
                    category=category,
                    match_value=ioc,
                    evasion_purpose=purpose or evasion_purpose,
                    description=f"From signature: {sig_name}",
                    sample_hash=sample_hash,
                )
        
        # Check if it's an environment variable
        if ioc.isupper() or ioc.startswith("LD_"):
            for pattern in LINUX_ENV_PATTERNS:
                if re.match(pattern, ioc, re.IGNORECASE):
                    seen.add(ioc)
                    return self.create_artifact(
                        artifact_type=ArtifactType.ENVIRONMENT_VAR,
                        category="environment_vars",
                        match_value=ioc,
                        evasion_purpose=evasion_purpose or EvasionPurpose.SANDBOX,
                        description=f"From signature: {sig_name}",
                        sample_hash=sample_hash,
                    )
        
        # Check if it's a process name
        category, purpose = categorize_linux_process(ioc)
        if category:
            seen.add(ioc)
            return self.create_artifact(
                artifact_type=ArtifactType.PROCESS,
                category=category,
                match_value=ioc,
                evasion_purpose=purpose or evasion_purpose,
                description=f"From signature: {sig_name}",
                sample_hash=sample_hash,
            )
        
        return None
    
    def _extract_from_processes(
        self,
        context: ExtractionContext,
        seen: set[str],
    ) -> list[Artifact]:
        """Extract artifacts from process enumeration."""
        artifacts = []
        
        for process in context.processes:
            name = process.get("name", "") or process.get("image", "")
            if not name:
                continue
            
            # Get just the process name
            if "/" in name:
                name = name.split("/")[-1]
            
            if name in seen:
                continue
            
            category, purpose = categorize_linux_process(name)
            if category:
                seen.add(name)
                artifacts.append(self.create_artifact(
                    artifact_type=ArtifactType.PROCESS,
                    category=category,
                    match_value=name,
                    evasion_purpose=purpose,
                    description=f"Process enumeration: {name}",
                    sample_hash=context.sample_hash,
                ))
        
        return artifacts
