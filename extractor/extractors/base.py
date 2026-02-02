"""
Base extractor interface and shared utilities.

All OS-specific extractors inherit from BaseExtractor and implement
the extract() method to pull artifacts from behavioral reports.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from extractor.models.artifact import (
    Artifact,
    ArtifactType,
    Deception,
    EvasionPurpose,
    MatchCriteria,
    MatchType,
    Metadata,
    OSType,
    Provenance,
)
from extractor.models.sample import SampleMetadata

logger = logging.getLogger(__name__)


@dataclass
class ExtractionContext:
    """
    Context for an extraction run.
    
    Contains all data sources available for extraction.
    """
    sample_metadata: SampleMetadata
    behavioral_report: dict[str, Any]
    kernel_logs: list[dict[str, Any]] | None = None
    
    # Extracted from behavioral_report for convenience
    signatures: list[dict[str, Any]] = field(default_factory=list)
    processes: list[dict[str, Any]] = field(default_factory=list)
    network_flows: list[dict[str, Any]] = field(default_factory=list)
    dumped_files: list[dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        """Extract commonly used fields from behavioral report."""
        # Debug: Log what data sources we have
        logger.debug(f"ExtractionContext for sample: {self.sample_metadata.triage.sample_id}")
        logger.debug(f"  Kernel logs: {'available' if self.kernel_logs else 'NOT available'}")
        
        # Extract nested data
        self.signatures = self.behavioral_report.get("signatures", [])
        self.processes = self.behavioral_report.get("processes", [])
        
        network = self.behavioral_report.get("network", {})
        self.network_flows = network.get("flows", [])
        
        self.dumped_files = self.behavioral_report.get("dumped", [])
        
        logger.debug(f"  Signatures: {len(self.signatures)}")
        logger.debug(f"  Processes: {len(self.processes)}")
        logger.debug(f"  Network flows: {len(self.network_flows)}")
        logger.debug(f"  Dumped files: {len(self.dumped_files)}")
    
    @property
    def has_kernel_logs(self) -> bool:
        """Check if kernel logs are available."""
        return self.kernel_logs is not None and len(self.kernel_logs) > 0
    
    @property
    def sample_hash(self) -> str:
        """Get the sample's SHA256 hash."""
        return self.sample_metadata.sha256


class BaseExtractor(ABC):
    """
    Base class for OS-specific extractors.
    
    Subclasses implement extract() to pull artifacts from behavioral data.
    """
    
    # OS this extractor handles
    os_type: OSType
    
    # Categories this extractor can extract
    categories: list[str] = []
    
    def __init__(self):
        """Initialize the extractor."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    def extract(self, context: ExtractionContext) -> list[Artifact]:
        """
        Extract artifacts from the given context.
        
        Args:
            context: Extraction context with all available data
            
        Returns:
            List of extracted artifacts
        """
        pass
    
    def create_artifact(
        self,
        artifact_type: ArtifactType,
        category: str,
        match_value: str,
        match_type: MatchType = MatchType.EXACT,
        evasion_purpose: EvasionPurpose | None = None,
        description: str = "",
        sample_hash: str = "",
        case_sensitive: bool | None = None,
        deception_value: str = "",
        deception_notes: str = "",
    ) -> Artifact:
        """
        Create an artifact with common fields filled in.
        
        Args:
            artifact_type: Type of artifact
            category: Category within the OS
            match_value: Value to match
            match_type: How to match (exact, pattern, etc.)
            evasion_purpose: What malware is detecting
            description: Human-readable description
            sample_hash: SHA256 of source sample
            case_sensitive: Override case sensitivity (default based on OS)
            deception_value: Recommended value for deception
            deception_notes: Notes for implementing deception
        """
        # Debug: Log artifact creation
        self.logger.debug(f"Creating {artifact_type.value} artifact: {match_value[:50]}...")
        
        # Determine case sensitivity based on OS if not specified
        if case_sensitive is None:
            case_sensitive = self.os_type in (OSType.ANDROID, OSType.LINUX, OSType.MACOS)
        
        # Build provenance
        provenance = Provenance(sample_count=1)
        if sample_hash:
            provenance.sample_hashes = [sample_hash]
        
        now = datetime.now(timezone.utc)
        
        return Artifact(
            os=self.os_type,
            category=category,
            artifact_type=artifact_type,
            match_criteria=MatchCriteria(
                type=match_type,
                value=match_value,
                case_sensitive=case_sensitive,
            ),
            metadata=Metadata(
                description=description,
                evasion_purpose=evasion_purpose,
                first_seen=now,
                last_seen=now,
            ),
            provenance=provenance,
            deception=Deception(
                recommended_value=deception_value,
                notes=deception_notes,
            ),
        )


# =============================================================================
# Shared extraction utilities
# =============================================================================

def extract_iocs_from_signature(signature: dict[str, Any]) -> list[str]:
    """
    Extract IOC values from a signature's indicators and marks.
    
    Args:
        signature: Signature dict from behavioral report
        
    Returns:
        List of IOC strings
    """
    iocs = []
    
    # Extract from indicators array
    indicators = signature.get("indicators", [])
    for indicator in indicators:
        ioc = indicator.get("ioc", "")
        if ioc:
            iocs.append(ioc)
    
    # Extract from marks array (Triage format)
    marks = signature.get("marks", [])
    for mark in marks:
        # Marks can have various fields depending on type
        if isinstance(mark, dict):
            # Check common IOC fields
            for field in ["ioc", "path", "key", "value", "query", "name", "file", "registry"]:
                val = mark.get(field, "")
                if val and isinstance(val, str) and len(val) > 3:
                    iocs.append(val)
            
            # Check call field for API calls
            call = mark.get("call", {})
            if isinstance(call, dict):
                for arg in call.get("arguments", []):
                    if isinstance(arg, dict):
                        val = arg.get("value", "")
                        if val and isinstance(val, str):
                            # Filter for path-like or registry-like strings
                            if any(x in val.lower() for x in [":\\", "hklm", "hkcu", "hkey", ".dll", ".sys", ".exe"]):
                                iocs.append(val)
    
    # Extract from desc field (sometimes has paths)
    desc = signature.get("desc", "")
    if desc:
        # Look for file paths in description
        import re
        path_pattern = r'[A-Za-z]:\\[^\s"\'<>|*?]+|\\\\[^\s"\'<>|*?]+'
        paths = re.findall(path_pattern, desc)
        iocs.extend(paths)
    
    return iocs


def is_evasion_signature(signature: dict[str, Any]) -> bool:
    """
    Check if a signature is related to evasion/anti-analysis.
    
    Args:
        signature: Signature dict from behavioral report
        
    Returns:
        True if this is an evasion-related signature
    """
    # Check tags
    tags = signature.get("tags", [])
    evasion_tags = {
        "evasion", "anti-vm", "anti-sandbox", "anti-debug",
        "anti-analysis", "defense_evasion", "anti_vm",
        "anti_sandbox", "anti_debug", "anti_analysis",
        # Discovery techniques are often used for evasion
        "discovery", "reconnaissance",
    }
    
    for tag in tags:
        if tag.lower() in evasion_tags:
            return True
    
    # Check signature name/label
    name = signature.get("name", "").lower()
    label = signature.get("label", "").lower()
    
    evasion_keywords = [
        "anti_vm", "anti-vm", "antivm",
        "anti_sandbox", "anti-sandbox", "antisandbox",
        "anti_debug", "anti-debug", "antidebug",
        "anti_analysis", "anti-analysis", "antianalysis",
        "evasion", "evade", "detect",
        "emulator", "virtualization", "virtual_machine",
        "sandbox", "debugger", "frida", "xposed",
        "root_detect", "root_check", "rooted", "is_root", "root",
        "sensor",  # sensor checks for emulator detection
        # Common evasion technique signatures from Triage
        "checks cpu", "cpu information", "cpu info",
        "checks memory", "memory information", "memory info",
        "checks disk", "disk information", "disk size",
        "checks bios", "bios information",
        "checks hardware", "hardware id",
        "checks mac address", "mac address",
        "checks username", "user name",
        "checks computer name", "computer name", "hostname",
        "checks registry", "registry key", "registry value",
        "checks process", "process enumeration", "process list",
        "vmware", "virtualbox", "vbox", "hyper-v", "hyperv",
        "qemu", "xen", "kvm", "parallels", "bochs",
        "wine", "anubis", "cwsandbox", "joesandbox", "threatexpert",
        "wmi query", "win32_",
        "timing check", "sleep", "tick count", "rdtsc",
        "ntquerysystem", "ntqueryinformation",
        "isdebugger", "isdebuggerpresent", "checkremotedebugger",
        "outputdebugstring", "ntsetinformationthread",
    ]
    
    for keyword in evasion_keywords:
        if keyword in name or keyword in label:
            return True
    
    # Check TTPs - Various evasion and discovery TTPs
    ttps = signature.get("ttp", [])
    evasion_ttps = {
        # Defense Evasion: Virtualization/Sandbox Evasion
        "T1497", "T1497.001", "T1497.002", "T1497.003",
        # Debugger Evasion
        "T1622",
        # Virtualization/Sandbox Evasion (Mobile)
        "T1633", "T1633.001",
        # Discovery techniques often used for evasion
        "T1082",  # System Information Discovery
        "T1614", "T1614.001",  # System Location Discovery
        "T1057",  # Process Discovery
        "T1012",  # Query Registry
        "T1518",  # Software Discovery
        "T1083",  # File and Directory Discovery
        "T1007",  # System Service Discovery
    }
    
    for ttp in ttps:
        if ttp in evasion_ttps:
            return True
    
    return False


def categorize_evasion_purpose(signature: dict[str, Any]) -> EvasionPurpose | None:
    """
    Determine the evasion purpose from a signature.
    
    Args:
        signature: Signature dict
        
    Returns:
        EvasionPurpose or None if not determinable
    """
    name = signature.get("name", "").lower()
    label = signature.get("label", "").lower()
    desc = signature.get("desc", "").lower()
    tags = [t.lower() for t in signature.get("tags", [])]
    
    combined = f"{name} {label} {desc} {' '.join(tags)}"
    
    if any(kw in combined for kw in ["emulator", "qemu", "goldfish", "genymotion"]):
        return EvasionPurpose.EMULATOR
    
    if any(kw in combined for kw in ["sandbox", "cuckoo", "any.run", "triage", "joe"]):
        return EvasionPurpose.SANDBOX
    
    if any(kw in combined for kw in ["debug", "debugger", "tracer", "ptrace"]):
        return EvasionPurpose.DEBUGGER
    
    if any(kw in combined for kw in ["vm", "virtual", "vmware", "virtualbox", "hyper-v"]):
        return EvasionPurpose.VM
    
    if any(kw in combined for kw in ["frida", "xposed", "hook", "substrate"]):
        return EvasionPurpose.HOOKING
    
    if any(kw in combined for kw in ["root", "su ", "superuser", "magisk"]):
        return EvasionPurpose.ROOT
    
    if any(kw in combined for kw in ["wireshark", "tcpdump", "procmon", "ida", "ghidra"]):
        return EvasionPurpose.RESEARCHER_TOOLS
    
    return None


def is_loopback_address(address: str) -> bool:
    """Check if an address is a loopback address."""
    if not address:
        return False
    
    # Extract IP from "ip:port" format
    ip = address.split(":")[0]
    
    return ip in ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def extract_port_from_flow(flow: dict[str, Any]) -> int | None:
    """Extract destination port from a network flow."""
    dst = flow.get("dst", "")
    if ":" in dst:
        try:
            return int(dst.split(":")[-1])
        except ValueError:
            pass
    return None


# =============================================================================
# Pattern matching utilities
# =============================================================================

# Known emulator/sandbox file patterns (Android)
ANDROID_EMULATOR_FILE_PATTERNS = [
    r"/system/bin/qemu.*",
    r"/dev/qemu.*",
    r"/dev/goldfish.*",
    r".*goldfish.*",
    r".*ranchu.*",
]

ANDROID_SANDBOX_FILE_PATTERNS = [
    r"/data/local/tmp/(frida|cuckoo|strace).*",
    r".*sandbox.*",
    r".*triage.*",
    r".*analysis.*",
]

ANDROID_HOOKING_FILE_PATTERNS = [
    r".*frida.*",
    r".*xposed.*",
    r".*substrate.*",
]

ANDROID_ROOT_FILE_PATTERNS = [
    r"/system/app/Superuser\.apk",
    r"/system/xbin/su",
    r"/system/bin/su",
    r"/system/bin/failsafe/su",
    r"/system/sd/xbin/su",
    r"/sbin/su",
    r"/su/bin/su",
    r"/data/local/su",
    r"/data/local/bin/su",
    r"/data/local/xbin/su",
    r".*superuser.*",
    r".*magisk.*",
]

# Known emulator properties (Android)
ANDROID_EMULATOR_PROPERTIES = {
    "ro.kernel.qemu": "1",
    "ro.hardware": "goldfish",
    "ro.product.model": "sdk",
    "ro.product.device": "generic",
    "ro.build.fingerprint": "generic",
    "init.svc.qemu-props": "running",
    "ro.build.characteristics": "emulator",
    "ro.debuggable": "1",
}

# Known analysis/hooking packages (Android)
ANDROID_ANALYSIS_PACKAGES = [
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
    "com.topjohnwu.magisk",
    "com.frida.server",
    "org.proxydroid",
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
]

# Known debug/analysis ports
ANALYSIS_PORTS = {
    27042: "Frida default",
    27043: "Frida alternate",
    5037: "ADB default",
    5555: "ADB wireless",
    8080: "Common proxy",
    8100: "Appium",
}


def matches_pattern(value: str, patterns: list[str]) -> bool:
    """Check if value matches any of the regex patterns."""
    for pattern in patterns:
        if re.match(pattern, value, re.IGNORECASE):
            return True
    return False


def categorize_android_file(path: str) -> tuple[str, EvasionPurpose] | None:
    """
    Categorize an Android file path.
    
    Returns:
        Tuple of (category, evasion_purpose) or None if not evasion-related
    """
    if matches_pattern(path, ANDROID_EMULATOR_FILE_PATTERNS):
        return ("emulator_files", EvasionPurpose.EMULATOR)
    
    if matches_pattern(path, ANDROID_SANDBOX_FILE_PATTERNS):
        return ("sandbox_files", EvasionPurpose.SANDBOX)
    
    if matches_pattern(path, ANDROID_HOOKING_FILE_PATTERNS):
        return ("hooking_frameworks", EvasionPurpose.HOOKING)
    
    if matches_pattern(path, ANDROID_ROOT_FILE_PATTERNS):
        return ("root_indicators", EvasionPurpose.ROOT)
    
    return None
