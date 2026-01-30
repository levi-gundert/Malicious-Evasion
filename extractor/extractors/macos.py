"""
macOS-specific artifact extractor.

Extracts evasion artifacts from macOS behavioral reports:
- Filesystem checks (VM files, sandbox indicators)
- System profiler / sysctl commands
- Process enumeration
"""

from __future__ import annotations

import logging
import re
from typing import Any

from extractor.extractors.base import (
    BaseExtractor,
    ExtractionContext,
    extract_iocs_from_signature,
    is_evasion_signature,
    categorize_evasion_purpose,
)
from extractor.models.artifact import (
    Artifact,
    ArtifactType,
    EvasionPurpose,
    MatchType,
    OSType,
)

logger = logging.getLogger(__name__)


# =============================================================================
# macOS-specific patterns
# =============================================================================

# VM detection file patterns
MACOS_VM_FILE_PATTERNS = [
    # VMware
    r".*/vmware.*",
    r".*/VMware Fusion\.app.*",
    r".*/VMware Tools.*",
    r"/Library/Application Support/VMware Tools",
    # VirtualBox
    r".*/VirtualBox.*",
    r".*/VBoxGuestAdditions.*",
    r"/Library/Extensions/VBoxGuest\.kext",
    # Parallels
    r".*/Parallels.*",
    r"/Library/Parallels.*",
    r".*/prl_.*",
    # QEMU
    r".*/qemu.*",
    # Generic VM
    r"/System/Library/CoreServices/SystemVersion\.plist",
    r"/System/Library/CoreServices/SystemVersionCompat\.plist",
]

# Sandbox detection file patterns
MACOS_SANDBOX_FILE_PATTERNS = [
    r".*/cuckoo.*",
    r".*/sandbox.*",
    r".*/analysis.*",
    r".*/malware.*",
    r"/Library/Caches/.*",
    r"/private/var/folders/.*",
]

# Analysis tool patterns
MACOS_ANALYSIS_FILE_PATTERNS = [
    r".*/Hopper.*",
    r".*/IDA.*",
    r".*/Ghidra.*",
    r".*/Wireshark.*",
    r".*/Charles.*",
    r".*/Burp Suite.*",
    r".*/Proxyman.*",
    r"/usr/bin/dtrace",
    r"/usr/bin/dtruss",
    r"/usr/bin/lldb",
    r"/usr/bin/sample",
    r"/usr/bin/instruments",
]

# System profiler commands checked
MACOS_PROFILER_COMMANDS = [
    "system_profiler SPHardwareDataType",
    "system_profiler SPSoftwareDataType",
    "system_profiler SPDisplaysDataType",
    "sysctl hw.model",
    "sysctl hw.machine",
    "sysctl machdep.cpu.brand_string",
    "sysctl kern.version",
    "ioreg -l",
    "ioreg -rd1 -c IOPlatformExpertDevice",
]

# VM process patterns
MACOS_VM_PROCESS_PATTERNS = [
    r"vmware.*",
    r"VMware.*",
    r"VBox.*",
    r"Parallels.*",
    r"prl_.*",
    r"qemu.*",
]

# Analysis tool process patterns
MACOS_ANALYSIS_PROCESS_PATTERNS = [
    r"Hopper.*",
    r"IDA.*",
    r"ida64",
    r"ghidra.*",
    r"Ghidra.*",
    r"lldb",
    r"dtrace",
    r"dtruss",
    r"Wireshark.*",
    r"Charles",
    r"Proxyman",
    r"mitmproxy",
    r"Little Snitch.*",
    r"tcpdump",
    r"fs_usage",
]


def categorize_macos_file(path: str) -> tuple[str, EvasionPurpose | None]:
    """
    Categorize a macOS file path for evasion detection.
    
    Returns:
        Tuple of (category, evasion_purpose)
    """
    path_lower = path.lower()
    
    # VM files
    for pattern in MACOS_VM_FILE_PATTERNS:
        if re.match(pattern, path_lower, re.IGNORECASE):
            return "vm_files", EvasionPurpose.ANTI_VM
    
    # Analysis tools
    for pattern in MACOS_ANALYSIS_FILE_PATTERNS:
        if re.match(pattern, path_lower, re.IGNORECASE):
            return "analysis_tools", EvasionPurpose.ANTI_SANDBOX
    
    # Sandbox indicators
    for pattern in MACOS_SANDBOX_FILE_PATTERNS:
        if re.match(pattern, path_lower, re.IGNORECASE):
            return "sandbox_files", EvasionPurpose.ANTI_SANDBOX
    
    return "", None


def categorize_macos_process(name: str) -> tuple[str, EvasionPurpose | None]:
    """
    Categorize a macOS process name for evasion detection.
    
    Returns:
        Tuple of (category, evasion_purpose)
    """
    # Analysis tools
    for pattern in MACOS_ANALYSIS_PROCESS_PATTERNS:
        if re.match(pattern, name, re.IGNORECASE):
            return "analysis_tools", EvasionPurpose.ANTI_SANDBOX
    
    # VM processes
    for pattern in MACOS_VM_PROCESS_PATTERNS:
        if re.match(pattern, name, re.IGNORECASE):
            return "vm_processes", EvasionPurpose.ANTI_VM
    
    return "", None


def categorize_macos_command(command: str) -> tuple[str, EvasionPurpose | None]:
    """
    Categorize a macOS system command for evasion detection.
    
    Returns:
        Tuple of (category, evasion_purpose)
    """
    command_lower = command.lower()
    
    # System profiler for hardware/VM detection
    if "system_profiler" in command_lower:
        return "system_profiler", EvasionPurpose.ANTI_VM
    
    # sysctl for hardware info
    if "sysctl" in command_lower:
        if "hw." in command_lower or "machdep." in command_lower:
            return "sysctl_checks", EvasionPurpose.ANTI_VM
    
    # ioreg for device tree
    if "ioreg" in command_lower:
        return "ioreg_checks", EvasionPurpose.ANTI_VM
    
    return "", None


class MacOSExtractor(BaseExtractor):
    """
    Extractor for macOS evasion artifacts.
    
    Handles:
    - Filesystem checks (VM, sandbox, analysis tools)
    - System profiler commands
    - sysctl/ioreg queries
    - Process enumeration
    """
    
    os_type = OSType.MACOS
    categories = [
        "vm_files",
        "sandbox_files",
        "analysis_tools",
        "vm_processes",
        "system_profiler",
        "sysctl_checks",
        "ioreg_checks",
    ]
    
    def extract(self, context: ExtractionContext) -> list[Artifact]:
        """Extract macOS evasion artifacts."""
        artifacts: list[Artifact] = []
        seen: set[str] = set()
        
        self.logger.info(f"Extracting macOS artifacts for {context.sample_hash[:8]}...")
        
        # Extract from kernel logs if available
        if context.has_kernel_logs:
            artifacts.extend(self._extract_from_kernel_logs(context, seen))
        
        # Extract from signatures
        artifacts.extend(self._extract_from_signatures(context, seen))
        
        # Extract from process list
        artifacts.extend(self._extract_from_processes(context, seen))
        
        # Extract from commands (if available in behavioral report)
        artifacts.extend(self._extract_from_commands(context, seen))
        
        self.logger.info(f"Extracted {len(artifacts)} macOS artifacts")
        return artifacts
    
    def _extract_from_kernel_logs(
        self,
        context: ExtractionContext,
        seen: set[str],
    ) -> list[Artifact]:
        """Extract artifacts from bigmac.json kernel logs."""
        artifacts = []
        
        if not context.kernel_logs:
            return artifacts
        
        for entry in context.kernel_logs:
            kind = entry.get("kind", "")
            
            if kind in ("file_stat", "file_open", "file_access", "getattrlist"):
                artifact = self._process_file_operation(entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
            
            elif kind in ("exec", "posix_spawn", "execve"):
                artifact = self._process_exec_operation(entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
        
        return artifacts
    
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
        
        if path in seen:
            return None
        
        category, evasion_purpose = categorize_macos_file(path)
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
    
    def _process_exec_operation(
        self,
        entry: dict[str, Any],
        sample_hash: str,
        seen: set[str],
    ) -> Artifact | None:
        """Process an exec/spawn operation from kernel logs."""
        # Get the executed command
        cmd = entry.get("path", "") or entry.get("command", "")
        args = entry.get("args", [])
        
        if isinstance(args, list) and args:
            full_cmd = " ".join([cmd] + args) if cmd else " ".join(args)
        else:
            full_cmd = cmd
        
        if not full_cmd:
            return None
        
        if full_cmd in seen:
            return None
        
        # Check if this is a VM detection command
        category, evasion_purpose = categorize_macos_command(full_cmd)
        if category:
            seen.add(full_cmd)
            return self.create_artifact(
                artifact_type=ArtifactType.COMMAND,
                category=category,
                match_value=full_cmd,
                evasion_purpose=evasion_purpose,
                description=f"Command execution: {full_cmd}",
                sample_hash=sample_hash,
            )
        
        return None
    
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
            
            sig_name = signature.get("name", "")
            evasion_purpose = categorize_evasion_purpose(signature)
            
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
            category, purpose = categorize_macos_file(ioc)
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
        
        # Check if it's a command
        category, purpose = categorize_macos_command(ioc)
        if category:
            seen.add(ioc)
            return self.create_artifact(
                artifact_type=ArtifactType.COMMAND,
                category=category,
                match_value=ioc,
                evasion_purpose=purpose or evasion_purpose,
                description=f"From signature: {sig_name}",
                sample_hash=sample_hash,
            )
        
        # Check if it's a process name
        category, purpose = categorize_macos_process(ioc)
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
            
            category, purpose = categorize_macos_process(name)
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
    
    def _extract_from_commands(
        self,
        context: ExtractionContext,
        seen: set[str],
    ) -> list[Artifact]:
        """Extract artifacts from executed commands in behavioral report."""
        artifacts = []
        
        # Check for commands in behavioral report
        commands = context.behavioral_report.get("commands", [])
        
        for cmd_entry in commands:
            if isinstance(cmd_entry, str):
                cmd = cmd_entry
            elif isinstance(cmd_entry, dict):
                cmd = cmd_entry.get("command", "") or cmd_entry.get("cmdline", "")
            else:
                continue
            
            if not cmd or cmd in seen:
                continue
            
            category, purpose = categorize_macos_command(cmd)
            if category:
                seen.add(cmd)
                artifacts.append(self.create_artifact(
                    artifact_type=ArtifactType.COMMAND,
                    category=category,
                    match_value=cmd,
                    evasion_purpose=purpose,
                    description=f"Executed command: {cmd}",
                    sample_hash=context.sample_hash,
                ))
        
        return artifacts
