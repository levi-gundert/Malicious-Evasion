"""
Android-specific extractor for evasion artifacts.

Extracts artifacts that Android malware checks for:
- Emulator files (qemu, goldfish, ranchu)
- System properties (ro.kernel.qemu, ro.hardware, etc.)
- Analysis packages (Frida, Xposed, Magisk)
- Debug port probes (ADB, Frida ports)
- Root indicators

Data sources (in order of preference):
1. Kernel logs (stahp.json) - most detailed syscall traces
2. Signatures with IOCs - behavioral detection results
3. Network flows - for port probes
"""

from __future__ import annotations

import logging
import re
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
    is_loopback_address,
    extract_port_from_flow,
    categorize_android_file,
    ANDROID_EMULATOR_PROPERTIES,
    ANDROID_ANALYSIS_PACKAGES,
    ANALYSIS_PORTS,
)

logger = logging.getLogger(__name__)


class AndroidExtractor(BaseExtractor):
    """
    Extractor for Android evasion artifacts.
    
    Handles:
    - File existence checks
    - System property reads
    - Package queries
    - Network port probes
    """
    
    os_type = OSType.ANDROID
    
    categories = [
        "emulator_files",
        "emulator_properties",
        "sandbox_files",
        "sandbox_packages",
        "hooking_frameworks",
        "root_indicators",
        "network_probes",
        "debugger_indicators",
    ]
    
    def extract(self, context: ExtractionContext) -> list[Artifact]:
        """
        Extract Android evasion artifacts from the context.
        
        Uses kernel logs if available, otherwise falls back to signatures.
        """
        self.logger.info(f"Extracting Android artifacts from {context.sample_hash[:16]}...")
        
        artifacts: list[Artifact] = []
        
        # Track what we've extracted to avoid duplicates
        seen_values: set[str] = set()
        
        # 1. Extract from kernel logs if available (most detailed)
        if context.has_kernel_logs:
            self.logger.debug("Using kernel logs for extraction")
            artifacts.extend(self._extract_from_kernel_logs(context, seen_values))
        
        # 2. Extract from signatures (good fallback)
        self.logger.debug("Extracting from signatures")
        artifacts.extend(self._extract_from_signatures(context, seen_values))
        
        # 3. Extract port probes from network flows
        self.logger.debug("Extracting from network flows")
        artifacts.extend(self._extract_port_probes(context, seen_values))
        
        self.logger.info(f"Extracted {len(artifacts)} Android artifacts")
        return artifacts
    
    def _extract_from_kernel_logs(
        self,
        context: ExtractionContext,
        seen: set[str]
    ) -> list[Artifact]:
        """Extract artifacts from stahp.json kernel logs."""
        artifacts = []
        
        if not context.kernel_logs:
            return artifacts
        
        for entry in context.kernel_logs:
            kind = entry.get("kind", "")
            
            # File operations
            if kind in ("file_stat", "file_open", "file_access", "file_exists"):
                artifact = self._process_file_operation(entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
            
            # Property reads
            elif kind == "prop_get":
                artifact = self._process_property_read(entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
            
            # Package queries
            elif kind == "pkg_query":
                artifact = self._process_package_query(entry, context.sample_hash, seen)
                if artifact:
                    artifacts.append(artifact)
        
        return artifacts
    
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
        
        # Categorize the path
        categorization = categorize_android_file(path)
        if not categorization:
            return None
        
        category, evasion_purpose = categorization
        seen.add(path)
        
        # Debug: Log what we found
        self.logger.debug(f"Found file check: {path} -> {category}")
        
        return self.create_artifact(
            artifact_type=ArtifactType.FILE,
            category=category,
            match_value=path,
            evasion_purpose=evasion_purpose,
            description=f"File existence check: {path}",
            sample_hash=sample_hash,
            deception_notes="Create empty file at this path",
        )
    
    def _process_property_read(
        self,
        entry: dict[str, Any],
        sample_hash: str,
        seen: set[str]
    ) -> Artifact | None:
        """Process a property read from kernel logs."""
        prop_name = entry.get("name", "")
        prop_value = entry.get("value", "")
        
        if not prop_name or prop_name in seen:
            return None
        
        # Check if this is a known emulator/analysis property
        if prop_name not in ANDROID_EMULATOR_PROPERTIES:
            # Also check for partial matches
            if not any(known in prop_name for known in ["qemu", "goldfish", "generic", "sdk", "emulator"]):
                return None
        
        seen.add(prop_name)
        
        # Debug: Log what we found
        self.logger.debug(f"Found property read: {prop_name}={prop_value}")
        
        # Get recommended deception value
        deception_value = ANDROID_EMULATOR_PROPERTIES.get(prop_name, prop_value)
        
        return self.create_artifact(
            artifact_type=ArtifactType.PROPERTY,
            category="emulator_properties",
            match_value=prop_name,
            evasion_purpose=EvasionPurpose.EMULATOR,
            description=f"System property check: {prop_name}",
            sample_hash=sample_hash,
            deception_value=deception_value,
            deception_notes="Set property via Android system APIs",
        )
    
    def _process_package_query(
        self,
        entry: dict[str, Any],
        sample_hash: str,
        seen: set[str]
    ) -> Artifact | None:
        """Process a package query from kernel logs."""
        package = entry.get("package", "")
        
        if not package or package in seen:
            return None
        
        # Check if this is a known analysis/hooking package
        if package not in ANDROID_ANALYSIS_PACKAGES:
            # Also check for partial matches
            if not any(kw in package.lower() for kw in ["frida", "xposed", "magisk", "superuser", "root", "substrate"]):
                return None
        
        seen.add(package)
        
        # Determine category based on package name
        category = "sandbox_packages"
        evasion_purpose = EvasionPurpose.SANDBOX
        
        if any(kw in package.lower() for kw in ["frida", "xposed", "substrate"]):
            category = "hooking_frameworks"
            evasion_purpose = EvasionPurpose.HOOKING
        elif any(kw in package.lower() for kw in ["superuser", "root", "magisk", "su"]):
            category = "root_indicators"
            evasion_purpose = EvasionPurpose.ROOT
        
        # Debug: Log what we found
        self.logger.debug(f"Found package query: {package} -> {category}")
        
        return self.create_artifact(
            artifact_type=ArtifactType.PACKAGE,
            category=category,
            match_value=package,
            evasion_purpose=evasion_purpose,
            description=f"Package installation check: {package}",
            sample_hash=sample_hash,
            deception_notes="Create matching package directory in /data/data/",
        )
    
    def _extract_from_signatures(
        self,
        context: ExtractionContext,
        seen: set[str]
    ) -> list[Artifact]:
        """
        Extract artifacts from behavioral signatures.
        
        Signatures often contain IOCs pointing to evasion checks.
        """
        artifacts = []
        
        for signature in context.signatures:
            # Check if this is an evasion-related signature
            if not is_evasion_signature(signature):
                continue
            
            # Debug: Log the signature we're processing
            sig_name = signature.get("name", "unknown")
            self.logger.debug(f"Processing evasion signature: {sig_name}")
            
            # Get IOCs from the signature
            iocs = extract_iocs_from_signature(signature)
            evasion_purpose = categorize_evasion_purpose(signature)
            
            for ioc in iocs:
                if ioc in seen:
                    continue
                
                # Try to categorize the IOC
                artifact = self._categorize_ioc(
                    ioc, 
                    signature, 
                    context.sample_hash, 
                    evasion_purpose
                )
                
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
        """
        Categorize an IOC and create an appropriate artifact.
        
        IOCs can be file paths, property names, package names, etc.
        """
        # Check if it looks like a file path
        if ioc.startswith("/"):
            categorization = categorize_android_file(ioc)
            if categorization:
                category, purpose = categorization
                return self.create_artifact(
                    artifact_type=ArtifactType.FILE,
                    category=category,
                    match_value=ioc,
                    evasion_purpose=purpose,
                    description=f"From signature: {signature.get('name', '')}",
                    sample_hash=sample_hash,
                )
        
        # Check if it looks like a property name
        if ioc.startswith("ro.") or ioc.startswith("init."):
            return self.create_artifact(
                artifact_type=ArtifactType.PROPERTY,
                category="emulator_properties",
                match_value=ioc,
                evasion_purpose=evasion_purpose or EvasionPurpose.EMULATOR,
                description=f"From signature: {signature.get('name', '')}",
                sample_hash=sample_hash,
            )
        
        # Check if it looks like a package name
        if "." in ioc and not ioc.startswith("/"):
            # Likely a package or class name
            if any(kw in ioc.lower() for kw in ["frida", "xposed", "magisk", "superuser", "root"]):
                category = "hooking_frameworks" if "frida" in ioc.lower() or "xposed" in ioc.lower() else "root_indicators"
                return self.create_artifact(
                    artifact_type=ArtifactType.PACKAGE,
                    category=category,
                    match_value=ioc,
                    evasion_purpose=evasion_purpose or EvasionPurpose.HOOKING,
                    description=f"From signature: {signature.get('name', '')}",
                    sample_hash=sample_hash,
                )
        
        # Check if it's a port number
        if ioc.isdigit():
            port = int(ioc)
            if port in ANALYSIS_PORTS:
                return self.create_artifact(
                    artifact_type=ArtifactType.PORT,
                    category="network_probes",
                    match_value=str(port),
                    evasion_purpose=EvasionPurpose.HOOKING if port in (27042, 27043) else EvasionPurpose.DEBUGGER,
                    description=f"{ANALYSIS_PORTS.get(port, 'Debug port')} - from signature",
                    sample_hash=sample_hash,
                    deception_notes=f"Bind listener on port {port}",
                )
        
        return None
    
    def _extract_port_probes(
        self,
        context: ExtractionContext,
        seen: set[str]
    ) -> list[Artifact]:
        """
        Extract port probe artifacts from network flows.
        
        Look for connections to localhost on known debug/analysis ports.
        """
        artifacts = []
        
        for flow in context.network_flows:
            dst = flow.get("dst", "")
            
            # Only interested in loopback connections
            if not is_loopback_address(dst):
                continue
            
            port = extract_port_from_flow(flow)
            if port is None:
                continue
            
            port_key = f"port:{port}"
            if port_key in seen:
                continue
            
            # Check if this is a known debug/analysis port
            if port in ANALYSIS_PORTS:
                seen.add(port_key)
                
                # Debug: Log what we found
                self.logger.debug(f"Found port probe: {port} ({ANALYSIS_PORTS[port]})")
                
                artifacts.append(self.create_artifact(
                    artifact_type=ArtifactType.PORT,
                    category="network_probes",
                    match_value=str(port),
                    evasion_purpose=EvasionPurpose.HOOKING if port in (27042, 27043) else EvasionPurpose.DEBUGGER,
                    description=f"Port probe: {ANALYSIS_PORTS[port]}",
                    sample_hash=context.sample_hash,
                    deception_notes=f"Bind listener on port {port}",
                ))
        
        return artifacts
