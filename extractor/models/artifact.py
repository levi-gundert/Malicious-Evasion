"""
Artifact data model for extracted evasion artifacts.

An Artifact represents something malware checks for to detect analysis
environments (sandboxes, VMs, debuggers, etc.). By cataloging these
checks, defenders can plant fake artifacts to trigger malware self-termination.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from extractor.models.id import artifact_id


class OSType(str, Enum):
    """Supported operating systems."""
    ANDROID = "android"
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class ArtifactType(str, Enum):
    """Types of artifacts that can be extracted."""
    FILE = "file"
    REGISTRY = "registry"
    PROCESS = "process"
    PROPERTY = "property"  # Android system properties
    PACKAGE = "package"    # Android packages
    PORT = "port"          # Network port probes
    WMI = "wmi"            # Windows WMI queries
    MUTEX = "mutex"        # Windows mutexes
    SERVICE = "service"    # Windows services
    ENVIRONMENT_VAR = "environment_var"  # Linux environment variables
    COMMAND = "command"    # macOS system commands


class MatchType(str, Enum):
    """How the artifact value should be matched."""
    EXACT = "exact"
    PATTERN = "pattern"    # Regex pattern
    PREFIX = "prefix"
    CONTAINS = "contains"


class EvasionPurpose(str, Enum):
    """What the malware is trying to detect."""
    EMULATOR = "emulator"
    SANDBOX = "sandbox"
    DEBUGGER = "debugger"
    VM = "vm"
    RESEARCHER_TOOLS = "researcher_tools"
    ROOT = "root"          # Android root detection
    HOOKING = "hooking"    # Frida/Xposed detection
    CONTAINER = "container"  # Docker/container detection


class MatchCriteria(BaseModel):
    """How to match this artifact."""
    model_config = ConfigDict(extra="forbid")
    
    type: MatchType = MatchType.EXACT
    value: str
    case_sensitive: bool = True
    
    @field_validator("value")
    @classmethod
    def value_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("match_criteria.value cannot be empty")
        return v


class Metadata(BaseModel):
    """Human-readable metadata about the artifact."""
    model_config = ConfigDict(extra="forbid")
    
    description: str = ""
    evasion_purpose: EvasionPurpose | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class Provenance(BaseModel):
    """Tracking where this artifact was found."""
    model_config = ConfigDict(extra="forbid")
    
    sample_count: int = 1
    sample_hashes: list[str] = Field(default_factory=list)  # SHA256 hashes
    sample_sha1s: list[str] = Field(default_factory=list)   # SHA1 hashes
    sample_ids: list[str] = Field(default_factory=list)     # Triage sample IDs
    families: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    
    @field_validator("sample_hashes", "sample_sha1s", "sample_ids")
    @classmethod
    def cap_sample_lists(cls, v: list[str]) -> list[str]:
        """Cap sample lists at 100 to prevent unbounded growth."""
        if len(v) > 100:
            return v[:100]
        return v
    
    @field_validator("confidence")
    @classmethod
    def confidence_in_range(cls, v: float) -> float:
        """Ensure confidence is between 0 and 1."""
        return max(0.0, min(1.0, v))


class Deception(BaseModel):
    """Guidance for planting this artifact as a deception."""
    model_config = ConfigDict(extra="forbid")
    
    recommended_value: str = ""
    plant_as: str = ""  # file, directory, symlink, etc.
    permissions: str = ""  # e.g., "755" for Linux
    notes: str = ""


class Artifact(BaseModel):
    """
    A single extracted evasion artifact.
    
    This represents something malware checks for to detect if it's running
    in an analysis environment. Each artifact includes:
    - What to match (match_criteria)
    - Where it came from (provenance)
    - How to use it for deception (deception)
    """
    model_config = ConfigDict(extra="forbid")
    
    id: str = ""  # Generated automatically if not provided
    os: OSType
    category: str  # OS-specific category (e.g., "emulator_files", "vm_registry")
    artifact_type: ArtifactType
    
    match_criteria: MatchCriteria
    metadata: Metadata = Field(default_factory=Metadata)
    provenance: Provenance = Field(default_factory=Provenance)
    deception: Deception = Field(default_factory=Deception)
    
    def model_post_init(self, __context: Any) -> None:
        """Generate ID if not provided."""
        if not self.id:
            self.id = artifact_id(
                self.os.value,
                self.artifact_type.value,
                self.match_criteria.value
            )
    
    @field_validator("category")
    @classmethod
    def category_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("category cannot be empty")
        return v.strip().lower()


# =============================================================================
# Factory functions for creating artifacts
# =============================================================================

def create_file_artifact(
    os_type: OSType,
    path: str,
    category: str,
    evasion_purpose: EvasionPurpose | None = None,
    sample_hash: str | None = None,
    sample_sha1: str | None = None,
    sample_id: str | None = None,
) -> Artifact:
    """
    Create a file artifact.
    
    Args:
        os_type: Target OS
        path: File path to check
        category: Category (e.g., "emulator_files", "sandbox_files")
        evasion_purpose: What the malware is detecting
        sample_hash: SHA256 of the sample that checks for this
        sample_sha1: SHA1 of the sample
        sample_id: Triage sample ID for linking
    """
    # Debug: Log artifact creation
    import logging
    logging.debug(f"Creating file artifact: {path}")
    
    # Determine case sensitivity based on OS
    case_sensitive = os_type in (OSType.ANDROID, OSType.LINUX, OSType.MACOS)
    
    provenance = Provenance()
    if sample_hash:
        provenance.sample_hashes = [sample_hash]
    if sample_sha1:
        provenance.sample_sha1s = [sample_sha1]
    if sample_id:
        provenance.sample_ids = [sample_id]
    provenance.sample_count = 1
    
    return Artifact(
        os=os_type,
        category=category,
        artifact_type=ArtifactType.FILE,
        match_criteria=MatchCriteria(
            type=MatchType.EXACT,
            value=path,
            case_sensitive=case_sensitive,
        ),
        metadata=Metadata(
            evasion_purpose=evasion_purpose,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        ),
        provenance=provenance,
        deception=Deception(
            plant_as="file",
            permissions="644" if os_type in (OSType.LINUX, OSType.ANDROID) else "",
        ),
    )


def create_property_artifact(
    property_name: str,
    category: str,
    recommended_value: str = "",
    sample_hash: str | None = None,
    sample_sha1: str | None = None,
    sample_id: str | None = None,
) -> Artifact:
    """Create an Android system property artifact."""
    import logging
    logging.debug(f"Creating property artifact: {property_name}")
    
    provenance = Provenance()
    if sample_hash:
        provenance.sample_hashes = [sample_hash]
    if sample_sha1:
        provenance.sample_sha1s = [sample_sha1]
    if sample_id:
        provenance.sample_ids = [sample_id]
    provenance.sample_count = 1
    
    return Artifact(
        os=OSType.ANDROID,
        category=category,
        artifact_type=ArtifactType.PROPERTY,
        match_criteria=MatchCriteria(
            type=MatchType.EXACT,
            value=property_name,
            case_sensitive=True,
        ),
        metadata=Metadata(
            evasion_purpose=EvasionPurpose.EMULATOR,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        ),
        provenance=provenance,
        deception=Deception(
            recommended_value=recommended_value,
            notes="Set via Android system property API",
        ),
    )


def create_registry_artifact(
    key: str,
    value_name: str | None = None,
    category: str = "vm_registry",
    sample_hash: str | None = None,
    sample_sha1: str | None = None,
    sample_id: str | None = None,
) -> Artifact:
    """Create a Windows registry artifact."""
    import logging
    logging.debug(f"Creating registry artifact: {key}")
    
    # Build match value
    match_value = key if not value_name else f"{key}\\{value_name}"
    
    provenance = Provenance()
    if sample_hash:
        provenance.sample_hashes = [sample_hash]
    if sample_sha1:
        provenance.sample_sha1s = [sample_sha1]
    if sample_id:
        provenance.sample_ids = [sample_id]
    provenance.sample_count = 1
    
    return Artifact(
        os=OSType.WINDOWS,
        category=category,
        artifact_type=ArtifactType.REGISTRY,
        match_criteria=MatchCriteria(
            type=MatchType.EXACT,
            value=match_value,
            case_sensitive=False,  # Windows registry is case-insensitive
        ),
        metadata=Metadata(
            evasion_purpose=EvasionPurpose.VM,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        ),
        provenance=provenance,
        deception=Deception(
            notes="Create registry key/value",
        ),
    )


def create_process_artifact(
    os_type: OSType,
    process_name: str,
    category: str,
    sample_hash: str | None = None,
    sample_sha1: str | None = None,
    sample_id: str | None = None,
) -> Artifact:
    """Create a process artifact."""
    import logging
    logging.debug(f"Creating process artifact: {process_name}")
    
    # Windows process names are case-insensitive
    case_sensitive = os_type != OSType.WINDOWS
    
    provenance = Provenance()
    if sample_hash:
        provenance.sample_hashes = [sample_hash]
    if sample_sha1:
        provenance.sample_sha1s = [sample_sha1]
    if sample_id:
        provenance.sample_ids = [sample_id]
    provenance.sample_count = 1
    
    return Artifact(
        os=os_type,
        category=category,
        artifact_type=ArtifactType.PROCESS,
        match_criteria=MatchCriteria(
            type=MatchType.EXACT,
            value=process_name,
            case_sensitive=case_sensitive,
        ),
        metadata=Metadata(
            evasion_purpose=EvasionPurpose.VM if "vm" in category.lower() else EvasionPurpose.RESEARCHER_TOOLS,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        ),
        provenance=provenance,
        deception=Deception(
            notes="Run dummy process with this name",
        ),
    )
