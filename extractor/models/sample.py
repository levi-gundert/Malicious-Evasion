"""
Sample metadata model for Triage samples.

This model represents metadata about a malware sample, populated from
the Triage overview.json report.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from extractor.models.artifact import OSType


class TriageInfo(BaseModel):
    """Triage-specific sample information."""
    model_config = ConfigDict(extra="ignore")  # Allow extra fields from API
    
    sample_id: str
    submitted_at: datetime | None = None
    completed_at: datetime | None = None
    score: int = 0


class Classification(BaseModel):
    """Sample classification information."""
    model_config = ConfigDict(extra="ignore")
    
    os: OSType | None = None
    file_type: str = ""
    families: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class SampleMetadata(BaseModel):
    """
    Complete metadata for a malware sample.
    
    Populated from Triage's overview.json report.
    """
    model_config = ConfigDict(extra="ignore")
    
    # Hashes
    sha256: str
    sha1: str = ""
    md5: str = ""
    
    # Basic info
    filename: str = ""
    size: int = 0
    
    # Triage info
    triage: TriageInfo
    
    # Classification
    classification: Classification = Field(default_factory=Classification)
    
    @field_validator("sha256")
    @classmethod
    def sha256_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("sha256 cannot be empty")
        return v.strip().lower()
    
    @classmethod
    def from_overview(cls, overview: dict[str, Any]) -> SampleMetadata:
        """
        Create SampleMetadata from a Triage overview.json response.
        
        Args:
            overview: Parsed overview.json dictionary
            
        Returns:
            SampleMetadata instance
        """
        import logging
        logging.debug("Parsing SampleMetadata from overview.json")
        
        sample = overview.get("sample", {})
        analysis = overview.get("analysis", {})
        tasks = overview.get("tasks", {})
        
        # Extract OS from tags or task info
        os_type = None
        tags = analysis.get("tags", [])
        
        # Check analysis tags
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower == "android":
                os_type = OSType.ANDROID
                break
            elif tag_lower == "windows":
                os_type = OSType.WINDOWS
                break
            elif tag_lower == "linux":
                os_type = OSType.LINUX
                break
            elif tag_lower == "macos":
                os_type = OSType.MACOS
                break
        
        # If not found in tags, check tasks
        if os_type is None:
            for task_name, task_info in tasks.items():
                if isinstance(task_info, dict):
                    os_str = task_info.get("os", "")
                    if "android" in os_str.lower():
                        os_type = OSType.ANDROID
                        break
                    elif "windows" in os_str.lower():
                        os_type = OSType.WINDOWS
                        break
                    elif "linux" in os_str.lower():
                        os_type = OSType.LINUX
                        break
                    elif "macos" in os_str.lower() or "darwin" in os_str.lower():
                        os_type = OSType.MACOS
                        break
        
        # Parse timestamps
        submitted_at = None
        completed_at = None
        
        created_str = sample.get("created") or sample.get("submitted")
        if created_str:
            try:
                submitted_at = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        completed_str = sample.get("completed")
        if completed_str:
            try:
                completed_at = datetime.fromisoformat(completed_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        # Extract families from analysis
        families = analysis.get("family", [])
        if isinstance(families, str):
            families = [families] if families else []
        
        return cls(
            sha256=sample.get("sha256", ""),
            sha1=sample.get("sha1", ""),
            md5=sample.get("md5", ""),
            filename=sample.get("target", ""),
            size=sample.get("size", 0),
            triage=TriageInfo(
                sample_id=sample.get("id", ""),
                submitted_at=submitted_at,
                completed_at=completed_at,
                score=sample.get("score", 0),
            ),
            classification=Classification(
                os=os_type,
                file_type=sample.get("target", "").split(".")[-1] if sample.get("target") else "",
                families=families,
                tags=tags,
            ),
        )
    
    @classmethod
    def from_behavioral(cls, behavioral: dict[str, Any]) -> SampleMetadata:
        """
        Create SampleMetadata from a Triage behavioral report.
        
        This is a fallback when overview.json is not available.
        
        Args:
            behavioral: Parsed report_triage.json dictionary
            
        Returns:
            SampleMetadata instance
        """
        import logging
        logging.debug("Parsing SampleMetadata from behavioral report")
        
        sample = behavioral.get("sample", {})
        analysis = behavioral.get("analysis", {})
        
        # Extract OS from analysis platform
        os_type = None
        platform = analysis.get("platform", "")
        
        if "android" in platform.lower():
            os_type = OSType.ANDROID
        elif "windows" in platform.lower():
            os_type = OSType.WINDOWS
        elif "linux" in platform.lower():
            os_type = OSType.LINUX
        elif "macos" in platform.lower() or "darwin" in platform.lower():
            os_type = OSType.MACOS
        
        # Parse timestamps
        submitted_at = None
        completed_at = None
        
        submitted_str = sample.get("submitted") or analysis.get("submitted")
        if submitted_str:
            try:
                submitted_at = datetime.fromisoformat(submitted_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        reported_str = analysis.get("reported")
        if reported_str:
            try:
                completed_at = datetime.fromisoformat(reported_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        tags = analysis.get("tags", [])
        
        return cls(
            sha256=sample.get("sha256", ""),
            sha1=sample.get("sha1", ""),
            md5=sample.get("md5", ""),
            filename=sample.get("target", ""),
            size=sample.get("size", 0),
            triage=TriageInfo(
                sample_id=sample.get("id", ""),
                submitted_at=submitted_at,
                completed_at=completed_at,
                score=analysis.get("score", 0),
            ),
            classification=Classification(
                os=os_type,
                file_type=sample.get("target", "").split(".")[-1] if sample.get("target") else "",
                families=[],  # Not available in behavioral report
                tags=tags,
            ),
        )
