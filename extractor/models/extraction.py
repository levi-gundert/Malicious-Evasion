"""
Extraction result model for complete extraction runs.

This model represents the output of an extraction run, including:
- Statistics about what was processed
- All extracted artifacts organized by OS
- Any errors encountered
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from extractor.models.artifact import Artifact, OSType


class ExtractionParameters(BaseModel):
    """Parameters used for this extraction run."""
    model_config = ConfigDict(extra="forbid")
    
    os_filter: list[str] = Field(default_factory=list)
    lookback_days: int = 7
    min_score: int = 7


class ExtractionStatistics(BaseModel):
    """Statistics about the extraction run."""
    model_config = ConfigDict(extra="forbid")
    
    samples_processed: int = 0
    artifacts_extracted: int = 0
    artifacts_new: int = 0
    artifacts_updated: int = 0
    
    by_os: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_confidence: dict[str, int] = Field(default_factory=lambda: {
        "high": 0,
        "medium": 0,
        "low": 0,
    })
    
    @property
    def total_artifacts(self) -> int:
        """Alias for artifacts_extracted for convenience."""
        return self.artifacts_extracted


class ExtractionError(BaseModel):
    """An error that occurred during extraction."""
    model_config = ConfigDict(extra="forbid")
    
    sample_id: str = ""
    error: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExtractionResult(BaseModel):
    """
    Complete result of an extraction run.
    
    This is the main output of the extractor, containing all artifacts
    found across all processed samples, organized by OS.
    """
    model_config = ConfigDict(extra="forbid")
    
    # Metadata
    version: str = "1.0"
    extraction_id: str = Field(default_factory=lambda: f"ext-{uuid.uuid4().hex[:12]}")
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Parameters used
    parameters: ExtractionParameters = Field(default_factory=ExtractionParameters)
    
    # Statistics
    statistics: ExtractionStatistics = Field(default_factory=ExtractionStatistics)
    
    # Artifacts by OS
    artifacts: dict[str, list[Artifact]] = Field(default_factory=lambda: {
        "android": [],
        "windows": [],
        "linux": [],
        "macos": [],
    })
    
    # Errors
    errors: list[ExtractionError] = Field(default_factory=list)
    
    def add_artifact(self, artifact: Artifact) -> None:
        """
        Add an artifact to the result.
        
        Args:
            artifact: The artifact to add
        """
        import logging
        logging.debug(f"Adding artifact: {artifact.id}")
        
        os_key = artifact.os.value
        if os_key not in self.artifacts:
            self.artifacts[os_key] = []
        
        self.artifacts[os_key].append(artifact)
        
        # Update statistics
        self.statistics.artifacts_extracted += 1
        self.statistics.by_os[os_key] = self.statistics.by_os.get(os_key, 0) + 1
        self.statistics.by_category[artifact.category] = (
            self.statistics.by_category.get(artifact.category, 0) + 1
        )
        
        # Update confidence bucket
        confidence = artifact.provenance.confidence
        if confidence >= 0.8:
            self.statistics.by_confidence["high"] += 1
        elif confidence >= 0.5:
            self.statistics.by_confidence["medium"] += 1
        else:
            self.statistics.by_confidence["low"] += 1
    
    def add_error(self, sample_id: str, error: str) -> None:
        """
        Record an error that occurred during extraction.
        
        Args:
            sample_id: The sample ID that caused the error
            error: Description of the error
        """
        import logging
        logging.warning(f"Extraction error for {sample_id}: {error}")
        
        self.errors.append(ExtractionError(
            sample_id=sample_id,
            error=error,
        ))
    
    def get_artifacts_for_os(self, os_type: OSType | str) -> list[Artifact]:
        """
        Get all artifacts for a specific OS.
        
        Args:
            os_type: OS type (enum or string)
            
        Returns:
            List of artifacts for that OS
        """
        if isinstance(os_type, OSType):
            os_key = os_type.value
        else:
            os_key = os_type.lower()
        
        return self.artifacts.get(os_key, [])
    
    def get_all_artifacts(self) -> list[Artifact]:
        """Get all artifacts across all OSes."""
        all_artifacts = []
        for artifacts_list in self.artifacts.values():
            all_artifacts.extend(artifacts_list)
        return all_artifacts
    
    def to_json_dict(self) -> dict[str, Any]:
        """
        Convert to a JSON-serializable dictionary.
        
        Returns:
            Dictionary suitable for JSON serialization
        """
        import logging
        logging.debug("Converting ExtractionResult to JSON dict")
        
        return {
            "version": self.version,
            "extraction_id": self.extraction_id,
            "generated_at": self.extracted_at.isoformat(),
            "parameters": self.parameters.model_dump(),
            "statistics": {
                "total_artifacts": self.statistics.artifacts_extracted,
                "samples_processed": self.statistics.samples_processed,
                "artifacts_new": self.statistics.artifacts_new,
                "artifacts_updated": self.statistics.artifacts_updated,
                "by_os": self.statistics.by_os,
                "by_category": self.statistics.by_category,
                "by_confidence": self.statistics.by_confidence,
            },
            "artifacts": {
                os_key: [artifact.model_dump(mode="json") for artifact in artifacts_list]
                for os_key, artifacts_list in self.artifacts.items()
            },
            "errors": [
                {
                    "sample_id": err.sample_id,
                    "error": err.error,
                    "timestamp": err.timestamp.isoformat(),
                }
                for err in self.errors
            ],
        }
    
    @classmethod
    def merge(cls, *results: ExtractionResult) -> ExtractionResult:
        """
        Merge multiple extraction results into one.
        
        Args:
            *results: ExtractionResult instances to merge
            
        Returns:
            Merged ExtractionResult
        """
        import logging
        logging.debug(f"Merging {len(results)} extraction results")
        
        merged = cls()
        
        for result in results:
            # Merge artifacts
            for os_key, artifacts_list in result.artifacts.items():
                for artifact in artifacts_list:
                    merged.add_artifact(artifact)
            
            # Merge errors
            merged.errors.extend(result.errors)
            
            # Sum samples processed
            merged.statistics.samples_processed += result.statistics.samples_processed
        
        return merged
