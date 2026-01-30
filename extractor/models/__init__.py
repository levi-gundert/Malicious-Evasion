"""
Data models for the Triage Evasion Artifact Extractor.

This package contains Pydantic models for:
- Artifact: Extracted evasion artifacts
- SampleMetadata: Sample information from Triage
- ExtractionResult: Complete extraction run results
"""

from extractor.models.artifact import (
    Artifact,
    MatchCriteria,
    MatchType,
    Metadata,
    Provenance,
    Deception,
    ArtifactType,
    EvasionPurpose,
    OSType,
)
from extractor.models.id import artifact_id
from extractor.models.sample import SampleMetadata
from extractor.models.extraction import ExtractionResult

__all__ = [
    # Artifact models
    "Artifact",
    "MatchCriteria",
    "MatchType",
    "Metadata",
    "Provenance",
    "Deception",
    "ArtifactType",
    "EvasionPurpose",
    "OSType",
    # ID generation
    "artifact_id",
    # Sample models
    "SampleMetadata",
    # Extraction models
    "ExtractionResult",
]
