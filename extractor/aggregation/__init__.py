"""
Artifact aggregation module.

Handles:
- Deduplication of artifacts by ID
- Confidence scoring based on sample count and family diversity
- Filtering by OS, category, and confidence thresholds
"""

from extractor.aggregation.deduplicator import deduplicate_artifacts, merge_artifacts
from extractor.aggregation.scorer import calculate_confidence, score_artifacts
from extractor.aggregation.filter import (
    filter_artifacts,
    FilterConfig,
)

__all__ = [
    "deduplicate_artifacts",
    "merge_artifacts",
    "calculate_confidence",
    "score_artifacts",
    "filter_artifacts",
    "FilterConfig",
]
