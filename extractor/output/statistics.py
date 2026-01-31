"""Statistics generation for extraction results."""

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ExtractionStatistics:
    """Statistics about an extraction run."""
    
    total_samples: int = 0
    total_artifacts: int = 0
    by_os: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    errors: int = 0


def generate_statistics(artifacts: dict[str, list]) -> ExtractionStatistics:
    """
    Generate statistics from extraction results.
    
    Args:
        artifacts: Dictionary of artifacts by OS
        
    Returns:
        ExtractionStatistics with counts
    """
    stats = ExtractionStatistics()
    
    for os_type, os_artifacts in artifacts.items():
        count = len(os_artifacts)
        stats.by_os[os_type] = count
        stats.total_artifacts += count
        
        for artifact in os_artifacts:
            # Count by type
            if hasattr(artifact, "artifact_type"):
                art_type = artifact.artifact_type.value if hasattr(artifact.artifact_type, "value") else str(artifact.artifact_type)
            elif isinstance(artifact, dict):
                art_type = artifact.get("artifact_type", "unknown")
            else:
                art_type = "unknown"
            
            stats.by_type[art_type] = stats.by_type.get(art_type, 0) + 1
            
            # Count by category
            if hasattr(artifact, "category"):
                category = artifact.category
            elif isinstance(artifact, dict):
                category = artifact.get("category", "unknown")
            else:
                category = "unknown"
            
            stats.by_category[category] = stats.by_category.get(category, 0) + 1
    
    return stats
