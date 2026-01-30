"""
Artifact filtering logic.

Filters artifacts based on:
- Operating system
- Category
- Minimum confidence threshold
- Minimum sample count
- Exclude patterns (for paths that are too generic)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

from extractor.models.artifact import Artifact, OSType

logger = logging.getLogger(__name__)


@dataclass
class FilterConfig:
    """Configuration for artifact filtering."""
    
    # Minimum thresholds
    min_confidence: float = 0.3
    min_sample_count: int = 1
    
    # OS filter (None = all OSes)
    os_types: list[OSType] | None = None
    
    # Category filter (None = all categories)
    categories: list[str] | None = None
    
    # Patterns to exclude (regex patterns)
    exclude_patterns: list[str] = field(default_factory=list)
    
    # Compiled patterns (internal)
    _compiled_patterns: list[re.Pattern] = field(default_factory=list, repr=False)
    
    def __post_init__(self):
        """Compile exclude patterns."""
        self._compiled_patterns = []
        for pattern in self.exclude_patterns:
            try:
                self._compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Invalid exclude pattern '{pattern}': {e}")
    
    def should_exclude_value(self, value: str) -> bool:
        """Check if a value matches any exclude pattern."""
        for pattern in self._compiled_patterns:
            if pattern.search(value):
                return True
        return False


def filter_by_confidence(
    artifacts: Iterable[Artifact],
    min_confidence: float = 0.3
) -> list[Artifact]:
    """
    Filter artifacts by minimum confidence score.
    
    Args:
        artifacts: Artifacts to filter
        min_confidence: Minimum confidence threshold
        
    Returns:
        Filtered list of artifacts
    """
    return [a for a in artifacts if a.provenance.confidence >= min_confidence]


def filter_by_sample_count(
    artifacts: Iterable[Artifact],
    min_count: int = 1
) -> list[Artifact]:
    """
    Filter artifacts by minimum sample count.
    
    Args:
        artifacts: Artifacts to filter
        min_count: Minimum sample count
        
    Returns:
        Filtered list of artifacts
    """
    return [a for a in artifacts if a.provenance.sample_count >= min_count]


def filter_by_os(
    artifacts: Iterable[Artifact],
    os_types: list[OSType] | None = None
) -> list[Artifact]:
    """
    Filter artifacts by operating system.
    
    Args:
        artifacts: Artifacts to filter
        os_types: List of OS types to include (None = all)
        
    Returns:
        Filtered list of artifacts
    """
    if os_types is None:
        return list(artifacts)
    
    return [a for a in artifacts if a.os in os_types]


def filter_by_category(
    artifacts: Iterable[Artifact],
    categories: list[str] | None = None
) -> list[Artifact]:
    """
    Filter artifacts by category.
    
    Args:
        artifacts: Artifacts to filter
        categories: List of categories to include (None = all)
        
    Returns:
        Filtered list of artifacts
    """
    if categories is None:
        return list(artifacts)
    
    # Normalize to lowercase for comparison
    categories_lower = [c.lower() for c in categories]
    return [a for a in artifacts if a.category.lower() in categories_lower]


def filter_by_exclude_patterns(
    artifacts: Iterable[Artifact],
    patterns: list[str] | None = None
) -> list[Artifact]:
    """
    Filter out artifacts matching exclude patterns.
    
    Args:
        artifacts: Artifacts to filter
        patterns: Regex patterns to exclude
        
    Returns:
        Filtered list of artifacts (excluding matches)
    """
    if not patterns:
        return list(artifacts)
    
    # Compile patterns
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error as e:
            logger.warning(f"Invalid exclude pattern '{pattern}': {e}")
    
    def should_include(artifact: Artifact) -> bool:
        value = artifact.match_criteria.value
        for pattern in compiled:
            if pattern.search(value):
                logger.debug(f"Excluding artifact {artifact.id}: matches pattern")
                return False
        return True
    
    return [a for a in artifacts if should_include(a)]


def filter_artifacts(
    artifacts: Iterable[Artifact],
    config: FilterConfig | None = None,
) -> list[Artifact]:
    """
    Apply all filters to a collection of artifacts.
    
    Args:
        artifacts: Artifacts to filter
        config: Filter configuration (uses defaults if None)
        
    Returns:
        Filtered list of artifacts
    """
    if config is None:
        config = FilterConfig()
    
    artifact_list = list(artifacts)
    initial_count = len(artifact_list)
    
    logger.info(f"Filtering {initial_count} artifacts...")
    
    # Apply filters in order
    result = artifact_list
    
    # 1. Filter by OS
    if config.os_types:
        result = filter_by_os(result, config.os_types)
        logger.debug(f"After OS filter: {len(result)} artifacts")
    
    # 2. Filter by category
    if config.categories:
        result = filter_by_category(result, config.categories)
        logger.debug(f"After category filter: {len(result)} artifacts")
    
    # 3. Filter by minimum sample count
    if config.min_sample_count > 1:
        result = filter_by_sample_count(result, config.min_sample_count)
        logger.debug(f"After sample count filter: {len(result)} artifacts")
    
    # 4. Filter by minimum confidence
    if config.min_confidence > 0:
        result = filter_by_confidence(result, config.min_confidence)
        logger.debug(f"After confidence filter: {len(result)} artifacts")
    
    # 5. Apply exclude patterns
    if config.exclude_patterns:
        result = filter_by_exclude_patterns(result, config.exclude_patterns)
        logger.debug(f"After exclude patterns: {len(result)} artifacts")
    
    filtered_count = initial_count - len(result)
    logger.info(f"Filtering complete: {len(result)} artifacts ({filtered_count} filtered out)")
    
    return result


def group_by_os(artifacts: Iterable[Artifact]) -> dict[OSType, list[Artifact]]:
    """
    Group artifacts by operating system.
    
    Args:
        artifacts: Artifacts to group
        
    Returns:
        Dictionary mapping OS to list of artifacts
    """
    result: dict[OSType, list[Artifact]] = {os: [] for os in OSType}
    
    for artifact in artifacts:
        result[artifact.os].append(artifact)
    
    return result


def group_by_category(artifacts: Iterable[Artifact]) -> dict[str, list[Artifact]]:
    """
    Group artifacts by category.
    
    Args:
        artifacts: Artifacts to group
        
    Returns:
        Dictionary mapping category to list of artifacts
    """
    result: dict[str, list[Artifact]] = {}
    
    for artifact in artifacts:
        if artifact.category not in result:
            result[artifact.category] = []
        result[artifact.category].append(artifact)
    
    return result
