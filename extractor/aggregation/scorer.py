"""
Confidence scoring for artifacts.

Calculates confidence based on:
- Sample count (more samples = higher confidence)
- Family diversity (seen in multiple families = higher confidence)
- Recency (recently seen = higher confidence)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Iterable

from extractor.models.artifact import Artifact

logger = logging.getLogger(__name__)


def calculate_confidence(
    sample_count: int,
    unique_families: int = 0,
    last_seen: datetime | None = None,
    recency_days: int = 30,
) -> float:
    """
    Calculate confidence score for an artifact.
    
    Formula:
        base_score = min(sample_count / 10, 0.5)      # Max 0.5 from sample count
        family_bonus = min(unique_families / 5, 0.3)  # Max 0.3 from family diversity
        recency_bonus = 0.2 if recent else 0.1        # Boost for recent sightings
        
        confidence = min(base_score + family_bonus + recency_bonus, 1.0)
    
    Args:
        sample_count: Number of samples containing this artifact
        unique_families: Number of unique malware families
        last_seen: When the artifact was last seen
        recency_days: Days threshold for "recent" (default 30)
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    # Base score from sample count (max 0.5 at 10+ samples)
    base_score = min(sample_count / 10.0, 0.5)
    
    # Family diversity bonus (max 0.3 at 5+ families)
    family_bonus = min(unique_families / 5.0, 0.3)
    
    # Recency bonus
    recency_bonus = 0.1  # Default for old/unknown
    
    if last_seen is not None:
        now = datetime.now(timezone.utc)
        # Ensure last_seen is timezone-aware
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        
        age = now - last_seen
        if age <= timedelta(days=recency_days):
            recency_bonus = 0.2  # Recent sighting
    
    # Calculate total confidence
    confidence = base_score + family_bonus + recency_bonus
    confidence = min(confidence, 1.0)  # Cap at 1.0
    
    # Debug: Log calculation
    logger.debug(
        f"Confidence calculation: base={base_score:.2f} + family={family_bonus:.2f} "
        f"+ recency={recency_bonus:.2f} = {confidence:.2f}"
    )
    
    return round(confidence, 2)


def score_artifact(artifact: Artifact) -> Artifact:
    """
    Calculate and update confidence score for an artifact.
    
    Args:
        artifact: Artifact to score
        
    Returns:
        Artifact with updated confidence score
    """
    confidence = calculate_confidence(
        sample_count=artifact.provenance.sample_count,
        unique_families=len(artifact.provenance.families),
        last_seen=artifact.metadata.last_seen,
    )
    
    # Update the artifact's confidence
    data = artifact.model_dump()
    data["provenance"]["confidence"] = confidence
    
    return Artifact.model_validate(data)


def score_artifacts(artifacts: Iterable[Artifact]) -> list[Artifact]:
    """
    Calculate confidence scores for all artifacts.
    
    Args:
        artifacts: Collection of artifacts to score
        
    Returns:
        List of artifacts with updated confidence scores
    """
    artifact_list = list(artifacts)
    logger.info(f"Scoring {len(artifact_list)} artifacts...")
    
    scored = [score_artifact(a) for a in artifact_list]
    
    # Debug: Log score distribution
    scores = [a.provenance.confidence for a in scored]
    if scores:
        avg_score = sum(scores) / len(scores)
        high = sum(1 for s in scores if s >= 0.8)
        medium = sum(1 for s in scores if 0.5 <= s < 0.8)
        low = sum(1 for s in scores if s < 0.5)
        
        logger.info(
            f"Score distribution: high={high}, medium={medium}, low={low} "
            f"(avg={avg_score:.2f})"
        )
    
    return scored
