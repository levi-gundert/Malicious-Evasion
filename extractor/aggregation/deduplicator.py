"""
Artifact deduplication logic.

Merges duplicate artifacts while preserving provenance information.
Duplicates are identified by their deterministic ID (os + type + value hash).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterable

from extractor.models.artifact import Artifact

logger = logging.getLogger(__name__)


def merge_artifacts(existing: Artifact, new: Artifact) -> Artifact:
    """
    Merge a new artifact into an existing one.
    
    Combines provenance information while keeping the artifact ID.
    
    Args:
        existing: The existing artifact to merge into
        new: The new artifact with additional data
        
    Returns:
        Merged artifact with combined provenance
    """
    # Debug: Log the merge
    logger.debug(f"Merging artifact {existing.id}: {existing.provenance.sample_count} + 1 samples")
    
    # Combine sample hashes (capped at 100)
    combined_hashes = list(existing.provenance.sample_hashes)
    for h in new.provenance.sample_hashes:
        if h not in combined_hashes:
            combined_hashes.append(h)
    combined_hashes = combined_hashes[:100]  # Cap at 100
    
    # Combine families
    combined_families = list(existing.provenance.families)
    for f in new.provenance.families:
        if f not in combined_families:
            combined_families.append(f)
    
    # Update timestamps
    first_seen = existing.metadata.first_seen
    last_seen = existing.metadata.last_seen
    
    if new.metadata.first_seen:
        if first_seen is None or new.metadata.first_seen < first_seen:
            first_seen = new.metadata.first_seen
    
    if new.metadata.last_seen:
        if last_seen is None or new.metadata.last_seen > last_seen:
            last_seen = new.metadata.last_seen
    
    # Create merged artifact by copying existing and updating fields
    merged_data = existing.model_dump()
    
    # Update provenance
    merged_data["provenance"]["sample_count"] = existing.provenance.sample_count + new.provenance.sample_count
    merged_data["provenance"]["sample_hashes"] = combined_hashes
    merged_data["provenance"]["families"] = combined_families
    
    # Update metadata timestamps
    merged_data["metadata"]["first_seen"] = first_seen
    merged_data["metadata"]["last_seen"] = last_seen
    
    # Prefer description from whichever has one
    if not existing.metadata.description and new.metadata.description:
        merged_data["metadata"]["description"] = new.metadata.description
    
    # Prefer deception info from whichever has it
    if not existing.deception.recommended_value and new.deception.recommended_value:
        merged_data["deception"]["recommended_value"] = new.deception.recommended_value
    if not existing.deception.notes and new.deception.notes:
        merged_data["deception"]["notes"] = new.deception.notes
    
    return Artifact.model_validate(merged_data)


def deduplicate_artifacts(artifacts: Iterable[Artifact]) -> list[Artifact]:
    """
    Deduplicate a collection of artifacts by their ID.
    
    Artifacts with the same ID (same os + type + value hash) are merged,
    combining their provenance data.
    
    Args:
        artifacts: Collection of artifacts to deduplicate
        
    Returns:
        List of unique artifacts with merged provenance
    """
    # Debug: Count input
    artifact_list = list(artifacts)
    logger.info(f"Deduplicating {len(artifact_list)} artifacts...")
    
    # Group by ID
    by_id: dict[str, Artifact] = {}
    
    for artifact in artifact_list:
        if artifact.id in by_id:
            # Merge into existing
            by_id[artifact.id] = merge_artifacts(by_id[artifact.id], artifact)
        else:
            # New artifact
            by_id[artifact.id] = artifact
    
    result = list(by_id.values())
    
    # Debug: Log results
    deduped_count = len(artifact_list) - len(result)
    logger.info(f"Deduplication complete: {len(result)} unique artifacts ({deduped_count} duplicates merged)")
    
    return result
