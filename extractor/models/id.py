"""
Deterministic artifact ID generation.

Artifact IDs follow the format: art-{os}-{type}-{hash8}
where hash8 is the first 8 characters of SHA256(os|type|match_value).

This ensures:
- Stable IDs across runs for the same artifact
- Uniqueness for different artifacts
- Human-readable prefix indicating OS and type
"""

from __future__ import annotations

import hashlib
import logging

logger = logging.getLogger(__name__)


def artifact_id(os_type: str, artifact_type: str, match_value: str) -> str:
    """
    Generate a deterministic artifact ID.
    
    Args:
        os_type: Operating system (android, windows, linux, macos)
        artifact_type: Type of artifact (file, registry, process, etc.)
        match_value: The value being matched (path, key, process name, etc.)
        
    Returns:
        Artifact ID in format: art-{os}-{type}-{hash8}
        
    Example:
        >>> artifact_id("android", "file", "/system/bin/qemu-props")
        'art-android-file-a1b2c3d4'
    """
    # Debug: Log the ID generation inputs
    logger.debug(f"Generating artifact ID: os={os_type}, type={artifact_type}, value={match_value[:50]}...")
    
    # Normalize inputs to lowercase for consistency
    os_type = os_type.lower().strip()
    artifact_type = artifact_type.lower().strip()
    
    # Create the hash input string
    # Use pipe delimiter to prevent collisions like:
    # "android|file|path" vs "androidfile|path"
    hash_input = f"{os_type}|{artifact_type}|{match_value}"
    
    # Generate SHA256 hash
    hash_bytes = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
    
    # Take first 8 characters
    hash8 = hash_bytes[:8]
    
    # Build the artifact ID
    artifact_id_str = f"art-{os_type}-{artifact_type}-{hash8}"
    
    # Debug: Log the generated ID
    logger.debug(f"Generated artifact ID: {artifact_id_str}")
    
    return artifact_id_str


def validate_artifact_id(artifact_id_str: str) -> bool:
    """
    Validate that a string is a properly formatted artifact ID.
    
    Args:
        artifact_id_str: The ID to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not artifact_id_str or not isinstance(artifact_id_str, str):
        return False
    
    parts = artifact_id_str.split("-")
    
    # Should have format: art-{os}-{type}-{hash8}
    if len(parts) < 4:
        return False
    
    if parts[0] != "art":
        return False
    
    # OS should be one of the supported types
    valid_os = {"android", "windows", "linux", "macos"}
    if parts[1] not in valid_os:
        return False
    
    # Hash should be 8 hex characters
    hash_part = parts[-1]
    if len(hash_part) != 8:
        return False
    
    try:
        int(hash_part, 16)  # Check if valid hex
    except ValueError:
        return False
    
    return True
