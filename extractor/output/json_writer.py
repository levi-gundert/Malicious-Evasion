"""JSON output writers for extraction results."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def write_artifacts_json(
    artifacts: dict[str, list],
    output_path: Path,
    pretty: bool = True,
) -> None:
    """
    Write artifacts to a JSON file.
    
    Args:
        artifacts: Dictionary of artifacts by OS
        output_path: Path to output file
        pretty: If True, format with indentation
    """
    logger.info(f"Writing artifacts to {output_path}")
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump({"artifacts": artifacts}, f, indent=2, default=str)
        else:
            json.dump({"artifacts": artifacts}, f, default=str)
    
    logger.info(f"Wrote {sum(len(v) for v in artifacts.values())} artifacts")


def write_per_os_json(
    artifacts: dict[str, list],
    output_dir: Path,
    pretty: bool = True,
) -> None:
    """
    Write separate JSON files for each OS.
    
    Args:
        artifacts: Dictionary of artifacts by OS
        output_dir: Directory to write files to
        pretty: If True, format with indentation
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for os_type, os_artifacts in artifacts.items():
        if not os_artifacts:
            continue
        
        output_path = output_dir / f"{os_type}_artifacts.json"
        logger.info(f"Writing {len(os_artifacts)} {os_type} artifacts to {output_path}")
        
        with open(output_path, "w", encoding="utf-8") as f:
            if pretty:
                json.dump({"os": os_type, "artifacts": os_artifacts}, f, indent=2, default=str)
            else:
                json.dump({"os": os_type, "artifacts": os_artifacts}, f, default=str)
