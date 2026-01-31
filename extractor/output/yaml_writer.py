"""YAML output writers for deception configurations."""

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def write_deception_yaml(
    artifacts: dict[str, list],
    output_path: Path,
) -> None:
    """
    Write deception configuration YAML.
    
    Args:
        artifacts: Dictionary of artifacts by OS
        output_path: Path to output file
    """
    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML not installed, skipping YAML output")
        return
    
    logger.info(f"Writing deception config to {output_path}")
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Build deception config structure
    config = {
        "version": "1.0",
        "artifacts": {},
    }
    
    for os_type, os_artifacts in artifacts.items():
        if not os_artifacts:
            continue
        
        config["artifacts"][os_type] = []
        for artifact in os_artifacts:
            if hasattr(artifact, "model_dump"):
                config["artifacts"][os_type].append(artifact.model_dump())
            elif isinstance(artifact, dict):
                config["artifacts"][os_type].append(artifact)
    
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    
    logger.info(f"Wrote deception config for {len(config['artifacts'])} OS types")
