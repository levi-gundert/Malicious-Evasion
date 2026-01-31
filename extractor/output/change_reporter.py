"""Change reporting between extraction runs."""

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def compare_and_write_report(
    current_artifacts: dict[str, list],
    previous_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """
    Compare current extraction with previous and write a change report.
    
    Args:
        current_artifacts: Current extraction results
        previous_path: Path to previous extraction JSON
        output_path: Path to write change report
        
    Returns:
        Dictionary with change summary
    """
    import json
    
    # Load previous if exists
    previous_artifacts = {}
    if previous_path.exists():
        try:
            with open(previous_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                previous_artifacts = data.get("artifacts", {})
        except Exception as e:
            logger.warning(f"Could not load previous artifacts: {e}")
    
    # Calculate changes
    changes = {
        "new": {},
        "removed": {},
        "summary": {
            "total_new": 0,
            "total_removed": 0,
        }
    }
    
    # Find new artifacts
    for os_type, os_artifacts in current_artifacts.items():
        current_ids = {a.get("id") if isinstance(a, dict) else getattr(a, "id", None) for a in os_artifacts}
        previous_ids = {a.get("id") for a in previous_artifacts.get(os_type, [])}
        
        new_ids = current_ids - previous_ids
        if new_ids:
            changes["new"][os_type] = len(new_ids)
            changes["summary"]["total_new"] += len(new_ids)
    
    # Find removed artifacts
    for os_type, os_artifacts in previous_artifacts.items():
        previous_ids = {a.get("id") for a in os_artifacts}
        current_ids = {a.get("id") if isinstance(a, dict) else getattr(a, "id", None) 
                       for a in current_artifacts.get(os_type, [])}
        
        removed_ids = previous_ids - current_ids
        if removed_ids:
            changes["removed"][os_type] = len(removed_ids)
            changes["summary"]["total_removed"] += len(removed_ids)
    
    # Write report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(changes, f, indent=2)
    
    logger.info(f"Change report: {changes['summary']['total_new']} new, {changes['summary']['total_removed']} removed")
    
    return changes
