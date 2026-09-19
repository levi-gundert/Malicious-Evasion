"""Export candidate recipes; exporting never executes a placement."""

from datetime import datetime, timezone
from pathlib import Path
import yaml
from extractor.output.json_writer import artifact_to_dict, normalize_artifacts


def artifact_to_deception_entry(artifact):
    a = artifact_to_dict(artifact)
    return {
        "id": a["id"],
        "value": a["match_criteria"]["value"],
        "match_type": a["match_criteria"]["type"],
        "confidence": a["provenance"]["confidence"],
        "sample_count": a["provenance"]["sample_count"],
        "recommended_value": a["deception"]["recommended_value"],
        "notes": a["deception"]["notes"],
        "artifact": a,
    }


def write_deception_yaml(artifacts, output_path: Path) -> list[Path]:
    models = normalize_artifacts(artifacts)
    output_path = Path(output_path)
    if output_path.suffix in (".yaml", ".yml"):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"version": "1.0", "artifacts": {}}
        for artifact in models:
            data["artifacts"].setdefault(artifact.os.value, []).append(
                artifact_to_dict(artifact)
            )
        output_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return [output_path]
    groups = {}
    categories = {
        "file": "files",
        "property": "system_properties",
        "registry": "registry_keys",
        "process": "processes",
    }
    for artifact in models:
        data = groups.setdefault(
            artifact.os.value, {"version": "1.0", "os": artifact.os.value}
        )
        data.setdefault(
            categories.get(artifact.artifact_type.value, artifact.artifact_type.value),
            [],
        ).append(artifact_to_deception_entry(artifact))
    output_path.mkdir(parents=True, exist_ok=True)
    paths = []
    for os_type, data in sorted(groups.items()):
        path = output_path / f"{os_type}_deception_config.yaml"
        header = f"# {os_type.upper()} candidate recipes\n# Generated: {datetime.now(timezone.utc).isoformat()}\n# Confidence describes observations, not protection efficacy.\n"
        path.write_text(
            header + yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
        )
        paths.append(path)
    return paths
