"""Versioned, JSON-safe serialization shared by CLI and GUI exports."""

import json
from pathlib import Path
from extractor.models.artifact import Artifact
from extractor.output.statistics import generate_statistics


def artifact_to_dict(artifact):
    return Artifact.model_validate(artifact).model_dump(mode="json")


def normalize_artifacts(artifacts):
    values = (
        (a for group in artifacts.values() for a in group)
        if isinstance(artifacts, dict)
        else artifacts
    )
    return [Artifact.model_validate(a) for a in values]


def write_artifacts_json(artifacts, output_path: Path, pretty: bool = True) -> Path:
    models = normalize_artifacts(artifacts)
    groups = {}
    for artifact in models:
        groups.setdefault(artifact.os.value, []).append(artifact_to_dict(artifact))
    data = {
        "version": "1.0",
        "statistics": generate_statistics(models).to_dict(),
        "artifacts": groups,
    }
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2 if pretty else None), encoding="utf-8"
    )
    return output_path


def write_per_os_json(artifacts, output_dir: Path, pretty: bool = True) -> list[Path]:
    groups = {}
    for artifact in normalize_artifacts(artifacts):
        groups.setdefault(artifact.os.value, []).append(artifact_to_dict(artifact))
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for os_type, records in sorted(groups.items()):
        path = output_dir / f"artifacts_{os_type}.json"
        path.write_text(
            json.dumps(
                {"version": "1.0", "os": os_type, "artifacts": records},
                indent=2 if pretty else None,
            ),
            encoding="utf-8",
        )
        paths.append(path)
    return paths
