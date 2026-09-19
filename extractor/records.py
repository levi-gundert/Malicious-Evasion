"""One model-to-database contract for imports and live extraction."""

import json
from extractor.models.artifact import Artifact
from extractor.models.id import artifact_id

EXTRACTOR_VERSION = "2"


def artifact_record(
    artifact,
    sample_id="",
    sample_sha1="",
    sample_sha256="",
    report_base="https://private.tria.ge",
):
    a = Artifact.model_validate(artifact)
    data = a.model_dump(mode="json")
    value = a.match_criteria.value
    privilege = "admin" if a.os.value == "windows" else "root"
    if a.os.value == "windows" and value.upper().startswith("HKCU\\"):
        privilege = "user"
    elif value.startswith(("/home/", "/tmp/", "/sdcard/", "/storage/")):
        privilege = "user"
    import os

    try:
        if os.path.isabs(value) and os.path.commonpath(
            [os.path.expanduser("~"), value]
        ) == os.path.expanduser("~"):
            privilege = "user"
    except ValueError:
        pass
    return {
        "id": artifact_id(a.os.value, a.artifact_type.value, value),
        "os": a.os.value,
        "artifact_type": a.artifact_type.value,
        "category": a.category,
        "value": value,
        "match_type": a.match_criteria.type.value,
        "case_sensitive": a.match_criteria.case_sensitive,
        "privilege_level": privilege,
        "confidence": a.provenance.confidence,
        "sample_count": a.provenance.sample_count,
        "description": a.metadata.description,
        "evasion_purpose": (
            a.metadata.evasion_purpose.value if a.metadata.evasion_purpose else ""
        ),
        "source_sample_id": sample_id or next(iter(a.provenance.sample_ids), ""),
        "source_sha1": sample_sha1 or next(iter(a.provenance.sample_sha1s), ""),
        "source_sha256": sample_sha256 or next(iter(a.provenance.sample_hashes), ""),
        "triage_url": f"{report_base.rstrip('/')}/{sample_id}" if sample_id else "",
        "first_seen": data["metadata"]["first_seen"],
        "last_seen": data["metadata"]["last_seen"],
        "deception": json.dumps(data["deception"]),
        "provenance_json": json.dumps(data["provenance"]),
        "validation_status": "candidate",
    }
