"""Observation statistics, never an estimate of protection efficacy."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from extractor.models.artifact import Artifact


@dataclass
class ExtractionStatistics:
    total_samples: int = 0
    total_artifacts: int = 0
    unique_artifacts: int = 0
    by_os: dict = field(default_factory=dict)
    by_type: dict = field(default_factory=dict)
    by_category: dict = field(default_factory=dict)
    by_confidence: dict = field(
        default_factory=lambda: {"low": 0, "medium": 0, "high": 0}
    )
    errors: int = 0
    extracted_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self):
        return asdict(self)


def generate_statistics(artifacts):
    values = (
        (a for group in artifacts.values() for a in group)
        if isinstance(artifacts, dict)
        else artifacts
    )
    stats = ExtractionStatistics()
    ids, samples = set(), set()
    for value in values:
        a = Artifact.model_validate(value)
        stats.total_artifacts += 1
        ids.add(a.id)
        samples.update(a.provenance.sample_hashes)
        for counts, key in (
            (stats.by_os, a.os.value),
            (stats.by_type, a.artifact_type.value),
            (stats.by_category, a.category),
        ):
            counts[key] = counts.get(key, 0) + 1
        score = a.provenance.confidence
        stats.by_confidence[
            "high" if score >= 0.8 else "medium" if score >= 0.5 else "low"
        ] += 1
    stats.unique_artifacts = len(ids)
    stats.total_samples = len(samples)
    return stats
