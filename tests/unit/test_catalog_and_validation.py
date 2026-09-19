import base64
from datetime import datetime, timedelta, timezone
import json
import pytest
from click.testing import CliRunner
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from extractor.catalog import load_catalog
from extractor.cli import cli
from extractor.validation import summarize_trials


def signed_catalog(tmp_path, expires=None, version=2):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = json.dumps(
        {
            "schema_version": 1,
            "catalog_version": version,
            "expires_at": expires
            or (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "recipes": [],
        }
    ).encode()
    catalog, signature, key = (
        tmp_path / name for name in ("catalog.json", "catalog.sig", "key.pub")
    )
    catalog.write_bytes(payload)
    signature.write_bytes(base64.b64encode(private.sign(payload)))
    key.write_bytes(base64.b64encode(public))
    return catalog, signature, key


def test_external_catalog_requires_trust_and_valid_signature(tmp_path):
    catalog, signature, key = signed_catalog(tmp_path)
    with pytest.raises(ValueError, match="require"):
        load_catalog(catalog)
    assert load_catalog(catalog, signature, key)["catalog_version"] == 2
    catalog.write_bytes(catalog.read_bytes() + b" ")
    with pytest.raises(InvalidSignature):
        load_catalog(catalog, signature, key)


def test_expiry_and_rollback_rejected(tmp_path):
    paths = signed_catalog(tmp_path, expires="2020-01-01T00:00:00Z")
    with pytest.raises(ValueError, match="expired"):
        load_catalog(*paths)
    paths = signed_catalog(tmp_path)
    with pytest.raises(ValueError, match="rollback"):
        load_catalog(*paths, minimum_version=3)


def test_benign_probe_cli(tmp_path):
    result = CliRunner().invoke(
        cli, ["placement", "probe", "--output", str(tmp_path / "report.json")]
    )
    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / "report.json").read_text())
    assert len(report["checks"]) == 2
    assert all(row["absent_after"] for row in report["checks"])


def trial(**changes):
    record = {
        "sample_sha256": "a" * 64,
        "family": "synthetic",
        "recipe": "candidate",
        "repeat": 1,
        "baseline_environment": "image-1",
        "decoy_environment": "image-1",
        "baseline_seconds": 300,
        "decoy_seconds": 300,
        "baseline_outcome": "harmful",
        "decoy_outcome": "terminated",
    }
    record.update(changes)
    return record


def test_validation_separates_termination_from_delay_and_failures():
    result = summarize_trials(
        [
            trial(),
            trial(repeat=2, decoy_outcome="delayed"),
            trial(repeat=3, baseline_outcome="failed"),
        ]
    )
    assert result["outcomes"] == {
        "observed_termination": 1,
        "delay_or_no_activity": 1,
        "inconclusive": 1,
    }


def test_unmatched_or_duplicate_trials_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        summarize_trials([trial(), trial()])
    with pytest.raises(ValueError, match="environments"):
        summarize_trials([trial(decoy_environment="different-image")])
