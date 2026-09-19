import json
from datetime import datetime, timezone
from unittest.mock import Mock
import pytest

from extractor.aggregation.deduplicator import merge_artifacts
from extractor.models.artifact import OSType, create_file_artifact
from extractor.models.id import artifact_id
from extractor.records import artifact_record
from gui.services.credentials import CredentialStore
from gui.services.database import ArtifactDatabase


@pytest.fixture
def db(tmp_path):
    db = ArtifactDatabase(tmp_path / "test.db")
    db.initialize()
    yield db
    db.close()


def test_repeated_sample_does_not_inflate_counts():
    a = create_file_artifact(
        OSType.WINDOWS, r"C:\decoy", "test", sample_hash="a" * 64, sample_id="report-1"
    )
    b = a.model_copy(deep=True)
    b.provenance.sample_ids = ["report-2"]
    merged = merge_artifacts(a, b)
    assert merged.provenance.sample_count == 1
    assert merged.provenance.sample_ids == ["report-1", "report-2"]


def test_deduplication_remembers_identities_beyond_display_cap():
    merged = create_file_artifact(OSType.WINDOWS, r"C:\decoy", "test", sample_hash="0")
    for number in range(1, 150):
        merged = merge_artifacts(
            merged,
            create_file_artifact(
                OSType.WINDOWS, r"C:\decoy", "test", sample_hash=str(number)
            ),
        )
    repeated = create_file_artifact(
        OSType.WINDOWS, r"C:\decoy", "test", sample_hash="149"
    )
    assert merge_artifacts(merged, repeated).provenance.sample_count == 150
    assert len(merged.provenance.sample_hashes) == 100


def test_one_identity_and_recipe_survives_conversion():
    a = create_file_artifact(OSType.WINDOWS, r"C:\decoy", "test")
    a.deception.plant_as = "directory"
    record = artifact_record(a)
    assert record["id"] == a.id
    assert json.loads(record["deception"])["plant_as"] == "directory"


def test_observations_count_unique_samples_across_reports(db):
    a = create_file_artifact(OSType.WINDOWS, r"C:\decoy", "test")
    db.add_artifact(artifact_record(a))
    for report in ("one", "two", "two"):
        db.record_observation(
            a.id,
            "hash-one",
            report,
            "behavioral1",
            "2020-01-01T00:00:00+00:00",
            ["family"],
            {"report": report},
        )
    record = db.get_artifact_by_id(a.id)
    assert record["sample_count"] == 1
    assert record["last_seen"].startswith("2020-")
    assert len(db.get_observations(a.id)) == 2


def test_old_processed_version_is_reprocessed(db):
    db.mark_sample_processed("sample", "windows")
    assert db.is_sample_processed("sample")
    db.conn.execute("UPDATE processed_samples SET extractor_version='1'")
    db.conn.commit()
    assert not db.is_sample_processed("sample")


def test_legacy_identity_migrates_placement_references(db):
    db.conn.execute(
        "INSERT INTO artifacts(id,os,artifact_type,category,value) VALUES('legacy','windows','file','test','C:\\legacy')"
    )
    db.conn.execute(
        "INSERT INTO placements(artifact_id,placed_path,status) VALUES('legacy','C:\\legacy','placed')"
    )
    db.conn.commit()
    db._create_schema()
    expected = artifact_id("windows", "file", r"C:\legacy")
    assert db.get_artifact_by_id(expected)
    assert (
        db.conn.execute("SELECT artifact_id FROM placements").fetchone()[0] == expected
    )
    assert db.conn.execute(
        "SELECT record FROM legacy_artifact_records WHERE id='legacy'"
    ).fetchone()


def test_secret_migration_and_session_fallback(db, monkeypatch):
    monkeypatch.delenv("TRIAGE_API_KEY", raising=False)
    backend = Mock()
    backend.set_password.side_effect = RuntimeError("unavailable")
    store = CredentialStore(backend)
    db.conn.execute("INSERT INTO settings VALUES('api_key','synthetic-test-secret')")
    db.conn.commit()
    store.migrate(db)
    assert store.get() == "synthetic-test-secret"
    assert store.mode == "session only"
    assert db.get_setting("api_key") is None
    with pytest.raises(ValueError):
        db.save_setting("api_key", "must-not-persist")


def test_secure_store_and_environment_precedence(monkeypatch):
    backend = Mock()
    store = CredentialStore(backend)
    assert store.save("synthetic") == "OS credential store"
    backend.set_password.assert_called_once_with(
        store.service, store.username, "synthetic"
    )
    monkeypatch.setenv("TRIAGE_API_KEY", "environment-value")
    assert store.get() == "environment-value"
