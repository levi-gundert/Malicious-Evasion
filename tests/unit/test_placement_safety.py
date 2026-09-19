import json
import os
from pathlib import Path
import pytest

from extractor.placement import (
    PlacementError,
    SafePlacement,
    host_os,
    make_plan,
    marker,
)
from gui.services.placement_engine import PlacementEngine


def artifact(path, **changes):
    data = {
        "os": host_os(),
        "artifact_type": "file",
        "value": str(path),
        "match_type": "exact",
    }
    data.update(changes)
    return data


@pytest.fixture
def engine(tmp_path):
    return SafePlacement(tmp_path / "state" / "placement-journal.db")


def test_existing_file_is_preserved(engine, tmp_path):
    target = tmp_path / "existing.txt"
    target.write_text("valuable original content")
    with pytest.raises(PlacementError, match="Existing"):
        engine.apply(artifact(target))
    assert target.read_text() == "valuable original content"
    assert engine.journal.records()[0]["status"] == "failed"


def test_repeated_place_remove_and_restart(engine, tmp_path):
    target = tmp_path / "decoy.txt"
    token = engine.apply(artifact(target))
    assert engine.apply(artifact(target)) == token
    restarted = SafePlacement(engine.journal.path)
    assert restarted.reconcile()[0]["status"] == "verified"
    assert restarted.remove(token)
    assert restarted.remove(token)
    assert not target.exists()


def test_modified_file_cannot_be_removed(engine, tmp_path):
    target = tmp_path / "decoy.txt"
    token = engine.apply(artifact(target))
    target.write_text("user changed this file")
    with pytest.raises(PlacementError, match="modified"):
        engine.remove(token)
    assert target.read_text() == "user changed this file"


def test_directory_contents_are_preserved(engine, tmp_path):
    target = tmp_path / "decoy-dir"
    token = engine.apply(artifact(target, deception={"plant_as": "directory"}))
    (target / "user.txt").write_text("valuable")
    with pytest.raises(PlacementError, match="other data"):
        engine.remove(token)
    assert (target / "user.txt").read_text() == "valuable"
    (target / "user.txt").unlink()
    assert engine.remove(token)


@pytest.mark.parametrize(
    "kind", ["process", "wmi", "property", "package", "mutex", "service"]
)
def test_unsupported_types_fail_before_mutation(engine, tmp_path, kind):
    with pytest.raises(PlacementError):
        engine.apply(artifact(tmp_path / "unused", artifact_type=kind))
    assert engine.journal.records() == []


@pytest.mark.parametrize(
    "value",
    [
        "relative.txt",
        "../escape",
        "C:\\temp\\$(anything).txt",
        "C:\\temp\\*.txt",
        "/tmp/`anything`",
        "%TEMP%/decoy",
        "/tmp/../etc/decoy",
        "\\\\server\\share\\decoy",
        "/tmp/a\0b",
    ],
)
def test_untrusted_paths_rejected(value):
    with pytest.raises(PlacementError):
        make_plan(artifact(value))


def test_foreign_os_and_pattern_rejected(engine, tmp_path):
    with pytest.raises(PlacementError):
        engine.plan(artifact(tmp_path / "x", os="foreign"))
    with pytest.raises(PlacementError):
        engine.plan(artifact(tmp_path / "x", match_type="pattern"))


def test_expired_recipe_cannot_be_placed(engine, tmp_path):
    with pytest.raises(PlacementError, match="revalidation"):
        engine.apply(
            artifact(
                tmp_path / "x",
                deception={"plant_as": "file", "retest_after": "2020-01-01T00:00:00Z"},
            )
        )


def test_missing_parent_not_implicitly_created(engine, tmp_path):
    target = tmp_path / "missing" / "decoy"
    with pytest.raises(PlacementError, match="Parent"):
        engine.apply(artifact(target))
    assert not target.parent.exists()


def test_symlink_parent_rejected(engine, tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(actual, target_is_directory=True)
    except OSError:
        pytest.skip("Host does not permit unprivileged symlink creation")
    with pytest.raises(PlacementError, match="Symlinks"):
        engine.apply(artifact(link / "decoy"))


def test_interrupted_file_creation_is_reconciled(engine, tmp_path):
    plan = engine.plan(artifact(tmp_path / "decoy"))
    row = engine.journal.reserve(plan)
    Path(plan.target).write_bytes(marker(row["id"]))
    assert engine.reconcile()[0]["status"] == "verified"
    assert engine.remove(row["id"])


def test_unowned_partial_file_is_preserved(engine, tmp_path):
    plan = engine.plan(artifact(tmp_path / "partial"))
    row = engine.journal.reserve(plan)
    Path(plan.target).write_bytes(b"")
    assert engine.reconcile()[0]["status"] == "needs_review"
    with pytest.raises(PlacementError):
        engine.remove(row["id"])
    assert Path(plan.target).exists()


def test_failed_helper_never_reports_success(tmp_path, monkeypatch):
    monkeypatch.setattr("gui.services.elevation.run_helper", lambda *args: False)
    engine = PlacementEngine(journal_path=tmp_path / "placement-journal.db")
    assert not engine.place_artifact(artifact(tmp_path / "decoy"), elevate=True)
    assert not (tmp_path / "decoy").exists()


def test_launch_success_without_object_is_not_verified(tmp_path, monkeypatch):
    monkeypatch.setattr("gui.services.elevation.run_helper", lambda *args: True)
    engine = PlacementEngine(journal_path=tmp_path / "placement-journal.db")
    assert not engine.place_artifact(artifact(tmp_path / "decoy"), elevate=True)


def test_legacy_removal_refused(tmp_path):
    engine = PlacementEngine(journal_path=tmp_path / "placement-journal.db")
    target = tmp_path / "original"
    target.write_text("original")
    assert not engine.remove_artifact(artifact(target))
    assert target.read_text() == "original"


def test_registry_requires_explicit_reviewed_recipe():
    candidate = {
        "os": "windows",
        "artifact_type": "registry",
        "value": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "deception": {
            "plant_as": "registry_value",
            "registry_name": "test",
            "registry_type": "REG_SZ",
            "registry_data": "anything",
        },
    }
    with pytest.raises(PlacementError, match="namespaces"):
        make_plan(candidate, "windows")


@pytest.mark.skipif(os.name != "nt", reason="Windows registry only")
def test_registry_roundtrip_and_existing_key_preserved(engine):
    import uuid
    import winreg

    namespace = r"SOFTWARE\MEAP"
    # Dedicated randomly named test key; no live VM or application key touched.
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, namespace) as key:
        pass
    path = "HKCU\\" + namespace + "\\test-" + uuid.uuid4().hex
    a = {
        "os": "windows",
        "artifact_type": "registry",
        "value": path,
        "deception": {
            "plant_as": "registry_value",
            "registry_name": "Probe",
            "registry_type": "REG_SZ",
            "registry_data": "sandbox",
        },
    }
    token = engine.apply(a)
    try:
        assert engine.apply(a) == token
        other = SafePlacement(engine.journal.path.parent / "other.db")
        with pytest.raises(PlacementError, match="Existing"):
            other.apply(a)
    finally:
        engine.remove(token)
