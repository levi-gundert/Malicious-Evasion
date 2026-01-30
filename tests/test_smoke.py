import subprocess
import sys


def test_import_extractor() -> None:
    import extractor  # noqa: F401


def test_cli_help() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "extractor.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_cli_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "extractor.cli", "version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Triage Artifact Extractor v1.0" in result.stdout
