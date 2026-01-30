from pathlib import Path

import pytest

from extractor.config import load_config


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def test_loads_minimal_config() -> None:
    config_path = FIXTURES_DIR / "config_minimal.yaml"
    config = load_config(config_path)
    assert config.triage.api_key == "test-key"
    assert config.output.directory == "./output"


def test_env_overrides_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = FIXTURES_DIR / "config_minimal.yaml"
    monkeypatch.setenv("EXTRACTOR_OUTPUT_DIR", "./custom-output")
    monkeypatch.setenv("EXTRACTOR_LOG_LEVEL", "DEBUG")
    config = load_config(config_path)
    assert config.output.directory == "./custom-output"
    assert config.logging.level == "DEBUG"


def test_invalid_config_raises_clear_error(tmp_path: Path) -> None:
    bad_config = tmp_path / "bad_config.yaml"
    bad_config.write_text("triage:\n  api_key:\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid configuration"):
        load_config(bad_config)
