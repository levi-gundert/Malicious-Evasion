from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class TriageRateLimit(BaseModel):
    requests_per_minute: int = 60
    retry_on_429: bool = True
    max_retries: int = 5


class TriageConfig(BaseModel):
    api_key: str
    base_url: str = "https://tria.ge/api/v0"
    rate_limit: TriageRateLimit = Field(default_factory=TriageRateLimit)


class ExtractionConfig(BaseModel):
    lookback_days: int = 7
    min_score: int = 7
    os_targets: list[str] = Field(
        default_factory=lambda: ["android", "windows", "linux", "macos"]
    )
    max_samples_per_os: int = 500


class ExcludePattern(BaseModel):
    regex: str | None = None
    contains: str | None = None

    @field_validator("regex", "contains")
    @classmethod
    def empty_string_to_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("contains")
    @classmethod
    def at_least_one_selector(cls, value: str | None, info):  # type: ignore[override]
        data = info.data
        if not value and not data.get("regex"):
            raise ValueError("exclude pattern must specify 'regex' or 'contains'")
        return value


class FilteringConfig(BaseModel):
    min_sample_count: int = 2
    min_confidence: float = 0.3
    exclude_patterns: list[ExcludePattern] = Field(default_factory=list)


class OutputConfig(BaseModel):
    directory: str = "./output"
    formats: list[str] = Field(default_factory=lambda: ["json", "yaml"])
    split_by_os: bool = True
    generate_deception_configs: bool = True
    generate_change_report: bool = True


class CacheConfig(BaseModel):
    enabled: bool = True
    path: str = "./cache/triage_cache.db"
    max_size_mb: int = 500


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str = "./logs/extractor.log"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    triage: TriageConfig
    extraction: ExtractionConfig = Field(default_factory=ExtractionConfig)
    filtering: FilteringConfig = Field(default_factory=FilteringConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


class ConfigError(ValueError):
    pass


def _interpolate_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _interpolate_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(item) for item in value]
    if isinstance(value, str):
        if value.startswith("${") and value.endswith("}"):
            env_var = value[2:-1]
            env_value = os.getenv(env_var)
            if env_value is None:
                raise ConfigError(f"Missing environment variable: {env_var}")
            return env_value
        return value
    return value


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    output_dir = os.getenv("EXTRACTOR_OUTPUT_DIR")
    if output_dir:
        data.setdefault("output", {})["directory"] = output_dir
    log_level = os.getenv("EXTRACTOR_LOG_LEVEL")
    if log_level:
        data.setdefault("logging", {})["level"] = log_level
    return data


def load_config(config_path: str | Path | None = None) -> AppConfig:
    if config_path is None:
        config_path = os.getenv("EXTRACTOR_CONFIG") or "./config.yaml"
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ConfigError("Invalid configuration format: root must be a mapping")

    data = _interpolate_env(data)
    data = _apply_env_overrides(data)

    try:
        return AppConfig.model_validate(data)
    except (ValidationError, ConfigError) as exc:
        raise ConfigError(f"Invalid configuration: {exc}") from exc
