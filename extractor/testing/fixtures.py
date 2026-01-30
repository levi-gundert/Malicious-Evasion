"""
Fixture loader utilities for test data.

This module provides helpers to load captured Triage API responses
stored as JSON fixtures. These are safe text files containing behavioral
metadata - NOT malware binaries.

Fixture layout:
    tests/fixtures/<os>/<sample_id>/
        overview.json
        behavioral1/
            report_triage.json
            logs/stahp.json (Android/Linux)
            logs/onemon.json (Windows)
            logs/bigmac.json (macOS)
        behavioral2/ (optional)
            ...
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Debug: Log fixture operations
FIXTURES_ROOT = Path(__file__).parent.parent.parent / "tests" / "fixtures"

# OS to kernel log filename mapping
KERNEL_LOG_FILES = {
    "android": "stahp.json",
    "linux": "stahp.json",
    "windows": "onemon.json",
    "macos": "bigmac.json",
}

SUPPORTED_OS = {"android", "windows", "linux", "macos"}


class FixtureError(Exception):
    """Raised when fixture loading fails."""
    pass


class NoFixturesError(FixtureError):
    """Raised when no fixtures exist - provides helpful guidance."""
    
    def __init__(self, message: str | None = None):
        if message is None:
            message = (
                "No test fixtures found.\n\n"
                "To capture fixtures from Triage API, run:\n\n"
                "  python scripts/capture_fixtures.py --os android --sample-id <SAMPLE_ID>\n\n"
                "Set TRIAGE_API_KEY environment variable first.\n"
                "Fixtures are JSON text files (behavioral reports), NOT malware binaries."
            )
        super().__init__(message)


def get_fixtures_root() -> Path:
    """Get the root directory for test fixtures."""
    return FIXTURES_ROOT


def fixtures_exist() -> bool:
    """Check if any fixtures have been captured."""
    # Debug: Log check
    logger.debug(f"Checking for fixtures in: {FIXTURES_ROOT}")
    
    if not FIXTURES_ROOT.exists():
        return False
    
    # Check for at least one OS directory with at least one sample
    for os_dir in FIXTURES_ROOT.iterdir():
        if os_dir.is_dir() and os_dir.name in SUPPORTED_OS:
            # Check for at least one sample directory with overview.json
            for sample_dir in os_dir.iterdir():
                if sample_dir.is_dir():
                    overview = sample_dir / "overview.json"
                    if overview.exists():
                        logger.debug(f"Found fixture: {overview}")
                        return True
    
    return False


def list_fixture_os() -> list[str]:
    """List OS types that have fixtures available."""
    if not FIXTURES_ROOT.exists():
        return []
    
    os_list = []
    for os_dir in FIXTURES_ROOT.iterdir():
        if os_dir.is_dir() and os_dir.name in SUPPORTED_OS:
            # Verify at least one sample exists
            samples = list_fixture_samples(os_dir.name)
            if samples:
                os_list.append(os_dir.name)
    
    return sorted(os_list)


def list_fixture_samples(os_type: str) -> list[str]:
    """
    List sample IDs available for a given OS.
    
    Args:
        os_type: One of 'android', 'windows', 'linux', 'macos'
        
    Returns:
        List of sample IDs that have fixtures
    """
    # Debug: Log listing
    logger.debug(f"Listing fixture samples for OS: {os_type}")
    
    if os_type not in SUPPORTED_OS:
        raise ValueError(f"Unsupported OS: {os_type}. Must be one of {SUPPORTED_OS}")
    
    os_dir = FIXTURES_ROOT / os_type
    if not os_dir.exists():
        return []
    
    samples = []
    for sample_dir in os_dir.iterdir():
        if sample_dir.is_dir():
            # Verify overview.json exists (minimum requirement)
            if (sample_dir / "overview.json").exists():
                samples.append(sample_dir.name)
    
    return sorted(samples)


def get_fixture_path(os_type: str, sample_id: str, *path_parts: str) -> Path:
    """
    Get the full path to a fixture file.
    
    Args:
        os_type: One of 'android', 'windows', 'linux', 'macos'
        sample_id: The Triage sample ID
        *path_parts: Additional path components (e.g., 'behavioral1', 'report_triage.json')
        
    Returns:
        Path to the fixture file
    """
    return FIXTURES_ROOT / os_type / sample_id / Path(*path_parts) if path_parts else FIXTURES_ROOT / os_type / sample_id


def load_fixture_json(os_type: str, sample_id: str, *path_parts: str) -> dict[str, Any]:
    """
    Load a JSON fixture file.
    
    Args:
        os_type: One of 'android', 'windows', 'linux', 'macos'
        sample_id: The Triage sample ID
        *path_parts: Path components to the JSON file
                    e.g., 'overview.json' or 'behavioral1', 'report_triage.json'
        
    Returns:
        Parsed JSON as a dictionary
        
    Raises:
        FixtureError: If file not found or JSON parsing fails
    """
    # Debug: Log load attempt
    logger.debug(f"Loading fixture: {os_type}/{sample_id}/{'/'.join(path_parts)}")
    
    path = get_fixture_path(os_type, sample_id, *path_parts)
    
    if not path.exists():
        raise FixtureError(f"Fixture not found: {path}")
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            logger.debug(f"Loaded fixture successfully: {path}")
            return data
    except json.JSONDecodeError as e:
        raise FixtureError(f"Invalid JSON in fixture {path}: {e}") from e


def load_overview(os_type: str, sample_id: str) -> dict[str, Any]:
    """Load the overview.json for a sample."""
    return load_fixture_json(os_type, sample_id, "overview.json")


def load_behavioral_report(os_type: str, sample_id: str, task: str = "behavioral1") -> dict[str, Any]:
    """
    Load the behavioral report (report_triage.json) for a sample.
    
    Args:
        os_type: OS type
        sample_id: Sample ID
        task: Task name, typically 'behavioral1' or 'behavioral2'
    """
    return load_fixture_json(os_type, sample_id, task, "report_triage.json")


def load_kernel_logs(os_type: str, sample_id: str, task: str = "behavioral1") -> dict[str, Any] | list[dict[str, Any]]:
    """
    Load platform-specific kernel logs for a sample.
    
    Args:
        os_type: OS type (determines which log file: stahp/onemon/bigmac)
        sample_id: Sample ID
        task: Task name, typically 'behavioral1' or 'behavioral2'
        
    Returns:
        Kernel log data (may be dict or list depending on format)
    """
    log_filename = KERNEL_LOG_FILES.get(os_type)
    if not log_filename:
        raise FixtureError(f"Unknown kernel log file for OS: {os_type}")
    
    return load_fixture_json(os_type, sample_id, task, "logs", log_filename)


def has_behavioral_report(os_type: str, sample_id: str, task: str = "behavioral1") -> bool:
    """Check if a behavioral report exists for a sample."""
    path = get_fixture_path(os_type, sample_id, task, "report_triage.json")
    return path.exists()


def has_kernel_logs(os_type: str, sample_id: str, task: str = "behavioral1") -> bool:
    """Check if kernel logs exist for a sample."""
    log_filename = KERNEL_LOG_FILES.get(os_type)
    if not log_filename:
        return False
    path = get_fixture_path(os_type, sample_id, task, "logs", log_filename)
    return path.exists()


def discover_all_samples() -> dict[str, list[str]]:
    """
    Discover all available fixture samples organized by OS.
    
    Returns:
        Dict mapping OS type to list of sample IDs
    """
    result = {}
    for os_type in SUPPORTED_OS:
        samples = list_fixture_samples(os_type)
        if samples:
            result[os_type] = samples
    return result
