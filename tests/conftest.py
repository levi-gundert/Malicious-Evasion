"""
Pytest configuration and shared fixtures.

This module provides:
- Custom markers for fixture-dependent tests
- Shared pytest fixtures
- Helper functions for test setup
"""

import pytest
from pathlib import Path

from extractor.testing.fixtures import (
    fixtures_exist,
    list_fixture_os,
    list_fixture_samples,
    discover_all_samples,
    NoFixturesError,
)


# =============================================================================
# Custom Markers
# =============================================================================

def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "requires_fixtures: mark test as requiring real Triage fixtures"
    )
    config.addinivalue_line(
        "markers", 
        "integration: mark test as an integration test"
    )


# =============================================================================
# Fixture Availability Checks
# =============================================================================

@pytest.fixture(scope="session")
def has_fixtures() -> bool:
    """Session-scoped fixture indicating if any fixtures exist."""
    return fixtures_exist()


@pytest.fixture(scope="session")
def available_os_fixtures() -> list[str]:
    """Session-scoped fixture listing available OS types with fixtures."""
    return list_fixture_os()


@pytest.fixture(scope="session")
def all_available_samples() -> dict[str, list[str]]:
    """Session-scoped fixture with all available samples by OS."""
    return discover_all_samples()


# =============================================================================
# Skip Helpers
# =============================================================================

def skip_if_no_fixtures():
    """
    Skip decorator for tests that require real fixtures.
    
    Usage:
        @skip_if_no_fixtures()
        def test_something_with_real_data():
            ...
    """
    if not fixtures_exist():
        return pytest.mark.skip(
            reason=(
                "No test fixtures found. "
                "Run: python scripts/capture_fixtures.py --os <os> --sample-id <id>"
            )
        )
    return pytest.mark.skipif(False, reason="")


@pytest.fixture
def require_fixtures():
    """
    Fixture that skips the test if no fixtures are available.
    
    Usage:
        def test_something(require_fixtures):
            # This test only runs if fixtures exist
            ...
    """
    if not fixtures_exist():
        pytest.skip(
            "No test fixtures found. "
            "Run: python scripts/capture_fixtures.py --os <os> --sample-id <id>"
        )


@pytest.fixture
def require_android_fixtures():
    """Fixture that skips if no Android fixtures are available."""
    samples = list_fixture_samples("android")
    if not samples:
        pytest.skip("No Android fixtures available")
    return samples


@pytest.fixture
def require_windows_fixtures():
    """Fixture that skips if no Windows fixtures are available."""
    samples = list_fixture_samples("windows")
    if not samples:
        pytest.skip("No Windows fixtures available")
    return samples


@pytest.fixture
def require_linux_fixtures():
    """Fixture that skips if no Linux fixtures are available."""
    samples = list_fixture_samples("linux")
    if not samples:
        pytest.skip("No Linux fixtures available")
    return samples


@pytest.fixture
def require_macos_fixtures():
    """Fixture that skips if no macOS fixtures are available."""
    samples = list_fixture_samples("macos")
    if not samples:
        pytest.skip("No macOS fixtures available")
    return samples


# =============================================================================
# Sample Fixtures (when available)
# =============================================================================

@pytest.fixture
def first_android_sample(require_android_fixtures) -> str:
    """Get the first available Android sample ID."""
    return require_android_fixtures[0]


@pytest.fixture
def first_windows_sample(require_windows_fixtures) -> str:
    """Get the first available Windows sample ID."""
    return require_windows_fixtures[0]


@pytest.fixture
def first_linux_sample(require_linux_fixtures) -> str:
    """Get the first available Linux sample ID."""
    return require_linux_fixtures[0]


@pytest.fixture
def first_macos_sample(require_macos_fixtures) -> str:
    """Get the first available macOS sample ID."""
    return require_macos_fixtures[0]


# =============================================================================
# Temporary Directory Fixtures
# =============================================================================

@pytest.fixture
def temp_output_dir(tmp_path) -> Path:
    """Provide a temporary directory for test outputs."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def temp_cache_dir(tmp_path) -> Path:
    """Provide a temporary directory for cache testing."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return cache_dir


# =============================================================================
# Informational Output
# =============================================================================

def pytest_report_header(config):
    """Add fixture status to pytest header."""
    lines = []
    
    if fixtures_exist():
        all_samples = discover_all_samples()
        total = sum(len(samples) for samples in all_samples.values())
        os_summary = ", ".join(f"{os}:{len(samples)}" for os, samples in all_samples.items())
        lines.append(f"Triage fixtures: {total} samples ({os_summary})")
    else:
        lines.append(
            "Triage fixtures: NONE - Run scripts/capture_fixtures.py to enable fixture-based tests"
        )
    
    return lines
