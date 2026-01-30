"""
Tests for fixture loading utilities.

These tests verify that the fixture system works correctly:
- When fixtures exist, they can be loaded
- When fixtures don't exist, we get helpful error messages
- Fixture discovery works correctly
"""

import json
import pytest
from pathlib import Path

from extractor.testing.fixtures import (
    FIXTURES_ROOT,
    SUPPORTED_OS,
    KERNEL_LOG_FILES,
    FixtureError,
    NoFixturesError,
    get_fixtures_root,
    fixtures_exist,
    list_fixture_os,
    list_fixture_samples,
    get_fixture_path,
    load_fixture_json,
    load_overview,
    load_behavioral_report,
    load_kernel_logs,
    has_behavioral_report,
    has_kernel_logs,
    discover_all_samples,
)


class TestFixtureConstants:
    """Test fixture system constants and configuration."""
    
    def test_supported_os_includes_all_platforms(self):
        """Verify all expected OS types are supported."""
        # Debug: Log what we're checking
        print(f"Supported OS types: {SUPPORTED_OS}")
        assert "android" in SUPPORTED_OS
        assert "windows" in SUPPORTED_OS
        assert "linux" in SUPPORTED_OS
        assert "macos" in SUPPORTED_OS
    
    def test_kernel_log_files_mapped_for_all_os(self):
        """Verify kernel log filenames are defined for all OS types."""
        # Debug: Log kernel log mapping
        print(f"Kernel log files: {KERNEL_LOG_FILES}")
        assert KERNEL_LOG_FILES["android"] == "stahp.json"
        assert KERNEL_LOG_FILES["linux"] == "stahp.json"
        assert KERNEL_LOG_FILES["windows"] == "onemon.json"
        assert KERNEL_LOG_FILES["macos"] == "bigmac.json"
    
    def test_fixtures_root_points_to_tests_fixtures(self):
        """Verify FIXTURES_ROOT is correctly configured."""
        # Debug: Log the path
        print(f"FIXTURES_ROOT: {FIXTURES_ROOT}")
        assert FIXTURES_ROOT.name == "fixtures"
        assert FIXTURES_ROOT.parent.name == "tests"


class TestFixturePathHelpers:
    """Test path construction helpers."""
    
    def test_get_fixtures_root_returns_path(self):
        """Verify get_fixtures_root returns a Path object."""
        root = get_fixtures_root()
        assert isinstance(root, Path)
        assert root == FIXTURES_ROOT
    
    def test_get_fixture_path_constructs_correct_path(self):
        """Verify fixture paths are constructed correctly."""
        path = get_fixture_path("android", "sample123", "overview.json")
        # Debug: Log the constructed path
        print(f"Constructed path: {path}")
        assert path == FIXTURES_ROOT / "android" / "sample123" / "overview.json"
    
    def test_get_fixture_path_handles_nested_paths(self):
        """Verify nested path construction works."""
        path = get_fixture_path("windows", "sample456", "behavioral1", "logs", "onemon.json")
        expected = FIXTURES_ROOT / "windows" / "sample456" / "behavioral1" / "logs" / "onemon.json"
        # Debug: Log comparison
        print(f"Got: {path}")
        print(f"Expected: {expected}")
        assert path == expected
    
    def test_get_fixture_path_without_parts_returns_sample_dir(self):
        """Verify path without parts returns sample directory."""
        path = get_fixture_path("linux", "sample789")
        assert path == FIXTURES_ROOT / "linux" / "sample789"


class TestFixtureValidation:
    """Test fixture validation and error handling."""
    
    def test_list_fixture_samples_rejects_invalid_os(self):
        """Verify invalid OS types are rejected."""
        with pytest.raises(ValueError, match="Unsupported OS"):
            list_fixture_samples("invalid_os")
    
    def test_load_fixture_json_raises_on_missing_file(self, tmp_path):
        """Verify FixtureError is raised for missing files."""
        with pytest.raises(FixtureError, match="Fixture not found"):
            load_fixture_json("android", "nonexistent_sample", "overview.json")
    
    def test_no_fixtures_error_has_helpful_message(self):
        """Verify NoFixturesError provides capture instructions."""
        error = NoFixturesError()
        message = str(error)
        # Debug: Log the error message
        print(f"NoFixturesError message:\n{message}")
        
        assert "capture_fixtures.py" in message
        assert "TRIAGE_API_KEY" in message
        assert "NOT malware binaries" in message or "JSON text files" in message


class TestFixtureDiscovery:
    """Test fixture discovery functions."""
    
    def test_fixtures_exist_returns_bool(self):
        """Verify fixtures_exist returns a boolean."""
        result = fixtures_exist()
        assert isinstance(result, bool)
        # Debug: Log the result
        print(f"fixtures_exist() returned: {result}")
    
    def test_list_fixture_os_returns_list(self):
        """Verify list_fixture_os returns a list."""
        result = list_fixture_os()
        assert isinstance(result, list)
        # Debug: Log the result
        print(f"list_fixture_os() returned: {result}")
    
    def test_discover_all_samples_returns_dict(self):
        """Verify discover_all_samples returns a dict."""
        result = discover_all_samples()
        assert isinstance(result, dict)
        # Debug: Log the result
        print(f"discover_all_samples() returned: {result}")


class TestFixtureLoadingWithMockData:
    """Test fixture loading with temporary mock fixtures."""
    
    @pytest.fixture
    def mock_fixture_dir(self, tmp_path, monkeypatch):
        """Create a temporary fixture directory with mock data."""
        # Create mock fixture structure
        fixture_root = tmp_path / "fixtures"
        
        # Create Android sample
        android_sample = fixture_root / "android" / "test-sample-123"
        android_sample.mkdir(parents=True)
        
        # Mock overview.json
        overview = {
            "version": "0.3",
            "sample": {
                "id": "test-sample-123",
                "md5": "abc123",
                "sha256": "def456",
            },
            "analysis": {
                "score": 10,
                "tags": ["android", "trojan"]
            }
        }
        (android_sample / "overview.json").write_text(json.dumps(overview))
        
        # Mock behavioral report
        behavioral_dir = android_sample / "behavioral1"
        behavioral_dir.mkdir()
        
        behavioral_report = {
            "version": "0.3",
            "task": {"task": "behavioral1"},
            "processes": [],
            "signatures": []
        }
        (behavioral_dir / "report_triage.json").write_text(json.dumps(behavioral_report))
        
        # Mock kernel logs
        logs_dir = behavioral_dir / "logs"
        logs_dir.mkdir()
        
        kernel_logs = [
            {"kind": "file_stat", "path": "/system/bin/qemu-props", "ret": -1}
        ]
        (logs_dir / "stahp.json").write_text(json.dumps(kernel_logs))
        
        # Monkeypatch the fixtures root
        import extractor.testing.fixtures as fixtures_module
        monkeypatch.setattr(fixtures_module, "FIXTURES_ROOT", fixture_root)
        
        return fixture_root
    
    def test_fixtures_exist_with_mock_data(self, mock_fixture_dir):
        """Verify fixtures_exist returns True when fixtures are present."""
        # Debug: Log the mock directory
        print(f"Mock fixture dir: {mock_fixture_dir}")
        assert fixtures_exist() is True
    
    def test_list_fixture_os_finds_android(self, mock_fixture_dir):
        """Verify list_fixture_os finds the mock Android fixtures."""
        os_list = list_fixture_os()
        # Debug: Log the result
        print(f"OS list: {os_list}")
        assert "android" in os_list
    
    def test_list_fixture_samples_finds_mock_sample(self, mock_fixture_dir):
        """Verify list_fixture_samples finds the mock sample."""
        samples = list_fixture_samples("android")
        # Debug: Log the result
        print(f"Samples: {samples}")
        assert "test-sample-123" in samples
    
    def test_load_overview_returns_mock_data(self, mock_fixture_dir):
        """Verify load_overview returns the mock data."""
        overview = load_overview("android", "test-sample-123")
        # Debug: Log the result
        print(f"Overview: {overview}")
        assert overview["sample"]["id"] == "test-sample-123"
        assert overview["analysis"]["score"] == 10
    
    def test_load_behavioral_report_returns_mock_data(self, mock_fixture_dir):
        """Verify load_behavioral_report returns the mock data."""
        report = load_behavioral_report("android", "test-sample-123", "behavioral1")
        # Debug: Log the result
        print(f"Behavioral report: {report}")
        assert report["task"]["task"] == "behavioral1"
    
    def test_load_kernel_logs_returns_mock_data(self, mock_fixture_dir):
        """Verify load_kernel_logs returns the mock data."""
        logs = load_kernel_logs("android", "test-sample-123", "behavioral1")
        # Debug: Log the result
        print(f"Kernel logs: {logs}")
        assert isinstance(logs, list)
        assert logs[0]["kind"] == "file_stat"
        assert logs[0]["path"] == "/system/bin/qemu-props"
    
    def test_has_behavioral_report_returns_true(self, mock_fixture_dir):
        """Verify has_behavioral_report returns True for existing report."""
        assert has_behavioral_report("android", "test-sample-123", "behavioral1") is True
        assert has_behavioral_report("android", "test-sample-123", "behavioral2") is False
    
    def test_has_kernel_logs_returns_true(self, mock_fixture_dir):
        """Verify has_kernel_logs returns True for existing logs."""
        assert has_kernel_logs("android", "test-sample-123", "behavioral1") is True
        assert has_kernel_logs("android", "test-sample-123", "behavioral2") is False
    
    def test_discover_all_samples_finds_mock_sample(self, mock_fixture_dir):
        """Verify discover_all_samples finds the mock sample."""
        all_samples = discover_all_samples()
        # Debug: Log the result
        print(f"All samples: {all_samples}")
        assert "android" in all_samples
        assert "test-sample-123" in all_samples["android"]
