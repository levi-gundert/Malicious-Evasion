"""
Tests for output writers.

Tests cover:
- JSON output generation
- YAML deception config generation
- Statistics generation
"""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from extractor.models.artifact import (
    Artifact,
    ArtifactType,
    MatchCriteria,
    MatchType,
    Metadata,
    OSType,
    Provenance,
    EvasionPurpose,
    Deception,
)
from extractor.output.statistics import generate_statistics, ExtractionStatistics
from extractor.output.json_writer import (
    artifact_to_dict,
    write_artifacts_json,
    write_per_os_json,
)
from extractor.output.yaml_writer import (
    artifact_to_deception_entry,
    write_deception_yaml,
)


# =============================================================================
# Test Fixtures
# =============================================================================

def create_test_artifact(
    os_type: OSType = OSType.ANDROID,
    artifact_type: ArtifactType = ArtifactType.FILE,
    category: str = "test_category",
    value: str = "/test/path",
    sample_count: int = 1,
    confidence: float = 0.5,
    recommended_value: str = "",
    notes: str = "",
) -> Artifact:
    """Create a test artifact with specified parameters."""
    return Artifact(
        os=os_type,
        category=category,
        artifact_type=artifact_type,
        match_criteria=MatchCriteria(
            type=MatchType.EXACT,
            value=value,
        ),
        metadata=Metadata(
            description="Test artifact",
            evasion_purpose=EvasionPurpose.EMULATOR,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        ),
        provenance=Provenance(
            sample_count=sample_count,
            confidence=confidence,
        ),
        deception=Deception(
            recommended_value=recommended_value,
            notes=notes,
        ),
    )


# =============================================================================
# Statistics Tests
# =============================================================================

class TestStatistics:
    """Tests for statistics generation."""
    
    def test_generate_statistics_counts(self):
        """Test basic counting."""
        artifacts = [
            create_test_artifact(os_type=OSType.ANDROID, value="/a"),
            create_test_artifact(os_type=OSType.ANDROID, value="/b"),
            create_test_artifact(os_type=OSType.WINDOWS, value="/c"),
        ]
        
        stats = generate_statistics(artifacts)
        
        assert stats.total_artifacts == 3
        assert stats.unique_artifacts == 3
        assert stats.by_os.get("android") == 2
        assert stats.by_os.get("windows") == 1
    
    def test_generate_statistics_confidence_levels(self):
        """Test confidence level breakdown."""
        artifacts = [
            create_test_artifact(value="/a", confidence=0.2),  # low
            create_test_artifact(value="/b", confidence=0.6),  # medium
            create_test_artifact(value="/c", confidence=0.9),  # high
        ]
        
        stats = generate_statistics(artifacts)
        
        assert stats.by_confidence["high"] == 1
        assert stats.by_confidence["medium"] == 1
        assert stats.by_confidence["low"] == 1
    
    def test_generate_statistics_categories(self):
        """Test category breakdown."""
        artifacts = [
            create_test_artifact(category="emulator_files", value="/a"),
            create_test_artifact(category="emulator_files", value="/b"),
            create_test_artifact(category="root_indicators", value="/c"),
        ]
        
        stats = generate_statistics(artifacts)
        
        assert stats.by_category.get("emulator_files") == 2
        assert stats.by_category.get("root_indicators") == 1
    
    def test_statistics_to_dict(self):
        """Test statistics serialization."""
        stats = ExtractionStatistics(
            total_artifacts=10,
            unique_artifacts=8,
            by_os={"android": 5, "windows": 3},
        )
        
        data = stats.to_dict()
        
        assert data["total_artifacts"] == 10
        assert data["by_os"]["android"] == 5
        assert "extracted_at" in data


# =============================================================================
# JSON Writer Tests
# =============================================================================

class TestJsonWriter:
    """Tests for JSON output writer."""
    
    def test_artifact_to_dict_serializes_correctly(self):
        """Test artifact serialization."""
        artifact = create_test_artifact(
            os_type=OSType.ANDROID,
            artifact_type=ArtifactType.FILE,
            value="/test/path",
        )
        
        data = artifact_to_dict(artifact)
        
        # Check basic fields
        assert data["os"] == "android"
        assert data["artifact_type"] == "file"
        assert data["match_criteria"]["value"] == "/test/path"
        assert data["match_criteria"]["type"] == "exact"
        
        # Check datetime is string
        assert isinstance(data["metadata"]["first_seen"], str)
    
    def test_write_artifacts_json(self):
        """Test writing artifacts to JSON file."""
        artifacts = [
            create_test_artifact(os_type=OSType.ANDROID, value="/a"),
            create_test_artifact(os_type=OSType.WINDOWS, value="/b"),
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "artifacts.json"
            
            result = write_artifacts_json(artifacts, output_path)
            
            assert result == output_path
            assert output_path.exists()
            
            # Verify content
            with open(output_path) as f:
                data = json.load(f)
            
            assert data["version"] == "1.0"
            assert "statistics" in data
            assert "artifacts" in data
            assert "android" in data["artifacts"]
            assert "windows" in data["artifacts"]
            assert len(data["artifacts"]["android"]) == 1
            assert len(data["artifacts"]["windows"]) == 1
    
    def test_write_per_os_json(self):
        """Test writing per-OS JSON files."""
        artifacts = [
            create_test_artifact(os_type=OSType.ANDROID, value="/a"),
            create_test_artifact(os_type=OSType.ANDROID, value="/b"),
            create_test_artifact(os_type=OSType.WINDOWS, value="/c"),
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            files = write_per_os_json(artifacts, output_dir)
            
            assert len(files) == 2
            
            # Check Android file
            android_file = output_dir / "artifacts_android.json"
            assert android_file.exists()
            
            with open(android_file) as f:
                data = json.load(f)
            
            assert data["os"] == "android"
            assert len(data["artifacts"]) == 2
            
            # Check Windows file
            windows_file = output_dir / "artifacts_windows.json"
            assert windows_file.exists()


# =============================================================================
# YAML Writer Tests
# =============================================================================

class TestYamlWriter:
    """Tests for YAML deception config writer."""
    
    def test_artifact_to_deception_entry(self):
        """Test deception entry generation."""
        artifact = create_test_artifact(
            value="/test/path",
            confidence=0.8,
            sample_count=5,
            recommended_value="test_value",
            notes="Test notes",
        )
        
        entry = artifact_to_deception_entry(artifact)
        
        assert entry["value"] == "/test/path"
        assert entry["match_type"] == "exact"
        assert entry["confidence"] == 0.8
        assert entry["sample_count"] == 5
        assert entry["recommended_value"] == "test_value"
        assert entry["notes"] == "Test notes"
    
    def test_write_deception_yaml(self):
        """Test writing deception YAML files."""
        artifacts = [
            create_test_artifact(
                os_type=OSType.ANDROID,
                artifact_type=ArtifactType.FILE,
                value="/system/bin/qemu",
            ),
            create_test_artifact(
                os_type=OSType.ANDROID,
                artifact_type=ArtifactType.PROPERTY,
                value="ro.kernel.qemu",
            ),
            create_test_artifact(
                os_type=OSType.WINDOWS,
                artifact_type=ArtifactType.FILE,
                value="C:\\vmware.dll",
            ),
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            files = write_deception_yaml(artifacts, output_dir)
            
            assert len(files) == 2
            
            # Check Android file
            android_file = output_dir / "android_deception_config.yaml"
            assert android_file.exists()
            
            with open(android_file) as f:
                content = f.read()
            
            # Debug: Show content
            print(f"Android YAML:\n{content}")
            
            # Verify YAML is valid
            data = yaml.safe_load(content)
            assert data["os"] == "android"
            assert "files" in data
            assert "system_properties" in data
            
            # Check Windows file
            windows_file = output_dir / "windows_deception_config.yaml"
            assert windows_file.exists()
    
    def test_yaml_has_header_comments(self):
        """Test that YAML files have helpful header comments."""
        artifacts = [
            create_test_artifact(os_type=OSType.ANDROID, value="/test"),
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            write_deception_yaml(artifacts, output_dir)
            
            android_file = output_dir / "android_deception_config.yaml"
            
            with open(android_file) as f:
                content = f.read()
            
            # Should have header comments
            assert content.startswith("# ANDROID")
            assert "Generated:" in content
            assert "confidence" in content.lower()
    
    def test_empty_artifacts_no_files(self):
        """Test that no files are written for empty artifact list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            files = write_deception_yaml([], output_dir)
            
            assert len(files) == 0
