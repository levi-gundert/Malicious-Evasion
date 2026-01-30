"""
Tests for Pydantic data models.

These tests verify:
- Model validation works correctly
- ID generation is deterministic
- Models can be created from real fixture data
"""

import json
import pytest
from datetime import datetime

from extractor.models.id import artifact_id, validate_artifact_id
from extractor.models.artifact import (
    Artifact,
    ArtifactType,
    MatchCriteria,
    MatchType,
    Metadata,
    Provenance,
    Deception,
    OSType,
    EvasionPurpose,
    create_file_artifact,
    create_property_artifact,
    create_registry_artifact,
    create_process_artifact,
)
from extractor.models.sample import SampleMetadata
from extractor.models.extraction import ExtractionResult, ExtractionParameters

from extractor.testing.fixtures import (
    fixtures_exist,
    list_fixture_samples,
    load_overview,
    load_behavioral_report,
)


# =============================================================================
# ID Generation Tests
# =============================================================================

class TestArtifactId:
    """Tests for artifact ID generation."""
    
    def test_id_is_deterministic(self):
        """Same inputs should produce same ID."""
        id1 = artifact_id("android", "file", "/system/bin/qemu-props")
        id2 = artifact_id("android", "file", "/system/bin/qemu-props")
        # Debug: Log the IDs
        print(f"ID1: {id1}, ID2: {id2}")
        assert id1 == id2
    
    def test_id_format_correct(self):
        """ID should follow art-{os}-{type}-{hash8} format."""
        aid = artifact_id("android", "file", "/system/bin/qemu-props")
        # Debug: Log the ID
        print(f"Generated ID: {aid}")
        assert aid.startswith("art-android-file-")
        assert len(aid.split("-")) == 4
        assert len(aid.split("-")[-1]) == 8
    
    def test_different_inputs_different_ids(self):
        """Different inputs should produce different IDs."""
        id1 = artifact_id("android", "file", "/path/a")
        id2 = artifact_id("android", "file", "/path/b")
        id3 = artifact_id("windows", "file", "/path/a")
        id4 = artifact_id("android", "registry", "/path/a")
        
        # All should be unique
        ids = [id1, id2, id3, id4]
        assert len(ids) == len(set(ids))
    
    def test_id_normalizes_case(self):
        """OS and type should be normalized to lowercase."""
        id1 = artifact_id("ANDROID", "FILE", "/path")
        id2 = artifact_id("android", "file", "/path")
        assert id1 == id2
    
    def test_validate_artifact_id_accepts_valid(self):
        """validate_artifact_id should accept valid IDs."""
        valid_id = artifact_id("android", "file", "/test")
        assert validate_artifact_id(valid_id) is True
    
    def test_validate_artifact_id_rejects_invalid(self):
        """validate_artifact_id should reject invalid IDs."""
        assert validate_artifact_id("") is False
        assert validate_artifact_id("invalid") is False
        assert validate_artifact_id("art-invalid-file-12345678") is False  # invalid OS
        assert validate_artifact_id("art-android-file-123") is False  # hash too short
        assert validate_artifact_id("art-android-file-ZZZZZZZZ") is False  # invalid hex


# =============================================================================
# MatchCriteria Tests
# =============================================================================

class TestMatchCriteria:
    """Tests for MatchCriteria model."""
    
    def test_default_values(self):
        """Test default values."""
        mc = MatchCriteria(value="/test/path")
        assert mc.type == MatchType.EXACT
        assert mc.case_sensitive is True
    
    def test_value_cannot_be_empty(self):
        """Value should not be empty."""
        with pytest.raises(ValueError, match="cannot be empty"):
            MatchCriteria(value="")
        
        with pytest.raises(ValueError, match="cannot be empty"):
            MatchCriteria(value="   ")


# =============================================================================
# Provenance Tests
# =============================================================================

class TestProvenance:
    """Tests for Provenance model."""
    
    def test_sample_hashes_capped_at_100(self):
        """sample_hashes should be capped at 100."""
        hashes = [f"hash{i}" for i in range(150)]
        prov = Provenance(sample_hashes=hashes)
        assert len(prov.sample_hashes) == 100
    
    def test_confidence_clamped_to_range(self):
        """confidence should be clamped to [0, 1]."""
        prov1 = Provenance(confidence=1.5)
        assert prov1.confidence == 1.0
        
        prov2 = Provenance(confidence=-0.5)
        assert prov2.confidence == 0.0


# =============================================================================
# Artifact Tests
# =============================================================================

class TestArtifact:
    """Tests for Artifact model."""
    
    def test_id_auto_generated(self):
        """ID should be auto-generated if not provided."""
        artifact = Artifact(
            os=OSType.ANDROID,
            category="emulator_files",
            artifact_type=ArtifactType.FILE,
            match_criteria=MatchCriteria(value="/system/bin/qemu-props"),
        )
        # Debug: Log the artifact
        print(f"Artifact ID: {artifact.id}")
        assert artifact.id.startswith("art-android-file-")
    
    def test_category_normalized_lowercase(self):
        """Category should be normalized to lowercase."""
        artifact = Artifact(
            os=OSType.ANDROID,
            category="EMULATOR_FILES",
            artifact_type=ArtifactType.FILE,
            match_criteria=MatchCriteria(value="/test"),
        )
        assert artifact.category == "emulator_files"
    
    def test_category_cannot_be_empty(self):
        """Category should not be empty."""
        with pytest.raises(ValueError, match="cannot be empty"):
            Artifact(
                os=OSType.ANDROID,
                category="",
                artifact_type=ArtifactType.FILE,
                match_criteria=MatchCriteria(value="/test"),
            )


# =============================================================================
# Factory Function Tests
# =============================================================================

class TestArtifactFactories:
    """Tests for artifact factory functions."""
    
    def test_create_file_artifact(self):
        """Test create_file_artifact factory."""
        artifact = create_file_artifact(
            os_type=OSType.ANDROID,
            path="/system/bin/qemu-props",
            category="emulator_files",
            evasion_purpose=EvasionPurpose.EMULATOR,
            sample_hash="abc123",
        )
        
        assert artifact.os == OSType.ANDROID
        assert artifact.artifact_type == ArtifactType.FILE
        assert artifact.match_criteria.value == "/system/bin/qemu-props"
        assert artifact.match_criteria.case_sensitive is True  # Android is case-sensitive
        assert "abc123" in artifact.provenance.sample_hashes
    
    def test_create_file_artifact_windows_case_insensitive(self):
        """Windows file artifacts should be case-insensitive."""
        artifact = create_file_artifact(
            os_type=OSType.WINDOWS,
            path="C:\\Windows\\System32\\vmci.sys",
            category="vm_files",
        )
        assert artifact.match_criteria.case_sensitive is False
    
    def test_create_property_artifact(self):
        """Test create_property_artifact factory."""
        artifact = create_property_artifact(
            property_name="ro.kernel.qemu",
            category="emulator_properties",
            recommended_value="1",
        )
        
        assert artifact.os == OSType.ANDROID
        assert artifact.artifact_type == ArtifactType.PROPERTY
        assert artifact.deception.recommended_value == "1"
    
    def test_create_registry_artifact(self):
        """Test create_registry_artifact factory."""
        artifact = create_registry_artifact(
            key="HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools",
            category="vm_registry",
        )
        
        assert artifact.os == OSType.WINDOWS
        assert artifact.artifact_type == ArtifactType.REGISTRY
        assert artifact.match_criteria.case_sensitive is False
    
    def test_create_process_artifact(self):
        """Test create_process_artifact factory."""
        artifact = create_process_artifact(
            os_type=OSType.WINDOWS,
            process_name="vmtoolsd.exe",
            category="vm_processes",
        )
        
        assert artifact.os == OSType.WINDOWS
        assert artifact.artifact_type == ArtifactType.PROCESS
        assert artifact.match_criteria.case_sensitive is False


# =============================================================================
# SampleMetadata Tests
# =============================================================================

class TestSampleMetadata:
    """Tests for SampleMetadata model."""
    
    def test_sha256_required(self):
        """sha256 is required and cannot be empty."""
        with pytest.raises(ValueError):
            SampleMetadata(
                sha256="",
                triage={"sample_id": "test"},
            )
    
    def test_from_overview_with_mock_data(self):
        """Test from_overview with mock data."""
        mock_overview = {
            "sample": {
                "id": "test-123",
                "sha256": "abc123def456",
                "sha1": "sha1hash",
                "md5": "md5hash",
                "target": "malware.apk",
                "size": 12345,
                "score": 8,
                "created": "2026-01-28T10:00:00Z",
                "completed": "2026-01-28T10:05:00Z",
            },
            "analysis": {
                "tags": ["android", "trojan"],
            },
            "tasks": {},
        }
        
        metadata = SampleMetadata.from_overview(mock_overview)
        
        assert metadata.sha256 == "abc123def456"
        assert metadata.triage.sample_id == "test-123"
        assert metadata.triage.score == 8
        assert metadata.classification.os == OSType.ANDROID
        assert "android" in metadata.classification.tags


# =============================================================================
# SampleMetadata Tests with Real Fixtures
# =============================================================================

class TestSampleMetadataWithFixtures:
    """Tests using real captured fixtures."""
    
    @pytest.fixture
    def android_samples(self):
        """Get available Android samples, skip if none."""
        samples = list_fixture_samples("android")
        if not samples:
            pytest.skip("No Android fixtures available")
        return samples
    
    def test_from_overview_real_fixture(self, android_samples):
        """Test from_overview with real fixture data."""
        sample_id = android_samples[0]
        overview = load_overview("android", sample_id)
        
        metadata = SampleMetadata.from_overview(overview)
        
        # Debug: Log what we got
        print(f"Sample ID: {metadata.triage.sample_id}")
        print(f"SHA256: {metadata.sha256}")
        print(f"OS: {metadata.classification.os}")
        print(f"Tags: {metadata.classification.tags}")
        
        # Basic validation
        assert metadata.sha256  # Not empty
        assert len(metadata.sha256) == 64  # SHA256 is 64 hex chars
        assert metadata.triage.sample_id == sample_id
        assert metadata.classification.os == OSType.ANDROID
    
    def test_from_behavioral_real_fixture(self, android_samples):
        """Test from_behavioral with real fixture data."""
        sample_id = android_samples[0]
        behavioral = load_behavioral_report("android", sample_id, "behavioral1")
        
        metadata = SampleMetadata.from_behavioral(behavioral)
        
        # Debug: Log what we got
        print(f"Sample ID: {metadata.triage.sample_id}")
        print(f"Platform OS: {metadata.classification.os}")
        
        # Basic validation
        assert metadata.sha256
        assert metadata.triage.sample_id == sample_id


# =============================================================================
# ExtractionResult Tests
# =============================================================================

class TestExtractionResult:
    """Tests for ExtractionResult model."""
    
    def test_extraction_id_auto_generated(self):
        """extraction_id should be auto-generated."""
        result = ExtractionResult()
        # Debug: Log the ID
        print(f"Extraction ID: {result.extraction_id}")
        assert result.extraction_id.startswith("ext-")
    
    def test_add_artifact_updates_statistics(self):
        """add_artifact should update statistics."""
        result = ExtractionResult()
        
        artifact = create_file_artifact(
            os_type=OSType.ANDROID,
            path="/test/path",
            category="emulator_files",
        )
        
        result.add_artifact(artifact)
        
        assert result.statistics.artifacts_extracted == 1
        assert result.statistics.by_os.get("android") == 1
        assert result.statistics.by_category.get("emulator_files") == 1
    
    def test_get_artifacts_for_os(self):
        """Test get_artifacts_for_os method."""
        result = ExtractionResult()
        
        android_artifact = create_file_artifact(
            os_type=OSType.ANDROID,
            path="/android/path",
            category="emulator_files",
        )
        windows_artifact = create_file_artifact(
            os_type=OSType.WINDOWS,
            path="C:\\windows\\path",
            category="vm_files",
        )
        
        result.add_artifact(android_artifact)
        result.add_artifact(windows_artifact)
        
        android_artifacts = result.get_artifacts_for_os(OSType.ANDROID)
        assert len(android_artifacts) == 1
        assert android_artifacts[0].os == OSType.ANDROID
        
        windows_artifacts = result.get_artifacts_for_os("windows")
        assert len(windows_artifacts) == 1
    
    def test_to_json_dict(self):
        """Test JSON serialization."""
        result = ExtractionResult()
        result.add_artifact(create_file_artifact(
            os_type=OSType.ANDROID,
            path="/test",
            category="test_category",
        ))
        
        json_dict = result.to_json_dict()
        
        # Should be JSON serializable
        json_str = json.dumps(json_dict)
        assert json_str
        
        # Check structure
        assert "version" in json_dict
        assert "extraction_id" in json_dict
        assert "statistics" in json_dict
        assert "artifacts" in json_dict
    
    def test_add_error(self):
        """Test error recording."""
        result = ExtractionResult()
        result.add_error("sample-123", "Test error message")
        
        assert len(result.errors) == 1
        assert result.errors[0].sample_id == "sample-123"
        assert result.errors[0].error == "Test error message"
    
    def test_merge_results(self):
        """Test merging multiple results."""
        result1 = ExtractionResult()
        result1.add_artifact(create_file_artifact(
            os_type=OSType.ANDROID,
            path="/path1",
            category="cat1",
        ))
        result1.statistics.samples_processed = 5
        
        result2 = ExtractionResult()
        result2.add_artifact(create_file_artifact(
            os_type=OSType.WINDOWS,
            path="C:\\path2",
            category="cat2",
        ))
        result2.statistics.samples_processed = 3
        
        merged = ExtractionResult.merge(result1, result2)
        
        assert merged.statistics.artifacts_extracted == 2
        assert merged.statistics.samples_processed == 8
        assert len(merged.get_artifacts_for_os(OSType.ANDROID)) == 1
        assert len(merged.get_artifacts_for_os(OSType.WINDOWS)) == 1
