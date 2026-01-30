"""
Tests for the extraction pipeline.

Tests cover:
- Single sample extraction
- OS detection
- Aggregation
- Output writing
"""

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from extractor.models.artifact import Artifact, ArtifactType, OSType
from extractor.models.extraction import ExtractionResult
from extractor.pipeline import (
    detect_os_from_overview,
    extract_sample,
    aggregate_results,
    write_outputs,
    extract_from_fixtures,
)
from extractor.aggregation.filter import FilterConfig
from extractor.testing.fixtures import (
    fixtures_exist,
    list_fixture_samples,
    load_overview,
    load_behavioral_report,
)


# =============================================================================
# OS Detection Tests
# =============================================================================

class TestOsDetection:
    """Tests for OS detection from overview data."""
    
    def test_detect_android_from_platform(self):
        """Test Android detection from platform field."""
        overview = {
            "targets": [
                {"platform": "android", "task_id": "behavioral1"}
            ]
        }
        
        result = detect_os_from_overview(overview)
        
        assert result == OSType.ANDROID
    
    def test_detect_windows_from_platform(self):
        """Test Windows detection from platform field."""
        overview = {
            "targets": [
                {"platform": "windows", "task_id": "behavioral1"}
            ]
        }
        
        result = detect_os_from_overview(overview)
        
        assert result == OSType.WINDOWS
    
    def test_detect_android_from_filename(self):
        """Test Android detection from .apk extension."""
        overview = {
            "targets": [],
            "sample": {"name": "malware.apk", "tags": []}
        }
        
        result = detect_os_from_overview(overview)
        
        assert result == OSType.ANDROID
    
    def test_detect_windows_from_filename(self):
        """Test Windows detection from .exe extension."""
        overview = {
            "targets": [],
            "sample": {"name": "malware.exe", "tags": []}
        }
        
        result = detect_os_from_overview(overview)
        
        assert result == OSType.WINDOWS
    
    def test_detect_unknown_returns_none(self):
        """Test that unknown samples return None."""
        overview = {
            "targets": [],
            "sample": {"name": "unknown_file", "tags": []}
        }
        
        result = detect_os_from_overview(overview)
        
        assert result is None


# =============================================================================
# Single Sample Extraction Tests
# =============================================================================

class TestExtractSample:
    """Tests for single sample extraction."""
    
    def test_extract_sample_basic(self):
        """Test basic sample extraction."""
        overview = {
            "sample": {
                "id": "test-123",
                "sha256": "abc123",
                "name": "test.apk",
                "score": 8,
                "tags": ["android"],
            },
            "targets": [
                {"platform": "android", "task_id": "behavioral1"}
            ]
        }
        
        behavioral = {
            "signatures": [
                {
                    "name": "anti_vm_check",
                    "tags": ["defense_evasion"],
                    "indicators": [
                        {"ioc": "/system/bin/qemu-props"}
                    ]
                }
            ],
            "network": {
                "flows": [
                    {"dst": "127.0.0.1:27042", "proto": "tcp"}
                ]
            }
        }
        
        result = extract_sample(overview, behavioral)
        
        # Debug: Log results
        print(f"Extracted {result.statistics.total_artifacts} artifacts")
        for a in result.get_all_artifacts():
            print(f"  - {a.artifact_type.value}: {a.match_criteria.value}")
        
        assert result.statistics.total_artifacts >= 1
        assert len(result.errors) == 0
    
    def test_extract_sample_with_os_override(self):
        """Test sample extraction with OS override."""
        overview = {
            "sample": {
                "id": "test-123",
                "sha256": "abc123",
                "name": "test.apk",
                "score": 8,
            },
            "targets": []  # No platform info
        }
        
        behavioral = {"signatures": []}
        
        result = extract_sample(
            overview, 
            behavioral, 
            os_type=OSType.ANDROID
        )
        
        # Should not fail even with empty behavioral data
        assert len(result.errors) == 0
    
    def test_extract_sample_unknown_os_creates_error(self):
        """Test that unknown OS creates an error entry."""
        overview = {
            "sample": {
                "id": "test-123",
                "sha256": "abc123",
                "name": "unknown_file",
            },
            "targets": []
        }
        
        behavioral = {}
        
        result = extract_sample(overview, behavioral)
        
        # Should have an error about OS detection
        assert len(result.errors) >= 1
        assert any("os" in e.error.lower() for e in result.errors)


# =============================================================================
# Aggregation Tests
# =============================================================================

class TestAggregation:
    """Tests for result aggregation."""
    
    def test_aggregate_empty_results(self):
        """Test aggregating empty results."""
        results = []
        
        aggregated = aggregate_results(results)
        
        assert aggregated.statistics.total_artifacts == 0
    
    def test_aggregate_combines_artifacts(self):
        """Test that aggregation combines artifacts from multiple results."""
        from extractor.models.artifact import (
            Artifact, ArtifactType, MatchCriteria, MatchType,
            OSType, Metadata, Provenance, EvasionPurpose
        )
        
        # Create two results with real artifacts
        artifact1 = Artifact(
            os=OSType.ANDROID,
            category="emulator_files",
            artifact_type=ArtifactType.FILE,
            match_criteria=MatchCriteria(type=MatchType.EXACT, value="/path/a"),
            metadata=Metadata(evasion_purpose=EvasionPurpose.EMULATOR),
            provenance=Provenance(sample_count=1, confidence=0.5),
        )
        
        artifact2 = Artifact(
            os=OSType.ANDROID,
            category="root_indicators",
            artifact_type=ArtifactType.FILE,
            match_criteria=MatchCriteria(type=MatchType.EXACT, value="/path/b"),
            metadata=Metadata(evasion_purpose=EvasionPurpose.ROOT),
            provenance=Provenance(sample_count=1, confidence=0.5),
        )
        
        result1 = ExtractionResult()
        result1.add_artifact(artifact1)
        
        result2 = ExtractionResult()
        result2.add_artifact(artifact2)
        
        aggregated = aggregate_results([result1, result2])
        
        assert aggregated.statistics.total_artifacts == 2


# =============================================================================
# Output Writing Tests
# =============================================================================

class TestWriteOutputs:
    """Tests for output writing."""
    
    def test_write_outputs_creates_files(self):
        """Test that write_outputs creates expected files."""
        # Create a result with artifacts
        from extractor.models.artifact import (
            Artifact, ArtifactType, MatchCriteria, MatchType, 
            OSType, Metadata, Provenance, EvasionPurpose
        )
        
        artifact = Artifact(
            os=OSType.ANDROID,
            category="emulator_files",
            artifact_type=ArtifactType.FILE,
            match_criteria=MatchCriteria(
                type=MatchType.EXACT,
                value="/system/bin/qemu-props",
            ),
            metadata=Metadata(evasion_purpose=EvasionPurpose.EMULATOR),
            provenance=Provenance(sample_count=1, confidence=0.5),
        )
        
        result = ExtractionResult()
        result.add_artifact(artifact)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            written = write_outputs(
                result=result,
                output_dir=output_dir,
                split_by_os=True,
                generate_deception=True,
            )
            
            # Check main JSON exists
            assert (output_dir / "artifacts.json").exists()
            
            # Check per-OS JSON exists
            assert (output_dir / "artifacts_android.json").exists()
            
            # Check deception YAML exists
            assert (output_dir / "android_deception_config.yaml").exists()
            
            # Verify written dict
            assert len(written["json"]) >= 2
            assert len(written["yaml"]) >= 1


# =============================================================================
# Fixture-based Integration Tests
# =============================================================================

class TestExtractFromFixtures:
    """Integration tests using real fixtures."""
    
    @pytest.fixture
    def skip_if_no_fixtures(self):
        """Skip test if no fixtures exist."""
        if not fixtures_exist():
            pytest.skip("No fixtures available")
    
    def test_extract_from_fixtures_basic(self, skip_if_no_fixtures):
        """Test extraction from local fixtures."""
        result = extract_from_fixtures()
        
        # Debug: Log results
        print(f"\nExtracted {result.statistics.total_artifacts} artifacts")
        print(f"By OS: {dict(result.statistics.by_os)}")
        print(f"Errors: {len(result.errors)}")
        
        # Should extract at least something
        assert result is not None
        # We may or may not have artifacts depending on fixture content
    
    def test_extract_from_fixtures_with_os_filter(self, skip_if_no_fixtures):
        """Test extraction with OS filter."""
        result = extract_from_fixtures(os_filter=["android"])
        
        # Debug: Log results
        print(f"\nFiltered to Android: {result.statistics.total_artifacts} artifacts")
        
        # If there are artifacts, they should all be Android
        for artifact in result.get_all_artifacts():
            assert artifact.os == OSType.ANDROID
    
    def test_extract_from_fixtures_with_confidence_filter(self, skip_if_no_fixtures):
        """Test extraction with confidence filter."""
        filter_config = FilterConfig(min_confidence=0.5)
        
        result = extract_from_fixtures(filter_config=filter_config)
        
        # All artifacts should meet minimum confidence
        for artifact in result.get_all_artifacts():
            assert artifact.provenance.confidence >= 0.5
    
    def test_full_pipeline_integration(self, skip_if_no_fixtures):
        """Test full pipeline with file output."""
        from extractor.pipeline import run_extraction_pipeline
        
        with tempfile.TemporaryDirectory() as tmpdir:
            summary = run_extraction_pipeline(
                output_dir=tmpdir,
                min_confidence=0.0,
                min_sample_count=1,
            )
            
            # Debug: Log summary
            print(f"\nPipeline summary:")
            print(f"  Extraction ID: {summary['extraction_id']}")
            print(f"  Total artifacts: {summary['statistics']['total_artifacts']}")
            print(f"  By OS: {summary['statistics']['by_os']}")
            print(f"  Output files: {summary['output_files']}")
            
            # Check summary structure
            assert "extraction_id" in summary
            assert "statistics" in summary
            assert "output_files" in summary
            
            # Check files were created
            output_dir = Path(tmpdir)
            assert (output_dir / "artifacts.json").exists()
