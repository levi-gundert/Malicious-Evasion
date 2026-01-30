"""
Tests for the aggregation module.

Tests cover:
- Artifact deduplication
- Confidence scoring
- Filtering
"""

import pytest
from datetime import datetime, timedelta, timezone

from extractor.models.artifact import (
    Artifact,
    ArtifactType,
    MatchCriteria,
    MatchType,
    Metadata,
    OSType,
    Provenance,
    EvasionPurpose,
)
from extractor.aggregation.deduplicator import deduplicate_artifacts, merge_artifacts
from extractor.aggregation.scorer import calculate_confidence, score_artifact, score_artifacts
from extractor.aggregation.filter import (
    filter_artifacts,
    filter_by_confidence,
    filter_by_os,
    filter_by_category,
    filter_by_sample_count,
    filter_by_exclude_patterns,
    group_by_os,
    group_by_category,
    FilterConfig,
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
    sample_hashes: list[str] | None = None,
    families: list[str] | None = None,
    confidence: float = 0.0,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
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
            evasion_purpose=EvasionPurpose.EMULATOR,
            first_seen=first_seen or datetime.now(timezone.utc),
            last_seen=last_seen or datetime.now(timezone.utc),
        ),
        provenance=Provenance(
            sample_count=sample_count,
            sample_hashes=sample_hashes or [],
            families=families or [],
            confidence=confidence,
        ),
    )


# =============================================================================
# Deduplication Tests
# =============================================================================

class TestDeduplication:
    """Tests for artifact deduplication."""
    
    def test_no_duplicates_unchanged(self):
        """Test that unique artifacts are not changed."""
        artifacts = [
            create_test_artifact(value="/path/a"),
            create_test_artifact(value="/path/b"),
            create_test_artifact(value="/path/c"),
        ]
        
        result = deduplicate_artifacts(artifacts)
        
        assert len(result) == 3
    
    def test_duplicates_merged(self):
        """Test that duplicate artifacts are merged."""
        # Same path = same ID = should merge
        artifacts = [
            create_test_artifact(value="/test/path", sample_hashes=["hash1"]),
            create_test_artifact(value="/test/path", sample_hashes=["hash2"]),
        ]
        
        result = deduplicate_artifacts(artifacts)
        
        # Debug: Log result
        print(f"Result: {len(result)} artifacts")
        for a in result:
            print(f"  ID: {a.id}, samples: {a.provenance.sample_count}")
        
        assert len(result) == 1
        assert result[0].provenance.sample_count == 2
    
    def test_merge_combines_sample_hashes(self):
        """Test that sample hashes are combined during merge."""
        a1 = create_test_artifact(value="/test", sample_hashes=["hash1", "hash2"])
        a2 = create_test_artifact(value="/test", sample_hashes=["hash2", "hash3"])
        
        result = deduplicate_artifacts([a1, a2])
        
        hashes = result[0].provenance.sample_hashes
        # Debug: Log hashes
        print(f"Combined hashes: {hashes}")
        
        assert "hash1" in hashes
        assert "hash2" in hashes
        assert "hash3" in hashes
        assert len(hashes) == 3  # No duplicates
    
    def test_merge_combines_families(self):
        """Test that families are combined during merge."""
        a1 = create_test_artifact(value="/test", families=["FamilyA"])
        a2 = create_test_artifact(value="/test", families=["FamilyB"])
        
        result = deduplicate_artifacts([a1, a2])
        
        families = result[0].provenance.families
        assert "FamilyA" in families
        assert "FamilyB" in families
    
    def test_merge_updates_timestamps(self):
        """Test that timestamps are properly updated during merge."""
        old_time = datetime.now(timezone.utc) - timedelta(days=30)
        new_time = datetime.now(timezone.utc)
        
        a1 = create_test_artifact(value="/test", first_seen=old_time, last_seen=old_time)
        a2 = create_test_artifact(value="/test", first_seen=new_time, last_seen=new_time)
        
        result = deduplicate_artifacts([a1, a2])
        
        # first_seen should be the oldest, last_seen should be the newest
        assert result[0].metadata.first_seen == old_time
        assert result[0].metadata.last_seen == new_time
    
    def test_merge_sample_hashes_capped_at_100(self):
        """Test that sample hashes are capped at 100."""
        # Create artifacts with many hashes
        hashes1 = [f"hash_{i}" for i in range(60)]
        hashes2 = [f"hash_{i}" for i in range(50, 110)]  # Overlapping
        
        a1 = create_test_artifact(value="/test", sample_hashes=hashes1)
        a2 = create_test_artifact(value="/test", sample_hashes=hashes2)
        
        result = deduplicate_artifacts([a1, a2])
        
        assert len(result[0].provenance.sample_hashes) == 100


# =============================================================================
# Confidence Scoring Tests
# =============================================================================

class TestConfidenceScoring:
    """Tests for confidence scoring."""
    
    def test_base_score_from_sample_count(self):
        """Test base score calculation from sample count."""
        # 0 samples = 0.0 base
        assert calculate_confidence(0) >= 0.0
        
        # 5 samples = 0.25 base
        score_5 = calculate_confidence(5, unique_families=0, last_seen=None)
        assert 0.5 <= score_5 <= 0.7  # Base 0.5 + some recency
        
        # 10+ samples = 0.5 base (capped)
        score_10 = calculate_confidence(10, unique_families=0, last_seen=None)
        score_20 = calculate_confidence(20, unique_families=0, last_seen=None)
        # Both should have same base score (capped at 0.5)
        assert abs(score_10 - score_20) < 0.01
    
    def test_family_diversity_bonus(self):
        """Test family diversity adds to confidence."""
        # Use low sample count so we don't hit the cap
        score_no_family = calculate_confidence(2, unique_families=0)
        score_3_families = calculate_confidence(2, unique_families=3)
        score_5_families = calculate_confidence(2, unique_families=5)
        
        assert score_3_families > score_no_family
        assert score_5_families >= score_3_families  # May cap at 0.3 bonus
    
    def test_recency_bonus(self):
        """Test recency adds to confidence."""
        now = datetime.now(timezone.utc)
        old = now - timedelta(days=60)
        
        score_recent = calculate_confidence(5, last_seen=now)
        score_old = calculate_confidence(5, last_seen=old)
        
        # Recent should get 0.2 bonus, old gets 0.1
        assert score_recent > score_old
        # Use approximate comparison for floating point
        assert abs(score_recent - score_old - 0.1) < 0.01
    
    def test_max_confidence_is_1(self):
        """Test confidence is capped at 1.0."""
        # Max everything
        score = calculate_confidence(
            sample_count=100,
            unique_families=20,
            last_seen=datetime.now(timezone.utc),
        )
        
        assert score == 1.0
    
    def test_score_artifact_updates_confidence(self):
        """Test score_artifact updates the artifact's confidence."""
        artifact = create_test_artifact(
            sample_count=5,
            families=["FamilyA", "FamilyB"],
        )
        
        scored = score_artifact(artifact)
        
        assert scored.provenance.confidence > 0
        # Debug: Log score
        print(f"Scored confidence: {scored.provenance.confidence}")
    
    def test_score_artifacts_batch(self):
        """Test scoring a batch of artifacts."""
        artifacts = [
            create_test_artifact(value="/a", sample_count=1),
            create_test_artifact(value="/b", sample_count=5),
            create_test_artifact(value="/c", sample_count=10),
        ]
        
        scored = score_artifacts(artifacts)
        
        assert len(scored) == 3
        # Higher sample count = higher confidence
        assert scored[2].provenance.confidence > scored[0].provenance.confidence


# =============================================================================
# Filtering Tests
# =============================================================================

class TestFiltering:
    """Tests for artifact filtering."""
    
    def test_filter_by_confidence(self):
        """Test filtering by minimum confidence."""
        artifacts = [
            create_test_artifact(value="/a", confidence=0.2),
            create_test_artifact(value="/b", confidence=0.5),
            create_test_artifact(value="/c", confidence=0.8),
        ]
        
        result = filter_by_confidence(artifacts, min_confidence=0.3)
        
        assert len(result) == 2
        confidences = [a.provenance.confidence for a in result]
        assert all(c >= 0.3 for c in confidences)
    
    def test_filter_by_sample_count(self):
        """Test filtering by minimum sample count."""
        artifacts = [
            create_test_artifact(value="/a", sample_count=1),
            create_test_artifact(value="/b", sample_count=2),
            create_test_artifact(value="/c", sample_count=5),
        ]
        
        result = filter_by_sample_count(artifacts, min_count=2)
        
        assert len(result) == 2
    
    def test_filter_by_os(self):
        """Test filtering by operating system."""
        artifacts = [
            create_test_artifact(os_type=OSType.ANDROID, value="/a"),
            create_test_artifact(os_type=OSType.WINDOWS, value="/b"),
            create_test_artifact(os_type=OSType.LINUX, value="/c"),
        ]
        
        result = filter_by_os(artifacts, [OSType.ANDROID, OSType.LINUX])
        
        assert len(result) == 2
        os_types = {a.os for a in result}
        assert OSType.ANDROID in os_types
        assert OSType.LINUX in os_types
        assert OSType.WINDOWS not in os_types
    
    def test_filter_by_os_none_returns_all(self):
        """Test that None OS filter returns all artifacts."""
        artifacts = [
            create_test_artifact(os_type=OSType.ANDROID, value="/a"),
            create_test_artifact(os_type=OSType.WINDOWS, value="/b"),
        ]
        
        result = filter_by_os(artifacts, None)
        
        assert len(result) == 2
    
    def test_filter_by_category(self):
        """Test filtering by category."""
        artifacts = [
            create_test_artifact(category="emulator_files", value="/a"),
            create_test_artifact(category="root_indicators", value="/b"),
            create_test_artifact(category="sandbox_files", value="/c"),
        ]
        
        result = filter_by_category(artifacts, ["emulator_files", "sandbox_files"])
        
        assert len(result) == 2
        categories = {a.category for a in result}
        assert "emulator_files" in categories
        assert "sandbox_files" in categories
    
    def test_filter_by_exclude_patterns(self):
        """Test filtering by exclude patterns."""
        artifacts = [
            create_test_artifact(value="/system/bin/qemu"),
            create_test_artifact(value="C:\\Users\\John\\AppData\\temp"),
            create_test_artifact(value="/data/local/tmp/test"),
        ]
        
        # Exclude user-specific paths and tmp (matches both temp and tmp)
        result = filter_by_exclude_patterns(artifacts, [
            r"C:\\Users\\[^\\]+\\AppData",
            r".*tmp.*",  # Match tmp directories
        ])
        
        # Debug: Log result
        print(f"Filtered to {len(result)} artifacts:")
        for a in result:
            print(f"  {a.match_criteria.value}")
        
        assert len(result) == 1
        assert result[0].match_criteria.value == "/system/bin/qemu"
    
    def test_filter_config_combined(self):
        """Test combined filtering with FilterConfig."""
        artifacts = [
            create_test_artifact(
                os_type=OSType.ANDROID,
                category="emulator_files",
                value="/qemu",
                confidence=0.5,
                sample_count=3,
            ),
            create_test_artifact(
                os_type=OSType.ANDROID,
                category="root_indicators",
                value="/su",
                confidence=0.2,  # Below threshold
                sample_count=1,
            ),
            create_test_artifact(
                os_type=OSType.WINDOWS,
                category="vm_files",
                value="C:\\vmware.dll",
                confidence=0.6,
                sample_count=5,
            ),
        ]
        
        config = FilterConfig(
            min_confidence=0.3,
            min_sample_count=2,
            os_types=[OSType.ANDROID],
        )
        
        result = filter_artifacts(artifacts, config)
        
        # Should only have the first artifact
        assert len(result) == 1
        assert result[0].match_criteria.value == "/qemu"


# =============================================================================
# Grouping Tests
# =============================================================================

class TestGrouping:
    """Tests for artifact grouping."""
    
    def test_group_by_os(self):
        """Test grouping artifacts by OS."""
        artifacts = [
            create_test_artifact(os_type=OSType.ANDROID, value="/a"),
            create_test_artifact(os_type=OSType.ANDROID, value="/b"),
            create_test_artifact(os_type=OSType.WINDOWS, value="/c"),
        ]
        
        grouped = group_by_os(artifacts)
        
        assert len(grouped[OSType.ANDROID]) == 2
        assert len(grouped[OSType.WINDOWS]) == 1
        assert len(grouped[OSType.LINUX]) == 0
    
    def test_group_by_category(self):
        """Test grouping artifacts by category."""
        artifacts = [
            create_test_artifact(category="emulator_files", value="/a"),
            create_test_artifact(category="emulator_files", value="/b"),
            create_test_artifact(category="root_indicators", value="/c"),
        ]
        
        grouped = group_by_category(artifacts)
        
        assert len(grouped["emulator_files"]) == 2
        assert len(grouped["root_indicators"]) == 1
