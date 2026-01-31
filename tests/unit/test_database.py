"""
Tests for GUI database service - processed samples tracking.

Tests the functionality that tracks which Triage samples have already been
analyzed to avoid re-processing them on subsequent updates.
"""

import pytest
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestProcessedSamplesTracking:
    """Tests for the processed samples tracking feature."""
    
    @pytest.fixture
    def db(self):
        """Create a temporary database for testing."""
        # Create a temporary file for the database
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = Path(f.name)
        
        # Import here to avoid Kivy initialization issues in test environment
        # We'll mock the Kivy App.get_running_app() call
        with patch("kivy.app.App.get_running_app") as mock_app:
            mock_app.return_value = None
            
            from gui.services.database import ArtifactDatabase
            
            database = ArtifactDatabase(db_path=db_path)
            database.initialize()
            
            yield database
            
            # Cleanup
            database.close()
            db_path.unlink(missing_ok=True)
    
    def test_is_sample_processed_returns_false_for_new_sample(self, db):
        """A sample that was never processed should return False."""
        result = db.is_sample_processed("260128-newsampl")
        assert result is False
    
    def test_mark_sample_processed_and_check(self, db):
        """A sample marked as processed should be detected as processed."""
        sample_id = "260128-abc123"
        
        # Initially not processed
        assert db.is_sample_processed(sample_id) is False
        
        # Mark as processed
        success = db.mark_sample_processed(
            sample_id=sample_id,
            os_type="android",
            artifacts_extracted=5,
            score=8,
            sha256="abc123def456",
        )
        assert success is True
        
        # Now should be detected as processed
        assert db.is_sample_processed(sample_id) is True
    
    def test_mark_sample_processed_without_optional_fields(self, db):
        """Marking a sample without optional fields should work."""
        sample_id = "260128-minimal"
        
        success = db.mark_sample_processed(
            sample_id=sample_id,
            os_type="windows",
        )
        assert success is True
        assert db.is_sample_processed(sample_id) is True
    
    def test_get_processed_sample_count(self, db):
        """Should correctly count processed samples."""
        # Initially zero
        assert db.get_processed_sample_count() == 0
        
        # Add some samples
        db.mark_sample_processed("sample-1", "android", artifacts_extracted=3)
        db.mark_sample_processed("sample-2", "android", artifacts_extracted=2)
        db.mark_sample_processed("sample-3", "windows", artifacts_extracted=5)
        
        # Total count
        assert db.get_processed_sample_count() == 3
        
        # Count by OS
        assert db.get_processed_sample_count(os_type="android") == 2
        assert db.get_processed_sample_count(os_type="windows") == 1
        assert db.get_processed_sample_count(os_type="linux") == 0
    
    def test_clear_processed_samples_all(self, db):
        """Clearing all processed samples should reset the tracking."""
        # Add some samples
        db.mark_sample_processed("sample-1", "android")
        db.mark_sample_processed("sample-2", "windows")
        
        assert db.get_processed_sample_count() == 2
        
        # Clear all
        db.clear_processed_samples()
        
        assert db.get_processed_sample_count() == 0
        assert db.is_sample_processed("sample-1") is False
        assert db.is_sample_processed("sample-2") is False
    
    def test_clear_processed_samples_by_os(self, db):
        """Clearing samples by OS should only remove those samples."""
        # Add samples for different OS types
        db.mark_sample_processed("android-1", "android")
        db.mark_sample_processed("android-2", "android")
        db.mark_sample_processed("windows-1", "windows")
        
        # Clear only Android
        db.clear_processed_samples(os_type="android")
        
        # Android samples should be cleared
        assert db.is_sample_processed("android-1") is False
        assert db.is_sample_processed("android-2") is False
        
        # Windows sample should still be there
        assert db.is_sample_processed("windows-1") is True
        assert db.get_processed_sample_count() == 1
    
    def test_mark_sample_processed_updates_on_duplicate(self, db):
        """Re-marking a sample should update the existing record."""
        sample_id = "sample-duplicate"
        
        # Mark first time with 0 artifacts
        db.mark_sample_processed(sample_id, "linux", artifacts_extracted=0)
        
        # Mark again with updated data
        db.mark_sample_processed(sample_id, "linux", artifacts_extracted=10, score=9)
        
        # Should still only have one record
        assert db.get_processed_sample_count() == 1
        
        # Verify updated data is stored
        cursor = db.conn.cursor()
        cursor.execute(
            "SELECT artifacts_extracted, score FROM processed_samples WHERE sample_id = ?",
            (sample_id,)
        )
        row = cursor.fetchone()
        assert row[0] == 10  # artifacts_extracted
        assert row[1] == 9   # score
    
    def test_processed_samples_table_in_schema(self, db):
        """The processed_samples table should exist with correct columns."""
        cursor = db.conn.cursor()
        cursor.execute("PRAGMA table_info(processed_samples)")
        columns = {row[1] for row in cursor.fetchall()}
        
        expected_columns = {
            "sample_id",
            "os_type",
            "processed_at",
            "artifacts_extracted",
            "score",
            "sha256",
        }
        
        assert expected_columns == columns
    
    def test_clear_all_includes_processed_samples(self, db):
        """The clear_all() method should also clear processed samples."""
        # Add a processed sample
        db.mark_sample_processed("sample-1", "android")
        assert db.get_processed_sample_count() == 1
        
        # Clear all data
        db.clear_all()
        
        # Processed samples should be cleared too
        assert db.get_processed_sample_count() == 0
