"""
SQLite Database for artifact storage.

Stores:
- Artifacts with privilege levels
- Placement history (for undo)
- Settings
- Update timestamps
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from kivy.app import App

logger = logging.getLogger(__name__)


class ArtifactDatabase:
    """
    SQLite database for storing artifacts and app state.
    
    Provides:
    - Artifact CRUD with filtering
    - Privilege level tagging
    - Placement history for undo
    - Settings storage
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the database.
        
        Args:
            db_path: Path to SQLite database file.
                    If None, uses app data directory.
        """
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
    
    def initialize(self):
        """Initialize the database connection and schema."""
        if self.db_path is None:
            app = App.get_running_app()
            if app:
                data_dir = app.get_data_dir()
            else:
                data_dir = Path.home() / ".evasion_artifact_placer"
            
            data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = data_dir / "artifacts.db"
        
        logger.info(f"Initializing database at: {self.db_path}")
        
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        
        self._create_schema()
        self._seed_initial_data()
    
    def _create_schema(self):
        """Create database tables if they don't exist."""
        cursor = self.conn.cursor()
        
        # Artifacts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                os TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                category TEXT NOT NULL,
                value TEXT NOT NULL,
                match_type TEXT DEFAULT 'exact',
                case_sensitive INTEGER DEFAULT 1,
                confidence REAL DEFAULT 0.5,
                privilege_level TEXT DEFAULT 'user',
                description TEXT,
                evasion_purpose TEXT,
                sample_count INTEGER DEFAULT 1,
                source_sha1 TEXT,
                source_sha256 TEXT,
                source_sample_id TEXT,
                triage_url TEXT,
                first_seen TEXT,
                last_seen TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Placement history (for undo)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS placements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT NOT NULL,
                placed_path TEXT,
                placed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                removed_at TEXT,
                status TEXT DEFAULT 'placed',
                FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
            )
        """)
        
        # Settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        
        # Update log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT,
                completed_at TEXT,
                artifacts_added INTEGER DEFAULT 0,
                artifacts_updated INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                error TEXT
            )
        """)
        
        # Processed samples tracking - prevents re-analyzing the same samples
        # This saves API calls and processing time on subsequent updates
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_samples (
                sample_id TEXT PRIMARY KEY,
                os_type TEXT NOT NULL,
                processed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                artifacts_extracted INTEGER DEFAULT 0,
                score INTEGER,
                sha256 TEXT
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_os ON artifacts(os)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_category ON artifacts(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_privilege ON artifacts(privilege_level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_placements_status ON placements(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_samples_os ON processed_samples(os_type)")
        
        # Migrate existing databases - add new columns if missing
        self._migrate_schema(cursor)
        
        self.conn.commit()
        logger.debug("Database schema created")
    
    def _migrate_schema(self, cursor):
        """Add new columns to existing databases."""
        # Check existing columns
        cursor.execute("PRAGMA table_info(artifacts)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        
        # Add missing columns for source sample tracking
        new_columns = [
            ("evasion_purpose", "TEXT"),
            ("source_sha1", "TEXT"),
            ("source_sha256", "TEXT"),
            ("source_sample_id", "TEXT"),
            ("triage_url", "TEXT"),
        ]
        
        for col_name, col_type in new_columns:
            if col_name not in existing_columns:
                logger.debug(f"Adding column {col_name} to artifacts table")
                cursor.execute(f"ALTER TABLE artifacts ADD COLUMN {col_name} {col_type}")
    
    def _seed_initial_data(self):
        """Seed database with initial artifacts if empty."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM artifacts")
        count = cursor.fetchone()[0]
        
        if count > 0:
            logger.debug(f"Database already has {count} artifacts")
            return
        
        logger.info("Seeding initial artifacts...")
        
        # Import artifacts from existing extractor output if available
        self._import_from_extractor_output()
        
        # If still empty, seed with common evasion artifacts
        cursor.execute("SELECT COUNT(*) FROM artifacts")
        if cursor.fetchone()[0] == 0:
            self._seed_common_artifacts()
    
    def _import_from_extractor_output(self):
        """Import artifacts from extractor output files."""
        # Check for output/artifacts.json
        project_root = Path(__file__).parent.parent.parent
        output_file = project_root / "output" / "artifacts.json"
        
        if not output_file.exists():
            logger.debug("No extractor output file found")
            return
        
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            artifacts = data.get("artifacts", {})
            imported = 0
            
            for os_type, os_artifacts in artifacts.items():
                for artifact in os_artifacts:
                    self._import_artifact(artifact, os_type)
                    imported += 1
            
            self.conn.commit()
            logger.info(f"Imported {imported} artifacts from extractor output")
            
        except Exception as e:
            logger.error(f"Failed to import artifacts: {e}")
    
    def _import_artifact(self, artifact: dict, os_type: str):
        """Import a single artifact from extractor format."""
        cursor = self.conn.cursor()
        
        # Determine privilege level based on path/value
        value = artifact.get("match_criteria", {}).get("value", "")
        privilege = self._determine_privilege_level(os_type, value)
        
        cursor.execute("""
            INSERT OR REPLACE INTO artifacts 
            (id, os, artifact_type, category, value, match_type, case_sensitive,
             confidence, privilege_level, description, sample_count, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            artifact.get("id"),
            os_type,
            artifact.get("artifact_type", "file"),
            artifact.get("category", "unknown"),
            value,
            artifact.get("match_criteria", {}).get("type", "exact"),
            1 if artifact.get("match_criteria", {}).get("case_sensitive", True) else 0,
            artifact.get("provenance", {}).get("confidence", 0.5),
            privilege,
            artifact.get("metadata", {}).get("description", ""),
            artifact.get("provenance", {}).get("sample_count", 1),
            artifact.get("metadata", {}).get("first_seen"),
            artifact.get("metadata", {}).get("last_seen"),
        ))
    
    def _determine_privilege_level(self, os_type: str, value: str) -> str:
        """
        Determine the privilege level required to place an artifact.
        
        Returns: 'user', 'admin', or 'root'
        """
        value_lower = value.lower()
        
        if os_type == "android":
            # Android: /sdcard is user-accessible, /system and /data need root
            if value_lower.startswith("/sdcard") or value_lower.startswith("/storage"):
                return "user"
            elif value_lower.startswith("/system") or value_lower.startswith("/data"):
                return "root"
            else:
                return "root"  # Default to root for unknown Android paths
        
        elif os_type == "windows":
            # Windows: User profile is accessible, System32/registry need admin
            if any(x in value_lower for x in ["%appdata%", "%localappdata%", "%temp%", "%userprofile%"]):
                return "user"
            elif any(x in value_lower for x in ["hklm", "system32", "windows\\", "program files"]):
                return "admin"
            elif value_lower.startswith("hkcu"):
                return "user"  # Current user registry
            else:
                return "admin"  # Default to admin for unknown Windows paths
        
        elif os_type == "linux":
            # Linux: Home and /tmp accessible, /usr /opt /etc need root
            if value_lower.startswith("~") or value_lower.startswith("/home") or value_lower.startswith("/tmp"):
                return "user"
            elif any(x in value_lower for x in ["/usr", "/opt", "/etc", "/var", "/sys", "/proc"]):
                return "root"
            else:
                return "root"  # Default to root for unknown Linux paths
        
        elif os_type == "macos":
            # macOS: Home and /tmp accessible, /Library /System need admin
            if value_lower.startswith("~") or value_lower.startswith("/users") or value_lower.startswith("/tmp"):
                return "user"
            elif any(x in value_lower for x in ["/library", "/system", "/applications"]):
                return "admin"
            else:
                return "admin"  # Default to admin for unknown macOS paths
        
        return "user"  # Fallback
    
    def _seed_common_artifacts(self):
        """Seed database with common evasion artifacts."""
        logger.info("Seeding common evasion artifacts...")
        
        # Common Android root detection files
        android_root_files = [
            ("/system/app/Superuser.apk", "Root management app"),
            ("/system/xbin/su", "Root binary"),
            ("/system/bin/su", "Root binary"),
            ("/sbin/su", "Root binary"),
            ("/data/local/su", "Root binary"),
            ("/data/local/bin/su", "Root binary"),
        ]
        
        for value, desc in android_root_files:
            self._insert_artifact(
                os="android",
                artifact_type="file",
                category="root_indicators",
                value=value,
                description=desc,
                privilege_level=self._determine_privilege_level("android", value),
            )
        
        # Common Windows VM detection files
        windows_vm_files = [
            ("C:\\Windows\\System32\\drivers\\VBoxGuest.sys", "VirtualBox driver"),
            ("C:\\Windows\\System32\\drivers\\vmhgfs.sys", "VMware driver"),
            ("C:\\Windows\\System32\\vboxdisp.dll", "VirtualBox display"),
        ]
        
        for value, desc in windows_vm_files:
            self._insert_artifact(
                os="windows",
                artifact_type="file",
                category="vm_files",
                value=value,
                description=desc,
                privilege_level=self._determine_privilege_level("windows", value),
            )
        
        # Windows VM registry keys
        windows_vm_registry = [
            ("HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions", "VirtualBox registry"),
            ("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools", "VMware registry"),
            ("HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__", "VirtualBox ACPI"),
        ]
        
        for value, desc in windows_vm_registry:
            self._insert_artifact(
                os="windows",
                artifact_type="registry",
                category="vm_registry",
                value=value,
                description=desc,
                privilege_level="admin",
            )
        
        self.conn.commit()
        logger.info("Seeded common artifacts")
    
    def _insert_artifact(self, os: str, artifact_type: str, category: str, 
                         value: str, description: str = "", 
                         privilege_level: str = "user",
                         confidence: float = 0.5):
        """Insert a single artifact."""
        import hashlib
        
        # Generate deterministic ID
        hash_input = f"{os}-{artifact_type}-{value}"
        hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
        artifact_id = f"art-{os}-{artifact_type}-{hash_value}"
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO artifacts 
            (id, os, artifact_type, category, value, privilege_level, description, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (artifact_id, os, artifact_type, category, value, privilege_level, description, confidence))
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.debug("Database connection closed")
    
    # =========================================================================
    # Artifact CRUD
    # =========================================================================
    
    def get_artifact_count(self) -> int:
        """Get total artifact count."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM artifacts")
        return cursor.fetchone()[0]
    
    def get_artifacts(
        self,
        os_type: Optional[str] = None,
        category: Optional[str] = None,
        privilege_level: Optional[str] = None,
        search_text: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Get artifacts with optional filtering.
        
        Args:
            os_type: Filter by OS (android, windows, linux, macos)
            category: Filter by category
            privilege_level: Filter by privilege (user, admin, root)
            search_text: Search in value field
            limit: Maximum results
            
        Returns:
            List of artifact dicts
        """
        query = "SELECT * FROM artifacts WHERE 1=1"
        params = []
        
        if os_type:
            query += " AND os = ?"
            params.append(os_type)
        
        if category:
            query += " AND category = ?"
            params.append(category)
        
        if privilege_level:
            query += " AND privilege_level = ?"
            params.append(privilege_level)
        
        if search_text:
            query += " AND value LIKE ?"
            params.append(f"%{search_text}%")
        
        query += " ORDER BY confidence DESC, sample_count DESC LIMIT ?"
        params.append(limit)
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_artifact_by_id(self, artifact_id: str) -> Optional[Dict[str, Any]]:
        """Get a single artifact by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def add_artifact(self, artifact: Dict[str, Any]) -> bool:
        """Add a new artifact."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO artifacts 
                (id, os, artifact_type, category, value, match_type, case_sensitive,
                 confidence, privilege_level, description, evasion_purpose, sample_count,
                 source_sha1, source_sha256, source_sample_id, triage_url, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                artifact.get("id"),
                artifact.get("os"),
                artifact.get("artifact_type"),
                artifact.get("category"),
                artifact.get("value"),
                artifact.get("match_type", "exact"),
                1 if artifact.get("case_sensitive", True) else 0,
                artifact.get("confidence", 0.5),
                artifact.get("privilege_level", "user"),
                artifact.get("description", ""),
                artifact.get("evasion_purpose", ""),
                artifact.get("sample_count", 1),
                artifact.get("source_sha1", ""),
                artifact.get("source_sha256", ""),
                artifact.get("source_sample_id", ""),
                artifact.get("triage_url", ""),
                artifact.get("first_seen"),
                artifact.get("last_seen"),
            ))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add artifact: {e}")
            return False
    
    def update_artifact(self, artifact_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing artifact."""
        try:
            set_clauses = []
            params = []
            
            for key, value in updates.items():
                if key != "id":
                    set_clauses.append(f"{key} = ?")
                    params.append(value)
            
            if not set_clauses:
                return True
            
            params.append(artifact_id)
            query = f"UPDATE artifacts SET {', '.join(set_clauses)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to update artifact: {e}")
            return False
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics for dashboard."""
        cursor = self.conn.cursor()
        
        # Total artifacts
        cursor.execute("SELECT COUNT(*) FROM artifacts")
        total = cursor.fetchone()[0]
        
        # Placed artifacts
        cursor.execute("SELECT COUNT(*) FROM placements WHERE status = 'placed'")
        placed = cursor.fetchone()[0]
        
        # User-space artifacts
        cursor.execute("SELECT COUNT(*) FROM artifacts WHERE privilege_level = 'user'")
        user_space = cursor.fetchone()[0]
        
        # Admin/root required
        cursor.execute("SELECT COUNT(*) FROM artifacts WHERE privilege_level IN ('admin', 'root')")
        admin_required = cursor.fetchone()[0]
        
        # Last update
        cursor.execute("SELECT completed_at FROM updates WHERE status = 'success' ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        last_update = row[0] if row else None
        
        return {
            "total": total,
            "placed": placed,
            "user_space": user_space,
            "admin_required": admin_required,
            "last_update": last_update,
        }
    
    # =========================================================================
    # Placement History
    # =========================================================================
    
    def log_placement(self, artifact: Dict[str, Any], placed_path: Optional[str] = None):
        """Log an artifact placement."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO placements (artifact_id, placed_path, status)
            VALUES (?, ?, 'placed')
        """, (artifact.get("id"), placed_path or artifact.get("value")))
        self.conn.commit()
    
    def get_placed_artifacts(self) -> List[Dict[str, Any]]:
        """Get all placed artifacts."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT p.*, a.value, a.artifact_type, a.os
            FROM placements p
            JOIN artifacts a ON p.artifact_id = a.id
            WHERE p.status = 'placed'
            ORDER BY p.placed_at DESC
        """)
        return [dict(row) for row in cursor.fetchall()]
    
    def mark_placement_removed(self, placement_id: int):
        """Mark a placement as removed."""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE placements 
            SET status = 'removed', removed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (placement_id,))
        self.conn.commit()
    
    def clear_placed_log(self):
        """Clear all placement history."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM placements")
        self.conn.commit()
    
    # =========================================================================
    # Settings
    # =========================================================================
    
    def get_settings(self) -> Dict[str, Any]:
        """Get all settings."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT key, value FROM settings")
        
        settings = {}
        for row in cursor.fetchall():
            try:
                settings[row["key"]] = json.loads(row["value"])
            except (json.JSONDecodeError, TypeError):
                settings[row["key"]] = row["value"]
        
        return settings
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a single setting."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        
        if row:
            try:
                return json.loads(row["value"])
            except (json.JSONDecodeError, TypeError):
                return row["value"]
        
        return default
    
    def save_settings(self, settings: Dict[str, Any]):
        """Save multiple settings."""
        cursor = self.conn.cursor()
        
        for key, value in settings.items():
            json_value = json.dumps(value) if not isinstance(value, str) else value
            cursor.execute("""
                INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)
            """, (key, json_value))
        
        self.conn.commit()
    
    def save_setting(self, key: str, value: Any):
        """Save a single setting."""
        self.save_settings({key: value})
    
    # =========================================================================
    # Data Management
    # =========================================================================
    
    def clear_all(self):
        """Clear all data from the database."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM placements")
        cursor.execute("DELETE FROM artifacts")
        cursor.execute("DELETE FROM settings")
        cursor.execute("DELETE FROM updates")
        cursor.execute("DELETE FROM processed_samples")
        self.conn.commit()
        logger.info("All data cleared")
    
    # =========================================================================
    # Processed Samples Tracking
    # =========================================================================
    
    def is_sample_processed(self, sample_id: str) -> bool:
        """
        Check if a sample has already been processed.
        
        Args:
            sample_id: Triage sample ID (e.g., "260128-abc123")
            
        Returns:
            True if the sample has been processed before
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT 1 FROM processed_samples WHERE sample_id = ?",
            (sample_id,)
        )
        result = cursor.fetchone() is not None
        logger.debug(f"Sample {sample_id} already processed: {result}")
        return result
    
    def mark_sample_processed(
        self,
        sample_id: str,
        os_type: str,
        artifacts_extracted: int = 0,
        score: Optional[int] = None,
        sha256: Optional[str] = None,
    ) -> bool:
        """
        Mark a sample as processed to skip it in future updates.
        
        Args:
            sample_id: Triage sample ID
            os_type: Detected OS type (android, windows, linux, macos)
            artifacts_extracted: Number of artifacts extracted from this sample
            score: Sample malware score (0-10)
            sha256: SHA256 hash of the sample
            
        Returns:
            True if successfully marked
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO processed_samples 
                (sample_id, os_type, processed_at, artifacts_extracted, score, sha256)
                VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?)
            """, (sample_id, os_type, artifacts_extracted, score, sha256))
            self.conn.commit()
            logger.debug(f"Marked sample {sample_id} as processed ({artifacts_extracted} artifacts)")
            return True
        except Exception as e:
            logger.error(f"Failed to mark sample as processed: {e}")
            return False
    
    def get_processed_sample_count(self, os_type: Optional[str] = None) -> int:
        """
        Get count of processed samples, optionally filtered by OS.
        
        Args:
            os_type: Optional OS filter
            
        Returns:
            Number of processed samples
        """
        cursor = self.conn.cursor()
        if os_type:
            cursor.execute(
                "SELECT COUNT(*) FROM processed_samples WHERE os_type = ?",
                (os_type,)
            )
        else:
            cursor.execute("SELECT COUNT(*) FROM processed_samples")
        return cursor.fetchone()[0]
    
    def clear_processed_samples(self, os_type: Optional[str] = None):
        """
        Clear processed samples history to force re-analysis.
        
        Args:
            os_type: If provided, only clear samples of this OS type.
                    If None, clears all processed samples.
        """
        cursor = self.conn.cursor()
        if os_type:
            cursor.execute(
                "DELETE FROM processed_samples WHERE os_type = ?",
                (os_type,)
            )
            logger.info(f"Cleared processed samples for OS: {os_type}")
        else:
            cursor.execute("DELETE FROM processed_samples")
            logger.info("Cleared all processed samples")
        self.conn.commit()