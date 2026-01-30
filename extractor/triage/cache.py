"""
SQLite cache for Triage API responses.

Caches API responses to reduce API calls and speed up repeated extractions.

TTL (time-to-live):
- Overview: 7 days (sample metadata rarely changes)
- Behavioral report: 30 days (analysis results are stable)
- Kernel logs: 30 days (analysis results are stable)
- Search results: 1 hour (frequently updated)
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class CacheConfig:
    """Configuration for the API cache."""
    db_path: Path = Path("./cache/triage_cache.db")
    
    # TTL values in seconds
    overview_ttl: int = 7 * 24 * 3600     # 7 days
    behavioral_ttl: int = 30 * 24 * 3600  # 30 days
    kernel_logs_ttl: int = 30 * 24 * 3600 # 30 days
    search_ttl: int = 3600                 # 1 hour
    
    # Maximum cache size in MB (0 = unlimited)
    max_size_mb: int = 500
    
    # Whether cache is enabled
    enabled: bool = True


class TriageCache:
    """
    SQLite-based cache for Triage API responses.
    
    Stores API responses with TTL-based expiration.
    Thread-safe for read operations.
    """
    
    # Cache entry types
    TYPE_OVERVIEW = "overview"
    TYPE_BEHAVIORAL = "behavioral"
    TYPE_KERNEL_LOGS = "kernel_logs"
    TYPE_SEARCH = "search"
    TYPE_SAMPLE = "sample"
    
    def __init__(self, config: Optional[CacheConfig] = None):
        """
        Initialize the cache.
        
        Args:
            config: Cache configuration. Uses defaults if not provided.
        """
        self.config = config or CacheConfig()
        self.conn: Optional[sqlite3.Connection] = None
        
        if self.config.enabled:
            self._initialize()
    
    def _initialize(self):
        """Initialize the database connection and schema."""
        # Ensure cache directory exists
        self.config.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.debug(f"Initializing cache at: {self.config.db_path}")
        
        self.conn = sqlite3.connect(
            str(self.config.db_path),
            check_same_thread=False,  # Allow multi-threaded access
        )
        self.conn.row_factory = sqlite3.Row
        
        self._create_schema()
        self._cleanup_expired()
    
    def _create_schema(self):
        """Create the cache table if it doesn't exist."""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                entry_type TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                size_bytes INTEGER DEFAULT 0
            )
        """)
        
        # Index for cleanup queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cache_expires 
            ON cache(expires_at)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cache_type 
            ON cache(entry_type)
        """)
        
        self.conn.commit()
    
    def _get_ttl(self, entry_type: str) -> int:
        """Get TTL in seconds for an entry type."""
        ttl_map = {
            self.TYPE_OVERVIEW: self.config.overview_ttl,
            self.TYPE_BEHAVIORAL: self.config.behavioral_ttl,
            self.TYPE_KERNEL_LOGS: self.config.kernel_logs_ttl,
            self.TYPE_SEARCH: self.config.search_ttl,
            self.TYPE_SAMPLE: self.config.overview_ttl,
        }
        return ttl_map.get(entry_type, 3600)  # Default 1 hour
    
    def _make_key(self, entry_type: str, *args) -> str:
        """Generate a cache key from type and arguments."""
        key_parts = [entry_type] + [str(a) for a in args]
        key_string = ":".join(key_parts)
        
        # Use hash for long keys
        if len(key_string) > 200:
            hash_value = hashlib.sha256(key_string.encode()).hexdigest()[:32]
            return f"{entry_type}:{hash_value}"
        
        return key_string
    
    def get(self, entry_type: str, *args) -> Optional[Dict[str, Any]]:
        """
        Get a cached entry.
        
        Args:
            entry_type: Type of entry (overview, behavioral, etc.)
            *args: Key components (e.g., sample_id, task_id)
            
        Returns:
            Cached data dict, or None if not found/expired
        """
        if not self.config.enabled or not self.conn:
            return None
        
        key = self._make_key(entry_type, *args)
        now = time.time()
        
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT data FROM cache WHERE key = ? AND expires_at > ?",
            (key, now)
        )
        
        row = cursor.fetchone()
        if row:
            try:
                logger.debug(f"Cache hit: {key}")
                return json.loads(row["data"])
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON in cache: {key}")
                self._delete(key)
                return None
        
        logger.debug(f"Cache miss: {key}")
        return None
    
    def set(self, entry_type: str, data: Dict[str, Any], *args) -> bool:
        """
        Store an entry in the cache.
        
        Args:
            entry_type: Type of entry
            data: Data to cache (must be JSON-serializable)
            *args: Key components
            
        Returns:
            True if stored successfully
        """
        if not self.config.enabled or not self.conn:
            return False
        
        key = self._make_key(entry_type, *args)
        now = time.time()
        ttl = self._get_ttl(entry_type)
        expires_at = now + ttl
        
        try:
            json_data = json.dumps(data)
            size_bytes = len(json_data.encode("utf-8"))
            
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO cache 
                (key, entry_type, data, created_at, expires_at, size_bytes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (key, entry_type, json_data, now, expires_at, size_bytes))
            
            self.conn.commit()
            logger.debug(f"Cached: {key} (TTL: {ttl}s)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cache {key}: {e}")
            return False
    
    def _delete(self, key: str):
        """Delete a cache entry."""
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM cache WHERE key = ?", (key,))
            self.conn.commit()
    
    def invalidate(self, entry_type: str, *args):
        """
        Invalidate a specific cache entry.
        
        Args:
            entry_type: Type of entry
            *args: Key components
        """
        if not self.conn:
            return
        
        key = self._make_key(entry_type, *args)
        self._delete(key)
        logger.debug(f"Invalidated: {key}")
    
    def invalidate_sample(self, sample_id: str):
        """Invalidate all cache entries for a sample."""
        if not self.conn:
            return
        
        cursor = self.conn.cursor()
        cursor.execute(
            "DELETE FROM cache WHERE key LIKE ?",
            (f"%{sample_id}%",)
        )
        deleted = cursor.rowcount
        self.conn.commit()
        logger.debug(f"Invalidated {deleted} entries for sample {sample_id}")
    
    def _cleanup_expired(self):
        """Remove expired entries from the cache."""
        if not self.conn:
            return
        
        now = time.time()
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM cache WHERE expires_at < ?", (now,))
        deleted = cursor.rowcount
        self.conn.commit()
        
        if deleted > 0:
            logger.debug(f"Cleaned up {deleted} expired cache entries")
    
    def clear(self):
        """Clear all cache entries."""
        if not self.conn:
            return
        
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM cache")
        deleted = cursor.rowcount
        self.conn.commit()
        logger.info(f"Cleared {deleted} cache entries")
    
    def clear_type(self, entry_type: str):
        """Clear all entries of a specific type."""
        if not self.conn:
            return
        
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM cache WHERE entry_type = ?", (entry_type,))
        deleted = cursor.rowcount
        self.conn.commit()
        logger.info(f"Cleared {deleted} {entry_type} cache entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if not self.conn:
            return {"enabled": False}
        
        cursor = self.conn.cursor()
        
        # Total entries
        cursor.execute("SELECT COUNT(*) as count FROM cache")
        total_count = cursor.fetchone()["count"]
        
        # Total size
        cursor.execute("SELECT SUM(size_bytes) as total FROM cache")
        row = cursor.fetchone()
        total_size = row["total"] or 0
        
        # Entries by type
        cursor.execute("""
            SELECT entry_type, COUNT(*) as count, SUM(size_bytes) as size
            FROM cache
            GROUP BY entry_type
        """)
        by_type = {row["entry_type"]: {
            "count": row["count"],
            "size_bytes": row["size"] or 0,
        } for row in cursor.fetchall()}
        
        # Expired entries
        now = time.time()
        cursor.execute("SELECT COUNT(*) as count FROM cache WHERE expires_at < ?", (now,))
        expired_count = cursor.fetchone()["count"]
        
        return {
            "enabled": True,
            "db_path": str(self.config.db_path),
            "total_entries": total_count,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "expired_entries": expired_count,
            "by_type": by_type,
        }
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.debug("Cache closed")
    
    # =========================================================================
    # Convenience methods for common cache operations
    # =========================================================================
    
    def get_overview(self, sample_id: str) -> Optional[Dict[str, Any]]:
        """Get cached overview for a sample."""
        return self.get(self.TYPE_OVERVIEW, sample_id)
    
    def set_overview(self, sample_id: str, data: Dict[str, Any]) -> bool:
        """Cache an overview."""
        return self.set(self.TYPE_OVERVIEW, data, sample_id)
    
    def get_behavioral(self, sample_id: str, task_id: str) -> Optional[Dict[str, Any]]:
        """Get cached behavioral report."""
        return self.get(self.TYPE_BEHAVIORAL, sample_id, task_id)
    
    def set_behavioral(self, sample_id: str, task_id: str, data: Dict[str, Any]) -> bool:
        """Cache a behavioral report."""
        return self.set(self.TYPE_BEHAVIORAL, data, sample_id, task_id)
    
    def get_kernel_logs(self, sample_id: str, task_id: str, os_type: str) -> Optional[Dict[str, Any]]:
        """Get cached kernel logs."""
        return self.get(self.TYPE_KERNEL_LOGS, sample_id, task_id, os_type)
    
    def set_kernel_logs(self, sample_id: str, task_id: str, os_type: str, data: Dict[str, Any]) -> bool:
        """Cache kernel logs."""
        return self.set(self.TYPE_KERNEL_LOGS, data, sample_id, task_id, os_type)
    
    def get_search(self, query: str) -> Optional[Dict[str, Any]]:
        """Get cached search results."""
        return self.get(self.TYPE_SEARCH, query)
    
    def set_search(self, query: str, data: Dict[str, Any]) -> bool:
        """Cache search results."""
        return self.set(self.TYPE_SEARCH, data, query)
