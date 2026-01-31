"""
Auto-Update Service.

Handles periodic updates from the Triage API:
- Background scheduling (daily by default)
- Incremental artifact updates
- Progress tracking and callbacks
- Notifications for new artifacts
"""

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Optional

from kivy.app import App
from kivy.clock import Clock

logger = logging.getLogger(__name__)


@dataclass
class UpdateProgress:
    """Tracks update progress."""
    status: str = "idle"  # idle, running, complete, error
    current_os: str = ""
    current_sample: int = 0
    total_samples: int = 0
    os_completed: int = 0
    total_os: int = 4  # android, windows, linux, macos
    artifacts_found: int = 0
    message: str = ""
    
    @property
    def percent(self) -> float:
        """Overall progress percentage."""
        if self.total_os == 0:
            return 0
        os_progress = self.os_completed / self.total_os
        if self.total_samples > 0:
            sample_progress = self.current_sample / self.total_samples / self.total_os
        else:
            sample_progress = 0
        return min((os_progress + sample_progress) * 100, 100)
    
    @property
    def description(self) -> str:
        """Human-readable progress description."""
        if self.status == "idle":
            return "Ready"
        elif self.status == "running":
            if self.current_os:
                return f"Fetching {self.current_os} ({self.current_sample}/{self.total_samples})..."
            return "Starting update..."
        elif self.status == "complete":
            return f"Complete: {self.artifacts_found} artifacts found"
        elif self.status == "error":
            return f"Error: {self.message}"
        return self.message or "Unknown"


class UpdateService:
    """
    Background service for updating artifacts from Triage API.
    
    Features:
    - Configurable update frequency
    - Background execution
    - Progress tracking with callbacks
    - New artifact notifications
    """
    
    # Update frequency options (in seconds)
    FREQUENCIES = {
        "Hourly": 3600,
        "Daily": 86400,
        "Weekly": 604800,
        "Manual": None,
    }
    
    # OS types to fetch
    OS_TYPES = ["android", "windows", "linux", "macos"]
    
    def __init__(self):
        """Initialize the update service."""
        self.is_running = False
        self.last_update: Optional[datetime] = None
        self.next_update: Optional[datetime] = None
        self.progress = UpdateProgress()
        self._update_thread: Optional[threading.Thread] = None
        self._schedule_event = None
        self._on_update_complete: Optional[Callable] = None
        self._on_update_error: Optional[Callable] = None
        self._on_new_artifacts: Optional[Callable[[int], None]] = None
        self._on_progress: Optional[Callable[[UpdateProgress], None]] = None
        self._selected_os_types: List[str] = self.OS_TYPES  # OS types for current update
    
    def start(
        self,
        frequency: str = "Daily",
        on_complete: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
        on_new_artifacts: Optional[Callable[[int], None]] = None,
        on_progress: Optional[Callable[[UpdateProgress], None]] = None,
    ):
        """
        Start the update service.
        
        Args:
            frequency: Update frequency (Hourly, Daily, Weekly, Manual)
            on_complete: Callback when update completes
            on_error: Callback on update error
            on_new_artifacts: Callback when new artifacts are found (receives count)
            on_progress: Callback for progress updates
        """
        self._on_update_complete = on_complete
        self._on_update_error = on_error
        self._on_new_artifacts = on_new_artifacts
        self._on_progress = on_progress
        
        interval = self.FREQUENCIES.get(frequency)
        
        if interval is None:
            logger.info("Update service set to manual mode")
            return
        
        logger.info(f"Starting update service with frequency: {frequency}")
        
        # Check if update is needed on startup
        self._check_and_schedule(interval)
    
    def stop(self):
        """Stop the update service."""
        if self._schedule_event:
            Clock.unschedule(self._schedule_event)
            self._schedule_event = None
        
        logger.info("Update service stopped")
    
    def _check_and_schedule(self, interval: int):
        """Check if update needed and schedule next."""
        app = App.get_running_app()
        if not app or not app.database:
            return
        
        # Get last update time
        last_update_str = app.database.get_setting("last_update_time")
        
        if last_update_str:
            try:
                self.last_update = datetime.fromisoformat(last_update_str)
            except ValueError:
                self.last_update = None
        
        # Check if update is due
        now = datetime.now(timezone.utc)
        
        if self.last_update is None:
            # Never updated - do it now
            self._run_update_async()
        else:
            # Check if interval has passed
            next_due = self.last_update + timedelta(seconds=interval)
            
            if now >= next_due:
                self._run_update_async()
            else:
                # Schedule for later
                seconds_until = (next_due - now).total_seconds()
                logger.info(f"Next update in {seconds_until/3600:.1f} hours")
        
        # Schedule periodic check
        self._schedule_event = Clock.schedule_interval(
            lambda dt: self._check_update_due(interval),
            interval / 10  # Check 10 times per interval
        )
        
        self.next_update = now + timedelta(seconds=interval)
    
    def _check_update_due(self, interval: int):
        """Periodic check if update is due."""
        now = datetime.now(timezone.utc)
        
        if self.last_update is None:
            self._run_update_async()
            return
        
        next_due = self.last_update + timedelta(seconds=interval)
        
        if now >= next_due and not self.is_running:
            self._run_update_async()
    
    def trigger_update(self, os_types: Optional[List[str]] = None):
        """
        Manually trigger an update.
        
        Args:
            os_types: List of OS types to fetch. If None, uses default OS_TYPES.
        """
        if self.is_running:
            logger.warning("Update already in progress")
            return
        
        # Store selected OS types for this update
        self._selected_os_types = os_types if os_types else self.OS_TYPES

        # Track the user's requested OS for UI filtering
        app = App.get_running_app()
        if app:
            if len(self._selected_os_types) == 1:
                app.last_update_os = self._selected_os_types[0]
            else:
                app.last_update_os = None
        
        logger.info(f"Manual update triggered for: {self._selected_os_types}")
        self._run_update_async()
    
    def _run_update_async(self):
        """Run update in background thread."""
        if self.is_running:
            return
        
        self.is_running = True
        self.progress = UpdateProgress(status="running", message="Starting update...")
        self._notify_progress()
        
        self._update_thread = threading.Thread(
            target=self._do_update,
            daemon=True,
        )
        self._update_thread.start()
    
    def _notify_progress(self):
        """Notify progress callback on main thread."""
        if self._on_progress:
            Clock.schedule_once(lambda dt: self._on_progress(self.progress), 0)
    
    def _do_update(self):
        """Perform the actual update."""
        logger.info("Starting update from Triage API...")
        
        app = App.get_running_app()
        if not app or not app.database:
            self._on_error("App not initialized")
            return
        
        try:
            # Get API key
            api_key = app.database.get_setting("api_key")
            
            if not api_key:
                self._on_error("No API key configured")
                return
            
            # Import extractor components
            from extractor.triage.client import TriageClient, TriageAPIError
            from extractor.pipeline import extract_sample, detect_os_from_overview
            from extractor.models.artifact import OSType
            from extractor.extractors.base import ExtractionContext
            from extractor.models.sample import SampleMetadata
            from extractor.aggregation.filter import FilterConfig
            
            # Initialize client
            client = TriageClient(api_key=api_key)
            
            # Test connection
            if not client.test_connection():
                self._on_error("Failed to connect to Triage API")
                return
            
            # Use selected OS types for this update
            os_types_to_fetch = self._selected_os_types
            self.progress.total_os = len(os_types_to_fetch)
            total_new = 0
            total_updated = 0
            total_artifacts = 0
            
            # Process each OS type
            for os_idx, os_type in enumerate(os_types_to_fetch):
                self.progress.current_os = os_type.upper()
                self.progress.os_completed = os_idx
                self.progress.current_sample = 0
                self._notify_progress()
                
                logger.info(f"Searching for {os_type} samples...")
                
                # Search for samples with tag:evasion, filtered by OS
                # The new API infers OS from file extension and platform fields
                try:
                    samples = list(client.search_evasion_samples(
                        os_filter=os_type,  # Filter by OS type
                        limit=30,
                        fetch_overview=True,  # Get overview for accurate OS detection
                    ))
                except Exception as e:
                    logger.warning(f"Error searching {os_type}: {e}")
                    continue
                
                self.progress.total_samples = len(samples)
                logger.info(f"Found {len(samples)} {os_type} samples")
                
                # Process each sample
                for sample_idx, sample in enumerate(samples):
                    self.progress.current_sample = sample_idx + 1
                    self._notify_progress()
                    
                    sample_id = sample.get("id")
                    if not sample_id:
                        continue
                    
                    # Use the inferred_os from search results (already filtered)
                    inferred_os = sample.get("inferred_os", os_type)
                    logger.debug(f"Processing {sample_id} (inferred OS: {inferred_os})")
                    
                    try:
                        # Fetch sample data
                        data = client.fetch_sample_data(sample_id)
                        overview = data.get("overview", {})
                        
                        if not overview:
                            logger.debug(f"No overview for {sample_id}, skipping")
                            continue
                        
                        # Extract sample hashes from overview
                        sample_info = overview.get("sample", {})
                        sample_sha1 = sample_info.get("sha1", "")
                        sample_sha256 = sample_info.get("sha256", "")
                        
                        # Check score
                        score = overview.get("analysis", {}).get("score", 0)
                        if score is None:
                            score = sample_info.get("score", 0)
                        if score is not None and score < 5:
                            logger.debug(f"Score {score} < 5 for {sample_id}, skipping")
                            continue
                        
                        # Use the already-detected OS from search, or re-detect from overview
                        detected_os = detect_os_from_overview(overview)
                        
                        if detected_os is None:
                            logger.debug(f"Could not detect OS for {sample_id}, skipping")
                            continue
                        
                        # Enforce OS selection: skip mismatches
                        if detected_os.value != os_type:
                            logger.debug(f"Sample {sample_id} is {detected_os.value}, not {os_type}; skipping")
                            continue
                        
                        logger.info(f"Extracting artifacts from {sample_id} ({detected_os.value})")
                        
                        result = extract_sample(
                            overview=overview,
                            behavioral_report=data.get("behavioral_report", {}),
                            kernel_logs=data.get("kernel_logs"),
                            os_type=detected_os,
                        )
                        
                        # Import artifacts to database - only for the requested OS
                        # result.artifacts is a dict keyed by OS
                        requested_os_key = os_type.lower()
                        other_os_artifacts = {
                            key: len(items)
                            for key, items in result.artifacts.items()
                            if key != requested_os_key and items
                        }
                        if other_os_artifacts:
                            logger.debug(
                                f"Sample {sample_id} produced artifacts for other OS: {other_os_artifacts}"
                            )

                        artifacts_for_os = result.artifacts.get(requested_os_key, [])
                        if not artifacts_for_os:
                            logger.debug(f"No {requested_os_key} artifacts found for {sample_id}")
                            continue

                        for artifact in artifacts_for_os:
                            artifact_dict = self._artifact_to_dict(
                                artifact,
                                sample_id=sample_id,
                                sample_sha1=sample_sha1,
                                sample_sha256=sample_sha256,
                            )

                            existing = app.database.get_artifact_by_id(artifact_dict["id"])

                            if existing:
                                app.database.update_artifact(artifact_dict["id"], {
                                    "confidence": max(existing["confidence"], artifact_dict["confidence"]),
                                    "sample_count": existing["sample_count"] + 1,
                                    "last_seen": datetime.now(timezone.utc).isoformat(),
                                })
                                total_updated += 1
                            else:
                                app.database.add_artifact(artifact_dict)
                                total_new += 1

                            total_artifacts += 1
                        
                        self.progress.artifacts_found = total_artifacts
                        
                    except Exception as e:
                        logger.debug(f"Error processing {sample_id}: {e}")
                        continue
                
                self.progress.os_completed = os_idx + 1
                self._notify_progress()
            
            # Update complete
            self.last_update = datetime.now(timezone.utc)
            app.database.save_setting("last_update_time", self.last_update.isoformat())
            
            self.progress.status = "complete"
            self.progress.artifacts_found = total_artifacts
            self.progress.message = f"{total_new} new, {total_updated} updated"
            self._notify_progress()
            
            logger.info(f"Update complete: {total_new} new, {total_updated} updated")
            
            # Callbacks
            self.is_running = False
            Clock.schedule_once(lambda dt: self._on_complete_main(total_new, total_updated), 0)
            
            if total_new > 0 and self._on_new_artifacts:
                Clock.schedule_once(lambda dt: self._on_new_artifacts(total_new), 0)
            
        except Exception as e:
            logger.error(f"Update failed: {e}")
            self._on_error(str(e))
    
    def _artifact_to_dict(
        self, 
        artifact, 
        sample_id: str = "",
        sample_sha1: str = "",
        sample_sha256: str = "",
    ) -> Dict[str, Any]:
        """
        Convert an Artifact model to database dict.
        
        Args:
            artifact: The Artifact model from extractor
            sample_id: Triage sample ID (e.g., "260128-abc123")
            sample_sha1: SHA1 hash of the source sample
            sample_sha256: SHA256 hash of the source sample
        """
        from extractor.models.artifact import Artifact
        
        artifact_id = f"art-{artifact.os.value}-{artifact.artifact_type.value}-{hash(artifact.match_criteria.value) & 0xFFFFFFFF:08x}"
        
        # Build Triage URL from sample ID
        triage_url = f"https://tria.ge/{sample_id}" if sample_id else ""
        
        return {
            "id": artifact_id,
            "os": artifact.os.value,
            "category": artifact.category,
            "artifact_type": artifact.artifact_type.value,
            "value": artifact.match_criteria.value,
            "match_type": artifact.match_criteria.type.value,
            "case_sensitive": artifact.match_criteria.case_sensitive,
            "confidence": artifact.provenance.confidence if artifact.provenance else 0.5,
            "sample_count": artifact.provenance.sample_count if artifact.provenance else 1,
            "privilege_level": self._determine_privilege(artifact.os.value, artifact.match_criteria.value),
            "description": artifact.metadata.description if artifact.metadata else "",
            "evasion_purpose": artifact.metadata.evasion_purpose.value if artifact.metadata and artifact.metadata.evasion_purpose else None,
            "source_sha1": sample_sha1,
            "source_sha256": sample_sha256,
            "source_sample_id": sample_id,
            "triage_url": triage_url,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
        }
    
    def _determine_privilege(self, os_type: str, value: str) -> str:
        """Determine privilege level for an artifact."""
        value_lower = value.lower()
        
        if os_type == "android":
            if value_lower.startswith(("/sdcard", "/storage")):
                return "user"
            return "root"
        elif os_type == "windows":
            if any(x in value_lower for x in ["%appdata%", "%localappdata%", "%temp%", "%userprofile%", "hkcu"]):
                return "user"
            return "admin"
        elif os_type in ("linux", "macos"):
            if value_lower.startswith(("/home", "/tmp", "~")):
                return "user"
            return "root"
        
        return "user"
    
    def _on_error(self, message: str):
        """Handle update error."""
        logger.error(f"Update error: {message}")
        self.is_running = False
        self.progress.status = "error"
        self.progress.message = message
        self._notify_progress()
        
        if self._on_update_error:
            Clock.schedule_once(lambda dt: self._on_update_error(message), 0)
    
    def _on_complete_main(self, new_count: int, updated_count: int):
        """Called on main thread when update completes."""
        if self._on_update_complete:
            self._on_update_complete()
