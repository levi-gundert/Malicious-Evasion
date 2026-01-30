#!/usr/bin/env python3
"""
Capture test fixtures from Triage API.

This script downloads JSON behavioral reports (NOT malware binaries) from
the Hatching Triage API and saves them as test fixtures.

What gets downloaded (all safe text/JSON files):
- overview.json: Sample metadata (hashes, scores, tags)
- report_triage.json: Behavioral analysis report
- Kernel logs (stahp.json/onemon.json/bigmac.json): Syscall traces

Usage:
    # Set your API key first
    export TRIAGE_API_KEY=your-api-key
    
    # Capture a specific sample
    python scripts/capture_fixtures.py --os android --sample-id abc123
    
    # Capture multiple samples
    python scripts/capture_fixtures.py --os windows --sample-id abc123 --sample-id def456
    
    # Custom output directory
    python scripts/capture_fixtures.py --os android --sample-id abc123 --out ./my-fixtures
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests

# Debug: Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Default output directory
DEFAULT_OUTPUT = Path(__file__).parent.parent / "tests" / "fixtures"

# API configuration
DEFAULT_BASE_URL = "https://private.tria.ge/api/v0"

# Kernel log filenames by OS
KERNEL_LOG_FILES = {
    "android": "stahp.json",
    "linux": "stahp.json", 
    "windows": "onemon.json",
    "macos": "bigmac.json",
}

SUPPORTED_OS = {"android", "windows", "linux", "macos"}


class TriageClient:
    """Simple Triage API client for fixture capture."""
    
    def __init__(self, api_key: str, base_url: str = DEFAULT_BASE_URL):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {api_key}"
        # Debug: Log client initialization
        logger.debug(f"TriageClient initialized with base_url: {self.base_url}")
    
    def _get(self, endpoint: str) -> requests.Response:
        """Make a GET request to the API."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        logger.debug(f"GET {url}")
        response = self.session.get(url, timeout=30)
        return response
    
    def get_sample(self, sample_id: str) -> dict[str, Any] | None:
        """Get sample metadata."""
        resp = self._get(f"/samples/{sample_id}")
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            logger.warning(f"Sample not found: {sample_id}")
            return None
        else:
            logger.error(f"Failed to get sample {sample_id}: {resp.status_code}")
            return None
    
    def get_overview(self, sample_id: str) -> dict[str, Any] | None:
        """Get overview report."""
        resp = self._get(f"/samples/{sample_id}/overview.json")
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            logger.warning(f"Overview not found for {sample_id}")
            return None
        else:
            logger.error(f"Failed to get overview for {sample_id}: {resp.status_code}")
            return None
    
    def get_behavioral_report(self, sample_id: str, task_id: str) -> dict[str, Any] | None:
        """Get behavioral report for a task."""
        resp = self._get(f"/samples/{sample_id}/{task_id}/report_triage.json")
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            logger.debug(f"Behavioral report not found: {sample_id}/{task_id}")
            return None
        else:
            logger.error(f"Failed to get behavioral report {sample_id}/{task_id}: {resp.status_code}")
            return None
    
    def get_kernel_logs(self, sample_id: str, task_id: str, os_type: str) -> dict[str, Any] | list | None:
        """Get kernel logs for a task."""
        log_file = KERNEL_LOG_FILES.get(os_type)
        if not log_file:
            logger.warning(f"Unknown kernel log for OS: {os_type}")
            return None
        
        resp = self._get(f"/samples/{sample_id}/{task_id}/logs/{log_file}")
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            logger.debug(f"Kernel logs not found: {sample_id}/{task_id}/logs/{log_file}")
            return None
        else:
            logger.error(f"Failed to get kernel logs: {resp.status_code}")
            return None


def save_json(data: Any, path: Path) -> None:
    """Save JSON data to a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved: {path}")


def capture_sample(
    client: TriageClient,
    sample_id: str,
    os_type: str,
    output_dir: Path,
    rate_limit_delay: float = 0.5
) -> bool:
    """
    Capture all fixture data for a single sample.
    
    Args:
        client: Triage API client
        sample_id: Sample ID to capture
        os_type: OS type for organizing fixtures
        output_dir: Base output directory
        rate_limit_delay: Delay between requests (seconds)
        
    Returns:
        True if at least overview was captured successfully
    """
    logger.info(f"Capturing fixtures for sample: {sample_id} (OS: {os_type})")
    
    sample_dir = output_dir / os_type / sample_id
    success = False
    
    # 1. Get overview (required)
    overview = client.get_overview(sample_id)
    if overview:
        save_json(overview, sample_dir / "overview.json")
        success = True
    else:
        logger.error(f"Failed to get overview for {sample_id}, skipping sample")
        return False
    
    time.sleep(rate_limit_delay)
    
    # 2. Get behavioral reports (behavioral1 and behavioral2)
    for task_id in ["behavioral1", "behavioral2"]:
        # Debug: Log task attempt
        logger.debug(f"Attempting to capture {task_id} for {sample_id}")
        
        report = client.get_behavioral_report(sample_id, task_id)
        if report:
            task_dir = sample_dir / task_id
            save_json(report, task_dir / "report_triage.json")
            
            time.sleep(rate_limit_delay)
            
            # 3. Get kernel logs for this task
            logs = client.get_kernel_logs(sample_id, task_id, os_type)
            if logs:
                log_file = KERNEL_LOG_FILES[os_type]
                save_json(logs, task_dir / "logs" / log_file)
        
        time.sleep(rate_limit_delay)
    
    return success


def detect_os_from_overview(overview: dict[str, Any]) -> str | None:
    """Try to detect OS type from overview report."""
    # Check analysis tags
    analysis = overview.get("analysis", {})
    tags = analysis.get("tags", [])
    
    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower in SUPPORTED_OS:
            return tag_lower
    
    # Check tasks
    tasks = overview.get("tasks", [])
    for task in tasks:
        platform = task.get("platform", "").lower()
        if platform in SUPPORTED_OS:
            return platform
        # Check task tags too
        task_tags = task.get("tags", [])
        for tag in task_tags:
            tag_lower = tag.lower()
            if tag_lower in SUPPORTED_OS:
                return tag_lower
    
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture test fixtures from Triage API (JSON reports, NOT malware)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--os",
        choices=sorted(SUPPORTED_OS),
        help="OS type for the sample(s). If not specified, will try to auto-detect."
    )
    parser.add_argument(
        "--sample-id", "-s",
        action="append",
        dest="sample_ids",
        required=True,
        help="Sample ID to capture (can be repeated for multiple samples)"
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})"
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Triage API base URL (default: {DEFAULT_BASE_URL})"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between API requests in seconds (default: 0.5)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get API key
    api_key = os.environ.get("TRIAGE_API_KEY")
    if not api_key:
        logger.error("TRIAGE_API_KEY environment variable not set")
        print("\nPlease set your Triage API key:")
        print("  export TRIAGE_API_KEY=your-api-key")
        return 1
    
    # Debug: Log configuration
    logger.debug(f"Configuration: os={args.os}, samples={args.sample_ids}, out={args.out}")
    
    client = TriageClient(api_key, args.base_url)
    
    captured = 0
    failed = 0
    
    for sample_id in args.sample_ids:
        os_type = args.os
        
        # Auto-detect OS if not specified
        if not os_type:
            logger.info(f"Auto-detecting OS for sample {sample_id}...")
            overview = client.get_overview(sample_id)
            if overview:
                os_type = detect_os_from_overview(overview)
                if os_type:
                    logger.info(f"Detected OS: {os_type}")
                else:
                    logger.error(f"Could not detect OS for {sample_id}, use --os flag")
                    failed += 1
                    continue
            else:
                logger.error(f"Could not fetch overview for {sample_id}")
                failed += 1
                continue
        
        if capture_sample(client, sample_id, os_type, args.out, args.delay):
            captured += 1
        else:
            failed += 1
    
    print(f"\n{'='*50}")
    print(f"Capture complete: {captured} succeeded, {failed} failed")
    print(f"Fixtures saved to: {args.out}")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
