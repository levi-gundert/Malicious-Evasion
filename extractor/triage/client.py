"""
Triage API client with rate limiting and error handling.

Supports both public API (api.tria.ge) and private cloud (private.tria.ge).
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


# =============================================================================
# OS Inference from File Extension
# =============================================================================

# File extension to OS mapping
# Based on common malware file types per platform
FILE_EXTENSION_TO_OS = {
    # Android
    ".apk": "android",
    ".aab": "android",  # Android App Bundle
    ".dex": "android",
    
    # Windows
    ".exe": "windows",
    ".dll": "windows",
    ".msi": "windows",
    ".scr": "windows",  # Screensaver (often used by malware)
    ".sys": "windows",  # Driver
    ".cpl": "windows",  # Control Panel
    ".ocx": "windows",  # ActiveX
    ".drv": "windows",  # Driver
    ".bat": "windows",
    ".cmd": "windows",
    ".ps1": "windows",  # PowerShell
    ".vbs": "windows",  # VBScript
    ".js": "windows",   # JScript (Windows context)
    ".hta": "windows",  # HTML Application
    ".lnk": "windows",  # Shortcut
    
    # macOS
    ".dmg": "macos",
    ".pkg": "macos",
    ".app": "macos",
    ".command": "macos",
    
    # Linux (note: many Linux binaries have no extension)
    ".elf": "linux",
    ".so": "linux",
    ".deb": "linux",
    ".rpm": "linux",
    ".sh": "linux",
}

# Platform string patterns in Triage task data
# Maps platform substrings to OS types
PLATFORM_PATTERNS = {
    "android": "android",
    "windows": "windows",
    "win7": "windows",
    "win10": "windows",
    "win11": "windows",
    "linux": "linux",
    "ubuntu": "linux",
    "debian": "linux",
    "centos": "linux",
    "macos": "macos",
    "darwin": "macos",
    "osx": "macos",
}


def infer_os_from_filename(filename: str) -> str | None:
    """
    Infer OS type from filename extension.
    
    Args:
        filename: The target filename (e.g., "malware.apk", "trojan.exe")
        
    Returns:
        OS type string ("android", "windows", "linux", "macos") or None if unknown
    """
    if not filename:
        logger.debug("infer_os_from_filename: empty filename")
        return None
    
    # Normalize and get extension
    filename_lower = filename.lower()
    
    # Try each extension mapping
    for ext, os_type in FILE_EXTENSION_TO_OS.items():
        if filename_lower.endswith(ext):
            logger.debug(f"infer_os_from_filename: '{filename}' -> {os_type} (matched {ext})")
            return os_type
    
    logger.debug(f"infer_os_from_filename: '{filename}' -> None (no extension match)")
    return None


def infer_os_from_platform(platform: str) -> str | None:
    """
    Infer OS type from Triage platform string.
    
    Args:
        platform: Platform string from task data (e.g., "windows10_x64", "android-11-x64")
        
    Returns:
        OS type string or None if unknown
    """
    if not platform:
        return None
    
    platform_lower = platform.lower()
    
    for pattern, os_type in PLATFORM_PATTERNS.items():
        if pattern in platform_lower:
            logger.debug(f"infer_os_from_platform: '{platform}' -> {os_type} (matched {pattern})")
            return os_type
    
    logger.debug(f"infer_os_from_platform: '{platform}' -> None (no pattern match)")
    return None


def infer_os_from_sample(sample_data: dict[str, Any]) -> str | None:
    """
    Infer OS type from sample data using multiple strategies.
    
    Tries in order:
    1. Task platform/os field (most reliable when available)
    2. Target filename extension
    3. Analysis tags
    
    Args:
        sample_data: Sample or overview data from Triage API
        
    Returns:
        OS type string or None if cannot be determined
    """
    # Strategy 1: Check tasks for platform/os field
    tasks = sample_data.get("tasks", {})
    if isinstance(tasks, dict):
        for task_id, task_info in tasks.items():
            if isinstance(task_info, dict):
                # Check 'os' field (e.g., "android-11-x64")
                os_field = task_info.get("os", "")
                os_type = infer_os_from_platform(os_field)
                if os_type:
                    logger.debug(f"infer_os_from_sample: found OS from task.os: {os_type}")
                    return os_type
                
                # Check 'platform' field (e.g., "windows10_x64")
                platform_field = task_info.get("platform", "")
                os_type = infer_os_from_platform(platform_field)
                if os_type:
                    logger.debug(f"infer_os_from_sample: found OS from task.platform: {os_type}")
                    return os_type
    
    # Strategy 2: Check target filename extension
    # Try multiple locations where filename might be
    # NOTE: Search results have 'filename' key directly, overview has 'target'/'sample.target'
    filename = (
        sample_data.get("filename") or  # Search results have this key
        sample_data.get("target") or
        sample_data.get("sample", {}).get("target") or
        sample_data.get("sample", {}).get("name") or
        ""
    )
    os_type = infer_os_from_filename(filename)
    if os_type:
        logger.debug(f"infer_os_from_sample: found OS from filename '{filename}': {os_type}")
        return os_type
    
    # Strategy 3: Check analysis tags
    analysis_tags = sample_data.get("analysis", {}).get("tags", [])
    for tag in analysis_tags:
        tag_lower = tag.lower()
        if "android" in tag_lower:
            logger.debug("infer_os_from_sample: found 'android' in analysis tags")
            return "android"
        if "windows" in tag_lower:
            logger.debug("infer_os_from_sample: found 'windows' in analysis tags")
            return "windows"
        if "linux" in tag_lower:
            logger.debug("infer_os_from_sample: found 'linux' in analysis tags")
            return "linux"
        if "macos" in tag_lower:
            logger.debug("infer_os_from_sample: found 'macos' in analysis tags")
            return "macos"
    
    # Strategy 4: Check sample-level tags
    sample_tags = sample_data.get("sample", {}).get("tags", [])
    for tag in sample_tags:
        tag_lower = tag.lower()
        if "android" in tag_lower or "apk" in tag_lower:
            return "android"
        if "windows" in tag_lower or "pe" in tag_lower:
            return "windows"
        if "linux" in tag_lower or "elf" in tag_lower:
            return "linux"
        if "macos" in tag_lower or "mach-o" in tag_lower:
            return "macos"
    
    logger.debug("infer_os_from_sample: could not determine OS")
    return None


class TriageAPIError(Exception):
    """Base exception for Triage API errors."""
    
    def __init__(self, message: str, status_code: int | None = None, response: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class RateLimitError(TriageAPIError):
    """Raised when rate limit is exceeded."""
    pass


class AuthenticationError(TriageAPIError):
    """Raised when authentication fails."""
    pass


class NotFoundError(TriageAPIError):
    """Raised when a resource is not found."""
    pass


@dataclass
class RateLimiter:
    """
    Simple rate limiter using token bucket algorithm.
    
    Default: 20 requests per minute (Triage API limit).
    """
    requests_per_minute: int = 20
    _tokens: float = field(default=20.0, init=False)
    _last_update: float = field(default_factory=time.time, init=False)
    
    def acquire(self) -> None:
        """
        Acquire a token, waiting if necessary.
        
        Blocks until a token is available.
        """
        now = time.time()
        elapsed = now - self._last_update
        
        # Refill tokens based on elapsed time
        refill = elapsed * (self.requests_per_minute / 60.0)
        self._tokens = min(self.requests_per_minute, self._tokens + refill)
        self._last_update = now
        
        if self._tokens < 1:
            # Wait for a token
            wait_time = (1 - self._tokens) * (60.0 / self.requests_per_minute)
            logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)
            self._tokens = 1
            self._last_update = time.time()
        
        self._tokens -= 1


class TriageClient:
    """
    Client for the Hatching Triage API.
    
    Handles:
    - Authentication
    - Rate limiting
    - Retries with exponential backoff
    - Error handling
    
    Example:
        client = TriageClient(api_key="your-key")
        # Search for evasion samples
        for sample in client.search_evasion_samples():
            print(f"Sample: {sample['id']}, OS: {sample.get('inferred_os')}")
    """
    
    # Known API base URLs
    PUBLIC_API = "https://api.tria.ge/v0"
    PRIVATE_API = "https://private.tria.ge/api/v0"
    
    # Kernel log filenames by OS
    KERNEL_LOGS = {
        "android": "stahp.json",
        "linux": "stahp.json",
        "windows": "onemon.json",
        "macos": "bigmac.json",
    }
    
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        use_private_cloud: bool = True,
        requests_per_minute: int = 20,
        timeout: int = 30,
        max_retries: int = 3,
        use_cache: bool = True,
    ):
        """
        Initialize the Triage client.
        
        Args:
            api_key: Triage API key (or TRIAGE_API_KEY env var)
            base_url: API base URL (overrides use_private_cloud if set)
            use_private_cloud: If True, use private.tria.ge; else use api.tria.ge
            requests_per_minute: Rate limit (default 20/min)
            timeout: Request timeout in seconds
            max_retries: Max retries for failed requests
            use_cache: Whether to use SQLite response cache
        """
        # Get API key from param or environment
        self.api_key = api_key or os.environ.get("TRIAGE_API_KEY")
        if not self.api_key:
            raise ValueError(
                "API key required. Set TRIAGE_API_KEY environment variable "
                "or pass api_key parameter."
            )
        
        # Base URL - configurable between public and private cloud
        if base_url:
            self.base_url = base_url
            logger.debug(f"Using custom base URL: {base_url}")
        elif use_private_cloud:
            self.base_url = self.PRIVATE_API
            logger.debug("Using private cloud API")
        else:
            self.base_url = self.PUBLIC_API
            logger.debug("Using public cloud API")
        
        self.timeout = timeout
        
        # Rate limiter
        self.rate_limiter = RateLimiter(requests_per_minute=requests_per_minute)
        
        # Initialize cache
        self.cache = None
        if use_cache:
            try:
                from extractor.triage.cache import TriageCache
                self.cache = TriageCache()
                logger.debug("API response cache enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize cache: {e}")
        
        # Set up session with retries
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "User-Agent": "TriageArtifactExtractor/1.0",
        })
        
        # Configure retries for transient errors
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        
        logger.info(f"Triage client initialized: {self.base_url}")
    
    def _request(
        self,
        method: str,
        endpoint: str,
        params: dict | None = None,
        **kwargs,
    ) -> requests.Response:
        """
        Make an API request with rate limiting and error handling.
        
        Args:
            method: HTTP method
            endpoint: API endpoint (relative to base_url)
            params: Query parameters
            **kwargs: Additional requests kwargs
            
        Returns:
            Response object
            
        Raises:
            TriageAPIError: On API error
        """
        # Apply rate limiting
        self.rate_limiter.acquire()
        
        url = f"{self.base_url}{endpoint}"
        
        logger.debug(f"{method} {url}")
        
        try:
            response = self.session.request(
                method,
                url,
                params=params,
                timeout=self.timeout,
                **kwargs,
            )
        except requests.exceptions.Timeout:
            raise TriageAPIError(f"Request timed out: {url}")
        except requests.exceptions.ConnectionError as e:
            raise TriageAPIError(f"Connection error: {e}")
        
        # Handle errors
        if response.status_code == 401:
            raise AuthenticationError(
                "Authentication failed. Check your API key.",
                status_code=401,
            )
        
        if response.status_code == 403:
            raise AuthenticationError(
                "Access forbidden. Your API key may not have permission.",
                status_code=403,
            )
        
        if response.status_code == 404:
            raise NotFoundError(
                f"Resource not found: {endpoint}",
                status_code=404,
            )
        
        if response.status_code == 429:
            raise RateLimitError(
                "Rate limit exceeded. Try again later.",
                status_code=429,
            )
        
        if response.status_code >= 400:
            try:
                error_data = response.json()
            except Exception:
                error_data = {"raw": response.text}
            
            raise TriageAPIError(
                f"API error {response.status_code}: {response.text[:200]}",
                status_code=response.status_code,
                response=error_data,
            )
        
        return response
    
    def _get_json(self, endpoint: str, params: dict | None = None) -> dict[str, Any]:
        """Make a GET request and return JSON."""
        response = self._request("GET", endpoint, params=params)
        return response.json()
    
    # =========================================================================
    # Search
    # =========================================================================
    
    def search(
        self,
        query: str,
        limit: int = 50,
    ) -> Iterator[dict[str, Any]]:
        """
        Search for samples matching a query.
        
        Args:
            query: Search query (e.g., "tag:android")
            limit: Maximum results to return
            
        Yields:
            Sample dicts from search results
        """
        logger.info(f"Searching: {query} (limit={limit})")
        
        offset = 0
        returned = 0
        
        while returned < limit:
            try:
                data = self._get_json("/search", params={
                    "query": query,
                    "offset": offset,
                })
            except NotFoundError:
                # Empty results
                break
            
            samples = data.get("data", [])
            if not samples:
                break
            
            for sample in samples:
                if returned >= limit:
                    break
                yield sample
                returned += 1
            
            # Check for more results
            if len(samples) < 50:  # Default page size
                break
            
            offset += len(samples)
        
        logger.info(f"Search returned {returned} samples")
    
    def search_evasion_samples(
        self,
        os_filter: str | list[str] | None = None,
        limit: int = 50,
        fetch_overview: bool = False,
        max_search: int = 500,
    ) -> Iterator[dict[str, Any]]:
        """
        Search for samples with evasion behavior (tag:evasion).
        
        This is the primary search method for finding malware samples with
        anti-analysis/evasion techniques. Since Triage doesn't have an OS filter
        in the search API, we search for tag:evasion and infer OS from:
        1. The task platform/os field
        2. The target filename extension
        3. Analysis tags
        
        Args:
            os_filter: Optional OS filter - "android", "windows", "linux", "macos"
                       or list of OS types. Samples not matching are skipped.
            limit: Maximum number of samples to return
            fetch_overview: If True, fetch full overview for each sample
                           (slower but provides more accurate OS detection)
            max_search: Maximum samples to search through when filtering by OS.
                       This allows finding rare OS types (e.g., Linux) by searching
                       deeper into the results. Default 500.
            
        Yields:
            Sample dicts with added 'inferred_os' field
            
        Example:
            # Get all evasion samples
            for sample in client.search_evasion_samples(limit=100):
                print(f"{sample['id']}: {sample['inferred_os']}")
            
            # Get only Windows evasion samples  
            for sample in client.search_evasion_samples(os_filter="windows"):
                print(sample['id'])
            
            # Search deeper to find rare Linux samples
            for sample in client.search_evasion_samples(os_filter="linux", max_search=1000):
                print(sample['id'])
        """
        # Normalize OS filter to a set for fast lookup
        os_filter_set: set[str] | None = None
        if os_filter:
            if isinstance(os_filter, str):
                os_filter_set = {os_filter.lower()}
            else:
                os_filter_set = {os.lower() for os in os_filter}
            logger.info(f"Searching for evasion samples, OS filter: {os_filter_set}, max_search: {max_search}")
        else:
            logger.info(f"Searching for all evasion samples (no OS filter)")
        
        # Build search query based on OS filter
        # For rare OS types (Linux, macOS), use tag:evasion AND tag:<os> for better results
        # The generic tag:evasion search is dominated by Android (~72%) and Windows (~28%)
        if os_filter_set and len(os_filter_set) == 1:
            os_type = list(os_filter_set)[0]
            if os_type in ("linux", "macos"):
                # Use combined tag search for rare OS types
                query = f"tag:evasion AND tag:{os_type}"
                logger.info(f"Using targeted search for rare OS: {query}")
            else:
                query = "tag:evasion"
        else:
            query = "tag:evasion"
        
        logger.debug(f"Executing search query: {query}")
        
        returned = 0
        searched = 0
        skipped_no_os = 0
        skipped_os_filter = 0
        
        # Calculate search limit: if filtering by OS, search deeper to find matches
        # For rare OS types like Linux, we need to search through many more samples
        search_limit = max_search if os_filter_set else limit * 2
        
        for sample in self.search(query, limit=search_limit):
            searched += 1
            
            # Stop if we've found enough matching samples
            if returned >= limit:
                break
            
            sample_id = sample.get("id")
            if not sample_id:
                continue
            
            # Infer OS from the search result data
            # Search results have limited data, so we may need the overview
            inferred_os = infer_os_from_sample(sample)
            
            # If we couldn't infer OS and fetch_overview is enabled, get full data
            if inferred_os is None and fetch_overview:
                logger.debug(f"Fetching overview for {sample_id} to determine OS")
                try:
                    overview = self.get_overview(sample_id)
                    inferred_os = infer_os_from_sample(overview)
                except TriageAPIError as e:
                    logger.warning(f"Failed to fetch overview for {sample_id}: {e}")
            
            # Skip if we still can't determine OS (unless no filter)
            if inferred_os is None:
                skipped_no_os += 1
                logger.debug(f"Could not infer OS for {sample_id}, skipping")
                continue
            
            # Apply OS filter if specified
            if os_filter_set and inferred_os not in os_filter_set:
                skipped_os_filter += 1
                # Log periodically to show search progress for rare OS types
                if skipped_os_filter % 50 == 0:
                    logger.info(f"Searched {searched} samples, found {returned}/{limit} {os_filter} matches so far...")
                logger.debug(f"Sample {sample_id} is {inferred_os}, not in filter {os_filter_set}")
                continue
            
            # Add inferred OS to sample data for downstream use
            sample["inferred_os"] = inferred_os
            
            returned += 1
            yield sample
        
        # Log summary
        logger.info(
            f"Evasion search complete: searched={searched}, returned={returned}, "
            f"skipped_no_os={skipped_no_os}, skipped_os_filter={skipped_os_filter}"
        )
    
    def search_evasion_samples_by_os(
        self,
        limit_per_os: int = 20,
        os_types: list[str] | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Search for evasion samples and group by OS type.
        
        Convenience method that searches for tag:evasion and groups results
        by inferred OS type.
        
        Args:
            limit_per_os: Maximum samples per OS type
            os_types: List of OS types to include (default: all)
            
        Returns:
            Dict mapping OS type to list of samples
            
        Example:
            samples_by_os = client.search_evasion_samples_by_os(limit_per_os=10)
            print(f"Android: {len(samples_by_os['android'])} samples")
            print(f"Windows: {len(samples_by_os['windows'])} samples")
        """
        if os_types is None:
            os_types = ["android", "windows", "linux", "macos"]
        
        result: dict[str, list[dict[str, Any]]] = {os: [] for os in os_types}
        
        logger.info(f"Searching for evasion samples, grouping by OS: {os_types}")
        
        # Calculate total limit based on desired per-OS limit
        total_limit = limit_per_os * len(os_types) * 2  # Over-fetch to get better coverage
        
        for sample in self.search_evasion_samples(limit=total_limit):
            os_type = sample.get("inferred_os")
            
            if os_type and os_type in result:
                if len(result[os_type]) < limit_per_os:
                    result[os_type].append(sample)
            
            # Check if we've filled all buckets
            if all(len(samples) >= limit_per_os for samples in result.values()):
                break
        
        # Log summary
        for os_type, samples in result.items():
            logger.info(f"Found {len(samples)} {os_type} evasion samples")
        
        return result
    
    # =========================================================================
    # Sample Data
    # =========================================================================
    
    def get_sample(self, sample_id: str) -> dict[str, Any]:
        """
        Get sample metadata.
        
        Args:
            sample_id: Sample ID
            
        Returns:
            Sample metadata dict
        """
        logger.debug(f"Fetching sample: {sample_id}")
        return self._get_json(f"/samples/{sample_id}")
    
    # Maximum time for overview download (seconds) - usually fast but protect against hangs
    MAX_OVERVIEW_TIME = 15
    
    def get_overview(self, sample_id: str) -> dict[str, Any] | None:
        """
        Get sample overview (detailed analysis summary) with timeout protection.
        
        Args:
            sample_id: Sample ID
            
        Returns:
            Overview dict, or None if timeout/error
        """
        # Check cache first
        if self.cache:
            cached = self.cache.get_overview(sample_id)
            if cached:
                logger.debug(f"Cache hit for overview: {sample_id}")
                return cached
        
        logger.debug(f"Fetching overview: {sample_id}")
        
        # Use thread-based timeout to prevent hangs
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
        
        def fetch_with_timeout():
            return self._get_json(f"/samples/{sample_id}/overview.json")
        
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(fetch_with_timeout)
                try:
                    data = future.result(timeout=self.MAX_OVERVIEW_TIME)
                except FuturesTimeoutError:
                    logger.warning(
                        f"Overview timeout ({self.MAX_OVERVIEW_TIME}s), skipping: {sample_id}"
                    )
                    future.cancel()
                    return None
            
            # Store in cache
            if self.cache and data:
                self.cache.set_overview(sample_id, data)
            
            return data
        except NotFoundError:
            logger.debug(f"Overview not found: {sample_id}")
            return None
        except TriageAPIError as e:
            logger.warning(f"Failed to get overview for {sample_id}: {e}")
            return None
    
    # Maximum time for behavioral report download (seconds)
    MAX_BEHAVIORAL_REPORT_TIME = 20
    
    def get_behavioral_report(
        self,
        sample_id: str,
        task_id: str = "behavioral1",
    ) -> dict[str, Any] | None:
        """
        Get behavioral analysis report with timeout protection.
        
        Args:
            sample_id: Sample ID
            task_id: Task ID (default: behavioral1)
            
        Returns:
            Behavioral report dict, or None if timeout/error
        """
        # Check cache first
        if self.cache:
            cached = self.cache.get_behavioral(sample_id, task_id)
            if cached:
                logger.debug(f"Cache hit for behavioral: {sample_id}/{task_id}")
                return cached
        
        logger.debug(f"Fetching behavioral report: {sample_id}/{task_id}")
        
        # Use thread-based timeout to handle slow/hanging downloads
        # Some behavioral reports are very large and can hang the update
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
        
        def fetch_with_timeout():
            """Fetch behavioral report with proper timeout."""
            return self._get_json(f"/samples/{sample_id}/{task_id}/report_triage.json")
        
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(fetch_with_timeout)
                try:
                    data = future.result(timeout=self.MAX_BEHAVIORAL_REPORT_TIME)
                except FuturesTimeoutError:
                    logger.warning(
                        f"Behavioral report timeout ({self.MAX_BEHAVIORAL_REPORT_TIME}s), skipping: {sample_id}/{task_id}"
                    )
                    future.cancel()
                    return None
            
            # Store in cache
            if self.cache and data:
                self.cache.set_behavioral(sample_id, task_id, data)
            
            return data
        except NotFoundError:
            logger.debug(f"Behavioral report not found: {sample_id}/{task_id}")
            return None
        except TriageAPIError as e:
            logger.warning(f"Failed to get behavioral report for {sample_id}: {e}")
            return None
    
    # Maximum size for kernel logs (100MB) - larger files cause memory/performance issues
    MAX_KERNEL_LOG_SIZE = 100 * 1024 * 1024  # 100MB
    
    def get_kernel_logs(
        self,
        sample_id: str,
        task_id: str = "behavioral1",
        os_type: str = "android",
    ) -> list[dict[str, Any]] | None:
        """
        Get kernel logs for a sample.
        
        Args:
            sample_id: Sample ID
            task_id: Task ID (default: behavioral1)
            os_type: OS type for selecting log file
            
        Returns:
            List of kernel log entries, or None if not available
        """
        log_file = self.KERNEL_LOGS.get(os_type.lower())
        if not log_file:
            logger.warning(f"No kernel log mapping for OS: {os_type}")
            return None
        
        # Check cache first
        if self.cache:
            cached = self.cache.get_kernel_logs(sample_id, task_id, os_type)
            if cached:
                logger.debug(f"Cache hit for kernel logs: {sample_id}/{task_id}/{os_type}")
                # Handle both list and dict formats
                if isinstance(cached, list):
                    return cached
                return cached.get("entries", cached.get("logs", []))
        
        logger.debug(f"Fetching kernel logs: {sample_id}/{task_id}/logs/{log_file}")
        
        # Check content-length first to avoid downloading huge files
        endpoint = f"/samples/{sample_id}/{task_id}/logs/{log_file}"
        size_known = False
        try:
            self.rate_limiter.acquire()
            head_response = self.session.head(
                f"{self.base_url}{endpoint}",
                timeout=10,
            )
            content_length = int(head_response.headers.get("Content-Length", 0))
            if content_length > self.MAX_KERNEL_LOG_SIZE:
                logger.warning(
                    f"Kernel logs too large ({content_length / 1024 / 1024:.1f}MB > "
                    f"{self.MAX_KERNEL_LOG_SIZE / 1024 / 1024:.0f}MB limit), skipping: {sample_id}"
                )
                return None
            size_known = content_length > 0
        except Exception as e:
            # If HEAD fails, continue with GET but use streaming to check size
            logger.debug(f"HEAD request failed, will use streaming GET: {e}")
        
        try:
            # Use thread-based timeout to handle slow/hanging downloads
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
            
            def fetch_with_timeout():
                """Fetch kernel logs with proper timeout handling."""
                self.rate_limiter.acquire()
                resp = self.session.get(
                    f"{self.base_url}{endpoint}",
                    timeout=(5, 10),  # (connect, read) timeouts
                )
                resp.raise_for_status()
                return resp.text
            
            # Use thread pool with hard timeout - this actually kills hung downloads
            max_download_time = 15  # 15 seconds max
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(fetch_with_timeout)
                try:
                    text = future.result(timeout=max_download_time)
                    logger.debug(f"Downloaded kernel logs for {sample_id}")
                except FuturesTimeoutError:
                    logger.warning(
                        f"Kernel logs download timeout ({max_download_time}s), skipping: {sample_id}"
                    )
                    future.cancel()
                    return None
            
            # Parse the response
            text = text.strip()
            if not text:
                return None
            
            try:
                data = json.loads(text)
            except ValueError:
                # Some kernel logs are NDJSON (one JSON object per line)
                entries = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse kernel log line for {sample_id}: {e}")
                        return None
                data = entries
            
            # Store in cache (as raw response)
            if self.cache and data:
                self.cache.set_kernel_logs(sample_id, task_id, os_type, data)
            
            # Kernel logs may be a list or wrapped in a dict
            if isinstance(data, list):
                return data
            return data.get("entries", data.get("logs", []))
        except NotFoundError:
            logger.debug(f"Kernel logs not available for {sample_id}")
            return None
    
    # =========================================================================
    # Convenience Methods
    # =========================================================================
    
    def fetch_sample_data(
        self,
        sample_id: str,
        include_kernel_logs: bool = True,
        target_os: str | None = None,
    ) -> dict[str, Any]:
        """
        Fetch all data for a sample in one call.
        
        Args:
            sample_id: Sample ID
            include_kernel_logs: Whether to fetch kernel logs
            target_os: Target OS type to fetch data for. If provided, will find
                      the behavioral task that matches this OS (important for
                      multi-platform samples like those with both Linux and Windows tasks).
            
        Returns:
            Dict with overview, behavioral report, and optionally kernel logs
        """
        logger.info(f"Fetching full data for sample: {sample_id}")
        
        result = {
            "sample_id": sample_id,
            "overview": None,
            "behavioral_report": None,
            "kernel_logs": None,
        }
        
        # Fetch overview - now handles timeout internally and returns None on failure
        result["overview"] = self.get_overview(sample_id)
        
        # If overview failed (timeout or error), we can't proceed
        if result["overview"] is None:
            logger.warning(f"Could not fetch overview for {sample_id}, skipping")
            return result
        
        # Detect OS from overview (or use target_os if provided)
        os_type = target_os or self._detect_os(result["overview"])
        result["os_type"] = os_type
        
        # Find the correct behavioral task for the target OS
        # Multi-platform samples may have behavioral1 on Windows but behavioral7 on Linux
        task_id = self._find_behavioral_task_for_os(result["overview"], os_type)
        logger.debug(f"Using behavioral task {task_id} for OS {os_type}")
        
        # Fetch behavioral report from the correct task
        try:
            result["behavioral_report"] = self.get_behavioral_report(sample_id, task_id)
        except NotFoundError:
            logger.debug(f"No behavioral report for {sample_id}/{task_id}")
        except TriageAPIError as e:
            logger.warning(f"Failed to get behavioral report: {e}")
        
        # Fetch kernel logs from the correct task
        if include_kernel_logs and os_type:
            result["kernel_logs"] = self.get_kernel_logs(sample_id, task_id, os_type=os_type)
        
        return result
    
    def _find_behavioral_task_for_os(
        self,
        overview: dict[str, Any],
        target_os: str | None,
    ) -> str:
        """
        Find the behavioral task ID that matches the target OS.
        
        Multi-platform samples in Triage may have tasks like:
        - behavioral1: windows7-x64
        - behavioral7: ubuntu-18.04-amd64
        - behavioral8: debian-9-armhf
        
        This method finds the first behavioral task matching the target OS.
        
        Args:
            overview: Sample overview data
            target_os: Target OS type (linux, windows, android, macos)
            
        Returns:
            Task ID suffix like "behavioral1" or "behavioral7"
        """
        if not target_os:
            return "behavioral1"
        
        tasks = overview.get("tasks", {})
        
        for task_id, task_info in tasks.items():
            if not isinstance(task_info, dict):
                continue
            
            # Only consider behavioral tasks
            if task_info.get("kind") != "behavioral":
                continue
            
            # Check if this task's OS matches our target
            task_os = task_info.get("os", "")
            inferred = infer_os_from_platform(task_os)
            
            if inferred == target_os:
                # Extract task suffix (e.g., "behavioral7" from "260129-xxx-behavioral7")
                task_suffix = task_id.split("-")[-1]
                logger.debug(f"Found matching task for {target_os}: {task_suffix} (os={task_os})")
                return task_suffix
        
        # Fallback to behavioral1
        logger.debug(f"No task found for OS {target_os}, falling back to behavioral1")
        return "behavioral1"
    
    def _detect_os(self, overview: dict[str, Any]) -> str | None:
        """
        Detect OS type from overview data.
        
        Uses the robust infer_os_from_sample function which checks:
        1. Task platform/os fields
        2. Target filename extension
        3. Analysis tags
        4. Sample tags
        
        Args:
            overview: Sample overview data from Triage
            
        Returns:
            OS type string or None if cannot be determined
        """
        return infer_os_from_sample(overview)
    
    def test_connection(self) -> bool:
        """
        Test the API connection.
        
        Returns:
            True if connection successful
        """
        try:
            # Try a simple search to verify authentication
            list(self.search("tag:android", limit=1))
            logger.info("API connection successful")
            return True
        except AuthenticationError:
            logger.error("Authentication failed")
            return False
        except TriageAPIError as e:
            logger.error(f"API error: {e}")
            return False
