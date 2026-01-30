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
        samples = client.search("tag:android AND score:>=7")
        for sample in samples:
            overview = client.get_overview(sample["id"])
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
        requests_per_minute: int = 20,
        timeout: int = 30,
        max_retries: int = 3,
        use_cache: bool = True,
    ):
        """
        Initialize the Triage client.
        
        Args:
            api_key: Triage API key (or TRIAGE_API_KEY env var)
            base_url: API base URL (auto-detected if None)
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
        
        # Base URL - try private cloud first since user has private key
        self.base_url = base_url or self.PRIVATE_API
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
    
    # Search queries by OS type
    # Windows samples are found via malware family names and behavior tags
    # Android samples use the "android" tag
    # Linux/macOS samples also need specific queries
    OS_SEARCH_QUERIES = {
        "android": [
            "tag:android",
        ],
        "windows": [
            # Known Windows malware families
            "family:emotet",
            "family:remcos",
            "family:redline",
            "family:lokibot",
            "family:formbook",
            "family:asyncrat",
            "family:njrat",
            "family:agenttesla",
            "family:raccoon",
            "family:vidar",
            "family:quasar",
            # Behavior-based tags
            "tag:stealer",
            "tag:ransomware",
            "tag:loader",
            "tag:rat",
        ],
        "linux": [
            "tag:linux",
            "tag:elf",
            "family:mirai",
            "family:gafgyt",
        ],
        "macos": [
            "tag:macos",
            "tag:mach-o",
        ],
    }
    
    def search_evasion_samples(
        self,
        os_type: str,
        min_score: int = 5,
        days: int = 7,
        limit: int = 20,
        include_evasion_tag: bool = True,
    ) -> Iterator[dict[str, Any]]:
        """
        Search for samples with evasion behavior.
        
        Note: Score is NOT available in search results, only in overview.
        The min_score parameter is documented but cannot be applied here.
        Filtering by score should happen after fetching the overview.
        
        Args:
            os_type: OS to search (android, windows, linux, macos)
            min_score: Minimum score threshold (for documentation only)
            days: Look back period in days
            limit: Maximum results
            include_evasion_tag: Also search for "tag:evasion" samples
            
        Yields:
            Sample dicts from search results
        """
        seen_ids = set()
        os_type_lower = os_type.lower()
        
        # Get search queries for this OS
        queries = self.OS_SEARCH_QUERIES.get(os_type_lower, [f"tag:{os_type_lower}"])
        
        logger.info(f"Searching for {os_type} samples using {len(queries)} queries (limit={limit})")
        
        # Calculate limit per query to avoid over-fetching
        # but ensure we get enough results
        per_query_limit = max(limit // len(queries), 5) if queries else limit
        
        for query in queries:
            if len(seen_ids) >= limit:
                break
            
            logger.debug(f"Running query: {query}")
            
            try:
                for sample in self.search(query, limit=per_query_limit):
                    sample_id = sample.get("id")
                    if sample_id and sample_id not in seen_ids:
                        seen_ids.add(sample_id)
                        yield sample
                        
                        if len(seen_ids) >= limit:
                            break
            except TriageAPIError as e:
                logger.warning(f"Query '{query}' failed: {e}")
                continue
        
        # Also search for samples tagged with "evasion"
        if include_evasion_tag and len(seen_ids) < limit:
            logger.debug("Searching for evasion-tagged samples")
            
            try:
                for sample in self.search("tag:evasion", limit=limit - len(seen_ids)):
                    sample_id = sample.get("id")
                    if sample_id and sample_id not in seen_ids:
                        seen_ids.add(sample_id)
                        yield sample
            except TriageAPIError:
                pass
        
        logger.info(f"Found {len(seen_ids)} unique samples for {os_type}")
    
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
    
    def get_overview(self, sample_id: str) -> dict[str, Any]:
        """
        Get sample overview (detailed analysis summary).
        
        Args:
            sample_id: Sample ID
            
        Returns:
            Overview dict
        """
        # Check cache first
        if self.cache:
            cached = self.cache.get_overview(sample_id)
            if cached:
                logger.debug(f"Cache hit for overview: {sample_id}")
                return cached
        
        logger.debug(f"Fetching overview: {sample_id}")
        data = self._get_json(f"/samples/{sample_id}/overview.json")
        
        # Store in cache
        if self.cache and data:
            self.cache.set_overview(sample_id, data)
        
        return data
    
    def get_behavioral_report(
        self,
        sample_id: str,
        task_id: str = "behavioral1",
    ) -> dict[str, Any]:
        """
        Get behavioral analysis report.
        
        Args:
            sample_id: Sample ID
            task_id: Task ID (default: behavioral1)
            
        Returns:
            Behavioral report dict
        """
        # Check cache first
        if self.cache:
            cached = self.cache.get_behavioral(sample_id, task_id)
            if cached:
                logger.debug(f"Cache hit for behavioral: {sample_id}/{task_id}")
                return cached
        
        logger.debug(f"Fetching behavioral report: {sample_id}/{task_id}")
        data = self._get_json(f"/samples/{sample_id}/{task_id}/report_triage.json")
        
        # Store in cache
        if self.cache and data:
            self.cache.set_behavioral(sample_id, task_id, data)
        
        return data
    
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
        
        try:
            response = self._request("GET", f"/samples/{sample_id}/{task_id}/logs/{log_file}")
            try:
                data = response.json()
            except ValueError:
                # Some kernel logs are NDJSON (one JSON object per line)
                text = (response.text or "").strip()
                if not text:
                    return None
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
    ) -> dict[str, Any]:
        """
        Fetch all data for a sample in one call.
        
        Args:
            sample_id: Sample ID
            include_kernel_logs: Whether to fetch kernel logs
            
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
        
        # Fetch overview
        try:
            result["overview"] = self.get_overview(sample_id)
        except TriageAPIError as e:
            logger.warning(f"Failed to get overview: {e}")
            return result
        
        # Detect OS from overview
        os_type = self._detect_os(result["overview"])
        result["os_type"] = os_type
        
        # Fetch behavioral report
        try:
            result["behavioral_report"] = self.get_behavioral_report(sample_id)
        except NotFoundError:
            logger.debug(f"No behavioral report for {sample_id}")
        except TriageAPIError as e:
            logger.warning(f"Failed to get behavioral report: {e}")
        
        # Fetch kernel logs
        if include_kernel_logs and os_type:
            result["kernel_logs"] = self.get_kernel_logs(sample_id, os_type=os_type)
        
        return result
    
    def _detect_os(self, overview: dict[str, Any]) -> str | None:
        """Detect OS type from overview data."""
        # Check analysis tags
        analysis = overview.get("analysis", {})
        tags = analysis.get("tags", [])
        
        for tag in tags:
            tag_lower = tag.lower()
            if "android" in tag_lower:
                return "android"
            if "windows" in tag_lower:
                return "windows"
            if "linux" in tag_lower:
                return "linux"
            if "macos" in tag_lower:
                return "macos"
        
        # Check sample target filename
        sample = overview.get("sample", {})
        filename = sample.get("target", "") or sample.get("name", "")
        
        if filename.endswith(".apk"):
            return "android"
        if filename.endswith((".exe", ".dll")):
            return "windows"
        
        return None
    
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
