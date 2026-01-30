"""
Triage API client module.

Provides authenticated access to the Hatching Triage API for:
- Searching samples by tag, score, date
- Fetching sample overviews
- Fetching behavioral reports
- Fetching kernel logs (when available)
- Response caching with SQLite
"""

from extractor.triage.client import TriageClient, TriageAPIError
from extractor.triage.cache import TriageCache, CacheConfig

__all__ = [
    "TriageClient",
    "TriageAPIError",
    "TriageCache",
    "CacheConfig",
]
