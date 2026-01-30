"""
OS-specific extractors for evasion artifacts.

Each extractor takes behavioral report data and extracts artifacts
that malware checks for to detect analysis environments.

Data sources (in order of preference):
1. Kernel logs (stahp.json/onemon.json/bigmac.json) - most detailed
2. Signatures with IOCs - good fallback
3. Network flows - for port probes
4. Process list - for process enumeration checks
"""

from extractor.extractors.base import BaseExtractor, ExtractionContext
from extractor.extractors.android import AndroidExtractor
from extractor.extractors.windows import WindowsExtractor
from extractor.extractors.linux import LinuxExtractor
from extractor.extractors.macos import MacOSExtractor

__all__ = [
    "BaseExtractor",
    "ExtractionContext",
    "AndroidExtractor",
    "WindowsExtractor",
    "LinuxExtractor",
    "MacOSExtractor",
]
