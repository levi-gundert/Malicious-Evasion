"""
macOS-specific platform helpers.

Provides:
- Path utilities
- Admin prompt helpers
- macOS-specific detection
"""

import os
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def get_user_paths():
    """Get common user-accessible paths on macOS."""
    home = Path.home()
    return {
        "home": home,
        "library": home / "Library",
        "app_support": home / "Library" / "Application Support",
        "preferences": home / "Library" / "Preferences",
        "caches": home / "Library" / "Caches",
        "tmp": Path("/tmp"),
    }


def get_system_paths():
    """Get common system paths on macOS (require admin)."""
    return {
        "library": Path("/Library"),
        "system_library": Path("/System/Library"),
        "applications": Path("/Applications"),
        "usr_local": Path("/usr/local"),
        "opt": Path("/opt"),
    }


def is_admin() -> bool:
    """Check if running with admin privileges."""
    return os.geteuid() == 0


def is_sip_enabled() -> bool:
    """Check if System Integrity Protection is enabled."""
    try:
        result = subprocess.run(
            ["csrutil", "status"],
            capture_output=True,
            timeout=5,
        )
        return b"enabled" in result.stdout.lower()
    except Exception:
        return True  # Assume enabled if we can't check


def get_macos_version():
    """Get macOS version information."""
    try:
        result = subprocess.run(
            ["sw_vers", "-productVersion"],
            capture_output=True,
            timeout=5,
        )
        return result.stdout.decode().strip()
    except Exception:
        return "Unknown"


def is_vm() -> bool:
    """Check if running in a virtual machine."""
    try:
        result = subprocess.run(
            ["system_profiler", "SPHardwareDataType"],
            capture_output=True,
            timeout=10,
        )
        output = result.stdout.decode().lower()
        
        vm_indicators = [
            "vmware",
            "virtualbox",
            "parallels",
            "qemu",
            "virtual machine",
        ]
        
        return any(ind in output for ind in vm_indicators)
    except Exception:
        return False
