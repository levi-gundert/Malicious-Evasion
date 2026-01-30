"""
Linux-specific platform helpers.

Provides:
- Path utilities
- Root detection
- PolicyKit/sudo helpers
"""

import os
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


def get_user_paths():
    """Get common user-accessible paths on Linux."""
    home = Path.home()
    return {
        "home": home,
        "config": home / ".config",
        "local": home / ".local",
        "cache": home / ".cache",
        "tmp": Path("/tmp"),
    }


def get_system_paths():
    """Get common system paths on Linux (require root)."""
    return {
        "usr_bin": Path("/usr/bin"),
        "usr_lib": Path("/usr/lib"),
        "opt": Path("/opt"),
        "etc": Path("/etc"),
        "var": Path("/var"),
    }


def is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def has_pkexec() -> bool:
    """Check if pkexec is available."""
    return shutil.which("pkexec") is not None


def has_sudo() -> bool:
    """Check if sudo is available."""
    return shutil.which("sudo") is not None


def is_container() -> bool:
    """Check if running in a container (Docker, etc.)."""
    indicators = [
        Path("/.dockerenv").exists(),
        Path("/run/.containerenv").exists(),
    ]
    
    # Check cgroup
    try:
        with open("/proc/1/cgroup", "r") as f:
            content = f.read()
            if "docker" in content or "lxc" in content or "kubepods" in content:
                return True
    except Exception:
        pass
    
    return any(indicators)


def get_distro_info():
    """Get Linux distribution information."""
    info = {
        "name": "Unknown",
        "version": "",
        "id": "",
    }
    
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("NAME="):
                    info["name"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("VERSION="):
                    info["version"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("ID="):
                    info["id"] = line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    
    return info
