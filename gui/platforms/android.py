"""
Android-specific platform helpers.

Provides:
- Path utilities
- Root detection
- Android-specific checks
"""

import os
import logging
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def get_user_paths():
    """Get common user-accessible paths on Android."""
    return {
        "sdcard": Path("/sdcard"),
        "storage": Path("/storage/emulated/0"),
        "download": Path("/sdcard/Download"),
        "dcim": Path("/sdcard/DCIM"),
    }


def get_system_paths():
    """Get common system paths on Android (require root)."""
    return {
        "system": Path("/system"),
        "system_app": Path("/system/app"),
        "system_bin": Path("/system/bin"),
        "system_xbin": Path("/system/xbin"),
        "data": Path("/data"),
        "data_app": Path("/data/app"),
    }


def is_rooted() -> bool:
    """Check if the device is rooted."""
    # Check for su binary
    su_paths = [
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/su/bin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
    ]
    
    for path in su_paths:
        if os.path.exists(path):
            logger.debug(f"Found su at: {path}")
            return True
    
    # Try to run su
    try:
        result = subprocess.run(
            ["su", "-c", "id"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0 and b"uid=0" in result.stdout:
            return True
    except Exception:
        pass
    
    # Check for root management apps
    root_apps = [
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/data/app/eu.chainfire.supersu",
        "/data/app/com.topjohnwu.magisk",
    ]
    
    for path in root_apps:
        if os.path.exists(path):
            return True
    
    return False


def get_device_info():
    """Get Android device information."""
    info = {
        "model": "",
        "manufacturer": "",
        "android_version": "",
        "sdk_version": "",
    }
    
    try:
        # Try getprop
        props = [
            ("model", "ro.product.model"),
            ("manufacturer", "ro.product.manufacturer"),
            ("android_version", "ro.build.version.release"),
            ("sdk_version", "ro.build.version.sdk"),
        ]
        
        for key, prop in props:
            result = subprocess.run(
                ["getprop", prop],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                info[key] = result.stdout.decode().strip()
    except Exception:
        pass
    
    return info


def is_emulator() -> bool:
    """Check if running in an Android emulator."""
    emulator_indicators = [
        # Files
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        # Properties
    ]
    
    for path in emulator_indicators:
        if os.path.exists(path):
            return True
    
    # Check properties
    try:
        emulator_props = [
            ("ro.kernel.qemu", "1"),
            ("ro.hardware", "goldfish"),
            ("ro.hardware", "ranchu"),
            ("ro.product.model", "sdk"),
            ("ro.product.model", "google_sdk"),
        ]
        
        for prop, value in emulator_props:
            result = subprocess.run(
                ["getprop", prop],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0 and value in result.stdout.decode().lower():
                return True
    except Exception:
        pass
    
    return False


def get_storage_path() -> Optional[Path]:
    """Get the best available storage path."""
    try:
        from android.storage import primary_external_storage_path
        return Path(primary_external_storage_path())
    except ImportError:
        # Not running on Android with pyjnius
        pass
    
    # Fallback to common paths
    paths = [
        "/sdcard",
        "/storage/emulated/0",
        os.environ.get("EXTERNAL_STORAGE", ""),
    ]
    
    for path in paths:
        if path and os.path.exists(path) and os.access(path, os.W_OK):
            return Path(path)
    
    return None
