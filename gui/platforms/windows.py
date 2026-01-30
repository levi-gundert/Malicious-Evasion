"""
Windows-specific platform helpers.

Provides:
- Registry operations
- UAC elevation
- Windows-specific paths
"""

import os
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def get_user_paths():
    """Get common user-accessible paths on Windows."""
    home = Path.home()
    return {
        "appdata": home / "AppData" / "Roaming",
        "local_appdata": home / "AppData" / "Local",
        "temp": Path(os.environ.get("TEMP", home / "AppData" / "Local" / "Temp")),
        "documents": home / "Documents",
        "desktop": home / "Desktop",
    }


def get_system_paths():
    """Get common system paths on Windows (require admin)."""
    windows = Path(os.environ.get("WINDIR", "C:\\Windows"))
    return {
        "system32": windows / "System32",
        "drivers": windows / "System32" / "drivers",
        "program_files": Path(os.environ.get("PROGRAMFILES", "C:\\Program Files")),
        "program_files_x86": Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")),
    }


def is_admin() -> bool:
    """Check if running with admin privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def create_registry_key(key_path: str, value_name: Optional[str] = None, 
                        value_data: Optional[str] = None) -> bool:
    """
    Create a registry key and optionally set a value.
    
    Args:
        key_path: Full registry path (e.g., HKLM\\SOFTWARE\\Test)
        value_name: Optional value name to create
        value_data: Optional value data
        
    Returns:
        True if successful
    """
    try:
        import winreg
        
        # Parse path
        parts = key_path.split("\\", 1)
        if len(parts) < 2:
            return False
        
        root_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU": winreg.HKEY_USERS,
        }
        
        root_key = root_map.get(parts[0].upper())
        if not root_key:
            return False
        
        subkey = parts[1]
        
        # Create key
        key = winreg.CreateKeyEx(root_key, subkey, 0, winreg.KEY_WRITE)
        
        # Set value if provided
        if value_name and value_data:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
        
        winreg.CloseKey(key)
        return True
        
    except Exception as e:
        logger.error(f"Registry error: {e}")
        return False


def delete_registry_key(key_path: str) -> bool:
    """Delete a registry key."""
    try:
        import winreg
        
        parts = key_path.split("\\", 1)
        if len(parts) < 2:
            return False
        
        root_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }
        
        root_key = root_map.get(parts[0].upper())
        if not root_key:
            return False
        
        winreg.DeleteKey(root_key, parts[1])
        return True
        
    except FileNotFoundError:
        return True  # Already deleted
    except Exception as e:
        logger.error(f"Registry delete error: {e}")
        return False
