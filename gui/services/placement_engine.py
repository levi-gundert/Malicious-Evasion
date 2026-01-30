"""
Placement Engine.

Handles OS-specific artifact placement:
- Create files
- Create registry keys (Windows)
- Set properties (Android)
- Log all placements for undo
"""

import logging
import os
import platform
from pathlib import Path
from typing import Any, Dict, Optional

from kivy.utils import platform as kivy_platform

logger = logging.getLogger(__name__)


class PlacementEngine:
    """
    Engine for placing artifacts on the filesystem.
    
    Supports:
    - File creation (all platforms)
    - Registry keys (Windows)
    - Properties (Android - requires root)
    - Processes (fake - limited support)
    """
    
    def __init__(self, current_os: Optional[str] = None):
        """
        Initialize the placement engine.
        
        Args:
            current_os: Override OS detection (android, windows, linux, macos)
        """
        self.current_os = current_os or self._detect_os()
        logger.debug(f"PlacementEngine initialized for: {self.current_os}")
    
    def _detect_os(self) -> str:
        """Detect the current operating system."""
        if kivy_platform == "android":
            return "android"
        elif kivy_platform == "win":
            return "windows"
        elif kivy_platform == "macosx":
            return "macos"
        elif kivy_platform == "linux":
            return "linux"
        else:
            # Fallback to platform module
            system = platform.system().lower()
            if system == "windows":
                return "windows"
            elif system == "darwin":
                return "macos"
            elif system == "linux":
                return "linux"
            return "unknown"
    
    def place_artifact(self, artifact: Dict[str, Any], elevate: bool = False) -> bool:
        """
        Place an artifact on the system.
        
        Args:
            artifact: Artifact dict with type, value, etc.
            elevate: Whether to request elevation for privileged placement
            
        Returns:
            True if successful, False otherwise
        """
        artifact_type = artifact.get("artifact_type", "file")
        value = artifact.get("value", "")
        privilege = artifact.get("privilege_level", "user")
        
        logger.info(f"Placing artifact: {artifact_type} = {value} (privilege: {privilege})")
        
        # Check if elevation is needed
        if privilege in ("admin", "root") and not elevate:
            logger.warning(f"Artifact requires elevation but elevate=False: {value}")
            return False
        
        # Route to appropriate handler
        if artifact_type == "file":
            return self._place_file(value, elevate)
        elif artifact_type == "registry":
            return self._place_registry(value, elevate)
        elif artifact_type == "property":
            return self._place_property(value)
        elif artifact_type == "package":
            return self._place_package_indicator(value)
        elif artifact_type == "mutex":
            return self._place_mutex(value)
        else:
            logger.warning(f"Unsupported artifact type: {artifact_type}")
            return False
    
    def remove_artifact(self, artifact: Dict[str, Any], placed_path: Optional[str] = None) -> bool:
        """
        Remove a previously placed artifact.
        
        Args:
            artifact: Artifact dict
            placed_path: Actual path where it was placed (if different from value)
            
        Returns:
            True if successful
        """
        artifact_type = artifact.get("artifact_type", "file")
        path = placed_path or artifact.get("value", "")
        
        logger.info(f"Removing artifact: {artifact_type} = {path}")
        
        if artifact_type == "file":
            return self._remove_file(path)
        elif artifact_type == "registry":
            return self._remove_registry(path)
        else:
            logger.warning(f"Cannot remove artifact type: {artifact_type}")
            return False
    
    # =========================================================================
    # File Placement
    # =========================================================================
    
    def _place_file(self, path: str, elevate: bool = False) -> bool:
        """
        Create a file at the specified path.
        
        The file will be created with placeholder content to trigger
        malware file existence checks.
        """
        try:
            # Expand path variables
            expanded_path = self._expand_path(path)
            
            logger.debug(f"Creating file: {expanded_path}")
            
            if elevate:
                return self._place_file_elevated(expanded_path)
            
            # Create parent directories
            parent = Path(expanded_path).parent
            parent.mkdir(parents=True, exist_ok=True)
            
            # Create file with placeholder content
            with open(expanded_path, "w", encoding="utf-8") as f:
                f.write(f"# Evasion artifact placeholder\n# Original path: {path}\n")
            
            logger.info(f"Created file: {expanded_path}")
            return True
            
        except PermissionError:
            logger.error(f"Permission denied creating file: {path}")
            return False
        except Exception as e:
            logger.error(f"Failed to create file {path}: {e}")
            return False
    
    def _place_file_elevated(self, path: str) -> bool:
        """Create a file with elevated privileges."""
        from gui.services.privilege_manager import PrivilegeManager
        
        pm = PrivilegeManager(self.current_os)
        
        # Create content for the file
        content = f"# Evasion artifact placeholder\n"
        
        if self.current_os == "windows":
            # Use PowerShell with elevation
            script = f'''
$content = @"
{content}
"@
$parent = Split-Path "{path}" -Parent
if (-not (Test-Path $parent)) {{ New-Item -ItemType Directory -Path $parent -Force }}
$content | Out-File -FilePath "{path}" -Encoding UTF8
'''
            return pm.run_elevated_powershell(script)
        
        elif self.current_os in ("linux", "macos"):
            # Use sudo
            commands = [
                f'mkdir -p "$(dirname "{path}")"',
                f'echo "{content}" > "{path}"',
            ]
            return pm.run_elevated_shell("; ".join(commands))
        
        elif self.current_os == "android":
            # Use su
            commands = [
                f'mkdir -p "$(dirname "{path}")"',
                f'echo "{content}" > "{path}"',
            ]
            return pm.run_su_command("; ".join(commands))
        
        return False
    
    def _remove_file(self, path: str) -> bool:
        """Remove a file."""
        try:
            expanded_path = self._expand_path(path)
            
            if os.path.exists(expanded_path):
                os.remove(expanded_path)
                logger.info(f"Removed file: {expanded_path}")
                return True
            else:
                logger.debug(f"File doesn't exist: {expanded_path}")
                return True  # Already removed
                
        except PermissionError:
            logger.error(f"Permission denied removing file: {path}")
            return False
        except Exception as e:
            logger.error(f"Failed to remove file {path}: {e}")
            return False
    
    # =========================================================================
    # Registry Placement (Windows)
    # =========================================================================
    
    def _place_registry(self, key_path: str, elevate: bool = False) -> bool:
        """
        Create a registry key (Windows only).
        
        Args:
            key_path: Registry key path (e.g., HKLM\\SOFTWARE\\VMware)
        """
        if self.current_os != "windows":
            logger.warning("Registry placement only supported on Windows")
            return False
        
        try:
            if elevate:
                return self._place_registry_elevated(key_path)
            
            import winreg
            
            # Parse the key path
            root_key, subkey = self._parse_registry_path(key_path)
            if root_key is None:
                return False
            
            # Create the key
            winreg.CreateKeyEx(root_key, subkey, 0, winreg.KEY_WRITE)
            logger.info(f"Created registry key: {key_path}")
            return True
            
        except PermissionError:
            logger.error(f"Permission denied creating registry key: {key_path}")
            return False
        except Exception as e:
            logger.error(f"Failed to create registry key {key_path}: {e}")
            return False
    
    def _place_registry_elevated(self, key_path: str) -> bool:
        """Create a registry key with elevation."""
        from gui.services.privilege_manager import PrivilegeManager
        
        pm = PrivilegeManager(self.current_os)
        
        # Use reg.exe with elevation
        script = f'reg add "{key_path}" /f'
        return pm.run_elevated_cmd(script)
    
    def _remove_registry(self, key_path: str) -> bool:
        """Remove a registry key."""
        if self.current_os != "windows":
            return False
        
        try:
            import winreg
            
            root_key, subkey = self._parse_registry_path(key_path)
            if root_key is None:
                return False
            
            winreg.DeleteKey(root_key, subkey)
            logger.info(f"Removed registry key: {key_path}")
            return True
            
        except FileNotFoundError:
            logger.debug(f"Registry key doesn't exist: {key_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove registry key {key_path}: {e}")
            return False
    
    def _parse_registry_path(self, path: str):
        """Parse a registry path into root key and subkey."""
        import winreg
        
        root_keys = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKU": winreg.HKEY_USERS,
            "HKEY_USERS": winreg.HKEY_USERS,
        }
        
        # Split path
        parts = path.replace("/", "\\").split("\\", 1)
        if len(parts) < 2:
            logger.error(f"Invalid registry path: {path}")
            return None, None
        
        root_name = parts[0].upper()
        subkey = parts[1]
        
        root_key = root_keys.get(root_name)
        if root_key is None:
            logger.error(f"Unknown registry root: {root_name}")
            return None, None
        
        return root_key, subkey
    
    # =========================================================================
    # Property Placement (Android)
    # =========================================================================
    
    def _place_property(self, prop_name: str) -> bool:
        """
        Set an Android system property.
        
        Note: This requires root access and may not persist across reboots.
        """
        if self.current_os != "android":
            logger.warning("Property placement only supported on Android")
            return False
        
        try:
            from gui.services.privilege_manager import PrivilegeManager
            
            pm = PrivilegeManager(self.current_os)
            
            # Set property using setprop
            # For evasion, we often want properties that indicate a real device
            command = f'setprop {prop_name} "1"'
            return pm.run_su_command(command)
            
        except Exception as e:
            logger.error(f"Failed to set property {prop_name}: {e}")
            return False
    
    # =========================================================================
    # Package Indicator (Android)
    # =========================================================================
    
    def _place_package_indicator(self, package_name: str) -> bool:
        """
        Create an indicator that a package is installed.
        
        Note: Actually installing packages requires APKs.
        This creates a marker file that some checks may look for.
        """
        if self.current_os != "android":
            logger.warning("Package placement only supported on Android")
            return False
        
        # Create a marker in an accessible location
        marker_path = f"/sdcard/.package_markers/{package_name}"
        return self._place_file(marker_path, elevate=False)
    
    # =========================================================================
    # Mutex Placement (Windows)
    # =========================================================================
    
    def _place_mutex(self, mutex_name: str) -> bool:
        """
        Create a named mutex (Windows only).
        
        Note: Mutexes only exist while the handle is open.
        This creates a background thread to keep the mutex alive.
        """
        if self.current_os != "windows":
            logger.warning("Mutex placement only supported on Windows")
            return False
        
        try:
            import ctypes
            from threading import Thread
            import time
            
            # Create mutex using Windows API
            kernel32 = ctypes.windll.kernel32
            
            def hold_mutex():
                handle = kernel32.CreateMutexW(None, False, mutex_name)
                if handle:
                    logger.info(f"Created mutex: {mutex_name}")
                    # Keep the mutex alive for a while
                    # In a real app, this would be managed more carefully
                    time.sleep(3600)  # 1 hour
                    kernel32.CloseHandle(handle)
            
            # Start background thread
            thread = Thread(target=hold_mutex, daemon=True)
            thread.start()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create mutex {mutex_name}: {e}")
            return False
    
    # =========================================================================
    # Utilities
    # =========================================================================
    
    def _expand_path(self, path: str) -> str:
        """Expand environment variables and ~ in path."""
        # Expand environment variables
        if self.current_os == "windows":
            expanded = os.path.expandvars(path)
        else:
            expanded = os.path.expandvars(path)
        
        # Expand ~
        expanded = os.path.expanduser(expanded)
        
        return expanded
    
    def get_user_space_path(self, artifact: Dict[str, Any]) -> Optional[str]:
        """
        Get a user-space alternative path for an artifact.
        
        If an artifact requires admin but user wants to place it
        in a user-accessible location, this suggests an alternative.
        
        Returns:
            Alternative path, or None if not applicable
        """
        value = artifact.get("value", "")
        artifact_type = artifact.get("artifact_type", "file")
        
        if artifact_type != "file":
            return None
        
        # Map system paths to user-space alternatives
        if self.current_os == "windows":
            if "System32" in value or "Windows" in value:
                filename = Path(value).name
                return str(Path.home() / "AppData" / "Local" / "EvasionArtifacts" / filename)
        
        elif self.current_os in ("linux", "macos"):
            if value.startswith("/usr") or value.startswith("/opt") or value.startswith("/etc"):
                filename = Path(value).name
                return str(Path.home() / ".evasion_artifacts" / filename)
        
        elif self.current_os == "android":
            if value.startswith("/system") or value.startswith("/data"):
                filename = Path(value).name
                return f"/sdcard/EvasionArtifacts/{filename}"
        
        return None
