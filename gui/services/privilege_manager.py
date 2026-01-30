"""
Privilege Manager.

Handles OS-specific elevation requests:
- Windows: UAC elevation
- Linux/macOS: pkexec or sudo
- Android: su binary
"""

import logging
import os
import platform
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


class PrivilegeManager:
    """
    Manages privilege elevation for artifact placement.
    
    Each platform has different mechanisms:
    - Windows: UAC prompts via ShellExecute or PowerShell
    - Linux: pkexec (PolicyKit) or sudo
    - macOS: osascript for admin prompts, or sudo
    - Android: su binary (requires rooted device)
    """
    
    def __init__(self, current_os: Optional[str] = None):
        """
        Initialize the privilege manager.
        
        Args:
            current_os: Override OS detection
        """
        self.current_os = current_os or self._detect_os()
        self._has_root_checked = False
        self._has_root = False
    
    def _detect_os(self) -> str:
        """Detect the current OS."""
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        elif system == "linux":
            # Check for Android
            try:
                import kivy.utils
                if kivy.utils.platform == "android":
                    return "android"
            except ImportError:
                pass
            return "linux"
        return "unknown"
    
    def is_elevated(self) -> bool:
        """Check if current process has elevated privileges."""
        if self.current_os == "windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        
        elif self.current_os in ("linux", "macos"):
            return os.geteuid() == 0
        
        elif self.current_os == "android":
            return self.has_root()
        
        return False
    
    def has_root(self) -> bool:
        """Check if root/su is available (Android)."""
        if self._has_root_checked:
            return self._has_root
        
        self._has_root_checked = True
        
        if self.current_os != "android":
            self._has_root = False
            return False
        
        # Check for su binary
        su_paths = ["/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su"]
        for path in su_paths:
            if os.path.exists(path):
                self._has_root = True
                logger.info(f"Root available: {path}")
                return True
        
        # Try running su
        try:
            result = subprocess.run(
                ["su", "-c", "id"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0 and b"uid=0" in result.stdout:
                self._has_root = True
                return True
        except Exception:
            pass
        
        self._has_root = False
        return False
    
    # =========================================================================
    # Windows Elevation
    # =========================================================================
    
    def run_elevated_powershell(self, script: str) -> bool:
        """
        Run a PowerShell script with elevation (Windows).
        
        This will trigger a UAC prompt.
        """
        if self.current_os != "windows":
            logger.error("PowerShell elevation only available on Windows")
            return False
        
        try:
            import ctypes
            
            # Create a temporary script file
            import tempfile
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".ps1",
                delete=False,
                encoding="utf-8"
            ) as f:
                f.write(script)
                script_path = f.name
            
            # Run with elevation using ShellExecute
            params = f'-ExecutionPolicy Bypass -File "{script_path}"'
            
            result = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                "powershell.exe",
                params,
                None,
                0,  # SW_HIDE
            )
            
            # Clean up
            try:
                os.unlink(script_path)
            except Exception:
                pass
            
            # ShellExecuteW returns > 32 on success
            if result > 32:
                logger.info("Elevated PowerShell command executed")
                return True
            else:
                logger.error(f"ShellExecute failed with code: {result}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to run elevated PowerShell: {e}")
            return False
    
    def run_elevated_cmd(self, command: str) -> bool:
        """
        Run a command with elevation (Windows).
        
        This will trigger a UAC prompt.
        """
        if self.current_os != "windows":
            logger.error("CMD elevation only available on Windows")
            return False
        
        try:
            import ctypes
            
            result = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                "cmd.exe",
                f"/c {command}",
                None,
                0,  # SW_HIDE
            )
            
            if result > 32:
                logger.info("Elevated command executed")
                return True
            else:
                logger.error(f"ShellExecute failed with code: {result}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to run elevated command: {e}")
            return False
    
    # =========================================================================
    # Linux/macOS Elevation
    # =========================================================================
    
    def run_elevated_shell(self, command: str) -> bool:
        """
        Run a shell command with elevation (Linux/macOS).
        
        Tries pkexec first (graphical), falls back to sudo.
        """
        if self.current_os not in ("linux", "macos"):
            logger.error("Shell elevation only available on Linux/macOS")
            return False
        
        # Try pkexec first (graphical prompt)
        if shutil.which("pkexec"):
            try:
                result = subprocess.run(
                    ["pkexec", "sh", "-c", command],
                    capture_output=True,
                    timeout=60,
                )
                if result.returncode == 0:
                    logger.info("Command executed via pkexec")
                    return True
            except subprocess.TimeoutExpired:
                logger.error("pkexec timed out")
            except Exception as e:
                logger.error(f"pkexec failed: {e}")
        
        # Try sudo with terminal
        if shutil.which("sudo"):
            try:
                # This will only work if sudo is configured for NOPASSWD
                # or in a terminal with user input
                result = subprocess.run(
                    ["sudo", "sh", "-c", command],
                    capture_output=True,
                    timeout=60,
                )
                if result.returncode == 0:
                    logger.info("Command executed via sudo")
                    return True
            except subprocess.TimeoutExpired:
                logger.error("sudo timed out")
            except Exception as e:
                logger.error(f"sudo failed: {e}")
        
        # macOS: Try osascript for admin prompt
        if self.current_os == "macos":
            return self._run_macos_admin(command)
        
        logger.error("No elevation method available")
        return False
    
    def _run_macos_admin(self, command: str) -> bool:
        """Run command with macOS admin prompt via osascript."""
        try:
            # Escape quotes in command
            escaped_command = command.replace('"', '\\"')
            
            apple_script = f'''
do shell script "{escaped_command}" with administrator privileges
'''
            
            result = subprocess.run(
                ["osascript", "-e", apple_script],
                capture_output=True,
                timeout=60,
            )
            
            if result.returncode == 0:
                logger.info("Command executed via osascript")
                return True
            else:
                logger.error(f"osascript failed: {result.stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"macOS admin prompt failed: {e}")
            return False
    
    # =========================================================================
    # Android Root
    # =========================================================================
    
    def run_su_command(self, command: str) -> bool:
        """
        Run a command as root via su (Android).
        
        Requires a rooted device with su binary.
        """
        if self.current_os != "android":
            logger.error("su command only available on Android")
            return False
        
        if not self.has_root():
            logger.error("Root not available")
            return False
        
        try:
            result = subprocess.run(
                ["su", "-c", command],
                capture_output=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                logger.info("Command executed via su")
                return True
            else:
                logger.error(f"su command failed: {result.stderr.decode()}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("su command timed out")
            return False
        except Exception as e:
            logger.error(f"su command failed: {e}")
            return False
    
    # =========================================================================
    # Utility
    # =========================================================================
    
    def get_elevation_method(self) -> str:
        """Get the available elevation method for the current platform."""
        if self.current_os == "windows":
            return "UAC (User Account Control)"
        
        elif self.current_os == "linux":
            if shutil.which("pkexec"):
                return "PolicyKit (pkexec)"
            elif shutil.which("sudo"):
                return "sudo"
            else:
                return "None available"
        
        elif self.current_os == "macos":
            return "Administrator Prompt (osascript)"
        
        elif self.current_os == "android":
            if self.has_root():
                return "su (root)"
            else:
                return "Root not available"
        
        return "Unknown"
    
    def get_elevation_warning(self, privilege_level: str) -> str:
        """Get a warning message for the required privilege level."""
        if privilege_level == "user":
            return "No special privileges required."
        
        elif privilege_level == "admin":
            if self.current_os == "windows":
                return "This will trigger a User Account Control (UAC) prompt."
            elif self.current_os == "macos":
                return "This will prompt for your administrator password."
            else:
                return "This requires administrator privileges."
        
        elif privilege_level == "root":
            if self.current_os == "android":
                if self.has_root():
                    return "This requires root access. Your device's superuser app may prompt for confirmation."
                else:
                    return "This requires root access, but your device does not appear to be rooted."
            else:
                return "This requires root privileges."
        
        return "Unknown privilege requirement."
