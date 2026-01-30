"""
Platform-specific modules.

Contains OS-specific helpers for:
- Windows: Registry, UAC
- Linux: PolicyKit, sudo
- macOS: osascript, admin prompts
- Android: su, root detection
"""

from kivy.utils import platform

def get_platform_module():
    """Get the appropriate platform module."""
    if platform == "win":
        from gui.platforms import windows
        return windows
    elif platform == "linux":
        from gui.platforms import linux
        return linux
    elif platform == "macosx":
        from gui.platforms import macos
        return macos
    elif platform == "android":
        from gui.platforms import android
        return android
    else:
        return None
