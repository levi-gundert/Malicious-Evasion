"""Privilege information. Arbitrary elevated command execution is unsupported."""

import os
from extractor.placement import host_os


class PrivilegeManager:
    def __init__(self, current_os=None):
        self.current_os = current_os or host_os()

    def is_elevated(self):
        if self.current_os == "windows":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def get_elevation_method(self):
        return {
            "windows": "UAC",
            "linux": "PolicyKit / sudo",
            "macos": "Administrator prompt",
        }.get(self.current_os, "Unavailable")

    def get_elevation_warning(self, privilege_level):
        return (
            "No elevation requested"
            if privilege_level == "user"
            else "The operating system will request permission for the displayed plan."
        )
