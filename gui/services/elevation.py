"""Launch only MEAP's validated helper and wait for its actual exit status."""

import base64
import ctypes
import json
from pathlib import Path
import shutil
import subprocess
import sys


def run_helper(request, current_os):
    helper = Path(__file__).resolve().parents[2] / "extractor" / "placement_helper.py"
    # parents[2] is gui's parent (the repository root).
    encoded = base64.b64encode(json.dumps(request).encode()).decode("ascii")
    args = [sys.executable, "-I", str(helper), encoded]
    if current_os == "windows":
        return run_windows(args)
    if current_os == "linux":
        command = ["pkexec", *args] if shutil.which("pkexec") else ["sudo", "-n", *args]
    elif current_os == "macos":
        # Fixed AppleScript; quoting happens in AppleScript from argv data.
        script = 'on run argv\nset cmd to ""\nrepeat with a in argv\nset cmd to cmd & quoted form of a & " "\nend repeat\ndo shell script cmd with administrator privileges\nend run'
        command = ["osascript", "-e", script, *args]
    else:
        raise ValueError("Elevated placement is unavailable on this platform")
    try:
        return subprocess.run(command, capture_output=True, timeout=120).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def run_windows(args):
    from ctypes import wintypes

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIcon", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    info = SHELLEXECUTEINFO()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40 | 0x100  # NOCLOSEPROCESS | NOASYNC
    info.lpVerb, info.lpFile = "runas", args[0]
    info.lpParameters = subprocess.list2cmdline(args[1:])
    info.nShow = 0
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFO)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    if not shell.ShellExecuteExW(ctypes.byref(info)):
        if ctypes.get_last_error() == 1223:
            raise PermissionError("Elevation cancelled by the user")
        return False  # Includes UAC cancellation.
    try:
        if kernel.WaitForSingleObject(info.hProcess, 120000) != 0:
            kernel.TerminateProcess(info.hProcess, 1)
            kernel.WaitForSingleObject(info.hProcess, 5000)
            return False
        code = wintypes.DWORD()
        return (
            bool(kernel.GetExitCodeProcess(info.hProcess, ctypes.byref(code)))
            and code.value == 0
        )
    finally:
        kernel.CloseHandle(info.hProcess)
