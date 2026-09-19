"""Windows handle guards for path replacement during a placement operation."""

from contextlib import contextmanager, ExitStack
import os
from pathlib import Path


@contextmanager
def pinned_parents(path):
    if os.name != "nt":
        yield
        return
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    invalid = ctypes.c_void_p(-1).value
    with ExitStack() as stack:
        for parent in reversed(Path(path).parents):
            # Open the reparse point itself; do not allow rename/deletion while held.
            handle = kernel.CreateFileW(str(parent), 0x80, 3, None, 3, 0x02200000, None)
            if handle == invalid:
                raise ctypes.WinError(ctypes.get_last_error())
            stack.callback(kernel.CloseHandle, handle)
            if getattr(parent.lstat(), "st_file_attributes", 0) & 0x400:
                raise ValueError("Reparse point in target ancestry")
        yield


def remove_owned_file(path, expected_bytes, expected_identity):
    """On Windows, verify and delete the same open object, never a later path occupant."""
    if os.name != "nt":
        # Refuse links and replacements immediately before unlinking. Native
        # adversarial rename-race testing on POSIX remains a release requirement.
        from extractor.placement import checked_path, fingerprint, PlacementError

        path = checked_path(str(path))
        if (
            expected_identity and fingerprint(path) != expected_identity
        ) or path.read_bytes() != expected_bytes:
            raise PlacementError("File changed during removal; preserved")
        path.unlink()
        return
    import ctypes
    import msvcrt
    from ctypes import wintypes
    from extractor.placement import PlacementError

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(path), 0x80010000, 1, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        identity = f"{info.st_dev}:{info.st_ino}"
        if (
            getattr(info, "st_file_attributes", 0) & 0x400
            or info.st_nlink != 1
            or (expected_identity and identity != expected_identity)
        ):
            raise PlacementError("File identity changed; preserved")
        if stream.read(len(expected_bytes) + 1) != expected_bytes:
            raise PlacementError("File content changed; preserved")
        delete = wintypes.BOOL(True)
        if not kernel.SetFileInformationByHandle(
            handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
