"""Exclusive Windows registry recipes. Never modify an existing key."""

import ctypes
from ctypes import wintypes

from extractor.placement import PlacementError


def parts(plan):
    import winreg

    hive, subkey = plan.target.split("\\", 1)
    roots = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    view = (
        winreg.KEY_WOW64_64KEY if plan.registry_view == 64 else winreg.KEY_WOW64_32KEY
    )
    return roots[hive.upper()], subkey, view


def expected(plan, token):
    import winreg

    values = {"MEAP_OWNER": (token, winreg.REG_SZ)}
    if plan.kind == "registry_value":
        if plan.registry_name.upper() == "MEAP_OWNER":
            raise PlacementError("Reserved ownership value")
        values[plan.registry_name] = (
            plan.registry_data,
            getattr(winreg, plan.registry_type),
        )
    return values


def create(plan, token):
    import winreg

    root, subkey, view = parts(plan)
    parent, name = subkey.rsplit("\\", 1)
    # Opening the parent prevents implicit creation of an unjournaled key tree.
    with winreg.OpenKey(
        root, parent, 0, winreg.KEY_CREATE_SUB_KEY | view
    ) as parent_key:
        api = ctypes.WinDLL("advapi32", use_last_error=True).RegCreateKeyExW
        api.argtypes = [
            wintypes.HKEY,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.HKEY),
            ctypes.POINTER(wintypes.DWORD),
        ]
        api.restype = wintypes.LONG
        handle, disposition = wintypes.HKEY(), wintypes.DWORD()
        result = api(
            int(parent_key),
            name,
            0,
            None,
            0,
            winreg.KEY_ALL_ACCESS | view,
            None,
            ctypes.byref(handle),
            ctypes.byref(disposition),
        )
        if result:
            raise ctypes.WinError(result)
        key = handle.value
        try:
            if disposition.value != 1:
                raise FileExistsError("Existing registry key preserved")
            for value_name, (value, kind) in expected(plan, token).items():
                winreg.SetValueEx(key, value_name, 0, kind, value)
            winreg.FlushKey(key)
        finally:
            winreg.CloseKey(key)


def verify(plan, token):
    import winreg

    root, subkey, view = parts(plan)
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | view) as key:
            children, count, _ = winreg.QueryInfoKey(key)
            if children:
                return False
            actual = {}
            for index in range(count):
                name, data, kind = winreg.EnumValue(key, index)
                actual[name] = (data, kind)
            return actual == expected(plan, token)
    except FileNotFoundError:
        return False


def remove(plan, token):
    import winreg

    if not verify(plan, token):
        raise PlacementError("Registry object changed; preserved")
    root, subkey, view = parts(plan)
    winreg.DeleteKeyEx(root, subkey, view, 0)
