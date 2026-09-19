import ctypes
import os
from unittest.mock import Mock
import pytest

from gui.services.elevation import run_windows
from extractor.placement_helper import execute
from extractor.placement import host_os


@pytest.mark.skipif(os.name != "nt", reason="Windows API contract")
@pytest.mark.parametrize("exit_code,expected", [(0, True), (5, False)])
def test_waits_for_actual_child_exit(monkeypatch, exit_code, expected):
    shell, kernel = Mock(), Mock()

    def launch(info):
        info._obj.hProcess = 7
        return True

    shell.ShellExecuteExW.side_effect = launch
    kernel.WaitForSingleObject.return_value = 0

    def read_exit(handle, code):
        code._obj.value = exit_code
        return True

    kernel.GetExitCodeProcess.side_effect = read_exit
    monkeypatch.setattr(
        ctypes, "WinDLL", lambda name, **kw: shell if name == "shell32" else kernel
    )
    assert run_windows(["python.exe", "-I", "helper.py", "encoded-data"]) is expected
    kernel.WaitForSingleObject.assert_called_once_with(7, 120000)
    kernel.CloseHandle.assert_called_once_with(7)


@pytest.mark.skipif(os.name != "nt", reason="Windows API contract")
def test_uac_cancel_is_distinct(monkeypatch):
    shell, kernel = Mock(), Mock()
    shell.ShellExecuteExW.return_value = False
    monkeypatch.setattr(
        ctypes, "WinDLL", lambda name, **kw: shell if name == "shell32" else kernel
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 1223)
    with pytest.raises(PermissionError, match="cancelled"):
        run_windows(["python.exe", "helper.py"])
    kernel.GetExitCodeProcess.assert_not_called()


def test_helper_accepts_only_structured_operations(tmp_path):
    with pytest.raises(ValueError, match="Unknown"):
        execute(
            {
                "action": "place",
                "command": "anything",
                "journal": str(tmp_path / "placement-journal.db"),
            }
        )
    target = tmp_path / "decoy.txt"
    request = {
        "action": "place",
        "journal": str(tmp_path / "placement-journal.db"),
        "artifact": {"os": host_os(), "artifact_type": "file", "value": str(target)},
    }
    token = execute(request)
    assert target.exists()
    assert execute({"action": "remove", "journal": request["journal"], "token": token})
    assert not target.exists()
