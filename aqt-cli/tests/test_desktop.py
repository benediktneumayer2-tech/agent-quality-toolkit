"""The desktop app's side of aqt: ``aqt open``, which aqt agents run (the "command" check), and the paths that
the frozen runtime writes into persisted commands."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from aqt_cli import checks, cli
from aqt_cli.checks import Context, check_command, trail_command


def fake_aqt(folder: Path, name="aqt") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    program = folder / name
    program.write_text("#!/bin/sh\nexit 0\n")
    program.chmod(0o755)
    return program


# -- aqt open ----------------------------------------------------------------------------------
@pytest.mark.parametrize("target, link", [
    ("quarantine:Q7SEGGW", "aqt://case/quarantine:Q7SEGGW"),
    ("aqt://case/plan:0:s01", "aqt://case/plan:0:s01"),
    ("aqt://change/0/api-v2", "aqt://change/0/api-v2"),
    ("aqt://case/../x", None), ("aqt://case/a:..:b", None), ("aqt://case/a?x=1", None), ("..", None),
    ("aqt://change/x/a", None), ("aqt://change/0/..", None), ("aqt://change/0/a/b", None), ("aqt://other/x", None),
    ("https://example.com/", None), ("aqt://case/", None)])
def test_open_accepts_case_ids_and_view_links_only(target, link):
    assert cli.app_link(target) == link


def test_open_hands_the_link_to_the_system(monkeypatch):
    calls = []
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: calls.append(argv) or subprocess.CompletedProcess(argv, 0))
    assert cli.main(["open", "quarantine:Q7SEGGW"]) == 0
    monkeypatch.setattr(sys, "platform", "darwin")
    assert cli.main(["open", "aqt://change/0/api-v2"]) == 0
    assert calls == [["xdg-open", "aqt://case/quarantine:Q7SEGGW"], ["open", "aqt://change/0/api-v2"]]


def test_open_refuses_other_text_and_reports_a_missing_handler(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 4))
    assert cli.main(["open", "file:///etc/passwd"]) == 2
    assert "neither a case id" in capsys.readouterr().err
    assert cli.main(["open", "capa:candidates"]) == 2
    assert "is the AQT desktop app installed" in capsys.readouterr().err


# -- which aqt agents run -----------------------------------------------------------------------
def test_command_check_is_ok_when_this_aqt_comes_first():
    result = check_command(Context())
    assert result.result == "ok" and result.data["path"] == str(Path(sys.executable).parent / "aqt")


def test_command_check_names_the_other_aqt_that_comes_first(tmp_path, monkeypatch):
    other = fake_aqt(tmp_path / "other")
    monkeypatch.setenv("PATH", f"{other.parent}{os.pathsep}{os.environ['PATH']}")
    result = check_command(Context())
    assert result.result == "warn" and str(other) in result.explanation and not result.can_apply
    assert result.data == {"path": str(other), "this": str(Path(sys.executable).parent / "aqt")}


def test_command_check_without_aqt_on_path(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    result = check_command(Context())
    assert result.result == "warn" and "no aqt command on PATH" in result.explanation
    assert result.fix == f"add {Path(sys.executable).parent} to PATH"


def test_frozen_appimage_runtime_counts_the_link_to_its_appimage(tmp_path, monkeypatch):
    image = fake_aqt(tmp_path / "Apps", "AQT.AppImage")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "aqt").symlink_to(image)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("APPIMAGE", str(image))
    monkeypatch.setenv("PATH", str(bin_dir))
    assert check_command(Context()).result == "ok"
    assert trail_command() == [str(bin_dir / "aqt"), "trail"]             # the systemd unit's stable command
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    result = check_command(Context())
    assert result.result == "warn" and "install the aqt command" in result.fix
    assert trail_command() == [str(image), "--cli", "trail"]


def test_the_command_check_is_in_aqt_status():
    assert "command" in [check.id for check in checks.CHECKS]
