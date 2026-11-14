"""The trail writer as a LaunchAgent (macOS): written and loaded by aqt setup, checked by aqt status.

The tests use a fake launchctl and a throw-away HOME, so the real ~/Library/LaunchAgents is never touched.
One test loads a real agent under a test label from the throw-away HOME, only on a CI runner.
"""
import json
import os
import plistlib
import subprocess
import uuid

import pytest
from aqt_evidence import platform

from aqt_cli import checks
from aqt_cli.checks import Context
from aqt_cli.cli import main, setup
from conftest import MACOS_LAUNCHD, by_id
from test_setup import Tools, _ctx

REAL_LAUNCHCTL = checks.launchctl_run          # taken at import, before the fixture replaces it with a fake


@pytest.mark.skipif(platform.IS_WINDOWS, reason="a LaunchAgent names a POSIX uid (gui/<uid>); Windows has a logon task")
def test_agent_plist_runs_the_writer_with_this_shells_folders():
    agent = plistlib.loads(checks.agent_plist())
    assert agent["Label"] == checks.LABEL and agent["ProgramArguments"] == [*checks.trail_command(), "serve"]
    assert agent["RunAtLoad"] is True and agent["KeepAlive"] == {"SuccessfulExit": False}
    assert agent["StandardOutPath"] == agent["StandardErrorPath"] == str(platform.state_dir() / "trail-writer.log")
    assert agent["EnvironmentVariables"]["XDG_STATE_HOME"] == os.environ["XDG_STATE_HOME"]
    assert agent["EnvironmentVariables"]["XDG_RUNTIME_DIR"] == os.environ["XDG_RUNTIME_DIR"]
    assert b"aqt never overwrites this file" in checks.agent_plist()


@MACOS_LAUNCHD
def test_setup_writes_and_loads_the_agent_and_a_rerun_changes_nothing(launchd, start_writer, capsys):
    launchd.available = True
    launchd.on_start = start_writer
    runner = Tools()
    assert setup(_ctx(yes=True, signer_id="human:alice", name="Alice Example", role="quality-manager",
                      run_tool=runner)) == 0
    agent = checks.agent_path()
    assert agent.parent == checks.Path.home() / "Library" / "LaunchAgents"
    assert ("bootstrap", f"gui/{os.getuid()}", str(agent)) in launchd.calls
    assert plistlib.loads(agent.read_bytes())["ProgramArguments"][-1] == "serve"
    capsys.readouterr()
    assert main(["status", "--json"]) == 0
    report = {c["id"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert report["service"]["result"] == "ok" and "running" in report["service"]["explanation"]
    before = agent.read_bytes()
    said = []
    assert setup(_ctx(yes=True, run_tool=runner, say=said.append)) == 0
    assert said[0] == "aqt setup: nothing to do" and agent.read_bytes() == before


@MACOS_LAUNCHD
def test_status_gives_the_fix_for_an_agent_that_is_not_loaded(launchd, start_writer):
    launchd.available = True
    assert Tools()("trail", ["init"]) == 0
    agent = checks.agent_path()
    agent.parent.mkdir(parents=True)
    agent.write_bytes(checks.agent_plist())
    results = by_id(checks.run_checks(Context()))
    assert results["service"].result == "warn" and results["service"].can_apply
    assert results["service"].fix == f"launchctl bootstrap gui/{os.getuid()} {agent}"
    assert results["writer"].result == "fail" and results["writer"].can_apply
    launchd.on_start = start_writer
    checks.step_writer(_ctx())                                     # not loaded: bootstrap, which starts it
    assert launchd.calls[-1][0] == "bootstrap"
    results = by_id(checks.run_checks(Context()))
    assert results["service"].result == "ok" and results["writer"].result == "ok"


@MACOS_LAUNCHD
def test_agent_with_a_missing_program_is_reported_not_rewritten(launchd):
    launchd.available = True
    assert Tools()("trail", ["init"]) == 0
    agent = checks.agent_path()
    agent.parent.mkdir(parents=True)
    agent.write_bytes(plistlib.dumps({"Label": checks.LABEL, "ProgramArguments": ["/gone/aqt-trail", "serve"]}))
    service = by_id(checks.run_checks(Context()))["service"]
    assert service.result == "warn" and not service.can_apply and "does not exist" in service.explanation
    assert f"launchctl bootout gui/{os.getuid()}/{checks.LABEL}" in service.fix


@MACOS_LAUNCHD
def test_without_a_login_session_the_writer_is_started_by_hand(launchd):
    assert Tools()("trail", ["init"]) == 0
    results = by_id(checks.run_checks(Context()))
    assert results["service"].result == "skip" and "launchd login session" in results["service"].explanation
    assert results["writer"].result == "fail" and not results["writer"].can_apply
    assert "aqt-trail serve" in results["writer"].fix


@MACOS_LAUNCHD
@pytest.mark.skipif(os.environ.get("GITHUB_ACTIONS") != "true", reason="loads a real LaunchAgent: CI runners only")
def test_a_real_agent_under_a_test_label_starts_the_writer(monkeypatch):
    monkeypatch.setattr(checks, "launchctl_run", REAL_LAUNCHCTL)
    monkeypatch.setattr(checks, "LABEL", f"{checks.LABEL}.test-{uuid.uuid4().hex[:8]}")
    ctx = _ctx(writer_wait_s=15.0)
    checks.step_trail_init(ctx)
    try:
        checks.step_service(ctx)
        service = by_id(checks.run_checks(Context()))
        assert service["service"].result == "ok", service["service"].explanation
        assert service["writer"].result == "ok", service["writer"].explanation
    finally:
        subprocess.run(["launchctl", "bootout", checks.launchd_target()], capture_output=True, timeout=30)
        checks.agent_path().unlink(missing_ok=True)

