"""The writer as a Windows logon task (Task Scheduler), with a fake ``schtasks``: the real Task Scheduler
is never touched. The definition itself is checked on every system."""

import sys
from pathlib import Path

from aqt_evidence import platform
from aqt_trail.config import load_config
from aqt_trail.state import init_state

from aqt_cli import checks
from aqt_cli.checks import Context, run_checks
from conftest import WINDOWS_TASK, by_id


def _ctx(**kw):
    kw.setdefault("say", lambda text: None)
    kw.setdefault("writer_wait_s", 5.0)
    return Context(**kw)


def test_the_task_definition_reads_back_with_its_command(schtasks):
    command = ["C:\\Users\\a b\\.venv\\Scripts\\pythonw.exe", "-m", "aqt_trail.cli", "--state",
               "C:\\Users\\a b\\AppData\\Local\\AQT\\trail", "serve"]
    definition = checks.task_xml(command, "S-1-5-21-1-2-3-1001")
    assert "<LogonType>InteractiveToken</LogonType>" in definition and "<ExecutionTimeLimit>PT0S" in definition
    assert "<MultipleInstancesPolicy>IgnoreNew" in definition and "<Interval>PT5M</Interval>" in definition
    schtasks.available = True
    schtasks.tasks[checks.TASK] = definition
    task = checks.query_task(_ctx())
    assert task == {"enabled": True, "command": command[0],
                    "arguments": '-m aqt_trail.cli --state "C:\\Users\\a b\\AppData\\Local\\AQT\\trail" serve'}
    schtasks.available = False
    assert checks.query_task(_ctx()) is None


def test_schtasks_output_in_utf16_and_the_console_code_page_is_read():
    assert checks._decode("<Task>ä</Task>".encode("utf-16")) == "<Task>ä</Task>"
    assert checks._decode("FEHLER: Zugriff verweigert".encode("utf-8")) == "FEHLER: Zugriff verweigert"


@WINDOWS_TASK
def test_setup_registers_the_logon_task_once_and_it_starts_the_writer(schtasks, start_writer):
    config = load_config()
    init_state(config, log_id="trail_test")
    schtasks.available = True
    schtasks.on_run = start_writer
    results = by_id(run_checks(_ctx()))
    assert results["service"].result == "warn" and results["service"].fix == "aqt setup"
    assert "no logon task aqt-trail" in results["service"].explanation
    assert results["writer"].result == "fail" and not results["writer"].can_apply
    checks.step_service(_ctx())
    created = [call for call in schtasks.calls if call[0] == "/Create"]
    assert len(created) == 1 and ("/Run", "/TN", "aqt-trail") in schtasks.calls
    task = checks.query_task(_ctx())
    assert Path(task["command"]).name.lower() in ("pythonw.exe", "aqtw.exe")      # no console window
    assert f'--state "{config.state}"' in task["arguments"] or f"--state {config.state}" in task["arguments"]
    results = by_id(run_checks(_ctx()))
    assert results["service"].result == "ok" and results["writer"].result == "ok"
    assert results["sink"].result == "ok"
    checks.step_service(_ctx())                                     # again: nothing replaced, nothing started
    assert len([call for call in schtasks.calls if call[0] == "/Create"]) == 1


@WINDOWS_TASK
def test_a_disabled_task_is_enabled_and_a_missing_program_reported(schtasks):
    init_state(load_config(), log_id="trail_test")
    schtasks.available = True
    schtasks.tasks[checks.TASK] = checks.task_xml([sys.executable, "-m", "aqt_trail.cli", "serve"], "S-1-5-21-1") \
        .replace("<Enabled>true</Enabled>\n    <Execution", "<Enabled>false</Enabled>\n    <Execution")
    service = by_id(run_checks(_ctx()))["service"]
    assert service.result == "warn" and "disabled" in service.explanation and service.can_apply
    schtasks.tasks[checks.TASK] = checks.task_xml(["C:\\gone\\pythonw.exe", "serve"], "S-1-5-21-1")
    service = by_id(run_checks(_ctx()))["service"]
    assert service.result == "warn" and "does not exist" in service.explanation and not service.can_apply


def test_service_line_names_the_logon_task_on_windows_only():
    describe = {check.id: check.describe(_ctx()) for check in checks.CHECKS}
    assert ("logon task aqt-trail" in describe["service"]) == platform.IS_WINDOWS
    assert ("schtasks /Run" in describe["writer"]) == platform.IS_WINDOWS
