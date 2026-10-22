import io
import json
import subprocess

import pytest

from aqt_change import hooks, plans, receipts
from aqt_change.cli import main
from aqt_change.ledger import Ledger
from conftest import edit, git, read

P = "plans/s01.md"


def test_stop_hook_blocks_phantom_completion(ledger, project):
    plans.begin(ledger, P)
    assert hooks.claude_code({"hook_event_name": "Stop"}, ledger)[0] == 0
    edit(project / P, "- [ ] [V01]", "- [x] [V01]")
    code, message = hooks.claude_code({"hook_event_name": "Stop"}, ledger)
    assert code == 2 and "V01 is ticked" in message
    code, message = hooks.claude_code({"hook_event_name": "Stop", "stop_hook_active": True}, ledger)
    assert code == 0 and "not blocking again" in message
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    assert hooks.claude_code({"hook_event_name": "Stop"}, ledger)[0] == 0


def test_stop_hook_blocks_unreconciled_plan(ledger, project):
    plans.begin(ledger, P)
    edit(project / P, "Add a calculator.", "Add a calculator (edited).")
    code, message = hooks.claude_code({"hook_event_name": "SubagentStop"}, ledger)
    assert code == 2 and "unreconciled" in message


def test_task_completed_hook_checks_referenced_items(ledger, project):
    plans.begin(ledger, P)
    payload = {"hook_event_name": "TaskCompleted", "task_subject": "Verify [V01] passes", "session_id": "x"}
    assert hooks.claude_code(payload, ledger)[0] == 2
    assert hooks.claude_code({**payload, "task_subject": "Write docs"}, ledger)[0] == 0
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    assert hooks.claude_code(payload, ledger)[0] == 0


def test_hooks_ignore_projects_without_active_plans(ledger, project):
    assert hooks.claude_code({"hook_event_name": "Stop"}, ledger) == (0, "")
    assert hooks.claude_code({"hook_event_name": "PreToolUse"}, ledger) == (0, "")


def test_commit_msg_checks_trailers(ledger, project, tmp_path):
    plans.begin(ledger, P)
    [good] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    msg = tmp_path / "msg"
    msg.write_text("Work\n\nAQT-Plan: s01 sha256:abc\nAQT-Receipts: " + good["id"] + "\nAQT-Finish: s01/k1\n")
    assert hooks.commit_msg(ledger, str(msg)) == (0, "")
    msg.write_text("Work\n\nAQT-Plan: nope sha256:abc\nAQT-Receipts: rec_000000000000ffffffffffffffff\n")
    code, message = hooks.commit_msg(ledger, str(msg))
    assert code == 1 and "unknown plan" in message and "unknown receipt" in message
    msg.write_text("Plain commit\n")
    assert hooks.commit_msg(ledger, str(msg))[0] == 0
    assert hooks.commit_msg(ledger, str(msg), require=True)[0] == 1


def test_installed_git_hook_runs_on_real_commits(ledger, project):
    target = hooks.install_git_hook(ledger)
    assert target.exists() and "aqt_change.cli hook commit-msg" in target.read_text()
    with pytest.raises(Exception):
        hooks.install_git_hook(ledger)
    plans.begin(ledger, P)
    (project / "src/x.py").write_text("x = 1\n")
    git(project, "add", "src/x.py")
    bad = subprocess.run(["git", "-C", str(project), "commit", "-qm", "x\n\nAQT-Plan: missing sha256:0"],
                         capture_output=True, text=True)
    assert bad.returncode != 0 and "unknown plan" in bad.stderr
    git(project, "commit", "-qm", "x\n\nAQT-Plan: s01 sha256:0")


def test_hooks_print_snippet(capsys):
    assert main(["hooks", "print"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data["hooks"]) == {"TaskCompleted", "Stop", "SubagentStop"}


def run_cli(capsys, *args):
    code = main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_end_to_end(project, capsys, monkeypatch, tmp_path):
    assert run_cli(capsys, "plan", "status")[0] == 0
    edit(project / P, "Add a calculator.", "Add a small calculator.")
    code, out, _ = run_cli(capsys, "plan", "status", P, "--json")
    assert code == 1 and json.loads(out)["plans"][0]["state"] == "unregistered"
    assert run_cli(capsys, "plan", "add", P)[0] == 0
    assert run_cli(capsys, "begin", P)[0] == 0
    code, out, _ = run_cli(capsys, "run", "--plan", P, "--all", "--quiet")
    assert code == 0 and out.startswith("PASS V01")
    code, _, err = run_cli(capsys, "finish", P, "--key", "k1", "--summary", "done")
    assert code == 1 and "finish_evidence_missing" in err          # V02 not attested
    assert run_cli(capsys, "attest", P, "--item", "V02", "--reason", "checked by hand")[0] == 0
    code, _, err = run_cli(capsys, "finish", P, "--key", "k1", "--summary", "done")
    assert code == 1 and "finish_ack_required" in err              # open tasks
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")
    code, out, _ = run_cli(capsys, "finish", P, "--key", "k1", "--summary", "done", "--json")
    assert code == 0 and json.loads(out)["gate"] == "GO"
    gate_file = tmp_path / "gate.json"
    report_file = tmp_path / "report.html"
    code, out, _ = run_cli(capsys, "report", P, "--format", "html", "--out", str(report_file),
                           "--gate", str(gate_file))
    assert code == 0 and json.loads(gate_file.read_text())["decision"] == "GO"
    html = report_file.read_text()
    assert "<table>" in html and "not a validated system" in html
    code, out, _ = run_cli(capsys, "report", P)
    assert "## Verification" in out and "| V01 |" in out
    assert run_cli(capsys, "gate", P)[0] == 0
    (project / "src/calc.py").write_text("def add(a, b):\n    return 0\n")
    code, out, _ = run_cli(capsys, "gate", P)
    assert code == 1 and json.loads(out)["decision"] == "NO-GO"
    code, out, _ = run_cli(capsys, "reconcile-diff", P, "--json")
    assert code == 1 and json.loads(out)["data"]["missing_evidence"]


def test_cli_usage_errors(project, capsys):
    code, _, err = run_cli(capsys, "run")
    assert code == 2 and "command_required" in err
    code, _, err = run_cli(capsys, "reconcile", "plans/missing.md", "--kind", "editorial")
    assert code == 2 and "plan_not_found" in err
    code, _, err = run_cli(capsys, "finish", P, "--key", "bad key", "--summary", "x")
    assert code == 2


def test_cli_claude_code_hook_reads_stdin(project, capsys, monkeypatch):
    led = Ledger.open(project)
    plans.begin(led, P)
    edit(project / P, "- [ ] [V01]", "- [x] [V01]")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "Stop", "cwd": str(project)})))
    code, _, err = run_cli(capsys, "hook", "claude-code")
    assert code == 2 and "no fresh passing receipt" in err


def test_every_written_record_is_valid(project, capsys, evidence_file):
    from aqt_evidence import read_jsonl, validate_record
    run_cli(capsys, "begin", P)
    run_cli(capsys, "run", "--plan", P, "--all", "--quiet")
    run_cli(capsys, "attest", P, "--item", "V02", "--reason", "seen")
    run_cli(capsys, "review", "add", P, "--reviewer", "agent:codex:1", "--independence", "fresh-context",
            "--verdict", "PASS", "--reason", "fine")
    run_cli(capsys, "reconcile-diff", P)
    run_cli(capsys, "finish", P, "--key", "k1", "--summary", "done", "--ack-warnings", "tasks later")
    records = list(read_jsonl(evidence_file))
    assert {r["type"] for r in records} == {"change.plan.reconciled", "change.receipt", "change.review",
                                            "change.reconciliation", "change.finish"}
    assert all(validate_record(r) == [] for r in records)
