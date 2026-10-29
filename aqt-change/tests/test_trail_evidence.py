"""Receipts and reviews must be in the trail when a trail is in use; hidden working-tree changes block.

A small stand-in for the aqt-trail writer (ping and append over a Unix socket into
``trail.jsonl`` at the default trail location) keeps this suite free of an aqt-trail dependency.
"""

import copy
import json
import os
import shutil
import socketserver
import tempfile
import threading
from pathlib import Path

import pytest
from aqt_evidence import canonical_json, new_id

from aqt_change import gitio, hooks, plans, receipts
from aqt_change.errors import ChangeError
from aqt_change.finish import finish
from aqt_change.gate import gate
from aqt_change.ledger import Ledger
from aqt_change.review import add_review
from aqt_change.scope import reconcile_diff
from conftest import CHECK_SCRIPT, edit, git

P = "plans/s01.md"


class FakeTrail:
    def __init__(self, state: Path, socket_path: Path):
        state.mkdir(parents=True, exist_ok=True)
        (state / "trail.json").write_text("{}")
        self.log, self.seq, self.lock = state / "trail.jsonl", -1, threading.Lock()
        trail = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                payload = json.loads(self.rfile.readline())
                if payload.get("op") == "append":
                    answer = {"ok": True, "record": trail.add(payload["record"], "socket"), "created": True}
                else:
                    answer = {"ok": True, "version": "fake"}
                self.wfile.write(canonical_json(answer) + b"\n")

        self.server = socketserver.UnixStreamServer(str(socket_path), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def add(self, record: dict, via: str) -> dict:
        with self.lock:
            self.seq += 1
            stored = dict(record, observed={"via": via, "process_chain": []},
                          chain={"seq": self.seq, "prev": "sha256:" + "0" * 64})
            with open(self.log, "ab") as handle:
                handle.write(canonical_json(stored) + b"\n")
            return stored


@pytest.fixture
def trail(isolated, monkeypatch):
    short = Path(tempfile.mkdtemp(prefix="aqtc", dir="/tmp"))
    monkeypatch.setenv("AQT_SINK", f"unix:{short / 'trail.sock'}")
    fake = FakeTrail(isolated / "state" / "aqt" / "trail", short / "trail.sock")
    yield fake
    fake.server.shutdown()
    fake.server.server_close()
    shutil.rmtree(short, ignore_errors=True)


def reasons(result):
    return {r["code"] for r in result["reasons"]}


def forge(ledger, receipt: dict, **data) -> dict:
    """What a gaming agent can do without the writer: append to the local mirror."""
    fake = copy.deepcopy(receipt)
    for key in ("chain", "observed", "sig"):
        fake.pop(key, None)
    fake["id"] = new_id()
    fake["data"].update(data)
    with open(ledger.state / "records.jsonl", "ab") as handle:
        handle.write(canonical_json(fake) + b"\n")
    return fake


def broken(ledger, project) -> dict:
    """Begin, break the code, tick V01 and record the honest failing receipt."""
    plans.begin(ledger, P)
    (project / "src/calc.py").write_text("def add(a, b):\n    return a - b\n")
    edit(project / P, "- [ ] [V01]", "- [x] [V01]")
    [failed] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    assert failed["data"]["passed"] is False and failed["observed"]["via"] == "socket"
    return failed


def test_forged_mirror_receipt_does_not_count_with_a_trail(ledger, project, trail, tmp_path):
    failed = broken(ledger, project)
    fake = forge(ledger, failed, passed=True, exit_code=0, outcome="passed",
                 counts={"source": "pytest", "passed": 1, "total": 1})
    result = gate(ledger, P)
    assert result["decision"] == "NO-GO" and "receipt_unverified" in reasons(result)
    assert result["trail"]["checked"] and fake["id"] not in result["receipts"]
    code, message = hooks.claude_code({"hook_event_name": "Stop"}, ledger)       # same verdict as the gate
    assert code == 2 and "not in the aqt-trail log" in message
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done", ack_warnings="tasks later")
    assert info.value.code == "finish_evidence_missing" and "unverified" in info.value.message
    msg = tmp_path / "msg"
    msg.write_text(f"Work\n\nAQT-Plan: s01 sha256:abc\nAQT-Receipts: {fake['id']}\n")
    code, message = hooks.commit_msg(ledger, str(msg))
    assert code == 1 and "not in the aqt-trail log" in message


def test_file_sink_in_the_environment_does_not_switch_the_check_off(ledger, project, trail, tmp_path, monkeypatch):
    failed = broken(ledger, project)
    forge(ledger, failed, passed=True, exit_code=0, outcome="passed", counts={"source": "pytest", "passed": 1, "total": 1})
    monkeypatch.setenv("AQT_SINK", f"file:{tmp_path / 'x.jsonl'}")       # the agent's own environment
    result = gate(ledger, P)
    assert result["trail"]["checked"] and result["decision"] == "NO-GO" and "receipt_unverified" in reasons(result)
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done", ack_warnings="tasks later")
    assert info.value.code == "finish_evidence_missing" and "unverified" in info.value.message
    assert hooks.claude_code({"hook_event_name": "Stop"}, ledger)[0] == 2


def test_edited_mirror_copy_mismatches_the_trail(ledger, project, trail):
    failed = broken(ledger, project)
    lines = (ledger.state / "records.jsonl").read_bytes().splitlines()
    edited = copy.deepcopy(failed)
    edited["data"].update(passed=True, exit_code=0, outcome="passed")
    lines = [canonical_json(edited) if json.loads(line)["id"] == failed["id"] else line for line in lines]
    (ledger.state / "records.jsonl").write_bytes(b"\n".join(lines) + b"\n")
    result = gate(ledger, P)
    assert result["decision"] == "NO-GO"
    assert any(r["code"] == "receipt_unverified" and "differs" in r["detail"] for r in result["reasons"])


def test_honest_run_through_the_trail_reaches_go(ledger, project, trail):
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    receipts.attest(ledger, P, "V02", [], "seen")
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")
    finish(ledger, P, key="k1", summary="done")
    result = gate(ledger, P)
    assert result["decision"] == "GO", result["reasons"]
    # a spooled copy drained into the trail has no observed sender: manual verification
    [again] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    trail.add(forge(ledger, again), "spool")
    result = gate(ledger, P)
    assert result["decision"] == "MANUAL_VERIFY_REQUIRED"
    assert any("through the spool" in r.get("detail", "") for r in result["reasons"])


def test_forged_review_cannot_replace_a_fail(ledger, project, trail):
    plans.begin(ledger, P)
    fail = add_review(ledger, P, reviewer="agent:x:1", independence="same-session", verdict="FAIL", reason="broken")
    forge(ledger, fail, verdict="PASS")
    result = gate(ledger, P)
    assert {"review_fail", "review_unverified"} <= reasons(result) and result["decision"] == "NO-GO"


def test_trail_in_use_but_log_unreadable_needs_manual_check(ledger, project, trail):
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    trail.log.rename(trail.log.with_suffix(".moved"))
    entry = receipts.evaluate(ledger, plans.read_plan(ledger, P)[1])["V01"]
    assert entry["state"] == "unverified" and entry["untrusted"][0]["trust"] == "unreadable"


def test_without_a_trail_the_mirror_counts(ledger, project):
    """No trail log and a file sink: today's behaviour, a documented limit."""
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    entry = receipts.evaluate(ledger, plans.read_plan(ledger, P)[1])["V01"]
    assert entry["state"] == "ok" and entry["untrusted"] == []


@pytest.mark.parametrize("flag", ["--skip-worktree", "--assume-unchanged"])
def test_index_flags_cannot_hide_a_weakened_check(ledger, project, flag):
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    git(project, "update-index", flag, "tests/check.py")
    assert "hidden_worktree_change" not in reasons(gate(ledger, P))                 # flag alone: nothing hidden
    (project / "src/calc.py").write_text("def add(a, b):\n    return a - b\n")
    (project / "tests/check.py").write_text(CHECK_SCRIPT.replace("ok = calc.add(2, 3) == 5", "ok = True"))
    assert "check.py" not in git(project, "status", "--porcelain")                  # Git hides it
    assert receipts.evaluate(ledger, plans.read_plan(ledger, P)[1])["V01"]["state"] == "stale"
    [record] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    assert record["data"]["passed"] and "hidden_worktree_change" in {w["code"] for w in record["data"]["warnings"]}
    result = gate(ledger, P)
    assert result["decision"] == "NO-GO" and "hidden_worktree_change" in reasons(result)
    edit(project / P, "- [ ] [V01]", "- [x] [V01]")
    code, message = hooks.claude_code({"hook_event_name": "Stop"}, ledger)
    assert code == 2 and "tests/check.py" in message
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done", waivers={"V02": "no screen"}, ack_warnings="later")
    assert info.value.code == "finish_hidden_changes"


def test_sparse_checkout_needs_manual_check_not_no_go(ledger, project):
    plans.begin(ledger, P)
    git(project, "sparse-checkout", "set", "src", "plans")
    assert not (project / "tests/check.py").exists()
    result = gate(ledger, P)
    assert "sparse_checkout" in reasons(result) and "hidden_worktree_change" not in reasons(result)


# --- hidden changes through Git's stat cache ------------------------------------------------------

def _fsmonitor(project, tmp_path):
    """A core.fsmonitor hook that always answers 'nothing changed' (protocol v2: token, NUL, no paths)."""
    hook = tmp_path / "fsmonitor.sh"
    hook.write_text("#!/bin/sh\nprintf 'token\\0'\n")
    hook.chmod(0o755)
    git(project, "config", "core.fsmonitor", str(hook))
    git(project, "status", "--porcelain")
    git(project, "status", "--porcelain")


def _relaxed_stat(project, tmp_path):
    """core.checkStat=minimal and core.trustctime=false: a same-size edit with the old mtime is not seen."""
    git(project, "config", "core.checkStat", "minimal")
    git(project, "config", "core.trustctime", "false")
    for name in ("tests/check.py", "src/calc.py"):
        os.utime(project / name, (1_600_000_000, 1_600_000_000))      # older than the index: not racy
    git(project, "status", "--porcelain")                                        # Git stores the new stat data


def _same_size_edit(path, old, new):
    stamp = path.stat().st_mtime
    assert len(old) == len(new)
    edit(path, old, new)
    os.utime(path, (stamp, stamp))


@pytest.mark.parametrize("hide", [_fsmonitor, _relaxed_stat], ids=["fsmonitor", "checkstat"])
def test_stat_cache_cannot_hide_a_weakened_check(ledger, project, tmp_path, hide):
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    hide(project, tmp_path)
    _same_size_edit(project / "src/calc.py", "return a + b", "return a - b")
    _same_size_edit(project / "tests/check.py", "ok = calc.add(2, 3) == 5", "ok = calc.add(2, 3) != 5")
    status = git(project, "status", "--porcelain")
    assert "check.py" not in status and "calc.py" not in status                    # Git sees nothing
    entry = receipts.evaluate(ledger, plans.read_plan(ledger, P)[1])["V01"]
    assert entry["state"] == "stale"                                                # the content changed
    [record] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    assert record["data"]["passed"] and "hidden_worktree_change" in {w["code"] for w in record["data"]["warnings"]}
    result = gate(ledger, P)
    assert result["decision"] == "NO-GO" and "hidden_worktree_change" in reasons(result)
    assert "tests/check.py" in next(r["detail"] for r in result["reasons"] if r["code"] == "hidden_worktree_change")
    edit(project / P, "- [ ] [V01]", "- [x] [V01]")
    code, message = hooks.claude_code({"hook_event_name": "Stop"}, ledger)
    assert code == 2 and "tests/check.py" in message
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done", paths=["src/calc.py"], waivers={"V02": "no screen"},
               ack_warnings="later")
    assert info.value.code == "finish_hidden_changes"


def test_untouched_tree_has_the_same_fingerprint_as_before(ledger, project):
    """Hashing every tracked file gives the value the stat-based fingerprint gave: old receipts stay fresh."""
    (project / "src/calc.py").write_text("def add(a, b):\n    return a + b  # edited\n")
    (project / "notes.txt").write_text("untracked\n")
    (project / "tests/check.py").unlink()
    tree = ledger.git.head_tree()
    tree.pop("tests/check.py")
    tree.update(ledger.git.hash_paths(["src/calc.py", "notes.txt"]))
    assert ledger.fingerprint([P]) == gitio._digest(tree, {P}, [])
    os.symlink("calc.py", project / "src/alias.py")             # a symlink counts by its link text, as Git stores it
    git(project, "add", "src/alias.py")
    tree["src/alias.py"] = git(project, "ls-files", "-s", "src/alias.py").split()[1]
    assert ledger.fingerprint([P]) == gitio._digest(tree, {P}, [])
    assert ledger.git.hidden_changes() == []


# --- the project can require the trail --------------------------------------------------------------

def _require_trail(project):
    (project / ".aqt").mkdir()
    (project / ".aqt/change.toml").write_text("# aqt-change project settings\nrequire_trail = true\n")
    git(project, "add", ".aqt/change.toml")
    git(project, "commit", "-qm", "require the trail")


def _agent_env(monkeypatch, tmp_path):
    """What an agent can do to its own environment: no trail found, records to a file."""
    empty = tmp_path / "empty"
    empty.mkdir(exist_ok=True)
    for name in ("XDG_STATE_HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR"):
        monkeypatch.setenv(name, str(empty))
    monkeypatch.setenv("AQT_SINK", f"file:{empty / 'evidence.jsonl'}")
    monkeypatch.delenv("AQT_EVIDENCE", raising=False)


def test_required_trail_missing_blocks_everything(ledger, project, tmp_path, monkeypatch):
    _require_trail(project)
    _agent_env(monkeypatch, tmp_path)
    plans.begin(ledger, P)
    edit(project / P, "- [ ] [V01]", "- [x] [V01]")
    [receipt] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    result = gate(ledger, P)
    assert result["decision"] == "NO-GO" and {"trail_required", "receipt_unverified"} <= reasons(result)
    assert result["trail"]["checked"] and result["trail"]["required"]
    assert "require_trail" in next(r["detail"] for r in result["reasons"] if r["code"] == "trail_required")
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done", waivers={"V02": "no screen"}, ack_warnings="later")
    assert info.value.code == "finish_trail_required"
    code, message = hooks.claude_code({"hook_event_name": "Stop"}, ledger)
    assert code == 2 and "require_trail" in message
    msg = tmp_path / "msg"
    msg.write_text(f"Work\n\nAQT-Plan: s01 sha256:abc\nAQT-Receipts: {receipt['id']}\n")
    code, message = hooks.commit_msg(ledger, str(msg))
    assert code == 1 and "require_trail" in message


def test_required_trail_cannot_be_switched_off_during_a_plan(ledger, project, tmp_path, monkeypatch):
    _require_trail(project)
    plans.begin(ledger, P)
    _agent_env(monkeypatch, tmp_path)
    (project / ".aqt/change.toml").write_text("require_trail = false\n")              # working tree only
    assert ledger.trail_check().required
    git(project, "commit", "-qam", "relax")                                          # committed: still the base's
    assert Ledger.open(project).trail_check().required
    result = gate(Ledger.open(project), P)
    assert {"trail_required", "project_settings_changed"} <= reasons(result) and result["decision"] == "NO-GO"
    assert reconcile_diff(Ledger.open(project), P)["data"]["settings_changed"] == [".aqt/change.toml"]


def test_required_trail_with_the_trail_reaches_go(ledger, project, trail):
    _require_trail(project)
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    receipts.attest(ledger, P, "V02", [], "seen")
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")
    finish(ledger, P, key="k1", summary="done")
    result = gate(ledger, P)
    assert result["decision"] == "GO", result["reasons"]
    assert result["trail"]["required"] and result["trail"]["logs"]


def test_invalid_project_settings_refuse(ledger, project):
    (project / ".aqt").mkdir()
    (project / ".aqt/change.toml").write_text("require_trail = 'yes'\n")
    with pytest.raises(ChangeError) as info:
        gate(ledger, P)
    assert info.value.code == "config_invalid"


def test_trail_history_keeps_the_check_on_without_a_trail(ledger, project, trail, tmp_path, monkeypatch):
    """Records came back from a writer earlier; an environment without a trail does not count the mirror."""
    failed = broken(ledger, project)
    fake = forge(ledger, failed, passed=True, exit_code=0, outcome="passed",
                 counts={"source": "pytest", "passed": 1, "total": 1})
    _agent_env(monkeypatch, tmp_path)
    led = Ledger.open(project)
    entry = receipts.evaluate(led, plans.read_plan(led, P)[1])["V01"]
    assert entry["state"] == "unverified" and entry["untrusted"] == [{"receipt": fake["id"], "trust": "unreadable"}]
    result = gate(led, P)
    assert result["decision"] != "GO" and "receipt_unverified" in reasons(result) and result["trail"]["checked"]
    with pytest.raises(ChangeError) as info:
        finish(led, P, key="k1", summary="done", paths=["src/calc.py"], ack_warnings="tasks later")
    assert info.value.code == "finish_evidence_missing"
    assert hooks.claude_code({"hook_event_name": "Stop"}, led)[0] == 2
