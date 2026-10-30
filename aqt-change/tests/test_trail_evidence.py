"""Receipts and reviews must be in the trail when a trail is in use; hidden working-tree changes block.

A small stand-in for the aqt-trail writer (ping and append over a Unix socket into
``trail.jsonl`` at the default trail location, records signed with a fixed service key whose public key
is in ``keys/``) keeps this suite free of an aqt-trail dependency.
"""

import copy
import json
import os
import py_compile
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest
from aqt_evidence import GENESIS, canonical_json, new_id, sign_record, signer_from_seed
from aqt_evidence.crypto import public_pem

from aqt_change import gitio, hooks, plans, receipts
from aqt_change.errors import ChangeError
from aqt_change.finish import finish
from aqt_change.gate import gate
from aqt_change.ledger import Ledger, TrailCheck
from aqt_change.review import add_review
from aqt_change.scope import reconcile_diff
from conftest import CHECK_SCRIPT, edit, git

P = "plans/s01.md"


class FakeTrail:
    def __init__(self, state: Path, socket_path: Path):
        state.mkdir(parents=True, exist_ok=True)
        (state / "trail.json").write_text("{}")
        self.log, self.seq, self.lock = state / "trail.jsonl", -1, threading.Lock()
        self.signer = signer_from_seed(b"\x01" * 32)
        self.key_id = self.signer.key_id
        (state / "keys").mkdir(exist_ok=True)
        (state / "keys" / "service.key.pub").write_bytes(public_pem(self.signer.public_key))
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
            stored = sign_record(dict(record, observed={"via": via, "process_chain": []},
                                      chain={"seq": self.seq, "prev": "sha256:" + "0" * 64}), self.signer)
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


# --- pinned trail keys -------------------------------------------------------------------------------

def _pin(project, *key_ids, commit=True):
    (project / ".aqt").mkdir(exist_ok=True)
    (project / ".aqt/change.toml").write_text("trail_keys = [" + ", ".join(f'"{k}"' for k in key_ids) + "]\n")
    if commit:
        git(project, "add", ".aqt/change.toml")
        git(project, "commit", "-qm", "pin the trail key")


def _own_log(tmp_path, records, public_key) -> Path:
    """A trail.jsonl the agent writes itself: the records as if received over the socket, signed by its own
    key, next to a keys/ folder with ``public_key``."""
    agent = signer_from_seed(b"\x02" * 32)
    own = tmp_path / "own"
    (own / "keys").mkdir(parents=True, exist_ok=True)
    (own / "keys" / "service.key.pub").write_bytes(public_pem(public_key or agent.public_key))
    lines = [canonical_json(sign_record(dict(r, observed={"via": "socket"}, chain={"seq": n, "prev": GENESIS}),
                                        agent)) for n, r in enumerate(records)]
    (own / "trail.jsonl").write_bytes(b"\n".join(lines) + b"\n")
    return own / "trail.jsonl"


def test_pinned_trail_key_rejects_a_log_the_agent_wrote(ledger, project, trail, tmp_path, monkeypatch):
    _require_trail(project)
    failed = broken(ledger, project)
    _pin(project, trail.key_id, commit=False)           # the real trail's service key (any copy pins it)
    fake = forge(ledger, failed, passed=True, exit_code=0, outcome="passed", tree_fingerprint=ledger.fingerprint([P]),
                 counts={"source": "pytest", "passed": 1, "total": 1})
    _agent_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AQT_EVIDENCE", str(_own_log(tmp_path, [fake], None)))
    assert TrailCheck([fake], required=True).status(fake) == "ok"     # unpinned: the agent's own log confirms it
    led = Ledger.open(project)
    entry = receipts.evaluate(led, plans.read_plan(led, P)[1])["V01"]
    assert entry["state"] == "unverified" and entry["untrusted"][0]["trust"] == "required"
    result = gate(led, P)
    assert result["decision"] == "NO-GO" and "trail_required" in reasons(result)
    assert result["trail"]["keys"] == [trail.key_id] and result["trail"]["logs"] == []
    # with the real public key copied next to its log, the agent's signature still is not the writer's
    monkeypatch.setenv("AQT_EVIDENCE", str(_own_log(tmp_path, [fake], trail.signer.public_key)))
    led = Ledger.open(project)
    entry = receipts.evaluate(led, plans.read_plan(led, P)[1])["V01"]
    assert entry["state"] == "unverified" and entry["untrusted"][0]["trust"] == "unsigned"
    result = gate(led, P)
    assert result["decision"] == "NO-GO" and any(r["code"] == "receipt_unverified" and "pinned" in r["detail"]
                                                 for r in result["reasons"])
    with pytest.raises(ChangeError) as info:
        finish(led, P, key="k1", summary="done", waivers={"V02": "no screen"}, ack_warnings="later")
    assert info.value.code == "finish_evidence_missing"


def test_pinned_trail_key_cannot_be_widened_in_the_working_tree(ledger, project, trail, tmp_path, monkeypatch):
    _pin(project, trail.key_id)
    failed = broken(ledger, project)
    agent_key = signer_from_seed(b"\x02" * 32).key_id
    _pin(project, trail.key_id, agent_key, commit=False)                        # the agent adds its own key
    fake = forge(ledger, failed, passed=True, exit_code=0, outcome="passed", tree_fingerprint=ledger.fingerprint([P]),
                 counts={"source": "pytest", "passed": 1, "total": 1})
    monkeypatch.setenv("AQT_EVIDENCE", str(_own_log(tmp_path, [fake], None)))
    led = Ledger.open(project)
    assert led.project_settings()["trail_keys"] == [trail.key_id]               # only what every copy pins
    assert receipts.evaluate(led, plans.read_plan(led, P)[1])["V01"]["state"] == "unverified"


def test_pinned_trail_key_with_the_real_trail_reaches_go(ledger, project, trail):
    _pin(project, trail.key_id)
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    receipts.attest(ledger, P, "V02", [], "seen")
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")
    finish(ledger, P, key="k1", summary="done")
    result = gate(ledger, P)
    assert result["decision"] == "GO", result["reasons"]
    assert result["trail"]["required"] and result["trail"]["keys"] == [trail.key_id] and result["trail"]["logs"]


# --- files that only local ignore rules hide ------------------------------------------------------------

@pytest.mark.parametrize("rule", ["info-exclude", "excludes-file"])
def test_locally_ignored_files_do_not_escape_the_fingerprint(ledger, project, isolated, rule):
    """A conftest.py hidden by .git/info/exclude or core.excludesFile is loaded by the test run but is not in a
    clean checkout: the gate asks for a manual check, and deleting it after the run makes the receipt stale."""
    if rule == "info-exclude":
        with open(project / ".git/info/exclude", "a") as handle:
            handle.write("conftest.py\n")
    else:                                                   # Git's default core.excludesFile
        (isolated / "config" / "git").mkdir(parents=True)
        (isolated / "config" / "git" / "ignore").write_text("conftest.py\n")
    plans.begin(ledger, P)
    (project / "conftest.py").write_text("# steers the test run\n")
    assert "conftest.py" not in git(project, "status", "--porcelain")               # Git hides it
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    receipts.attest(ledger, P, "V02", [], "seen")
    result = gate(ledger, P)
    detail = next(r["detail"] for r in result["reasons"] if r["code"] == "locally_ignored_files")
    assert "conftest.py" in detail
    (project / "conftest.py").unlink()
    entry = receipts.evaluate(ledger, plans.read_plan(ledger, P)[1])["V01"]
    assert entry["state"] == "stale"
    assert "locally_ignored_files" not in reasons(gate(ledger, P))


def test_locally_ignored_file_in_the_plan_scope_blocks_finish(ledger, project):
    with open(project / ".git/info/exclude", "a") as handle:
        handle.write("src/helper.py\n")
    plans.begin(ledger, P)
    (project / "src/helper.py").write_text("HELP = 1\n")
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    receipts.attest(ledger, P, "V02", [], "seen")
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done")
    assert info.value.code == "finish_tested_change_not_committed"
    assert "src/helper.py (ignored locally)" in info.value.message and "info/exclude" in info.value.message


def test_untracked_gitignore_does_not_hide_files(ledger, project):
    """An untracked .gitignore that ignores itself is a local rule: a package it hides (src/calc/ shadows the
    committed src/calc.py for the test run) is fingerprinted, reported and blocks finish."""
    plans.begin(ledger, P)
    (project / "src/calc.py").write_text("def add(a, b):\n    return a - b\n")            # wrong, committed later
    (project / "src/calc").mkdir()
    (project / "src/calc/__init__.py").write_text("def add(a, b):\n    return a + b\n")   # what the run imports
    (project / "src/.gitignore").write_text("/.gitignore\n/calc/\n")
    assert git(project, "status", "--porcelain") == " M plans/s01.md\n M src/calc.py\n"   # Git hides both
    [record] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    assert record["data"]["passed"]
    receipts.attest(ledger, P, "V02", [], "seen")
    assert ledger.git.local_ignored() == ["src/.gitignore", "src/calc/__init__.py"]
    result = gate(ledger, P)
    detail = next(r["detail"] for r in result["reasons"] if r["code"] == "locally_ignored_files")
    assert "src/calc/__init__.py" in detail and "untracked .gitignore" in detail
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done", paths=["src/calc.py"])
    assert info.value.code == "finish_tested_change_not_committed"
    assert "src/calc/__init__.py (ignored locally)" in info.value.message
    shutil.rmtree(project / "src/calc")                                                   # removed after the run
    assert receipts.evaluate(ledger, plans.read_plan(ledger, P)[1])["V01"]["state"] == "stale"


def test_tracked_gitignore_rules_ignore_as_git_does(project):
    """Only tracked .gitignore files count, read with Git's meaning (nested, anchored, negated, directory-only)."""
    rules = {".gitignore": "__pycache__/\n*.log\n!keep.log\n/top.txt\nbuild/\n\\#hash\n",
             "a/.gitignore": "*.tmp\n/only.txt\nsub/deep.txt\n!important.tmp\nnested/\n**/z.dat\n",
             "a/b/.gitignore": "*\r\n!*.keep\r\n!.gitignore\r\n", "we*rd/.gitignore": "x*\n!xkeep\n"}
    for name, text in rules.items():
        (project / name).parent.mkdir(parents=True, exist_ok=True)
        (project / name).write_text(text)
    git(project, "add", *rules)
    git(project, "commit", "-qm", "ignore rules")
    for name in ("top.txt", "a/top.txt", "x.log", "keep.log", "a/x.log", "a/keep.log", "build/o", "a/build/o",
                 "#hash", "a/y.tmp", "a/important.tmp", "a/c/w.tmp", "a/only.txt", "a/b/only.txt", "a/sub/deep.txt",
                 "a/q/sub/deep.txt", "a/m/z.dat", "z.dat", "a/nested/f", "a/x/nested/f", "a/b/f.keep", "a/b/f.txt",
                 "we*rd/xa", "we*rd/xkeep", "we*rd/d/xb", "we*rd/ya"):
        (project / name).parent.mkdir(parents=True, exist_ok=True)
        (project / name).write_text("x\n")
    led = Ledger.open(project)
    assert sorted(led.git.untracked(repository_rules=True)) == sorted(
        led.git._others("--exclude-per-directory=.gitignore"))
    assert "a/keep.log" in led.git.untracked(repository_rules=True) and led.git.local_ignored() == []
    for folder in ("aqt/.venv", ".pytest_cache", "src/calc"):                    # a tool's own "ignore all of me"
        (project / folder).mkdir(parents=True)
        (project / folder / ".gitignore").write_text("*\n")
        (project / folder / "inside.py").write_text("x = 1\n")
    assert led.git.local_ignored() == ["src/calc/.gitignore", "src/calc/inside.py"]   # only tool folders count


def test_existing_bytecode_does_not_stand_in_for_the_source(ledger, project):
    """A .pyc of a correct implementation in src/__pycache__/ (ignored by the committed .gitignore) makes plain
    Python pass while the committed source is wrong; aqt-change runs with a fresh bytecode cache."""
    plans.begin(ledger, P)
    good = project.parent / "good_calc.py"
    good.write_text("def add(a, b):\n    return a + b\n")
    (project / "src/calc.py").write_text("def add(a, b):\n    return a - b\n")
    cached = project / "src/__pycache__" / f"calc.{sys.implementation.cache_tag}.pyc"
    py_compile.compile(str(good), cfile=str(cached), dfile="src/calc.py",
                       invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPYCACHEPREFIX"}
    assert subprocess.run([sys.executable, "tests/check.py"], cwd=project, env=env,
                          capture_output=True).returncode == 0                          # plain Python is fooled
    [record] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    assert record["data"]["passed"] is False and record["data"]["env"]["python_bytecode"] == "fresh"
    assert cached.exists() and not any(p.name != cached.name for p in cached.parent.iterdir())
    assert gate(ledger, P, rerun=True)["items"]["V01"]["state"] == "failed"


# --- the plan's base commit ---------------------------------------------------------------------------------

def _strict_settings(project):
    (project / ".aqt").mkdir(exist_ok=True)
    (project / ".aqt/change.toml").write_text("require_trail = true\n[gate]\nrequire_signed_approval = true\n")
    git(project, "add", ".aqt/change.toml")
    git(project, "commit", "-qm", "project settings")


def _drop_settings_and_move_base(ledger, project, status=None):
    """The agent: a plain commit that removes the project settings, then the plan state's base commit (and
    perhaps its status) set to the new HEAD, so the diff no longer shows the removal."""
    git(project, "rm", "-q", ".aqt/change.toml")
    git(project, "commit", "-qm", "chore: tidy config")
    path = ledger.state / "plans" / "s01.json"
    state = json.loads(path.read_text())
    state["base_commit"] = git(project, "rev-parse", "HEAD").strip()
    if status:
        state["status"] = status
    path.write_text(json.dumps(state))


def _done(ledger, project):
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    receipts.attest(ledger, P, "V02", [], "seen")
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")


@pytest.mark.parametrize("status", [None, "completed"])
def test_edited_base_commit_cannot_drop_the_project_settings(ledger, project, trail, status):
    _strict_settings(project)
    _done(ledger, project)
    before = gate(ledger, P)
    assert before["policy"]["require_signed_approval"] and "approval_unsigned" in reasons(before)
    _drop_settings_and_move_base(ledger, project, status)
    led = Ledger.open(project)
    receipts.run(led, [], plan_path=P, item="V01", echo=False)
    receipts.attest(led, P, "V02", [], "seen")
    result = gate(led, P)
    assert result["decision"] == "NO-GO"
    assert reasons(result) == {"plan_base_mismatch", "approval_unsigned", "not_finished"}
    assert result["policy"]["require_signed_approval"] and result["trail"]["required"]
    detail = next(r["detail"] for r in result["reasons"] if r["code"] == "plan_base_mismatch")
    assert "aqt-trail log" in detail and before["scope"]["base_commit"] in detail
    with pytest.raises(ChangeError) as info:
        finish(led, P, key="k1", summary="done")
    assert info.value.code == "finish_plan_base_mismatch"
    # a made-up begin record for the new base, sent through the writer: still a manual check, settings strict
    real = next(r for r in led.records("change.plan.reconciled") if r["action"] == "begin")
    made_up = copy.deepcopy({k: v for k, v in real.items() if k not in ("chain", "observed", "sig")})
    made_up["id"], made_up["data"]["base_commit"] = new_id(), git(project, "rev-parse", "HEAD").strip()
    trail.add(made_up, "socket")
    led = Ledger.open(project)
    problem = led.base_problem("s01", led.trail_check("s01"))
    assert problem["code"] == "plan_base_mismatch" and not problem["nogo"]             # several: MANUAL
    result = gate(led, P)
    assert {"plan_base_mismatch", "approval_unsigned"} <= reasons(result) and result["policy"]["require_signed_approval"]


def test_edited_base_commit_without_a_trail_needs_a_manual_check(ledger, project):
    """Without a trail, the begin record in the local mirror still names the real base commit."""
    _strict_settings(project)
    _done(ledger, project)
    _drop_settings_and_move_base(ledger, project)
    result = gate(Ledger.open(project), P)
    assert {"plan_base_mismatch", "approval_unsigned"} <= reasons(result) and result["policy"]["require_signed_approval"]
    assert "local mirror" in next(r["detail"] for r in result["reasons"] if r["code"] == "plan_base_mismatch")


def test_settings_set_by_a_commit_during_the_plan_count_after_it_is_reverted(ledger, project):
    _done(ledger, project)
    (project / ".aqt").mkdir()
    (project / ".aqt/change.toml").write_text("[gate]\nrequire_signed_approval = true\n")
    git(project, "add", ".aqt/change.toml")
    git(project, "commit", "-qm", "stricter")                                        # the owner, during the plan
    (project / ".aqt/change.toml").write_text("require_trail = 'yes'\n")
    git(project, "commit", "-qam", "unreadable")                                     # a broken copy in between
    git(project, "rm", "-q", ".aqt/change.toml")
    git(project, "commit", "-qm", "gone again")                                      # the agent
    result = gate(Ledger.open(project), P)
    assert result["policy"]["require_signed_approval"] and "approval_unsigned" in reasons(result)
    assert "project_settings_changed" in reasons(result)
