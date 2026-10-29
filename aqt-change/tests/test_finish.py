import json
import shutil
import subprocess

import pytest
from aqt_evidence import read_jsonl, validate_record

from aqt_change import plans, receipts
from aqt_change.config import Config
from aqt_change.errors import ChangeError
from aqt_change.finish import finish
from aqt_change.gitio import Git, trailers
from aqt_change.ledger import Ledger
from aqt_change.gate import gate
from conftest import CHECK_SCRIPT, PLAN, edit, git, read

P = "plans/s01.md"


def prepare(ledger, project, *, attest=True):
    plans.begin(ledger, P)
    (project / "src/calc.py").write_text("def add(a, b):\n    return a + b  # checked\n")
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")
    receipts.run(ledger, [], plan_path=P, all_items=True, echo=False)
    if attest:
        receipts.attest(ledger, P, "V02", [], "screenshot looked right")


def test_finish_commits_exact_paths_with_trailers(project, evidence_file):
    (project / ".aqt").mkdir()
    (project / ".aqt/change.toml").write_text('[gate]\nalways_allowed_paths = ["notes.txt"]\n')
    git(project, "add", ".aqt/change.toml")
    git(project, "commit", "-qm", "project settings")
    ledger = Ledger.open(project)
    (project / "notes.txt").write_text("keep me out")  # untracked, outside the plan's paths: may stay out
    prepare(ledger, project)
    result = finish(ledger, P, key="k1", summary="calculator done", paths=["src/calc.py"])
    assert result["result"] == "completed" and result["gate"] == "GO"  # V02 attested by a human
    sha = result["commit"]
    message = git(project, "log", "-1", "--format=%B", sha)
    pairs = dict(trailers(message))
    assert pairs["AQT-Finish"] == "s01/k1" and pairs["AQT-Plan"].startswith("s01 sha256:")
    assert pairs["AQT-Receipts"].startswith("rec_")
    assert git(project, "show", "--name-only", "--format=", sha).split() == ["plans/s01.md", "src/calc.py"]
    assert "notes.txt" in git(project, "status", "--porcelain")
    text = read(project / P)
    assert "status: completed" in text and "- [x] [V01]" in text and "Completed (aqt-change)" in text
    assert plans.status(ledger, P)["state"] == "clean"
    record = list(read_jsonl(evidence_file))[-1]
    assert record["type"] == "change.finish" and validate_record(record) == []
    for key in ("plan_ref", "receipts", "waivers", "gate"):
        assert key in record["data"]
    assert record["data"]["commit"] == sha
    assert receipts.evaluate(ledger, plans.read_plan(ledger, P)[1])["V01"]["state"] == "ok"


def test_finish_refuses_without_fresh_receipts(ledger, project):
    plans.begin(ledger, P)
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="x")
    assert info.value.code == "finish_evidence_missing"
    assert not (ledger.state / "attempts" / "s01" / "k1.json").exists()


def test_finish_requires_ack_for_open_tasks_and_records_waivers(ledger, project, evidence_file):
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="x", waivers={"V02": "no screen available"})
    assert info.value.code == "finish_ack_required"
    result = finish(ledger, P, key="k2", summary="x", waivers={"V02": "no screen available"},
                    ack_warnings="tasks moved to s02")
    assert result["gate"] == "MANUAL_VERIFY_REQUIRED"
    record = list(read_jsonl(evidence_file))[-1]
    assert record["data"]["waivers"] == [{"item": "V02", "reason": "no screen available"}]
    assert record["data"]["verification"]["V02"] == "waived"
    text = read(project / P)
    assert "V02: waived" in text and "**Completion warning override:** tasks moved to s02" in text


def test_finish_is_idempotent(ledger, project):
    prepare(ledger, project)
    first = finish(ledger, P, key="k1", summary="done", paths=["src/calc.py"])
    again = finish(ledger, P, key="k1", summary="done", paths=["src/calc.py"])
    assert again["replayed"] and again["record"] == first["record"] and again["commit"] == first["commit"]
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="different", paths=["src/calc.py"])
    assert info.value.code == "idempotency_conflict"


def test_finish_resumes_after_commit_failure(ledger, project, monkeypatch):
    prepare(ledger, project)
    original = Git.commit_exact_paths

    def broken(self, paths, message):
        raise ChangeError("git_commit_failed", "simulated hook failure")

    monkeypatch.setattr(Git, "commit_exact_paths", broken)
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done", paths=["src/calc.py"])
    assert info.value.details["phase"] == "plan_written_commit_pending"
    assert plans.status(ledger, P)["state"] == "finish_pending"
    monkeypatch.setattr(Git, "commit_exact_paths", original)
    result = finish(ledger, P, key="k1", summary="done", paths=["src/calc.py"])
    assert result["result"] == "completed" and result["commit"]


def test_finish_adopts_commit_made_before_a_crash(ledger, project, monkeypatch):
    prepare(ledger, project)
    import aqt_change.finish as finish_mod
    original_emit = Ledger.emit
    calls = {"n": 0}

    def crash_once(self, record):
        if record["type"] == "change.finish" and calls["n"] == 0:
            calls["n"] += 1
            raise RuntimeError("crash after commit")
        return original_emit(self, record)

    monkeypatch.setattr(Ledger, "emit", crash_once)
    with pytest.raises(RuntimeError):
        finish_mod.finish(ledger, P, key="k1", summary="done", paths=["src/calc.py"])
    head = git(project, "rev-parse", "HEAD").strip()
    result = finish_mod.finish(ledger, P, key="k1", summary="done", paths=["src/calc.py"])
    assert result["commit"] == head
    assert len(git(project, "log", "--format=%H").split()) == 2  # initial and exactly one finish commit


def test_finish_refuses_unrelated_staged_paths(ledger, project):
    (project / "src/other.txt").write_text("staged")
    git(project, "add", "src/other.txt")
    prepare(ledger, project)
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done", paths=["src/calc.py"])
    assert info.value.code == "git_staged_scope_conflict"


def test_finish_refuses_unreconciled_plan(ledger, project):
    prepare(ledger, project)
    edit(project / P, "Add a calculator.", "Add a calculator?")
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done")
    assert info.value.code == "plan_unreconciled"


def test_finish_without_git(tmp_path, monkeypatch):
    root = tmp_path / "plain"
    (root / "plans").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "tests").mkdir()
    from conftest import CHECK_SCRIPT
    (root / "src/calc.py").write_text("def add(a, b):\n    return a + b\n")
    (root / "tests/check.py").write_text(CHECK_SCRIPT)
    (root / P).write_text(PLAN.replace("- [ ] [V02] Screenshot reviewed\n", ""))
    monkeypatch.chdir(root)
    led = Ledger.open(root)
    assert led.git is None and "change" in str(led.state)
    plans.begin(led, P)
    receipts.run(led, [], plan_path=P, all_items=True, echo=False)
    result = finish(led, P, key="k1", summary="done", ack_warnings="tasks tracked elsewhere")
    assert result["commit"] is None and "status: completed" in read(root / P)


def test_external_lifecycle_owner_never_writes_the_plan(project):
    led = Ledger.open(project, config=Config(lifecycle_owner="external"))
    edit(project / P, "status: planned", "status: in_progress")
    before = read(project / P)
    plans.begin(led, P)
    receipts.run(led, [], plan_path=P, all_items=True, echo=False)
    receipts.attest(led, P, "V02", [], "ok")
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")
    edit(project / P, "status: in_progress", "status: completed")   # written by the external tracker
    assert plans.status(led, P)["state"] == "status_neutral"
    result = finish(led, P, key="k1", summary="done")
    assert result["commit"] is None
    assert read(project / P) != before and "Completed (aqt-change)" not in read(project / P)


def test_finish_refuses_a_tested_change_left_out_of_the_commit(ledger, project):
    """The receipts tested the working tree; a commit of only some paths must not leave tested changes behind
    (a weakened check, a new helper module), or a clean checkout is not what passed."""
    (project / "tests/check.py").write_text(CHECK_SCRIPT.replace("ok = calc.add(2, 3) == 5", "ok = True"))
    (project / "src/helper.py").write_text("HELP = 1\n")
    prepare(ledger, project)
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done", paths=["src/calc.py"])
    assert info.value.code == "finish_tested_change_not_committed"
    assert "tests/check.py (modified)" in info.value.message and "src/helper.py (untracked)" in info.value.message
    assert not (ledger.state / "attempts" / "s01" / "k1.json").exists()
    assert len(git(project, "log", "--format=%H").split()) == 1
    result = finish(ledger, P, key="k2", summary="done", paths=["src/calc.py", "tests/check.py", "src/helper.py"])
    assert result["result"] == "completed"
    assert git(project, "status", "--porcelain") == ""
    assert "tested_change_not_committed" not in {r["code"] for r in gate(ledger, P)["reasons"]}


def test_gate_after_finish_without_commit_needs_the_tested_tree_in_head(ledger, project):
    prepare(ledger, project)
    result = finish(ledger, P, key="k1", summary="done", no_commit=True)
    assert result["commit"] is None
    reasons = {r["code"]: r.get("detail", "") for r in gate(ledger, P)["reasons"]}
    assert set(reasons) == {"tested_change_not_committed"} and "src/calc.py (modified)" in reasons[
        "tested_change_not_committed"]
    git(project, "commit", "-qam", "the tested change")
    assert gate(ledger, P)["decision"] == "GO"
    (project / "tests/check.py").write_text(CHECK_SCRIPT + "\n")   # a later edit: stale, not "not committed"
    assert {r["code"] for r in gate(ledger, P)["reasons"]} == {"receipt_stale"}


def test_run_that_changes_the_tree_needs_a_clean_rerun(ledger, project):
    """A check that changes the working tree while it runs (here it deletes a file; a cheating test could patch
    the code and delete itself) does not count by itself; a later run that leaves the tree unchanged does."""
    (project / "src/tmp.txt").write_text("gone after the run\n")
    (project / "tests/check.py").write_text("import pathlib\npathlib.Path('src/tmp.txt').unlink(missing_ok=True)\n"
                                            + CHECK_SCRIPT)
    prepare(ledger, project)
    record = list(ledger.records("change.receipt"))[-2]               # V01's run (the last one is V02's attest)
    assert record["data"]["tree_fingerprint_before"] != record["data"]["tree_fingerprint"]
    result = gate(ledger, P)
    assert any(r["code"] == "command_modified_worktree" and r["item"] == "V01" for r in result["reasons"])
    with pytest.raises(ChangeError) as info:
        finish(ledger, P, key="k1", summary="done", paths=["src/calc.py", "tests/check.py"])
    assert info.value.code == "finish_command_modified_worktree" and "V01" in info.value.message
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)       # the file is gone: a clean run
    receipts.attest(ledger, P, "V02", [], "seen")
    result = finish(ledger, P, key="k2", summary="done", paths=["src/calc.py", "tests/check.py"])
    assert result["gate"] == "GO"


def test_ignored_build_output_does_not_count_as_a_tree_change(ledger, project):
    (project / ".gitignore").write_text("__pycache__/\nbuild/\n")
    git(project, "commit", "-qam", "ignore build output")
    (project / "tests/check.py").write_text("import pathlib\npathlib.Path('build').mkdir(exist_ok=True)\n"
                                            "pathlib.Path('build/out.txt').write_text('x')\n" + CHECK_SCRIPT)
    prepare(ledger, project)
    record = list(ledger.records("change.receipt"))[-2]
    assert (project / "build/out.txt").exists()
    assert record["data"]["tree_fingerprint_before"] == record["data"]["tree_fingerprint"]
    assert "command_modified_worktree" not in {r["code"] for r in gate(ledger, P)["reasons"]}
