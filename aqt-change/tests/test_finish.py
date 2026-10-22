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
from conftest import PLAN, edit, git, read

P = "plans/s01.md"


def prepare(ledger, project, *, attest=True):
    plans.begin(ledger, P)
    (project / "src/calc.py").write_text("def add(a, b):\n    return a + b  # checked\n")
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")
    receipts.run(ledger, [], plan_path=P, all_items=True, echo=False)
    if attest:
        receipts.attest(ledger, P, "V02", [], "screenshot looked right")


def test_finish_commits_exact_paths_with_trailers(ledger, project, evidence_file):
    (project / "src/notes.txt").write_text("keep me out")  # before the run: part of the tested tree
    prepare(ledger, project)
    result = finish(ledger, P, key="k1", summary="calculator done", paths=["src/calc.py"])
    assert result["result"] == "completed" and result["gate"] == "GO"  # V02 attested by a human
    sha = result["commit"]
    message = git(project, "log", "-1", "--format=%B", sha)
    pairs = dict(trailers(message))
    assert pairs["AQT-Finish"] == "s01/k1" and pairs["AQT-Plan"].startswith("s01 sha256:")
    assert pairs["AQT-Receipts"].startswith("rec_")
    assert git(project, "show", "--name-only", "--format=", sha).split() == ["plans/s01.md", "src/calc.py"]
    assert "src/notes.txt" in git(project, "status", "--porcelain")
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
