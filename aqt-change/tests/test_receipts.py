import sys
import time

import pytest
from aqt_evidence import validate_record

from aqt_change import plans, receipts
from aqt_change.errors import ChangeError
from aqt_change.plan import parse_plan
from conftest import edit, git, read

P = "plans/s01.md"
I6_RECEIPT = ("argv", "exit_code", "passed", "plan_basis_hash", "tree_fingerprint", "counts")


def item_state(ledger, project, item="V01"):
    return receipts.evaluate(ledger, parse_plan(read(project / P)))[item]["state"]


def test_run_declared_command_records_passing_receipt(ledger, project):
    plans.begin(ledger, P)
    [record] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    assert validate_record(record) == []
    data = record["data"]
    assert all(key in data for key in I6_RECEIPT)
    assert data["passed"] is True and data["exit_code"] == 0 and data["outcome"] == "passed"
    assert data["counts"]["passed"] == 1 and data["counts"]["source"] == "pytest"
    assert data["stdout"]["sha256"].startswith("sha256:") and "1 passed" in data["stdout"]["tail"]
    assert data["git"]["head"] == git(project, "rev-parse", "HEAD").strip()
    assert record["subject"] == {"kind": "plan-item", "ref": "s01#V01"}
    assert ledger.get_object("logs", data["stdout"]["sha256"]).startswith(b"collected")
    assert item_state(ledger, project) == "ok"


def test_failing_command_and_staleness(ledger, project):
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, all_items=True, echo=False)
    (project / "src/calc.py").write_text("def add(a, b):\n    return a - b\n")
    assert item_state(ledger, project) == "stale"
    [record] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    assert record["data"]["passed"] is False and record["data"]["counts"]["failed"] == 1
    assert item_state(ledger, project) == "failed"


def test_receipt_survives_commit_of_same_content_and_ticks(ledger, project):
    plans.begin(ledger, P)
    (project / "src/calc.py").write_text("def add(a, b):\n    return b + a\n")
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    edit(project / P, "- [ ] [V01]", "- [x] [V01]")
    git(project, "add", "-A")
    git(project, "commit", "-qm", "work")
    assert item_state(ledger, project) == "ok"


def test_plan_change_makes_receipt_stale(ledger, project):
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    edit(project / P, "Add a calculator.", "Add a calculator, fast.")
    assert item_state(ledger, project) == "stale"
    plans.reconcile(ledger, P, "editorial", "wording")
    assert item_state(ledger, project) == "stale"


def test_command_matching_and_manual_items(ledger, project):
    plans.begin(ledger, P)
    with pytest.raises(ChangeError) as info:
        receipts.run(ledger, ["true"], plan_path=P, item="V01", echo=False)
    assert info.value.code == "command_mismatch"
    with pytest.raises(ChangeError) as info:
        receipts.run(ledger, [], plan_path=P, item="V02", echo=False)
    assert info.value.code == "item_manual"
    declared = parse_plan(read(project / P)).item("V01").commands[0]
    [record] = receipts.run(ledger, declared, plan_path=P, echo=False)
    assert record["data"]["item"] == "V01"
    [free] = receipts.run(ledger, [sys.executable, "-c", "print('hi')"], plan_path=P, echo=False)
    assert free["data"]["item"] is None and free["data"]["passed"] is True


def test_attest_manual_item(ledger, project):
    plans.begin(ledger, P)
    (project / "shot.png").write_bytes(b"\x89PNG fake")
    record = receipts.attest(ledger, P, "V02", ["shot.png"], "looked at it")
    assert record["meaning"] == "verified" and record["data"]["attested_by"] == "human"
    assert record["data"]["evidence"][0]["path"] == "shot.png"
    assert item_state(ledger, project, "V02") == "ok"
    with pytest.raises(ChangeError):
        receipts.attest(ledger, P, "V01", [], "nope")


def test_unbound_run_without_plan(ledger, project):
    [record] = receipts.run(ledger, [sys.executable, "-c", "import sys; sys.exit(3)"], echo=False)
    assert record["data"]["exit_code"] == 3 and record["data"]["passed"] is False
    assert record["data"]["plan_basis_hash"] is None


def test_missing_executable_is_an_error_receipt(ledger, project):
    [record] = receipts.run(ledger, ["definitely-not-a-command-xyz"], echo=False)
    assert record["data"]["outcome"] == "error" and record["data"]["exit_code"] == 127


def test_timeout_is_recorded(ledger, project):
    [record] = receipts.run(ledger, [sys.executable, "-c", "import time; time.sleep(5)"], timeout=1, echo=False)
    assert record["data"]["outcome"] == "timeout" and record["data"]["passed"] is False


def test_count_parsers():
    assert receipts.parse_counts("==== 3 passed, 1 skipped, 2 warnings in 0.12s ====")["total"] == 4
    failed = receipts.parse_counts("1 failed, 2 passed, 1 error in 1.0s")
    assert failed["failed"] == 1 and failed["errors"] == 1
    unit = receipts.parse_counts("....\n------\nRan 4 tests in 0.001s\n\nFAILED (failures=1)\n")
    assert unit == {"source": "unittest", "total": 4, "failed": 1, "passed": 3}
    assert receipts.parse_counts("no summary here") == {}
    assert receipts.judge(0, "completed", {"total": 0, "source": "pytest"}) is False
    assert receipts.judge(0, "completed", {}) is True


def test_junit_counts_and_staleness(ledger, project, tmp_path):
    plans.begin(ledger, P)
    xml = ('<testsuites><testsuite name="a" tests="3" failures="1" errors="0" skipped="0"/>'
           '<testsuite name="b" tests="2" failures="0" errors="0" skipped="1"/></testsuites>')
    script = f"open('report.xml','w').write({xml!r})"
    [record] = receipts.run(ledger, [sys.executable, "-c", script], junit="report.xml", echo=False)
    assert record["data"]["counts"] == {"source": "junit", "total": 5, "failed": 1, "errors": 0, "skipped": 1,
                                        "passed": 3}
    assert record["data"]["passed"] is False and record["data"]["junit_sha256"].startswith("sha256:")
    old = time.time() - 3600
    import os
    os.utime(project / "report.xml", (old, old))
    [stale] = receipts.run(ledger, [sys.executable, "-c", "pass"], junit="report.xml", echo=False)
    assert any(w["code"] == "junit_stale" for w in stale["data"]["warnings"])


def test_anti_gaming_warnings(ledger, project):
    from aqt_change import antigaming
    (project / "tests/test_calc.py").write_text("def test_add():\n    assert 1\n\ndef test_two():\n    assert 2\n")
    git(project, "add", "-A")
    git(project, "commit", "-qm", "tests")
    plans.begin(ledger, P)
    (project / "tests/test_calc.py").write_text("import pytest\n\n@pytest.mark.skip\ndef test_add():\n    pass\n")
    (project / "pyproject.toml").write_text("[tool.pytest.ini_options]\naddopts = \"-k 'not slow'\"\n")
    [record] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    found = {w["code"] for w in record["data"]["warnings"]}
    assert {"skip_added", "test_config_changed", "asserts_removed", "tests_removed"} <= found
    (project / "tests/test_calc.py").unlink()
    base = ledger.plan_state("s01")["base_commit"]
    assert "test_file_deleted" in {w["code"] for w in antigaming.scan(ledger.git, base)}
    assert antigaming.scan(None, base) == []



def _user_excludes(project, globs):
    from aqt_change.config import Config
    from aqt_change.ledger import Ledger
    return Ledger.open(project, config=Config(fingerprint_exclude=globs))


def test_user_fingerprint_exclude_cannot_hide_tested_code(project):
    """The user configuration is within the agent's reach: its globs leave out only untracked files outside the
    plan's paths (tool output), never tracked files or anything inside the plan's paths."""
    led = _user_excludes(project, ["**"])
    plans.begin(led, P)
    receipts.run(led, [], plan_path=P, item="V01", echo=False)
    (project / "coverage.xml").write_text("<coverage/>")                # untracked, outside: left out
    assert item_state(led, project) == "ok"
    (project / "src/generated.txt").write_text("x")                     # untracked, inside the plan's paths
    assert item_state(led, project) == "stale"
    (project / "src/generated.txt").unlink()
    assert item_state(led, project) == "ok"
    (project / ".gitignore").write_text("__pycache__/\n# edited\n")    # tracked, outside the plan's paths
    assert item_state(led, project) == "stale"
    (project / ".gitignore").write_text("__pycache__/\n")
    (project / "src/calc.py").write_text("def add(a, b):\n    return a - b\n")
    assert item_state(led, project) == "stale"


def test_project_fingerprint_exclude_counts_for_tracked_files(project):
    (project / "docs").mkdir()
    (project / "docs/notes.md").write_text("notes\n")
    (project / ".aqt").mkdir()
    (project / ".aqt/change.toml").write_text('fingerprint_exclude = ["docs/**"]\n')
    git(project, "add", "-A")
    git(project, "commit", "-qm", "docs and project settings")
    from aqt_change.ledger import Ledger
    led = Ledger.open(project)
    plans.begin(led, P)
    receipts.run(led, [], plan_path=P, item="V01", echo=False)
    (project / "docs/notes.md").write_text("edited notes\n")
    assert item_state(led, project) == "ok"


def test_junit_path_cannot_hide_a_tracked_file(ledger, project):
    plans.begin(ledger, P)
    [record] = receipts.run(ledger, [], plan_path=P, item="V01", junit="src/calc.py", echo=False)
    assert "src/calc.py" not in record["data"]["fingerprint_excludes"]
    (project / "src/calc.py").write_text("def add(a, b):\n    return a - b\n")
    assert item_state(ledger, project) == "stale"
