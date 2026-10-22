import json
import sys

import pytest

from aqt_evidence import JsonlSink, validate_record
from aqt_validate import evidence
from aqt_validate.config import records
from aqt_validate.detector import RunRefused
from aqt_validate.protocol import load_protocol
from aqt_validate.reviewer import build_cases, changed_lines, detects, make_snapshot, parse_findings, run_reviewer
from conftest import FIXTURES, read_records

ACTOR = {"kind": "human", "id": "human:tester"}

PROTOCOL = """
[protocol]
id = "test-reviewer"
kind = "reviewer"
subject = "stub reviewer"
intended_use = "Synthetic test of reviewer qualification."
validity_days = 30

[reviewer]
id = "stub-{mode}"
harness = "stub"
model = "stub-model"
version = "1"
argv = ["{python}", "{stub}", "{mode}", "{{diff}}"{extra}]
stdin = "none"
runs = {runs}
min_severity = "medium"
line_tolerance = 1
knowledge_cutoff = "2025-06-01"

[cases]
dir = "cases"
repo = "{repo}"

[[criteria]]
id = "R1"
metric = "detection_rate"
op = ">="
bound = "point"
target = 0.9

[[criteria]]
id = "R2"
metric = "false_alarm_rate"
op = "<="
bound = "point"
target = 0.1
"""


def project(root, repo, mode, runs=2, extra=""):
    root.mkdir(parents=True, exist_ok=True)
    build_cases(repo, root / "cases")
    path = root / "protocol.toml"
    path.write_text(PROTOCOL.format(python=sys.executable, stub=FIXTURES / "stub_reviewer.py", mode=mode, runs=runs,
                                    repo=repo, extra=extra))
    return load_protocol(path)


def run(protocol, env, **kw):
    sink = JsonlSink(env.sink)
    if kw.pop("lock", True) and not evidence.find_lock(records({}), protocol.sha256):
        evidence.emit(sink, evidence.RUN, ACTOR, "protocol-locked", reason="t",
                      data={"kind": "reviewer", "protocol": protocol.ref})
    return run_reviewer(protocol, split=kw.pop("split", "test"), state_dir=env.state, sink=sink,
                        records=records({}), actor=ACTOR, **kw)


def test_build_cases_from_history(git_repo, tmp_path):
    manifest = build_cases(git_repo, tmp_path / "cases")
    assert manifest["counts"] == {"seeded": 2, "clean": 1}
    cases = {c: json.loads((tmp_path / "cases" / c / "case.json").read_text()) for c in manifest["cases"]}
    seeded = [c for c in cases.values() if c["kind"] == "seeded"]
    assert all(c["files"] == ["src/calc.py"] for c in seeded)  # test file excluded
    expected = sorted((e["file"], e["start"], e["end"]) for c in seeded for e in c["expected"])
    assert expected == [("src/calc.py", 2, 2), ("src/calc.py", 6, 6)]
    clean = next(c for c in cases.values() if c["kind"] == "clean")
    assert clean["files"] == ["src/util.py"]  # "feat: faster mul" is excluded: calc.py was fixed later
    diff = (tmp_path / "cases" / seeded[0]["id"] / "diff.patch").read_text()
    assert "+    return a" in diff and "oops" in diff


def test_snapshot_has_the_defect(git_repo, tmp_path):
    build_cases(git_repo, tmp_path / "cases")
    case_id = next(c for c in json.loads((tmp_path / "cases/cases.json").read_text())["cases"] if c.startswith("fix"))
    case = json.loads((tmp_path / "cases" / case_id / "case.json").read_text())
    work = tmp_path / "work"
    work.mkdir()
    make_snapshot(git_repo, case, "", work)
    assert "oops" in (work / "src/calc.py").read_text() and (work / "src/util.py").exists()
    status = __import__("subprocess").run(["git", "-C", str(git_repo), "status", "--porcelain"],
                                          capture_output=True, text=True).stdout
    assert status == ""  # repository untouched


def test_changed_lines_and_matching():
    diff = "--- a/x.py\n+++ b/x.py\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"
    assert changed_lines(diff) == [{"file": "x.py", "start": 2, "end": 2}]
    expected = [{"file": "src/x.py", "start": 10, "end": 12}]
    assert detects([{"file": "./src/x.py", "line": 13, "severity": "high"}], expected, min_severity="medium", tolerance=1)
    assert not detects([{"file": "src/x.py", "line": 14, "severity": "high"}], expected, min_severity="medium", tolerance=1)
    assert not detects([{"file": "src/x.py", "line": 11, "severity": "low"}], expected, min_severity="medium", tolerance=1)
    assert not detects([{"file": "src/y.py", "line": 11}], expected, min_severity="medium", tolerance=1)
    assert detects([{"file": "x.py", "line": 1, "end_line": 20}], expected, min_severity="low", tolerance=0)


def test_parse_findings_variants():
    assert parse_findings('{"findings": []}') == []
    assert parse_findings('Sure! {"findings": [{"file": "a", "line": 1}]} done') == [{"file": "a", "line": 1}]
    wrapped = json.dumps({"result": 'text {"findings": [{"file": "b"}]}'})
    assert parse_findings(wrapped) == [{"file": "b"}]
    with pytest.raises(ValueError):
        parse_findings("no json here")


def test_perfect_reviewer_meets(git_repo, aqt_env):
    protocol = project(aqt_env.tmp / "p", git_repo, "perfect")
    result = run(protocol, aqt_env)
    m = result.results["metrics"]
    assert m["detection_rate"]["k"] == 2 and m["detection_rate"]["n"] == 2
    assert m["false_alarm_rate"]["k"] == 0 and m["false_alarm_rate"]["n"] == 1
    assert m["agreement"] == 1.0 and m["errors"] == 0
    assert set(m["by_period"]) == {"before-cutoff", "after-cutoff"}
    assert m["by_period"]["after-cutoff"]["n"] == 1
    assert result.results["conclusion"] == "meets" and result.exit_code == 0
    recs = read_records(aqt_env.sink)
    assert all(validate_record(r) == [] for r in recs)
    run_rec = next(r for r in recs if r["type"] == "validate.run" and r["action"] == "completed")
    assert run_rec["data"]["kind"] == "reviewer" and run_rec["data"]["agreement_ppm"] == 1_000_000
    assert "Reviewer qualification report" in (result.run_dir / "report.md").read_text()


def test_always_flagging_reviewer_fails_false_alarms(git_repo, aqt_env):
    result = run(project(aqt_env.tmp / "p", git_repo, "always"), aqt_env)
    m = result.results["metrics"]
    assert m["detection_rate"]["k"] == 2 and m["false_alarm_rate"]["k"] == 1
    assert result.results["conclusion"] == "does-not-meet"


def test_silent_and_wrapped(git_repo, aqt_env):
    silent = run(project(aqt_env.tmp / "s", git_repo, "silent"), aqt_env).results["metrics"]
    assert silent["detection_rate"]["k"] == 0
    wrapped = run(project(aqt_env.tmp / "w", git_repo, "wrapped"), aqt_env).results["metrics"]
    assert wrapped["detection_rate"]["k"] == 2


def test_alternating_reviewer_disagrees_and_cache_avoids_reruns(git_repo, aqt_env):
    counter = aqt_env.tmp / "calls.txt"
    protocol = project(aqt_env.tmp / "p", git_repo, "alternate", runs=2, extra=f', "{counter}"')
    result = run(protocol, aqt_env)
    m = result.results["metrics"]
    assert int(counter.read_text()) == 6  # 3 cases x 2 runs
    seeded = [c for c in result.results["cases"] if c["kind"] == "seeded"]
    assert all(c["outcomes"] == [True, False] for c in seeded)
    assert m["agreement"] == pytest.approx(1 / 3)  # only the clean case agrees (never flagged)
    assert m["detection_runs"]["k"] == 2 and m["detection_runs"]["n"] == 4
    run(protocol, aqt_env)
    assert int(counter.read_text()) == 6  # cached


def test_crashing_reviewer_counts_errors_and_retry(git_repo, aqt_env):
    protocol = project(aqt_env.tmp / "p", git_repo, "crash", runs=1)
    result = run(protocol, aqt_env)
    res = result.results
    assert res["metrics"]["errors"] == 3 and res["conclusion"] == "does-not-meet"
    assert next(c for c in res["criteria"] if c["id"] == "E0")["status"] == "fail"
    assert res["metrics"]["detection_rate"] == {"k": 0, "n": 0}
    assert run(protocol, aqt_env, retry_errors=True).results["metrics"]["errors"] == 3


def test_reviewer_test_run_needs_lock_and_dev_trial(git_repo, aqt_env):
    protocol = project(aqt_env.tmp / "p", git_repo, "perfect")
    with pytest.raises(RunRefused):
        run(protocol, aqt_env, lock=False)
    trial = run(protocol, aqt_env, lock=False, split="dev", limit=1)
    assert len(trial.results["cases"]) == 1 and trial.results["split_read"] == "dev"


def test_user_supplied_defect(git_repo, tmp_path):
    defects = tmp_path / "defects"
    defects.mkdir()
    (defects / "neg.patch").write_text("--- a/src/util.py\n+++ b/src/util.py\n@@ -1,3 +1,3 @@\n def helper(value):\n"
                                       "-    doubled = value * 2\n+    doubled = value * -2  # oops\n     return doubled\n")
    (defects / "neg.json").write_text(json.dumps({"base": "HEAD", "diff": "neg.patch",
                                                  "expected": [{"file": "src/util.py", "start": 2, "end": 2}]}))
    manifest = build_cases(git_repo, tmp_path / "cases", defects_dir=defects)
    assert "user-neg" in manifest["cases"]
    case = json.loads((tmp_path / "cases/user-neg/case.json").read_text())
    work = tmp_path / "work"
    work.mkdir()
    make_snapshot(git_repo, case, (defects / "neg.patch").read_text(), work)
    assert "-2  # oops" in (work / "src/util.py").read_text()
