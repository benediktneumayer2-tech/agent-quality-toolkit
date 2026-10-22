"""The MVP slice end to end: scan -> decide -> investigate -> act -> approve -> effectiveness -> close -> trends -> rebuild."""

from __future__ import annotations

import json

import pytest
from aqt_evidence import read_jsonl, validate_record

from aqt_capa.capa import Blocked, Refused
from aqt_capa.store import Store
from aqt_capa.trends import render_markdown, trends
from conftest import AGENT, rec, sessions, synthetic_evidence


def test_full_capa_cycle(env, repo, monkeypatch):
    env.add(synthetic_evidence())
    capa = env.capa(repos=[repo])

    # 1-2. Scan: one candidate per source (the held case is folded into its threat declaration).
    new = capa.scan()
    rules = sorted(c["rule"] for c in new)
    assert rules == ["git-revert", "quarantine-threat", "receipt-failed", "refused", "review-fail",
                     "trail-review-finding"]
    assert capa.scan() == []  # idempotent
    by_rule = {c["rule"]: c for c in new}

    capa.dismiss(by_rule["git-revert"]["candidate_id"], reason="revert was part of a planned rollback")
    opened = capa.accept(by_rule["receipt-failed"]["candidate_id"], severity="major", category="instructions",
                         reason="agent claimed done with failing tests")
    dev = opened["data"]["dev_id"]
    assert dev == "DEV-0001"
    assert opened["links"] == [{"rel": "source", "ref": by_rule["receipt-failed"]["source_ref"]}]
    with pytest.raises(Blocked):
        capa.accept(by_rule["receipt-failed"]["candidate_id"], reason="again")

    # Recurrence: a related manual deviation shows the first one as similar.
    second = capa.new_deviation(title="Failed verification receipt: pytest -q ignored", description="tests failed",
                                severity="minor", category="instructions")
    assert second["data"]["similar"][0]["dev_id"] == dev

    # 3. Investigation: an agent may draft; approval from an agent context is refused and recorded.
    env.is_agent = True
    draft = capa.investigate(dev, whys=["tests failed", "agent ignored output"], factors=["method:no rule"],
                             root_cause="AGENTS.md lacks a rule", root_category="instructions", draft=True)
    assert draft["action"] == "drafted" and draft["actor"]["kind"] == "agent"
    with pytest.raises(Refused):
        capa.investigate(dev, whys=["x"], factors=[], root_cause="x", root_category="instructions")
    env.is_agent = False
    inv = capa.investigate(dev, whys=["tests failed", "agent reported done anyway", "no rule requires green tests"],
                           factors=["method:AGENTS.md has no completion rule", "measurement:no receipt check"],
                           root_cause="Completion criteria missing from agent instructions",
                           root_category="instructions", impact="one change merged without passing tests")
    assert inv["action"] == "recorded"

    # 4. Action on AGENTS.md: plan (agent), edit, implement (agent), approve (human), verify.
    env.is_agent = True
    plan = capa.plan(dev, kind="corrective", target="AGENTS.md", description="Require a passing receipt before done",
                     window_sessions=3)
    aid = plan["data"]["action_id"]
    assert aid == "CAPA-0001-1"
    (env.root / "AGENTS.md").write_text("# Agent rules\n\n- Run the tests.\n- Never report done with failing tests.\n")
    impl = capa.implement(aid)
    assert impl["data"]["target"]["after_sha256"] != impl["data"]["target"]["before_sha256"]
    assert "+- Never report done" in impl["data"]["diff_excerpt"]
    with pytest.raises(Refused):
        capa.approve(aid, reason="looks fine")
    env.is_agent = False
    capa.approve(aid, reason="rule is clear and testable")
    assert capa.verify(aid)[0]["status"] == "ok"

    # 5. Effectiveness: pending until 3 sessions; then effective.
    assert capa.effectiveness(aid)[0]["result"] == "pending"
    with pytest.raises(Blocked, match="pending"):
        capa.close(dev, reason="done")
    env.add(sessions(3))
    # The remaining undecided candidates are older than the approval, so they do not block.
    result = capa.effectiveness(aid)[0]
    assert result["result"] == "effective", result["reasons"]

    # 6. Close on effectiveness; --no-action refused for critical.
    closure = capa.close(dev, reason="CAPA effective over 3 sessions")
    assert closure["data"]["basis"] == "effective"
    with pytest.raises(Blocked):
        capa.close(dev, reason="again")
    crit = capa.new_deviation(title="Secret printed to log", description=None, severity="critical", category="security")
    capa.investigate(crit["data"]["dev_id"], whys=["x"], factors=[], root_cause="y", root_category="security")
    with pytest.raises(Blocked, match="critical"):
        capa.close(crit["data"]["dev_id"], reason="no action", no_action=True)

    # 7. Trends.
    report = trends(capa)
    assert report["deviations_in_range"] == 3
    assert report["totals"]["by_severity"] == {"major": 1, "minor": 1, "critical": 1}
    assert report["effectiveness"]["effective"] == 1 and report["effectiveness"]["rate_ppm"] == 1_000_000
    assert report["candidates"]["dismissed"] == 1
    assert "CAPA trend review" in render_markdown(report)

    # Every written record is a valid aqt-spec record.
    written = list(read_jsonl(env.sink_path))
    assert written and all(validate_record(r) == [] for r in written)
    assert {r["type"] for r in written} >= {"capa.deviation", "capa.investigation", "capa.action",
                                            "capa.effectiveness", "capa.closure", "capa.refused"}
    action_data = [r["data"] for r in written if r["type"] == "capa.action"]
    assert all({"path", "before_sha256", "after_sha256"} <= set(d["target"]) and "effectiveness_criterion" in d
               for d in action_data)

    # 8. Rebuild reproduces the index from the evidence alone.
    before = capa.store.snapshot()
    fresh = Store(env.db.parent / "rebuilt.db")
    fresh.rebuild([env.others, env.sink_path])
    assert fresh.snapshot() == before


def test_not_effective_then_second_action_closes(env):
    capa = env.capa()
    dev = capa.new_deviation(title="Agent skipped review", description=None, severity="major",
                             category="instructions")["data"]["dev_id"]
    capa.investigate(dev, whys=["no rule"], factors=[], root_cause="missing rule", root_category="instructions")
    env.is_agent = True
    aid = capa.plan(dev, kind="corrective", target="AGENTS.md", description="add rule", window_sessions=1)["data"]["action_id"]
    (env.root / "AGENTS.md").write_text("v2\n")
    capa.implement(aid)
    env.is_agent = False
    capa.approve(aid, reason="ok")
    capa.new_deviation(title="Agent skipped review again", description=None, severity="minor", category="instructions")
    assert capa.effectiveness(aid)[0]["result"] == "not-effective"
    with pytest.raises(Blocked):
        capa.close(dev, reason="x")

    env.is_agent = True
    aid2 = capa.plan(dev, kind="preventive", target="AGENTS.md", description="hook", window_sessions=1)["data"]["action_id"]
    (env.root / "AGENTS.md").write_text("v3\n")
    capa.implement(aid2)
    env.is_agent = False
    capa.approve(aid2, reason="ok")
    env.add(sessions(1, start=500))
    results = {r["action_id"]: r["result"] for r in capa.effectiveness(dev)}
    assert results == {aid: "not-effective", aid2: "effective"}
    assert capa.close(dev, reason="second action effective")["data"]["basis"] == "effective"


def test_trail_gap_and_changed_target_keep_pending(env):
    capa = env.capa()
    dev = capa.new_deviation(title="t", description=None, severity="minor", category="tool")["data"]["dev_id"]
    env.is_agent = True
    aid = capa.plan(dev, kind="corrective", target="AGENTS.md", description="d", window_sessions=1)["data"]["action_id"]
    (env.root / "AGENTS.md").write_text("changed\n")
    capa.implement(aid)
    env.is_agent = False
    capa.approve(aid, reason="ok")
    env.add(sessions(1) + [rec("trail.gap", "gap", data={"from_seq": 3, "count": 2})])
    ev = capa.effectiveness(aid)[0]
    assert ev["result"] == "pending" and any("gap" in r for r in ev["reasons"])
    (env.root / "AGENTS.md").write_text("edited after approval\n")
    assert capa.verify(aid)[0]["status"] == "changed-since-approval"
    ev = capa.evaluate(aid)
    assert any("changed since approval" in r for r in ev["reasons"])


def test_minor_closes_without_action(env):
    capa = env.capa()
    dev = capa.new_deviation(title="t", description=None, severity="minor", category="tool")["data"]["dev_id"]
    with pytest.raises(Blocked, match="investigation"):
        capa.close(dev, reason="x", no_action=True)
    capa.investigate(dev, whys=["flaky network in CI"], factors=["environment:CI"], root_cause="transient",
                     root_category="environment")
    assert capa.close(dev, reason="one-off; correction only", no_action=True)["data"]["basis"] == "no-action"


def test_rebuild_when_index_missing_keeps_ids(env):
    capa = env.capa()
    capa.new_deviation(title="a", description=None, severity="minor", category="tool")
    env.db.unlink()
    again = env.capa()
    assert again.new_deviation(title="b", description=None, severity="minor",
                               category="tool")["data"]["dev_id"] == "DEV-0002"


def test_self_approval_refused_by_default(env):
    capa = env.capa()
    dev = capa.new_deviation(title="t", description=None, severity="minor", category="tool")["data"]["dev_id"]
    aid = capa.plan(dev, kind="corrective", target="AGENTS.md", description="d")["data"]["action_id"]
    (env.root / "AGENTS.md").write_text("x\n")
    capa.implement(aid)
    with pytest.raises(Blocked, match="another person"):
        capa.approve(aid, reason="mine")
    assert env.capa(allow_self_approval=True).approve(aid, reason="solo project")["action"] == "approved"
