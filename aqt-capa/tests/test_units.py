"""Focused checks: source rules, similarity, approval via signoff records, windows in days, the human guard."""

from __future__ import annotations

from datetime import timedelta

import pytest
from aqt_evidence import AgentContext, HumanCheckError, actor, read_jsonl, require_human, subject

from aqt_capa import sources
from aqt_capa.capa import Refused
from aqt_capa.similarity import score_ppm, similar
from aqt_capa.util import now, parse_since, parse_time
from conftest import HUMAN, git, rec, sessions


def test_receipt_behind_finish_is_major_and_finish_rules():
    failed = rec("change.receipt", "run", data={"argv": ["make", "test"], "exit_code": 2, "passed": False,
                                                "plan_basis_hash": "x", "tree_fingerprint": "y", "counts": {}})
    finish = rec("change.finish", "finish", data={"plan_ref": "plans/s1.md", "receipts": [failed["id"]],
                                                  "waivers": [{"item": "V2"}], "gate": "MANUAL_VERIFY_REQUIRED"})
    go = rec("change.finish", "finish", data={"plan_ref": "p", "receipts": [], "waivers": [], "gate": "GO"})
    out = {c.rule: c for c in sources.from_records([failed, finish, go])}
    assert out["receipt-failed"].severity == "major"
    assert out["finish-not-go"].severity == "minor"
    assert len(out) == 2


def test_held_alone_unknown_outcome_and_disabled_rules():
    held = rec("quarantine.held", "hold", data={"case_id": "QC-9", "band": "hold", "score_ppm": 700_000,
                                                "source": {"tool": "WebFetch", "ref": "r", "domain": "d.test"}})
    outcome = rec("signoff.action.outcome", "outcome", data={"outcome": "unknown", "action_id": "act_1"})
    ok = rec("signoff.action.outcome", "outcome", data={"outcome": "succeeded", "action_id": "act_2"})
    rules = [c.rule for c in sources.from_records([held, outcome, ok])]
    assert rules == ["quarantine-held", "action-outcome-unknown"]
    assert sources.from_records([held, outcome], disabled=["quarantine-held"])[0].rule == "action-outcome-unknown"
    assert sources.from_records([held])[0].session == "s-001"


def test_git_revert_filter_by_agent_trailer(repo):
    assert len(sources.from_git(repo)) == 1
    assert len(sources.from_git(repo, ["Co-Authored-By: Example Agent"])) == 1
    assert sources.from_git(repo, ["Generated-By: nobody"]) == []
    assert sources.from_git(repo.parent / "missing") == []


def test_similarity_scores_in_ppm():
    a = {"dev_id": "DEV-0001", "title": "Failed receipt pytest", "category": "tool", "source_type": "change.receipt"}
    b = {"dev_id": "DEV-0002", "title": "Failed receipt pytest again", "category": "tool",
         "source_type": "change.receipt"}
    c = {"dev_id": "DEV-0003", "title": "Web page injection", "category": "security"}
    assert isinstance(score_ppm(a, b), int) and score_ppm(a, b) > score_ppm(a, c)
    assert [s["dev_id"] for s in similar(a, [b, c], 300_000)] == ["DEV-0002"]


def _implemented(env, capa, *, window_days=None, window_sessions=None):
    dev = capa.new_deviation(title="t", description=None, severity="minor", category="tool")["data"]["dev_id"]
    env.is_agent = True
    aid = capa.plan(dev, kind="corrective", target="AGENTS.md", description="d", window_days=window_days,
                    window_sessions=window_sessions)["data"]["action_id"]
    (env.root / "AGENTS.md").write_text("new rule\n")
    impl = capa.implement(aid)
    env.is_agent = False
    return dev, aid, impl


def test_signoff_signature_counts_as_unverified_approval(env, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "aqt_signoff", None)      # as without aqt-signoff (see test_signed_approval)
    capa = env.capa()
    dev, aid, impl = _implemented(env, capa, window_sessions=1)
    act = capa.store.action(aid)
    assert capa.approval(act)["status"] == "awaiting-approval"
    statement = {"aqt_signature": "0.1", "signer": {"id": HUMAN, "name": "QA Lead", "role": "quality"},
                 "key": "ed25519:0123456789abcdef", "meaning": "approved", "reason": "ok",
                 "signed_at": "2026-10-21T10:00:00.000000Z",
                 "subject": {"kind": "record", "ref": impl["id"], "sha256": act["implemented_hash"]}}
    sig = rec("signoff.signature", "sign", who=actor("human", HUMAN), meaning="approved", reason="ok",
              subject=subject("record", impl["id"], sha256=act["implemented_hash"]),
              data={"signature": {"statement": statement, "alg": "ed25519", "key": statement["key"], "value": "AA=="},
                    "meaning": "approved"})
    env.add([sig])
    status = capa.approval(capa.store.action(aid))
    assert status["approved"] and status["status"] == "signed-unverified"
    env.add(sessions(1))
    assert capa.evaluate(aid)["result"] == "effective"


def test_days_window_with_injected_clock(env):
    capa = env.capa()
    _, aid, _ = _implemented(env, capa, window_days=14)
    capa.approve(aid, reason="ok")
    assert capa.evaluate(aid)["result"] == "pending"
    assert capa.evaluate(aid, now=now() + timedelta(days=15))["result"] == "effective"


def test_evaluation_recorded_only_on_change(env):
    capa = env.capa()
    _, aid, _ = _implemented(env, capa, window_sessions=2)
    capa.approve(aid, reason="ok")
    capa.effectiveness(aid)
    capa.effectiveness(aid)
    evaluated = [r for r in read_jsonl(env.sink_path) if r["type"] == "capa.effectiveness"]
    assert len(evaluated) == 1
    capa.extend(aid, reason="low activity this month", window_sessions=1)
    env.add(sessions(1))
    assert capa.effectiveness(aid)[0]["result"] == "effective"


def test_guard_records_refusal(env):
    env.is_agent = True
    capa = env.capa()
    dev = capa.new_deviation(title="t", description=None, severity="minor", category="tool")["data"]["dev_id"]
    with pytest.raises(Refused):
        capa.close(dev, reason="x", no_action=True)
    refused = [r for r in read_jsonl(env.sink_path) if r["type"] == "capa.refused"]
    assert refused[0]["action"] == "refused"
    assert refused[0]["actor"]["id"] == HUMAN  # the claimed actor
    assert refused[0]["data"] == {"attempted_action": "deviation.close", "reason_code": "agent-context",
                                  "agent_markers": ["env:CLAUDECODE"]}
    # The deviation opened from the agent context is attributed to an agent.
    assert capa.store.deviation(dev)["opened_by"].startswith("agent:claude-code")


def test_shared_human_check_detects_markers():
    with pytest.raises(HumanCheckError):
        require_human(environ={"CLAUDECODE": "1"}, chain=["python"], require_tty=False)
    assert isinstance(require_human(environ={}, chain=["python", "bash"], require_tty=False), AgentContext)


def test_time_helpers():
    assert parse_time("2026-10-21T10:00:00Z") == parse_time("2026-10-21T12:00:00+02:00")
    ref = parse_time("2026-10-21T00:00:00Z")
    assert parse_since("7d", reference=ref) == ref - timedelta(days=7)
    assert parse_since("2026-01-01") == parse_time("2026-01-01T00:00:00Z")
