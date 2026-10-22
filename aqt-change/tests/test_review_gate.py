import json
import sys
import types

import pytest
from aqt_evidence import AgentContext, HumanCheckError, JsonlSink, actor, new_record, read_jsonl, record_content_hash

from aqt_change import actors, plans, receipts
from aqt_change.approval import approval_state
from aqt_change.config import Config, GatePolicy
from aqt_change.errors import ChangeError
from aqt_change.finish import finish
from aqt_change.gate import gate
from aqt_change.ledger import Ledger
from aqt_change.review import add_review
from aqt_change.scope import reconcile_diff
from conftest import edit, git

P = "plans/s01.md"


def done(ledger, project):
    plans.begin(ledger, P)
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "- [ ] [T02]", "- [x] [T02]")
    receipts.run(ledger, [], plan_path=P, all_items=True, echo=False)
    receipts.attest(ledger, P, "V02", [], "seen")


def reasons(result):
    return {r["code"] for r in result["reasons"]}


def test_review_record_binds_diff(ledger, project, tmp_path):
    plans.begin(ledger, P)
    (project / "src/calc.py").write_text("def add(a, b):\n    return a + b + 0\n")
    findings = tmp_path / "f.json"
    findings.write_text(json.dumps([{"severity": "minor", "title": "redundant + 0", "path": "src/calc.py", "line": 2}]))
    record = add_review(ledger, P, reviewer="agent:codex:r1", harness="codex", model="m1",
                        independence="different-model", verdict="concerns", reason="one nit",
                        findings_file=str(findings))
    data = record["data"]
    for key in ("verdict", "independence", "diff_sha256", "findings"):
        assert key in data
    assert data["verdict"] == "CONCERNS" and data["findings"][0]["line"] == 2
    assert record["meaning"] == "reviewed" and data["diff_sha256"].startswith("sha256:")
    assert data["diff"]["base"] == ledger.plan_state("s01")["base_commit"]


def test_human_review_requires_a_human(ledger, project, evidence_file, monkeypatch):
    plans.begin(ledger, P)

    def refuse():
        raise HumanCheckError(AgentContext(True, "claude-code", ["env:CLAUDECODE"]), "refused: agent")

    monkeypatch.setattr(actors, "human_check", refuse)
    with pytest.raises(ChangeError) as info:
        add_review(ledger, P, reviewer="human:alice", independence="human", verdict="PASS", reason="ok")
    assert info.value.code == "human_required"
    refusal = list(read_jsonl(evidence_file))[-1]
    assert refusal["type"] == "change.refused"
    assert refusal["data"] == {"attempted_action": "review.add(human)", "reason_code": "human_required",
                               "agent_markers": ["env:CLAUDECODE"]}


def test_agent_actor_cannot_claim_human_identity(monkeypatch):
    monkeypatch.setenv("AQT_ACTOR", "human:alice")
    value = actors.current_actor(None, AgentContext(True, "claude-code", ["env:CLAUDECODE"]))
    assert value["kind"] == "agent" and value["id"].startswith("agent:claude-code:")
    assert actors.current_actor(None, AgentContext(False))["id"] == "human:alice"


def test_gate_go_after_clean_finish(ledger, project):
    done(ledger, project)
    assert gate(ledger, P)["decision"] == "NO-GO"           # not finished yet
    finish(ledger, P, key="k1", summary="done")
    result = gate(ledger, P)
    assert result["decision"] == "GO", result["reasons"]


def test_gate_reasons(ledger, project):
    done(ledger, project)
    finish(ledger, P, key="k1", summary="done")
    add_review(ledger, P, reviewer="agent:x:1", independence="same-session", verdict="FAIL", reason="broken")
    assert "review_fail" in reasons(gate(ledger, P))
    (project / "README.md").write_text("outside the declared scope\n")
    result = gate(ledger, P)
    assert result["decision"] == "NO-GO"
    assert {"receipt_stale", "unapproved_change", "review_fail"} <= reasons(result)  # FAIL stays open
    add_review(ledger, P, reviewer="agent:x:1", independence="same-session", verdict="PASS", reason="fixed")
    assert "review_fail" not in reasons(gate(ledger, P))


def test_review_policy_and_concerns(project):
    policy = Config(gate=GatePolicy(min_review_independence="fresh-context"))
    led = Ledger.open(project, config=policy)
    done(led, project)
    finish(led, P, key="k1", summary="done")
    assert "review_independence_below_policy" in reasons(gate(led, P))
    add_review(led, P, reviewer="agent:x:2", independence="fresh-context", verdict="PASS", reason="ok")
    assert gate(led, P)["decision"] == "GO"
    add_review(led, P, reviewer="agent:x:3", independence="different-model", verdict="CONCERNS", reason="hm")
    assert gate(led, P)["decision"] == "MANUAL_VERIFY_REQUIRED"


def test_waiver_and_agent_attestation_need_manual_verification(ledger, project, monkeypatch):
    plans.begin(ledger, P)
    receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    finish(ledger, P, key="k1", summary="done", waivers={"V02": "no screen"}, ack_warnings="tasks later")
    result = gate(ledger, P)
    assert result["decision"] == "MANUAL_VERIFY_REQUIRED" and "waiver_present" in reasons(result)


def test_reconcile_diff_reports_unapproved_paths(ledger, project, evidence_file):
    plans.begin(ledger, P)
    (project / "src/calc.py").write_text("def add(a, b):\n    return a + b  # in scope\n")
    (project / "setup.cfg").write_text("[metadata]\n")
    record = reconcile_diff(ledger, P)
    data = record["data"]
    assert record["type"] == "change.reconciliation"
    assert data["unapproved"] == ["setup.cfg"] and data["result"] == "findings"
    assert set(data["missing_evidence"]) == {"V01", "V02"}
    assert {c["path"] for c in data["changed"]} == {"src/calc.py", "setup.cfg"}


def test_scope_undeclared(ledger, project):
    edit(project / P, "aqt:\n  paths:\n    - src/**\n    - tests/**\n", "")
    git(project, "commit", "-qam", "no scope")
    plans.begin(ledger, P)
    assert reconcile_diff(ledger, P)["data"]["result"] == "scope_undeclared"


def _signature(target: dict, path):
    signer = actor("human", "human:alice", role="quality-manager")
    record = new_record("signoff.signature", signer, "sign", meaning="approved", reason="plan approved",
                        subject={"kind": "record", "ref": target["id"], "sha256": record_content_hash(target)},
                        data={"meaning": "approved", "signature": {"statement": {}, "alg": "ed25519",
                                                                     "key": "ed25519:0000000000000000", "value": "x"}})
    JsonlSink(path).append(record)
    return record


def test_approval_states(ledger, project, tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "aqt_signoff", None)   # not installed
    plans.begin(ledger, P)
    sources = [tmp_path / "signoff.jsonl"]
    assert approval_state(ledger, "s01", sources)["state"] == "unsigned"
    target = ledger.record(ledger.plan_state("s01")["approval_targets"][-1])
    _signature(target, sources[0])
    assert approval_state(ledger, "s01", sources)["state"] == "unverified"
    fake = types.ModuleType("aqt_signoff")
    fake.is_approved = lambda sha, meaning="approved", policy=None, sources=None: sha == record_content_hash(target)
    monkeypatch.setitem(sys.modules, "aqt_signoff", fake)
    assert approval_state(ledger, "s01", sources)["state"] == "signed"
    rejecting = types.ModuleType("aqt_signoff")
    rejecting.is_approved = lambda sha, meaning="approved", policy=None, sources=None: False
    monkeypatch.setitem(sys.modules, "aqt_signoff", rejecting)
    assert approval_state(ledger, "s01", sources)["state"] == "invalid"
    monkeypatch.setitem(sys.modules, "aqt_signoff", fake)
    edit(project / P, "- [ ] [T02] Document add", "- [ ] [T02] Document add\n- [ ] [T03] More")
    plans.reconcile(ledger, P, "semantic", "scope grew")
    assert approval_state(ledger, "s01", sources)["state"] == "stale"


def test_require_signed_approval_policy(project, tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "aqt_signoff", None)
    led = Ledger.open(project, config=Config(gate=GatePolicy(require_signed_approval=True)))
    done(led, project)
    finish(led, P, key="k1", summary="done")
    assert "approval_unsigned" in reasons(gate(led, P, sources=[tmp_path / "none.jsonl"]))


def test_gate_rerun_reexecutes_commands(ledger, project):
    done(ledger, project)
    finish(ledger, P, key="k1", summary="done")
    before = len(list(ledger.records("change.receipt")))
    result = gate(ledger, P, rerun=True)
    assert len(list(ledger.records("change.receipt"))) == before + 1
    assert result["decision"] == "GO"
