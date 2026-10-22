import json
from datetime import UTC, datetime, timedelta

import pytest

from aqt_evidence import HumanCheckError, JsonlSink, validate_record
from aqt_validate import evidence
from aqt_validate.config import records
from aqt_validate.decisions import DecisionError, check, qualify
from aqt_validate.detector import run_detector
from aqt_validate.protocol import load_protocol
from conftest import HUMAN, FakeTTY, detector_project, read_records

HUMAN_ACTOR = {"kind": "human", "id": "human:tester"}
AGENT_ACTOR = {"kind": "agent", "id": "agent:claude-code:unknown"}


@pytest.fixture
def qualified_run(aqt_env):
    protocol = load_protocol(detector_project(aqt_env.tmp / "p"))
    sink = JsonlSink(aqt_env.sink)
    evidence.emit(sink, evidence.RUN, HUMAN_ACTOR, "protocol-locked", reason="t",
                  data={"kind": "detector", "protocol": protocol.ref})
    result = run_detector(protocol, split="test", state_dir=aqt_env.state, sink=sink, records=records({}),
                          actor=HUMAN_ACTOR)
    assert result.results["conclusion"] == "meets"
    return protocol, result, sink


def do_qualify(run_dir, sink, decision="approve", **kw):
    return qualify(run_dir, decision=decision, reason=kw.pop("reason", "criteria met, reviewed report"), sink=sink,
                   records=records({}), human=HUMAN_ACTOR, claimed_actor=kw.pop("claimed", HUMAN_ACTOR),
                   **{**HUMAN, **kw})


def test_agent_cannot_qualify_and_refusal_is_recorded(qualified_run, aqt_env):
    _, result, sink = qualified_run
    with pytest.raises(HumanCheckError):
        do_qualify(result.run_dir, sink, environ={"CLAUDECODE": "1"}, claimed=AGENT_ACTOR)
    refused = [r for r in read_records(aqt_env.sink) if r["type"] == "validate.refused"]
    assert len(refused) == 1
    assert refused[0]["data"]["attempted_action"] == "qualify"
    assert refused[0]["data"]["reason_code"] == "agent-context"
    assert refused[0]["data"]["agent_markers"] == ["env:CLAUDECODE"]
    assert refused[0]["actor"] == AGENT_ACTOR
    with pytest.raises(HumanCheckError):
        do_qualify(result.run_dir, sink, stdin=object())  # no terminal
    assert read_records(aqt_env.sink)[-1]["data"]["reason_code"] == "no-terminal"
    assert not [r for r in read_records(aqt_env.sink) if r["type"] == "validate.qualification"]


def test_human_approval_record(qualified_run, aqt_env):
    _, result, sink = qualified_run
    now = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
    record = do_qualify(result.run_dir, sink, valid_days=10, now=now)
    assert validate_record(record) == []
    assert record["type"] == "validate.qualification" and record["action"] == "approve"
    assert record["meaning"] == "approved" and record["actor"] == HUMAN_ACTOR
    data = record["data"]
    assert data["configuration_hash"] == result.run_record["data"]["configuration_hash"]
    assert data["valid_until"] == "2026-10-31T12:00:00Z"
    assert data["thresholds_sha256"] == result.report_record["data"]["thresholds_sha256"]
    assert data["expected_fpr_upper_ppm"] == result.results["bands"][-1]["fpr_heldout"]["upper1_ppm"]
    assert {l["rel"] for l in record["links"]} == {"report", "run"}


def test_qualify_guards(qualified_run, aqt_env):
    protocol, result, sink = qualified_run
    with pytest.raises(DecisionError, match="reason"):
        do_qualify(result.run_dir, sink, reason=" ")
    original = (result.run_dir / "thresholds.json").read_text()
    (result.run_dir / "thresholds.json").write_text(original.replace('"calibrated": true', '"calibrated": false'))
    with pytest.raises(DecisionError, match="thresholds.json differs"):
        do_qualify(result.run_dir, sink)
    (result.run_dir / "thresholds.json").write_text(original)
    (result.run_dir / "report.md").write_text("edited")
    with pytest.raises(DecisionError, match="differs"):
        do_qualify(result.run_dir, sink)
    dev = run_detector(protocol, split="dev", state_dir=aqt_env.state, sink=sink, records=records({}), actor=HUMAN_ACTOR)
    with pytest.raises(DecisionError, match="dev run"):
        do_qualify(dev.run_dir, sink)


def test_approving_a_failed_run_needs_accept_deviation(aqt_env):
    criteria = '[[criteria]]\nid = "X"\nmetric = "auroc"\nop = ">="\ntarget = 0.9999\n'
    protocol = load_protocol(detector_project(aqt_env.tmp / "p", criteria=criteria))
    sink = JsonlSink(aqt_env.sink)
    evidence.emit(sink, evidence.RUN, HUMAN_ACTOR, "protocol-locked", reason="t",
                  data={"kind": "detector", "protocol": protocol.ref})
    result = run_detector(protocol, split="test", state_dir=aqt_env.state, sink=sink, records=records({}), actor=HUMAN_ACTOR)
    assert result.results["conclusion"] == "does-not-meet"
    with pytest.raises(DecisionError, match="accept-deviation"):
        do_qualify(result.run_dir, sink)
    record = do_qualify(result.run_dir, sink, accept_deviation=True, reason="AUROC target too strict; accepted")
    assert record["data"]["accepted_deviation"] is True
    assert do_qualify(result.run_dir, sink, decision="reject", reason="no")["meaning"] == "rejected"


def test_check_lifecycle(qualified_run, aqt_env):
    protocol, result, sink = qualified_run
    now = datetime(2026, 10, 21, tzinfo=UTC)

    def run_check(**kw):
        return check(protocol, records=records({}), sink=sink, actor=HUMAN_ACTOR, now=kw.pop("now", now), **kw)

    assert run_check().status == "not-qualified"
    do_qualify(result.run_dir, sink, valid_days=30, now=now)
    thresholds = result.run_dir / "thresholds.json"
    ok = run_check(thresholds=thresholds)
    assert ok.status == "valid" and ok.exit_code == 0
    # thresholds edited -> requalification, recorded once
    edited = aqt_env.tmp / "thresholds-edited.json"
    data = json.loads(thresholds.read_text())
    data["bands"][0]["thresholds"]["marker"] += 1
    edited.write_text(json.dumps(data))
    first = run_check(thresholds=edited)
    assert first.status == "requalify" and first.exit_code == 1
    assert first.record["data"]["trigger"] == "thresholds-changed"
    assert validate_record(first.record) == []
    second = run_check(thresholds=edited)
    assert second.record["id"] == first.record["id"]
    assert len([r for r in read_records(aqt_env.sink) if r["type"] == "validate.requalification"]) == 1
    # expiry
    late = run_check(now=now + timedelta(days=31))
    assert [f["trigger"] for f in late.fired] == ["expired"]
    # drift: many observed false positives
    drift = run_check(observed_fp=(40, 100))
    assert [f["trigger"] for f in drift.fired] == ["drift"]
    assert run_check(observed_fp=(0, 100)).status == "valid"


def test_configuration_change_and_rejection(qualified_run, aqt_env):
    protocol, result, sink = qualified_run
    do_qualify(result.run_dir, sink)
    (protocol.base / "model.bin").write_bytes(b"synthetic model v2")
    changed = load_protocol(protocol.path)
    res = check(changed, records=records({}), sink=sink, actor=HUMAN_ACTOR)
    assert res.status == "requalify" and res.fired[0]["trigger"] == "configuration-changed"
    later = datetime.now(UTC) + timedelta(seconds=1)
    do_qualify(result.run_dir, sink, decision="reject", reason="model replaced", now=later)
    assert check(changed, records=records({}), sink=sink, actor=HUMAN_ACTOR).status == "not-qualified"
