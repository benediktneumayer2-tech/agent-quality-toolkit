"""Every record aqt-signoff writes conforms to the published aqt-spec schemas."""

import json

import pytest

from aqt_evidence import actor, conformance, read_jsonl
from aqt_evidence import schemas
from aqt_evidence.cli import main as evidence_main
from aqt_signoff import AuthFailed, Refused

pytest.importorskip("jsonschema")

AGENT = actor("agent", "agent:test:s1", harness="test")
ALL_TYPES = {"signoff.key.enrolled", "signoff.key.revoked", "signoff.signature", "signoff.invalidation",
             "signoff.refused", "signoff.auth.failed", "signoff.action.prepared", "signoff.action.approved",
             "signoff.action.rejected", "signoff.action.claimed", "signoff.action.outcome"}


def scenario(people, make, clock, isolated):
    alice, bob = people["human:alice"], people["human:bob"]
    doc = isolated / "doc.md"
    doc.write_text("v1")
    signed = alice.sign(alice.file_subject(doc), "approved", "fine")
    bob.sign(bob.file_subject(doc), "reviewed", "read it")
    alice.withdraw(signed["id"], "wrong revision")
    doc.write_text("v2")
    alice.verify_file(doc)                                        # content-changed invalidation
    with pytest.raises(Refused):
        make("human:alice", environ={"CLAUDECODE": "1"}).sign(alice.file_subject(doc), "approved", "x")
    with pytest.raises(AuthFailed):
        make("human:alice", passphrase="wrong-passphrase").sign(alice.file_subject(doc), "approved", "x")
    ok = alice.actions.prepare("command", "ok", {"argv": ["true"]}, description="no-op", who=AGENT)
    alice.actions.approve(ok["id"], ok["action_sha256"], "ok", valid_for_ms=60_000)
    alice.actions.run(ok["id"])
    no = alice.actions.prepare("command", "no", {"argv": ["false"]}, who=AGENT)
    alice.actions.reject(no["id"], no["action_sha256"], "not needed")
    lost = alice.actions.prepare("other", "lost", {"text": "manual step"}, who=AGENT)
    alice.actions.approve(lost["id"], lost["action_sha256"], "ok")
    alice.actions.claim(lost["id"], lost["action_sha256"], who=AGENT)
    clock.advance(minutes=10)
    alice.actions.resolve(lost["id"], "not-applied", "checked by hand")
    bob.revoke("human:bob", "rotation", compromised_since=None)


def test_every_record_matches_its_schema(people, make, clock, isolated):
    scenario(people, make, clock, isolated)
    records = list(read_jsonl(make.sink))
    assert {r["type"] for r in records} == ALL_TYPES
    for record in records:
        assert schemas.validate_schema(record, "envelope") == [], record["type"]
        assert schemas.validate_payload(record) == [], record["type"]
        block = record.get("data", {}).get("signature")
        if block:
            assert schemas.validate_schema(block, "signature") == [], record["type"]
    result = conformance(records, level=1)
    assert result.ok and result.payloads_checked, result.problems
    assert result.warnings == []
    registry = json.loads((isolated / "config/aqt/signers.json").read_text())
    assert schemas.validate_schema(registry, "signers") == []


def test_aqt_evidence_conform_level_1_on_sink(people, make, clock, isolated, capsys):
    scenario(people, make, clock, isolated)
    assert evidence_main(["conform", str(make.sink), "--level", "1"]) == 0
    assert "L1 reached" in capsys.readouterr().out
