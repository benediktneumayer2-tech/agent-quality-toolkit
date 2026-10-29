import json
import os
import stat

import pytest

from aqt_evidence import (GENESIS, actor, link, new_record, read_jsonl, record_content_hash, subject,
                          validate_record)
from aqt_signoff import AuthFailed, Refused, is_approved, verify_subject
from aqt_signoff.manifest import render
from aqt_signoff.statements import check_block


def records(make):
    return list(read_jsonl(make.sink))


def test_init_writes_registry_keys_and_enrolment(people, make, isolated):
    registry = json.loads((isolated / "config/aqt/signers.json").read_text())
    assert registry["version"] == 1
    alice = next(s for s in registry["signers"] if s["id"] == "human:alice")
    assert alice["name"] == "Alice Example" and alice["role"] == "quality-manager"
    key = alice["keys"][0]
    assert key["key_id"].startswith("ed25519:") and key["public_pem"].startswith("-----BEGIN PUBLIC KEY")
    assert key["revoked_at"] is None and key["enrolled_at"].endswith("Z")
    key_file = isolated / "config/aqt/keys/human-alice.key"
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    assert b"ENCRYPTED" in key_file.read_bytes()
    enrolled = [r for r in records(make) if r["type"] == "signoff.key.enrolled"]
    assert len(enrolled) == 3
    so = people["human:alice"]
    assert all(check_block(r["data"]["signature"], so.registry, record=r).valid for r in enrolled)
    with pytest.raises(Exception, match="already exists"):
        make("human:alice").init_signer("human:alice", "Alice", "qm")


def test_two_person_rule_valid_then_invalidated_on_change(people, make, clock, isolated, tmp_path):
    cfg = tmp_path / "policy.toml"
    cfg.write_text('[signoff]\ntz = "America/New_York"\n[policy.approved]\nmin_signatures = 2\n'
                   'distinct_from_author = true\n', encoding="utf-8")
    alice, bob, carol = (make(s, config_path=cfg) for s in ("human:alice", "human:bob", "human:carol"))
    doc = isolated / "report.md"
    doc.write_text("# Validation report\n")
    bob.sign(bob.file_subject(doc), "authored", "I wrote it")
    with pytest.raises(Refused) as refused:
        bob.sign(bob.file_subject(doc), "approved", "approving my own work")
    assert refused.value.code == "self_approval"
    alice.sign(alice.file_subject(doc), "approved", "Checked against CR-12")
    report = alice.verify_file(doc, required=["approved"])
    assert not report.ok and "1 more" in report.policies["approved"].note
    clock.advance(seconds=5)
    carol.sign(carol.file_subject(doc), "approved", "Second approval")
    report = alice.verify_file(doc, required=["approved"])
    assert report.ok and report.policies["approved"].met
    assert {s.status for s in report.signatures} == {"valid"}

    doc.write_text("# Validation report\nedited\n")
    report = alice.verify_file(doc, required=["approved"])
    assert not report.ok and report.summary().startswith("UNSIGNED")
    assert {s.status for s in report.signatures} == {"invalidated"}
    assert len(report.recorded) == 3
    again = alice.verify_file(doc)
    assert again.recorded == []                     # recorded once per change
    inval = [r for r in records(make) if r["type"] == "signoff.invalidation"]
    assert len(inval) == 3 and all(r["data"]["cause"] == "content-changed" for r in inval)
    refused_records = [r for r in records(make) if r["type"] == "signoff.refused"]
    assert refused_records[0]["data"]["reason_code"] == "self_approval"
    assert all(not validate_record(r) for r in records(make))


def test_tampered_statement_is_invalid(people, make, isolated):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    alice = people["human:alice"]
    alice.sign(alice.file_subject(doc), "approved", "fine")
    lines = make.sink.read_text().splitlines()
    tampered = []
    for line in lines:
        record = json.loads(line)
        if record["type"] == "signoff.signature":
            record["data"]["signature"]["statement"]["signer"]["name"] = "Mallory"
        tampered.append(json.dumps(record))
    make.sink.write_text("\n".join(tampered) + "\n")
    report = alice.verify_file(doc)
    assert report.signatures[0].status == "invalid" and not report.ok


def test_statement_moved_to_other_content_does_not_count(people, isolated):
    alice = people["human:alice"]
    (isolated / "a.txt").write_text("alpha")
    (isolated / "b.txt").write_text("beta")
    alice.sign(alice.file_subject(isolated / "a.txt"), "approved", "fine")
    assert not alice.verify_file(isolated / "b.txt").signatures


def test_unknown_signer_with_other_registry(people, make, isolated):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    people["human:alice"].sign(people["human:alice"].file_subject(doc), "approved", "fine")
    stranger = make("human:alice", registry=isolated / "other.json")
    report = stranger.verify_file(doc)
    assert report.signatures[0].status == "unknown-signer"


def test_wrong_passphrase_fails_and_is_recorded(people, make, isolated):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    mallory = make("human:alice", passphrase="not-the-passphrase")
    with pytest.raises(AuthFailed):
        mallory.sign(mallory.file_subject(doc), "approved", "fine")
    failed = [r for r in records(make) if r["type"] == "signoff.auth.failed"]
    assert failed and failed[0]["data"]["signer"] == "human:alice"
    assert not [r for r in records(make) if r["type"] == "signoff.signature"]


def test_agent_session_is_refused_and_recorded(people, make, isolated):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    agent = make("human:alice", environ={"CLAUDECODE": "1"})
    with pytest.raises(Refused) as refused:
        agent.sign(agent.file_subject(doc), "approved", "the agent approves itself")
    assert refused.value.code == "agent_context"
    record = [r for r in records(make) if r["type"] == "signoff.refused"][-1]
    assert record["action"] == "refused"
    assert record["data"] == {"attempted_action": "sign", "reason_code": "agent_context",
                              "agent_markers": ["env:CLAUDECODE"]}
    chained = make("human:alice", chain=["aqt-signoff", "bash", "claude"])
    with pytest.raises(Refused):
        chained.sign(chained.file_subject(doc), "approved", "fine")


def test_revocation_with_compromise_time(people, make, clock, isolated):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    alice = people["human:alice"]
    early = alice.sign(alice.file_subject(doc), "reviewed", "early")
    clock.advance(minutes=10)
    alice.sign(alice.file_subject(doc), "approved", "late")
    clock.advance(minutes=10)
    since = early["data"]["signature"]["statement"]["signed_at"]
    alice.revoke("human:alice", "laptop stolen", compromised_since=since.replace("12:00:01", "12:05:00"))
    fresh = make("human:alice")
    statuses = {s.meaning: s.status for s in fresh.verify_file(doc).signatures}
    assert statuses == {"reviewed": "valid", "approved": "revoked"}
    assert list((isolated / "config/aqt/keys").glob("human-alice.*.revoked.key"))
    with pytest.raises(AuthFailed):
        fresh.sign(fresh.file_subject(doc), "approved", "after revocation")
    fresh.init_signer("human:alice", "", "", add_key=True)
    clock.advance(seconds=1)
    newest = make("human:alice")
    newest.sign(newest.file_subject(doc), "approved", "new key")
    assert any(s.valid and s.reason == "new key" for s in newest.verify_file(doc).signatures)
    revoked = [r for r in records(make) if r["type"] == "signoff.key.revoked"]
    assert revoked and revoked[0]["reason"] == "laptop stolen"


def test_withdrawal_invalidates(people, isolated):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    alice = people["human:alice"]
    signature = alice.sign(alice.file_subject(doc), "approved", "fine")
    alice.withdraw(signature["id"], "signed the wrong revision")
    status = alice.verify_file(doc).signatures[0]
    assert status.status == "invalidated" and "withdrawn" in status.detail


def test_signature_over_record_survives_trail_storage(people, make, clock):
    alice = people["human:alice"]
    target = new_record("change.finish", actor("agent", "agent:test:s1"), "finish", reason="done",
                        data={"plan_ref": "plan.md", "receipts": [], "waivers": [], "gate": "GO"},
                        time="2026-10-21T12:00:00.000000Z")
    alice.sink.append(target)
    subject_, _ = alice.record_subject(target["id"])
    assert subject_["sha256"] == record_content_hash(target)
    signature = alice.sign(subject_, "approved", "Release approved")
    assert {"rel": "signs", "ref": target["id"]} in signature["links"]
    # simulate aqt-trail: chain, restamp time, add observed, drop sig
    trail = []
    enrolments = [r for r in records(make) if r["type"] == "signoff.key.enrolled"]
    for seq, record in enumerate([*enrolments, target, signature]):
        stored = link(record, seq=seq, prev=GENESIS)
        stored["observed"] = {"pid": 1, "client_time": stored["time"]}
        stored["time"] = "2026-10-21T13:00:00.000000Z"
        trail.append(stored)
    trail_file = make.sink.with_name("trail.jsonl")
    trail_file.write_text("".join(json.dumps(r) + "\n" for r in trail))
    reader = make("human:alice", evidence=[trail_file])
    report = reader.verify_record(target["id"])
    assert report.ok and report.signatures[0].valid
    assert report.policies["approved"].authors == ["agent:test:s1"]


def test_shared_api_verify_subject_and_is_approved(people, make, isolated):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    alice, carol = people["human:alice"], people["human:carol"]
    sha = alice.file_subject(doc)["sha256"]
    alice.sign(alice.file_subject(doc), "approved", "one")
    statuses = verify_subject(sha, sources=[make.sink])
    assert [s.status for s in statuses] == ["valid"]
    assert is_approved(sha, sources=[make.sink])
    assert not is_approved(sha, policy={"min_signatures": 2}, sources=[make.sink])
    assert not is_approved(sha, meaning="released", sources=[make.sink])
    carol.sign(carol.file_subject(doc), "approved", "two")
    assert is_approved(sha, policy={"min_signatures": 2}, sources=[make.sink])
    assert verify_subject("sha256:" + "0" * 64, sources=[make.sink]) == []


def test_role_policy(people, make, tmp_path, isolated):
    cfg = tmp_path / "roles.toml"
    cfg.write_text('[policy.released]\nroles = ["quality-manager"]\n', encoding="utf-8")
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    bob = make("human:bob", config_path=cfg)
    with pytest.raises(Refused) as refused:
        bob.sign(bob.file_subject(doc), "released", "release")
    assert refused.value.code == "role_not_allowed"
    alice = make("human:alice", config_path=cfg)
    alice.sign(alice.file_subject(doc), "released", "release")


def test_manifest_shows_name_meaning_zone_and_hash(people, isolated):
    doc = isolated / "report.md"
    doc.write_text("content")
    alice = people["human:alice"]
    alice.sign(alice.file_subject(doc), "approved", "Checked | piped")
    report = alice.verify_file(doc)
    md = render(report, "md")
    assert "Alice Example" in md and "human:alice" in md and "quality-manager" in md and "approved" in md
    assert "EDT (America/New_York)" in md and report.subject["sha256"] in md and "Checked \\| piped" in md
    html_text = render(report, "html")
    assert "<td>Alice Example</td>" in html_text and report.subject["sha256"] in html_text
    doc.write_text("changed")
    assert "invalidated" in render(alice.verify_file(doc, record_invalidations=False), "md")


def test_hash_subject_and_meaning_mirror(people):
    alice = people["human:alice"]
    sha = "sha256:" + "ab" * 32
    record = alice.sign(subject("diff", "PR-7", sha256=sha), "reviewed", "diff reviewed")
    assert record["meaning"] == record["data"]["signature"]["statement"]["meaning"] == "reviewed"
    assert record["data"]["signature"]["statement"]["record_type"] == "signoff.signature"
    assert alice.verify_hash(sha).ok
