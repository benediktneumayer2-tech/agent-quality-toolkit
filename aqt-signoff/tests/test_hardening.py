"""Regression tests for the security review (replay, rebinding, action binding, registry trust, keys)."""

import json
import os
import stat
import sys

import pytest
from cryptography.hazmat.primitives import serialization

from aqt_evidence import (actor, canonical_json, generate_key, load_public_key, load_signer, new_record, read_jsonl,
                          record_content_hash, subject)
from aqt_evidence.crypto import public_pem
from aqt_signoff import AlreadyClaimed, Refused, UsageError, is_approved, load_settings
from aqt_signoff.cli import main
from aqt_signoff.registry import SignerEntry

from conftest import PASSWORDS

AGENT = actor("agent", "agent:test:s1", harness="test")


def records(make, type_=None):
    return [r for r in read_jsonl(make.sink) if type_ is None or r["type"] == type_]


def key_of(so, signer_id):
    return load_signer(so.registry.key_path(signer_id), passphrase=PASSWORDS[signer_id].encode())


def policy_config(tmp_path, text):
    path = tmp_path / "policy.toml"
    path.write_text(text, encoding="utf-8")
    return path


def counter_action(so, tmp_path, key="count-1"):
    out = tmp_path / "count.txt"
    argv = [sys.executable, "-c", f"open({str(out)!r}, 'a').write('x\\n')"]
    return so.actions.prepare("command", key, {"argv": argv}, description="append one line", who=AGENT), out


# ---- signed statements: replay and rebinding (A-2, AQT-EI-007, KEYS-04, AQT-EI-012) --------------------
def test_replayed_statement_counts_once_and_stays_withdrawn(people, make, isolated):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    alice = people["human:alice"]
    signature = alice.sign(alice.file_subject(doc), "approved", "fine")
    alice.withdraw(signature["id"], "signed the wrong revision")
    sha = alice.file_subject(doc)["sha256"]
    assert not is_approved(sha, sources=[make.sink])
    # an agent copies the withdrawn statement into a fresh record
    copy = new_record("signoff.signature", signature["actor"], "sign", subject=signature["subject"],
                      reason=signature["reason"], meaning="approved", data=signature["data"])
    alice.sink.append(copy)
    assert not is_approved(sha, sources=[make.sink])
    report = make("human:alice").verify_file(doc, record_invalidations=False)
    by_id = {s.record_id: s for s in report.signatures}
    assert by_id[signature["id"]].status == "invalidated"
    assert by_id[copy["id"]].status == "invalid" and "replayed" in by_id[copy["id"]].detail
    assert not report.ok


def test_withdrawal_cannot_be_redirected_to_another_signature(people, make, isolated):
    alice = people["human:alice"]
    (isolated / "a.txt").write_text("a")
    (isolated / "b.txt").write_text("b")
    first = alice.sign(alice.file_subject(isolated / "a.txt"), "approved", "a is fine")
    second = alice.sign(alice.file_subject(isolated / "b.txt"), "approved", "b is fine")
    withdrawal = alice.withdraw(first["id"], "a was wrong")
    assert withdrawal["data"]["signature"]["statement"]["withdraws"]
    forged = new_record("signoff.invalidation", withdrawal["actor"], "withdraw", subject=withdrawal["subject"],
                        reason=withdrawal["reason"], links=[{"rel": "invalidates", "ref": second["id"]}],
                        data={**withdrawal["data"], "signature_record": second["id"]})
    alice.sink.append(forged)
    reader = make("human:alice")
    assert reader.verify_file(isolated / "b.txt").ok
    assert reader.verify_file(isolated / "a.txt", record_invalidations=False).signatures[0].status == "invalidated"


def test_withdrawal_written_before_this_version_still_applies(people, make, isolated):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    alice = people["human:alice"]
    signature = alice.sign(alice.file_subject(doc), "approved", "fine")
    key, signer = key_of(alice, "human:alice"), alice.registry.get("human:alice")
    old = alice.signed_record(       # the withdrawal as earlier versions wrote it: no signed "withdraws"
        "signoff.invalidation", "withdraw", signer=signer, key=key, meaning="rejected", reason="old style",
        subject=subject("record", signature["id"], sha256=record_content_hash(signature)), envelope_meaning=False,
        links=[{"rel": "invalidates", "ref": signature["id"]}],
        data={"signature_record": signature["id"], "cause": "withdrawn",
              "signed_sha256": signature["subject"]["sha256"]})
    assert "withdraws" not in old["data"]["signature"]["statement"]
    alice.emit(old, key)
    status = make("human:alice").verify_file(doc, record_invalidations=False).signatures[0]
    assert status.status == "invalidated" and "old style" in status.detail


# ---- approved actions (AQT-EI-004/005/006, KEYS-02, D-4, D-5) -------------------------------------------
def test_altered_action_body_is_never_run(people, tmp_path):
    alice = people["human:alice"]
    view, out = counter_action(alice, tmp_path)
    alice.actions.approve(view["id"], view["action_sha256"], "argv reviewed")
    body = alice.store.action(view["id"])["spec"]
    body["spec"]["argv"] = [sys.executable, "-c", f"open({str(out)!r}, 'w').write('MUTATED')"]
    alice.store.db.execute("UPDATE actions SET spec=? WHERE id=?", (json.dumps(body), view["id"]))
    with pytest.raises(Refused) as refused:
        alice.actions.run(view["id"])
    assert refused.value.code == "action_altered" and not out.exists()
    assert "no longer matches its hash" in alice.actions.show(view["id"])["detail"]


def test_preparer_comes_from_the_hashed_action(people):
    alice = people["human:alice"]
    view = alice.actions.prepare("command", "mine", {"argv": ["true"]}, who=actor("human", "human:alice"))
    assert view["spec"]["preparer"] == "human:alice"
    alice.store.db.execute("UPDATE actions SET preparer=? WHERE id=?",
                           (json.dumps(actor("agent", "agent:someone-else")), view["id"]))
    with pytest.raises(Refused) as refused:
        alice.actions.approve(view["id"], view["action_sha256"], "mine")
    assert refused.value.code == "self_approval"


def test_only_an_action_approval_authorises_a_claim(people, isolated):
    alice = people["human:alice"]
    view = alice.actions.prepare("other", "manual", {"text": "rotate the certificate"}, who=AGENT)
    as_action = alice.sign(subject("action", view["id"], sha256=view["action_sha256"]), "approved", "generic")
    path = isolated / view["id"]                       # a file whose bytes hash to the action hash
    path.write_bytes(canonical_json(view["spec"]))
    file_subject = alice.file_subject(path)
    assert file_subject == {"kind": "file", "ref": view["id"], "sha256": view["action_sha256"]}
    as_file = alice.sign(file_subject, "approved", "the file is fine")
    alice.store.db.execute("UPDATE actions SET approvals=?, status='approved' WHERE id=?",
                           (json.dumps([as_action, as_file]), view["id"]))
    with pytest.raises(Refused) as refused:
        alice.actions.claim(view["id"], view["action_sha256"], who=AGENT)
    assert refused.value.code == "not_approved"


def test_rolled_back_index_does_not_run_an_action_twice(people, tmp_path):
    alice = people["human:alice"]
    view, out = counter_action(alice, tmp_path)
    alice.actions.approve(view["id"], view["action_sha256"], "ok")
    assert alice.actions.run(view["id"])["data"]["outcome"] == "succeeded"
    alice.store.db.execute("UPDATE actions SET status='approved', claim_id=NULL, claimed_at=NULL, outcome=NULL "
                           "WHERE id=?", (view["id"],))
    with pytest.raises(AlreadyClaimed) as already:
        alice.actions.run(view["id"])
    assert already.value.details["record"] and out.read_text() == "x\n"


def test_claim_grace_is_never_shorter_than_the_run_timeout(people, clock, tmp_path):
    short = load_settings(config=policy_config(tmp_path, "[signoff]\nclaim_grace_ms = 1000\nrun_timeout_ms = 5000\n"))
    assert short.claim_grace == 5000                  # a shorter configured grace is raised to the run timeout
    defaults = load_settings(config=tmp_path / "missing.toml")
    assert defaults.claim_grace_ms > defaults.run_timeout_ms
    alice = people["human:alice"]
    alice.settings.claim_grace_ms = 1000             # set in code: the run timeout still wins
    view = alice.actions.prepare("other", "slow", {"text": "long job"}, who=AGENT)
    alice.actions.approve(view["id"], view["action_sha256"], "ok")
    alice.actions.claim(view["id"], view["action_sha256"], who=AGENT)
    clock.advance(minutes=9)
    assert alice.actions.show(view["id"])["status"] == "claimed"
    with pytest.raises(Refused) as refused:
        alice.actions.resolve(view["id"], "not-applied", "looks idle")
    assert refused.value.code == "claim_in_progress"
    command = alice.actions.prepare("command", "cmd", {"argv": ["true"]}, who=AGENT)
    with pytest.raises(UsageError):
        alice.actions.run(command["id"], timeout_ms=alice.settings.claim_grace + 1)


def test_bound_payload_is_required_and_fed_on_stdin(people, tmp_path):
    alice = people["human:alice"]
    out = tmp_path / "got.bin"
    argv = [sys.executable, "-c", f"import sys; open({str(out)!r}, 'wb').write(sys.stdin.buffer.read())"]
    view = alice.actions.prepare("command", "pay", {"argv": argv}, payload=b"APPROVED", who=AGENT)
    alice.actions.approve(view["id"], view["action_sha256"], "payload reviewed")
    with pytest.raises(Refused) as refused:
        alice.actions.run(view["id"])
    assert refused.value.code == "payload_required" and not out.exists()
    with pytest.raises(Refused) as refused:
        alice.actions.run(view["id"], payload=b"SWAPPED")
    assert refused.value.code == "payload_mismatch" and not out.exists()
    result = alice.actions.run(view["id"], payload=b"APPROVED")
    assert result["data"]["outcome"] == "succeeded" and out.read_bytes() == b"APPROVED"


# ---- roles and authors (KEYS-05, KEYS-06) -----------------------------------------------------------------
def test_role_comes_from_the_registry_not_the_statement(people, make, tmp_path, isolated):
    cfg = policy_config(tmp_path, '[policy.released]\nroles = ["quality-manager"]\n')
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    bob = people["human:bob"]                              # registry role: developer
    entry = bob.registry.get("human:bob")
    claimed = SignerEntry(entry.id, entry.name, "quality-manager", entry.keys)
    key = key_of(bob, "human:bob")
    bob.emit(bob.signed_record("signoff.signature", "sign", signer=claimed, key=key, meaning="released",
                               reason="release", subject=bob.file_subject(doc), data={"meaning": "released"}), key)
    report = make("human:alice", config_path=cfg).verify_file(doc, required=["released"])
    status = report.signatures[0]
    assert status.valid and status.role == "quality-manager" and status.authorized_role is None
    assert not report.policies["released"].met and not report.ok


def test_record_author_is_excluded_in_shared_checks_and_when_signing(people, make, tmp_path):
    cfg = policy_config(tmp_path, "[policy.approved]\ndistinct_from_author = true\n")
    alice = make("human:alice", config_path=cfg)
    target = new_record("change.finish", actor("human", "human:alice"), "finish", reason="done",
                        data={"plan_ref": "plan.md", "receipts": [], "waivers": [], "gate": "GO"})
    alice.sink.append(target)
    sha = record_content_hash(target)
    with pytest.raises(Refused) as refused:                # e.g. the UI's plan approval passes no authors
        alice.sign(subject("record", target["id"], sha256=sha), "approved", "my own plan")
    assert refused.value.code == "self_approval"
    key = key_of(alice, "human:alice")                     # a self-approval made some other way
    alice.emit(alice.signed_record("signoff.signature", "sign", signer=alice.registry.get("human:alice"), key=key,
                                   meaning="approved", reason="mine", subject=subject("record", target["id"], sha256=sha),
                                   data={"meaning": "approved"}), key)
    policy = {"distinct_from_author": True}
    assert not is_approved(sha, policy=policy, sources=[make.sink])
    assert not alice.verify_hash(sha, required=["approved"]).ok
    carol = make("human:carol", config_path=cfg)
    carol.sign(subject("record", target["id"], sha256=sha), "approved", "independent check")
    assert is_approved(sha, policy=policy, sources=[make.sink])


# ---- the signer registry is checked against the evidence (B-1, KEYS-01, B-5) -------------------------------
def _add_forged_signer(isolated, signer_id, role, *, to=None):
    """What a same-user process can do: write a key file and a registry entry, no enrolment record."""
    keys = isolated / "config/aqt/keys"
    path = keys / f"{signer_id.replace(':', '-')}.forged.key"
    generate_key(path, passphrase=b"attacker-passphrase")
    kid, public = load_public_key(f"{path}.pub")
    registry_path = isolated / "config/aqt/signers.json"
    doc = json.loads(registry_path.read_text())
    entry = {"key_id": kid, "public_pem": public_pem(public).decode(), "enrolled_at": "2020-01-01T00:00:00.000000Z",
             "revoked_at": None}
    if to:
        next(s for s in doc["signers"] if s["id"] == to)["keys"].append(entry)
    else:
        doc["signers"].append({"id": signer_id, "name": signer_id.split(":")[1].title(), "role": role,
                               "keys": [entry]})
    registry_path.write_text(json.dumps(doc))
    return load_signer(path, passphrase=b"attacker-passphrase")


def test_registry_entries_without_enrolment_records_do_not_count(people, make, tmp_path, isolated, capsys):
    cfg = policy_config(tmp_path, '[policy.approved]\nmin_signatures = 2\nroles = ["quality-manager"]\n'
                                  'distinct_from_author = true\n')
    doc = isolated / "release.md"
    doc.write_text("ship it\n")
    so = make("human:alice", config_path=cfg)
    forged = {sid: _add_forged_signer(isolated, sid, "quality-manager") for sid in ("human:mallory", "human:trent")}
    forged["human:alice"] = _add_forged_signer(isolated, "human:alice", "", to="human:alice")   # extra key for Alice
    so.reload_registry()
    for sid, key in forged.items():
        so.emit(so.signed_record("signoff.signature", "sign", signer=so.registry.get(sid), key=key, meaning="approved",
                                 reason="looks good", subject=so.file_subject(doc), data={"meaning": "approved"}), key)
    report = make("human:alice", config_path=cfg).verify_file(doc, required=["approved"])
    assert {s.status for s in report.signatures} == {"unknown-signer"} and not report.ok
    assert all("not backed by its enrolment record" in s.detail for s in report.signatures)
    assert {k["signer"] for k in report.registry_problems} == {"human:mallory", "human:trent", "human:alice"}
    check = so.check_signers()
    assert not check["ok"]
    assert {k["signer"] for k in check["keys"] if not k["counts"]} == {"human:mallory", "human:trent", "human:alice"}
    assert main(["--sink", f"file:{make.sink}", "signers", "check"]) == 1
    assert "DOES NOT COUNT" in capsys.readouterr().out


def test_registry_edits_of_role_or_revocation_do_not_take_effect(people, make, isolated, clock):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    bob = people["human:bob"]
    old_key = key_of(bob, "human:bob")
    bob.revoke("human:bob", "rotation")
    clock.advance(minutes=1)
    registry_path = isolated / "config/aqt/signers.json"
    data = json.loads(registry_path.read_text())
    entry = next(s for s in data["signers"] if s["id"] == "human:bob")
    entry["keys"][0]["revoked_at"] = None                 # un-revoke in the file
    carol = next(s for s in data["signers"] if s["id"] == "human:carol")
    carol["role"] = "quality-manager"                     # promote in the file
    registry_path.write_text(json.dumps(data))
    reader = make("human:alice")
    signer = reader.registry.get("human:bob")
    reader.emit(reader.signed_record("signoff.signature", "sign", signer=signer, key=old_key, meaning="approved",
                                     reason="after revocation", subject=reader.file_subject(doc),
                                     data={"meaning": "approved"}), old_key)
    assert reader.verify_file(doc).signatures[0].status == "revoked"
    keys = {k["signer"]: k for k in reader.check_signers()["keys"]}
    assert keys["human:bob"]["counts"] and any("revocation applies" in n for n in keys["human:bob"]["notes"])
    assert not keys["human:carol"]["counts"] and "differs from the enrolled role" in keys["human:carol"]["problems"][0]


def test_key_enrolled_by_another_tool_is_recorded_at_first_use(make, isolated):
    path = isolated / "config/aqt/keys/human-dana.key"     # e.g. aqt-quarantine init: registry entry, no record
    kid = generate_key(path, passphrase=b"dana-passphrase-1")
    registry_path = isolated / "config/aqt/signers.json"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(json.dumps({"version": 1, "signers": [{
        "id": "human:dana", "name": "Dana Example", "role": "qa",
        "keys": [{"key_id": kid, "public_pem": path.with_name("human-dana.key.pub").read_text(),
                  "enrolled_at": "2026-10-01T00:00:00.000000Z", "revoked_at": None}]}]}))
    dana = make("human:dana", passphrase="dana-passphrase-1")
    assert not dana.check_signers()["ok"]
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    dana.sign(dana.file_subject(doc), "reviewed", "read it")
    enrolled = records(make, "signoff.key.enrolled")
    assert len(enrolled) == 1 and enrolled[0]["data"]["adopted"] is True
    assert enrolled[0]["data"]["signature"]["statement"]["enrolled_at"] == "2026-10-01T00:00:00.000000Z"
    assert make("human:dana").verify_file(doc).ok
    check = make("human:dana").check_signers()
    assert check["ok"] and any("outside 'aqt-signoff init'" in n for n in check["keys"][0]["notes"])


def test_enrolment_must_be_in_the_trail_when_there_is_one(people, make, isolated):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    people["human:alice"].sign(people["human:alice"].file_subject(doc), "approved", "fine")
    trail_dir = isolated / "trail"
    trail_dir.mkdir()
    (trail_dir / "trail.json").write_text("{}")
    trail = trail_dir / "trail.jsonl"
    trail.write_text("")
    side_file_only = make("human:alice", evidence=[trail, make.sink])
    assert side_file_only.verify_file(doc).signatures[0].status == "unknown-signer"
    trail.write_text("".join(canonical_json(r).decode() + "\n" for r in records(make, "signoff.key.enrolled")))
    assert make("human:alice", evidence=[trail, make.sink]).verify_file(doc).ok


# ---- key files (B-2, KEYS-11, B-4) --------------------------------------------------------------------------
def test_new_keys_use_scrypt_and_earlier_keys_are_re_encrypted_at_unlock(people, isolated):
    from aqt_evidence.crypto import key_file_format
    keys_dir = isolated / "config/aqt/keys"
    assert stat.S_IMODE(os.stat(keys_dir).st_mode) == 0o700
    path = keys_dir / "human-alice.key"
    assert key_file_format(path) == "aqt-key"
    private = load_signer(path, passphrase=PASSWORDS["human:alice"].encode()).private_key
    path.unlink()                                          # the same key as an earlier version stored it
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.BestAvailableEncryption(PASSWORDS["human:alice"].encode())))
    assert key_file_format(path) == "pkcs8-encrypted"
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    alice = people["human:alice"]
    alice.sign(alice.file_subject(doc), "approved", "fine")
    assert key_file_format(path) == "aqt-key" and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert alice.verify_file(doc).ok
    result = alice.rekey("human:alice")
    assert result["format"] == "aqt-key" and not result["upgraded"] and not result["enrolled"]
