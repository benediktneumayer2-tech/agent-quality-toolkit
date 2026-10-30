"""Counter-signed enrolment: the first signer counts at once, every later enrolment, extra key or role change
counts only after another enrolled signer approves it (security review round 3: self-signed enrolment records,
B-1, KEYS-01, KEYS-05; a trail added after the fallback file)."""

import json

import pytest

from aqt_evidence import (bytes_hash, content_hash, generate_key, load_public_key, load_signer, new_record, read_jsonl,
                          subject)
from aqt_evidence.crypto import public_pem
from aqt_signoff import Refused, UsageError
from aqt_signoff.cli import main
from aqt_signoff.registry import SignerEntry

from conftest import PASSWORDS, key_id_of

QM_POLICY = '[policy.approved]\nmin_signatures = 2\nroles = ["quality-manager"]\ndistinct_from_author = true\n'


def records(make, type_=None):
    return [r for r in read_jsonl(make.sink) if type_ is None or r["type"] == type_]


def key_of(make, signer_id):
    so = make(signer_id)
    return load_signer(so.registry.key_path(signer_id), passphrase=PASSWORDS[signer_id].encode())


def forge(make, isolated, signer_id, role, *, add_to=None, key=None, signed_at=None, enrolled_at=None):
    """What any same-user process can do without aqt-signoff or a terminal: make a key (or use one it holds),
    write it into signers.json and append a ``signoff.key.enrolled`` record that the key signs itself."""
    registry_path = isolated / "config/aqt/signers.json"
    doc = json.loads(registry_path.read_text())
    if key is None:
        path = isolated / f"{signer_id.replace(':', '-')}.forged.key"
        generate_key(path, passphrase=b"attacker-passphrase")
        key = load_signer(path, passphrase=b"attacker-passphrase")
        kid, public = load_public_key(f"{path}.pub")
        entry = {"key_id": kid, "public_pem": public_pem(public).decode(), "enrolled_at": "2020-01-01T00:00:00Z",
                 "revoked_at": None}
        if add_to:
            next(s for s in doc["signers"] if s["id"] == add_to)["keys"].append(entry)
        else:
            doc["signers"].append({"id": signer_id, "name": signer_id.split(":")[1].title(), "role": role,
                                   "keys": [entry]})
    else:
        entry = next(k for s in doc["signers"] for k in s["keys"] if k["key_id"] == key.key_id)
        next(s for s in doc["signers"] if s["id"] == signer_id)["role"] = role
    registry_path.write_text(json.dumps(doc))
    so = make()
    signer = so.reload_registry().get(signer_id)
    as_role = SignerEntry(signer.id, signer.name, role, signer.keys)
    if signed_at:                     # the statement claims an earlier time; the record keeps the clock's
        times = iter([signed_at])
        clock_now = so.now
        so.now = lambda: next(times, None) or clock_now()
    so.emit(so.signed_record("signoff.key.enrolled", "enroll", signer=as_role, key=key, meaning="acknowledged",
                             reason="Key enrolled for electronic signatures", envelope_meaning=False,
                             enrolled_at=enrolled_at or entry["enrolled_at"],
                             subject=subject("key", key.key_id, sha256=bytes_hash(entry["public_pem"].encode())),
                             data={"signer": signer_id, "name": signer.name, "role": role, "key_id": key.key_id,
                                   "public_pem": entry["public_pem"]}), key)
    return key


def sign_with(make, signer_id, key, path, meaning="approved", role=None):
    so = make()
    signer = so.reload_registry().get(signer_id)
    if role:
        signer = SignerEntry(signer.id, signer.name, role, signer.keys)
    return so.emit(so.signed_record("signoff.signature", "sign", signer=signer, key=key, meaning=meaning,
                                    reason="looks good", subject=so.file_subject(path), data={"meaning": meaning}), key)


def keys(so) -> dict:
    return {(k["signer"], k["key_id"]): k for k in so.check_signers()["keys"]}


# ---- B-1 / KEYS-01: a self-signed enrolment record no longer makes a counting key ---------------------------
def test_forged_signers_with_self_signed_enrolment_wait_for_approval(people, make, isolated, tmp_path, capsys):
    cfg = tmp_path / "policy.toml"
    cfg.write_text(QM_POLICY)
    doc = isolated / "release.md"
    doc.write_text("ship it\n")
    forged = {sid: forge(make, isolated, sid, "quality-manager") for sid in ("human:mallory", "human:trent")}
    for sid, key in forged.items():
        sign_with(make, sid, key, doc)
    report = make(config_path=cfg).verify_file(doc, required=["approved"])
    assert not report.ok and {s.status for s in report.signatures} == {"unknown-signer"}
    assert all("waits for approval" in s.detail for s in report.signatures)
    check = make().check_signers()
    assert not check["ok"] and check["bootstrap"]["signer"] == "human:alice"
    assert {p["signer"] for p in check["pending"]} == {"human:mallory", "human:trent"}
    assert all(k["pending"] and not k["counts"] for k in check["keys"] if k["signer"] in forged)
    assert main(["--sink", f"file:{make.sink}", "signers", "check"]) == 1
    out = capsys.readouterr().out
    assert "PENDING" in out and "first signer (counted without approval): human:alice" in out


def test_extra_key_for_an_existing_signer_waits_for_approval(people, make, isolated):
    doc = isolated / "release.md"
    doc.write_text("ship it\n")
    extra = forge(make, isolated, "human:alice", "quality-manager", add_to="human:alice")
    sign_with(make, "human:alice", extra, doc)
    status = make().verify_file(doc).signatures[0]
    assert status.status == "unknown-signer" and status.authorized_role is None
    row = keys(make())[("human:alice", extra.key_id)]
    assert row["pending"] and not row["counts"]
    assert keys(make())[("human:alice", key_id_of(make, "human:alice"))]["counts"] is False   # the file's active key
    original = next(k for k in make().reload_registry().get("human:alice").keys if k.key_id != extra.key_id)
    assert keys(make())[("human:alice", original.key_id)]["counts"]                           # Alice's own key still counts


# ---- KEYS-05: the holder of a developer key cannot re-enrol it as quality-manager --------------------------
def test_second_enrolment_record_for_a_key_is_a_conflict_not_a_role(people, make, isolated, tmp_path):
    cfg = tmp_path / "policy.toml"
    cfg.write_text('[policy.approved]\nroles = ["quality-manager"]\n')
    bob_key = key_of(make, "human:bob")
    forge(make, isolated, "human:bob", "quality-manager", key=bob_key, signed_at="2026-01-01T00:00:00.000000Z",
          enrolled_at="2026-01-01T00:00:00.000000Z")
    doc = isolated / "release.md"
    doc.write_text("ship it\n")
    sign_with(make, "human:bob", bob_key, doc, role="quality-manager")
    status = make(config_path=cfg).verify_file(doc, required=["approved"])
    assert not status.ok and status.signatures[0].status == "unknown-signer"
    assert status.signatures[0].authorized_role is None
    row = keys(make())[("human:bob", bob_key.key_id)]
    assert not row["counts"] and row["stopped_at"]                 # stopped by the conflict; the edited role too
    assert any("conflicting enrolment records" in p for p in row["notes"])
    assert any("a second, different enrolment record" in p for p in make().check_signers()["problems"])


def test_a_signer_cannot_approve_their_own_role_change(people, make, isolated, clock):
    bob = make("human:bob")
    with pytest.raises(UsageError) as error:
        bob.approve_enrolment("human:bob", key_id_of(make, "human:bob"), role="quality-manager")
    assert error.value.code == "self_approval"
    with pytest.raises(UsageError) as error:                      # a rotation keeps the role
        make("human:bob").init_signer("human:bob", "", "quality-manager", add_key=True)
    assert error.value.code == "role_change"
    # an approval record Bob makes with his own key for his own (new, pending) key: not a role change either
    second = forge(make, isolated, "human:bob", "developer", add_to="human:bob")
    request = records(make, "signoff.key.enrolled")[-1]
    so = make("human:bob")
    registry = so.reload_registry()
    entry = next(k for k in registry.get("human:bob").keys if k.key_id == second.key_id)
    so.emit(so._approval_record(registry.get("human:bob"), key_of(make, "human:bob"), request, "human:bob", entry,
                                "quality-manager", "promote myself"), key_of(make, "human:bob"))
    row = keys(make())[("human:bob", second.key_id)]
    assert not row["counts"] and any("cannot approve a role for themselves" in p for p in row["problems"])


def test_role_change_is_an_approval_by_another_signer_and_old_signatures_keep_their_role(people, make, isolated,
                                                                                         clock, tmp_path):
    cfg = tmp_path / "policy.toml"
    cfg.write_text('[policy.approved]\nroles = ["quality-manager"]\n')
    old, new = isolated / "old.md", isolated / "new.md"
    old.write_text("old\n")
    new.write_text("new\n")
    make("human:bob").sign(make("human:bob").file_subject(old), "approved", "as developer")
    clock.advance(minutes=1)
    approval = make("human:alice").approve_enrolment("human:bob", key_id_of(make, "human:bob"),
                                                     role="quality-manager", reason="Bob is now our QM")
    assert approval["data"]["role"] == "quality-manager"
    assert make().reload_registry().get("human:bob").role == "quality-manager"     # the registry follows
    clock.advance(minutes=1)
    make("human:bob").sign(make("human:bob").file_subject(new), "approved", "as QM")
    before = make(config_path=cfg).verify_file(old).signatures[0]
    after = make(config_path=cfg).verify_file(new, required=["approved"])
    assert before.valid and before.role == before.authorized_role == "developer"
    assert after.ok and after.signatures[0].authorized_role == "quality-manager"
    row = keys(make())[("human:bob", key_id_of(make, "human:bob"))]
    assert row["counts"] and [r["role"] for r in row["roles"]] == ["developer", "quality-manager"]


def test_editing_the_role_in_the_file_still_stops_the_key(people, make, isolated):
    path = isolated / "config/aqt/signers.json"
    doc = json.loads(path.read_text())
    next(s for s in doc["signers"] if s["id"] == "human:carol")["role"] = "quality-manager"
    path.write_text(json.dumps(doc))
    row = keys(make())[("human:carol", key_id_of(make, "human:carol"))]
    assert not row["counts"] and "differs from the enrolled role" in row["problems"][0]


# ---- rotation and re-bootstrap ------------------------------------------------------------------------------
def test_rotation_is_approved_by_the_old_key_which_is_revoked(people, make, isolated, clock):
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    alice = make("human:alice")
    old_key = key_id_of(make, "human:alice")
    signed = alice.sign(alice.file_subject(doc), "approved", "before rotation")
    clock.advance(seconds=5)
    request = make("human:alice").init_signer("human:alice", "", "", add_key=True)
    clock.advance(seconds=5)
    new_key = key_id_of(make, "human:alice")
    assert new_key == request["data"]["key_id"] != old_key
    rows = keys(make())
    assert rows[("human:alice", new_key)]["counts"] and rows[("human:alice", new_key)]["basis"] == "approved"
    assert rows[("human:alice", new_key)]["approvals"][0]["key"] == old_key
    assert rows[("human:alice", old_key)]["revoked_at"] and make().check_signers()["ok"]
    assert not make().check_signers()["unsigned_revocations"]        # the old key signed its own revocation
    statuses = {s.record_id: s.status for s in make().verify_file(doc).signatures}
    assert statuses[signed["id"]] == "valid"                         # signed before the rotation: still valid
    newer = make("human:alice")
    newer.sign(newer.file_subject(doc), "reviewed", "with the new key")
    assert {s.status for s in make().verify_file(doc).signatures} == {"valid"}
    assert list((isolated / "config/aqt/keys").glob("human-alice.*.revoked.key"))


def test_self_approval_of_an_extra_key_without_revoking_the_old_one_does_not_count(people, make, isolated):
    extra = forge(make, isolated, "human:carol", "qa", add_to="human:carol")
    request = records(make, "signoff.key.enrolled")[-1]
    so = make("human:carol")
    registry = so.reload_registry()
    entry = next(k for k in registry.get("human:carol").keys if k.key_id == extra.key_id)
    own = key_of(make, "human:carol")
    so.emit(so._approval_record(registry.get("human:carol"), own, request, "human:carol", entry, "qa",
                                "my second laptop"), own)
    row = keys(make())[("human:carol", extra.key_id)]
    assert not row["counts"] and any("it counts once" in p for p in row["problems"])


def test_rebootstrap_after_all_keys_are_revoked_counts_but_is_flagged(make, isolated, clock, capsys):
    make("human:alice").init_signer("human:alice", "Alice Example", "quality-manager")
    clock.advance(minutes=1)
    make("human:alice").revoke("human:alice", "passphrase forgotten", lost=True)
    clock.advance(minutes=1)
    make("human:alice").init_signer("human:alice", "", "", add_key=True)
    check = make().check_signers()
    new_key = key_id_of(make, "human:alice")
    assert keys(make())[("human:alice", new_key)]["counts"]
    assert not check["ok"] and check["rebootstrap"][0]["key_id"] == new_key
    assert any(n.startswith("RE-BOOTSTRAP") for n in keys(make())[("human:alice", new_key)]["notes"])
    assert main(["--sink", f"file:{make.sink}", "signers", "check"]) == 1
    assert "WARNING: RE-BOOTSTRAP" in capsys.readouterr().out
    assert [u["key_id"] for u in check["rebootstrap"][0]["unsigned_revocations"]] != []   # the --lost revocation
    clock.advance(minutes=1)
    bob = make("human:bob").init_signer("human:bob", "Bob Example", "developer")
    make("human:alice").approve_enrolment("human:bob", bob["data"]["key_id"])
    make("human:bob").approve_enrolment("human:alice", new_key, reason="I know Alice; she lost her passphrase")
    check = make().check_signers()           # Bob counts only through Alice's new key: he cannot vouch for it
    assert not check["ok"] and not check["rebootstrap"][0]["confirmed_by"]
    assert check["rebootstrap"][0]["not_confirming"][0]["by"] == "human:bob"


def test_forged_revocations_do_not_turn_a_pending_enrolment_into_a_rebootstrap(people, make, isolated):
    pending = forge(make, isolated, "human:mallory", "quality-manager")
    so = make()
    for signer in so.reload_registry().signers:                     # unsigned revocations of every other key
        for key in signer.keys:
            if key.key_id != pending.key_id:
                so.emit(so.record("signoff.key.revoked", {"kind": "human", "id": signer.id}, "revoke", reason="x",
                                  data={"signer": signer.id, "key_id": key.key_id,
                                        "revoked_at": "2020-01-01T00:00:00.000000Z", "signed": False}))
    row = keys(make())[("human:mallory", pending.key_id)]
    assert not row["counts"] and row["pending"] and not make().check_signers()["rebootstrap"]


# ---- times come from the record, not from the statement ----------------------------------------------------
def test_backdated_enrolment_counts_only_from_its_record_time(people, make, isolated, clock):
    clock.advance(hours=1)
    dora = forge(make, isolated, "human:dora", "qa", signed_at="2026-01-01T00:00:00.000000Z",
                 enrolled_at="2026-01-01T00:00:00.000000Z")
    make("human:alice").approve_enrolment("human:dora", dora.key_id)
    row = keys(make())[("human:dora", dora.key_id)]
    request = records(make, "signoff.key.enrolled")[-2]
    assert row["counts"] and row["enrolled_at"] == request["time"] != "2026-01-01T00:00:00.000000Z"
    doc = isolated / "a.txt"
    doc.write_text("alpha")
    so = make()
    so.now = lambda: "2026-06-01T00:00:00.000000Z"                   # a signature dated before the enrolment
    so.emit(so.signed_record("signoff.signature", "sign", signer=so.reload_registry().get("human:dora"), key=dora,
                             meaning="reviewed", reason="r", subject=so.file_subject(doc),
                             data={"meaning": "reviewed"}), dora)
    assert make().verify_file(doc).signatures[0].status == "unknown-signer"


def test_approval_by_a_pending_key_does_not_count(people, make, isolated):
    mallory = forge(make, isolated, "human:mallory", "quality-manager")
    trent = forge(make, isolated, "human:trent", "quality-manager")
    so = make()
    registry = so.reload_registry()
    request = next(r for r in records(make, "signoff.key.enrolled") if r["data"]["key_id"] == trent.key_id)
    entry = registry.get("human:trent").keys[0]
    so.emit(so._approval_record(registry.get("human:mallory"), mallory, request, "human:trent", entry,
                                "quality-manager", "vouch"), mallory)
    check = make().check_signers()
    assert keys(make())[("human:trent", trent.key_id)]["pending"]
    assert any("does not count or is revoked" in p for p in check["problems"])


# ---- adoption of a key made by another tool -----------------------------------------------------------------
def test_key_made_by_another_tool_is_pending_unless_it_is_the_first(people, make, isolated):
    path = isolated / "config/aqt/keys/human-dana.key"
    kid = generate_key(path, passphrase=b"dana-passphrase-1")
    registry_path = isolated / "config/aqt/signers.json"
    doc = json.loads(registry_path.read_text())
    doc["signers"].append({"id": "human:dana", "name": "Dana Example", "role": "qa", "keys": [
        {"key_id": kid, "public_pem": path.with_name("human-dana.key.pub").read_text(),
         "enrolled_at": "2026-10-01T00:00:00.000000Z", "revoked_at": None}]})
    registry_path.write_text(json.dumps(doc))
    dana = make("human:dana", passphrase="dana-passphrase-1")
    result = dana.rekey("human:dana")
    assert result["enrolled"] and result["pending"]
    doc_path = isolated / "a.txt"
    doc_path.write_text("alpha")
    with pytest.raises(Refused) as refused:
        make("human:dana", passphrase="dana-passphrase-1").sign(dana.file_subject(doc_path), "reviewed", "x")
    assert refused.value.code == "enrolment_pending"
    make("human:alice").approve_enrolment("human:dana", kid)
    make("human:dana", passphrase="dana-passphrase-1").sign(dana.file_subject(doc_path), "reviewed", "x")
    assert make().verify_file(doc_path).ok


# ---- a trail added after the fallback file (regression) -----------------------------------------------------
@pytest.fixture
def trail(isolated):
    folder = isolated / "trail"
    folder.mkdir()
    (folder / "trail.json").write_text("{}")
    (folder / "trail.jsonl").write_text("")
    return folder / "trail.jsonl"


@pytest.fixture
def with_trail(trail, make, clock, config):
    """A Signoff whose records go to the trail; the fallback file written before it is still read."""
    from aqt_signoff import Signoff, StaticPassphrase, load_settings

    def factory(signer=None):
        settings = load_settings(config=config, sink=f"file:{trail}", evidence=[trail, make.sink])
        settings.signer = signer
        return Signoff(settings, authenticator=StaticPassphrase(PASSWORDS.get(signer or "", "x" * 12)), environ={},
                       chain=[], require_tty=False, clock=clock)
    return factory


def test_trail_added_later_keeps_earlier_signatures_after_one_import(people, make, isolated, clock, trail,
                                                                     with_trail):
    doc, old = isolated / "release.md", isolated / "old.md"
    doc.write_text("v1\n")
    old.write_text("old\n")
    make("human:alice").sign(make("human:alice").file_subject(doc), "approved", "fine")
    make("human:bob").sign(make("human:bob").file_subject(old), "approved", "old approval")
    clock.advance(minutes=1)
    make("human:bob").revoke("human:bob", "left the company")
    clock.advance(minutes=1)
    assert with_trail().trail_sources() == [trail]
    assert with_trail().verify_file(doc).signatures[0].status == "unknown-signer"
    check = with_trail().check_signers()
    assert not check["ok"] and any("signers import" in p for p in check["problems"])
    with pytest.raises(Refused) as refused:          # no fresh enrolment over the old one
        with_trail("human:alice").sign(with_trail().file_subject(doc), "approved", "again")
    assert refused.value.code == "import_needed"
    with pytest.raises(UsageError) as error:
        with_trail("human:carol").init_signer("human:dora", "Dora Example", "qa")
    assert error.value.code == "import_needed"
    preview = with_trail().import_preview()
    assert {r["data"]["signer"] for r in preview["records"]} >= {"human:alice", "human:bob", "human:carol"}
    imported = with_trail("human:alice").import_enrolments()
    assert imported["data"]["imported"] == preview["records"]
    assert with_trail().verify_file(doc).ok
    assert with_trail().verify_file(old).signatures[0].status == "valid"     # Bob's, made before he left
    check = with_trail().check_signers()
    assert check["ok"] and check["bootstrap"]["via"] == "import" and check["imports"][0]["by"] == "human:alice"
    # records written to the old file after the import do not count: no backdating through it
    mallory = forge(make, isolated, "human:mallory", "quality-manager")      # make() still writes the old file
    later = isolated / "later.md"
    later.write_text("later\n")
    sign_with(with_trail, "human:mallory", mallory, later)
    assert with_trail().verify_file(later).signatures[0].status == "unknown-signer"
    assert not with_trail().check_signers()["ok"]


def test_import_by_a_signer_who_does_not_count_in_the_trail_is_ignored(people, make, isolated, with_trail):
    with_trail("human:alice").import_enrolments()
    mallory = forge(make, isolated, "human:mallory", "quality-manager")
    so = with_trail()
    registry = so.reload_registry()
    fake = [r for r in read_jsonl(make.sink) if r["data"].get("key_id") == mallory.key_id]
    so.emit(so.signed_record("signoff.key.enrolled", "enroll", signer=registry.get("human:mallory"), key=mallory,
                             meaning="approved", reason="import", envelope_meaning=False,
                             subject=subject("enrolment-import", "pre-trail",
                                             sha256=content_hash(fake)),
                             data={"signer": "human:mallory", "key_id": mallory.key_id, "imported": fake}), mallory)
    check = with_trail().check_signers()
    assert not check["ok"] and any("does not count in the trail" in n for n in check["problems"])   # a registered key
    assert not keys(with_trail())[("human:mallory", mallory.key_id)]["counts"]


# ---- round 4 (verification v3): re-bootstrap puppets, replayed requests, a second import, export -------------
def approve_with(make, approver_id, approver_key, target_id, target_key):
    """An approval record any holder of ``approver_key`` can write (no aqt-signoff checks)."""
    so = make()
    registry = so.reload_registry()
    request = next(r for r in records(make, "signoff.key.enrolled")
                   if r["data"]["key_id"] == target_key.key_id and "approves" not in r["data"])
    entry = next(k for k in registry.get(target_id).keys if k.key_id == target_key.key_id)
    return so.emit(so._approval_record(registry.get(approver_id), approver_key, request, target_id, entry,
                                       request["data"]["role"], "vouch"), approver_key)


def test_rebootstrap_after_unsigned_revocations_is_not_confirmed_by_its_own_puppet(people, make, isolated, clock,
                                                                                  tmp_path, capsys):
    so = make()
    reg_path = isolated / "config/aqt/signers.json"
    doc = json.loads(reg_path.read_text())
    revoked_at = so.now()
    for signer in doc["signers"]:             # no passphrase: unsigned revocations of every key, registry agrees
        for key in signer["keys"]:
            so.emit(so.record("signoff.key.revoked", {"kind": "human", "id": signer["id"]}, "revoke", reason="rotated",
                              data={"signer": signer["id"], "key_id": key["key_id"], "revoked_at": revoked_at}))
            key["revoked_at"] = revoked_at
    reg_path.write_text(json.dumps(doc))
    clock.advance(seconds=5)
    mallory = forge(make, isolated, "human:mallory", "quality-manager")          # the re-bootstrap
    clock.advance(seconds=5)
    trent = forge(make, isolated, "human:trent", "quality-manager")
    clock.advance(seconds=5)
    approve_with(make, "human:mallory", mallory, "human:trent", trent)
    clock.advance(seconds=5)
    approve_with(make, "human:trent", trent, "human:mallory", mallory)          # the puppet "confirms" it
    check = make().check_signers()
    entry = check["rebootstrap"][0]
    assert not check["ok"] and entry["signer"] == "human:mallory" and not entry["confirmed_by"]
    assert entry["not_confirming"][0]["by"] == "human:trent"
    assert {u["signer"] for u in entry["unsigned_revocations"]} == {"human:alice", "human:bob", "human:carol"}
    assert len(check["unsigned_revocations"]) == 3
    assert all(k["unsigned_revocations"] for k in check["keys"] if k["signer"] in PASSWORDS)
    assert main(["--sink", f"file:{make.sink}", "signers", "check"]) == 1
    out = capsys.readouterr().out
    assert "NOT signed" in out and "does not confirm it" in out and "WARNING: revocation" in out
    release = isolated / "release.md"
    release.write_text("ship\n")
    sign_with(make, "human:mallory", mallory, release)
    report = make().verify_file(release)          # still SIGNED (a solo owner must be able to recover), but loud
    assert report.ok and "RE-BOOTSTRAP human:mallory" in report.registry_warnings[0]
    assert set(entry["counted_before"]) == {k["key_id"] for k in check["keys"] if k["signer"] in PASSWORDS}


def test_replayed_enrolment_request_counts_once(people, make, isolated, clock):
    doc = isolated / "a.md"
    doc.write_text("a\n")
    make("human:alice").sign(make("human:alice").file_subject(doc), "approved", "fine")
    request = next(r for r in records(make, "signoff.key.enrolled") if r["data"]["signer"] == "human:alice"
                   and "approves" not in r["data"])
    copy = new_record(request["type"], request["actor"], request["action"], subject=request["subject"],
                      reason=request.get("reason"), data=request["data"])     # no key or passphrase needed
    make().sink.append(copy)
    report = make().verify_file(doc)
    assert report.ok and report.signatures[0].status == "valid"
    check = make().check_signers()
    assert check["ok"] and any("a copy of the enrolment request" in n for n in check["ignored"])
    clock.advance(seconds=1)
    make("human:alice").sign(make("human:alice").file_subject(doc), "reviewed", "again")    # not refused


def test_conflicting_enrolment_request_stops_the_key_from_its_record_time(people, make, isolated, clock):
    early, late = isolated / "early.md", isolated / "late.md"
    early.write_text("early\n")
    late.write_text("late\n")
    make("human:bob").sign(make("human:bob").file_subject(early), "reviewed", "before")
    clock.advance(minutes=1)
    bob_key = key_of(make, "human:bob")
    forge(make, isolated, "human:bob", "developer", key=bob_key)       # Bob signs a second, different request
    clock.advance(minutes=1)
    sign_with(make, "human:bob", bob_key, late, meaning="reviewed")
    assert make().verify_file(early).signatures[0].status == "valid"   # judged at its signed time
    after = make().verify_file(late).signatures[0]
    assert after.status == "revoked" and "conflicting enrolment records" in after.detail
    check = make().check_signers()
    assert not check["ok"] and any("a second, different enrolment record" in p for p in check["problems"])
    with pytest.raises(Refused) as refused:
        make("human:bob").sign(make("human:bob").file_subject(late), "reviewed", "after")
    assert refused.value.code == "registry_mismatch"


def plant_extra_key(make, isolated, signer_id, time):
    """The agent: a new key under ``signer_id`` in signers.json (before the real one) and a self-signed request
    with a backdated record time in the old evidence file."""
    registry_path = isolated / "config/aqt/signers.json"
    path = isolated / "agent.key"
    generate_key(path, passphrase=b"attacker-passphrase")
    key = load_signer(path, passphrase=b"attacker-passphrase")
    kid, public = load_public_key(f"{path}.pub")
    pem = public_pem(public).decode()
    reg = json.loads(registry_path.read_text())
    next(s for s in reg["signers"] if s["id"] == signer_id)["keys"].insert(
        0, {"key_id": kid, "public_pem": pem, "enrolled_at": time, "revoked_at": None})
    registry_path.write_text(json.dumps(reg))
    so = make()
    so.now = lambda: time
    signer = so.reload_registry().get(signer_id)
    so.emit(so.signed_record("signoff.key.enrolled", "enroll", signer=signer, key=key, meaning="acknowledged",
                             reason="Key enrolled for electronic signatures", envelope_meaning=False, enrolled_at=time,
                             subject=subject("key", kid, sha256=bytes_hash(pem.encode())),
                             data={"signer": signer_id, "name": signer.name, "role": signer.role, "key_id": kid,
                                   "public_pem": pem}), key)
    return key


def test_second_import_is_refused_and_later_records_never_count(people, make, isolated, clock, trail, with_trail,
                                                                capsys):
    with_trail("human:alice").import_enrolments()
    planted = plant_extra_key(make, isolated, "human:alice", "2025-01-01T00:00:00.000000Z")
    check = with_trail().check_signers()
    assert not any("signers import" in p for p in check["problems"])          # nobody is sent to import again
    row = keys(with_trail())[("human:alice", planted.key_id)]
    assert not row["counts"] and "never counts and cannot be imported" in row["problems"][0]
    with_trail("human:carol").init_signer("human:dora", "Dora Example", "qa")   # no import_needed
    with pytest.raises(UsageError) as error:
        with_trail("human:alice").import_enrolments()
    assert error.value.code == "already_imported"
    assert main(["--sink", f"file:{trail}", "--evidence", str(trail), "--evidence", str(make.sink),
                 "signers", "import", "--dry-run"]) == 2
    assert "imported once" in capsys.readouterr().err
    # a second import record signed by Alice's real key (another tool, an older version) does not count either
    so = with_trail("human:alice")
    planted_records = [r for r in read_jsonl(make.sink) if r["data"].get("key_id") == planted.key_id]
    alice = so.registry.get("human:alice")
    so.emit(so.signed_record("signoff.key.enrolled", "enroll", signer=alice, key=key_of(make, "human:alice"),
                             meaning="approved", reason="import", envelope_meaning=False,
                             subject=subject("enrolment-import", "pre-trail", sha256=content_hash(planted_records)),
                             data={"signer": "human:alice", "key_id": key_id_of(make, "human:alice"),
                                   "imported": planted_records}), key_of(make, "human:alice"))
    check = with_trail().check_signers()
    assert any("only the first import counts" in p for p in check["problems"])
    assert not keys(with_trail())[("human:alice", planted.key_id)]["counts"]
    late = isolated / "backdated.md"
    late.write_text("x\n")
    so = with_trail()
    so.now = lambda: "2025-06-01T00:00:00.000000Z"
    so.emit(so.signed_record("signoff.signature", "sign", signer=so.reload_registry().get("human:alice"), key=planted,
                             meaning="approved", reason="r", subject=so.file_subject(late),
                             data={"meaning": "approved"}), planted)
    assert with_trail().verify_file(late).signatures[0].status == "unknown-signer"


def test_import_preview_says_what_counts_and_flags_another_key(people, make, isolated, clock, trail, with_trail):
    from aqt_signoff.cli import _import_text
    planted = plant_extra_key(make, isolated, "human:alice", "2025-01-01T00:00:00.000000Z")
    with_trail().emit(with_trail().record("trail.event", {"kind": "service", "id": "service:t"}, "started"))
    clock.advance(minutes=1)
    late = forge(make, isolated, "human:erin", "qa")                  # written after the trail started
    preview = with_trail().import_preview()
    rows = {row["key_id"]: row for row in preview["outcome"]}
    assert rows[planted.key_id]["result"] == "pending" and rows[planted.key_id]["other_keys"]
    assert rows[key_id_of(make, "human:alice")]["result"] == "counts"
    assert late.key_id not in rows and any(r["data"]["key_id"] == late.key_id for r in preview["ignored"])
    text = _import_text(preview)
    assert "ANOTHER KEY for human:alice" in text and "does not count" not in text
    assert "COUNTS from" in text and "stays pending" in text and "never imported" in text
    with_trail("human:alice").import_enrolments()
    assert not keys(with_trail())[("human:alice", planted.key_id)]["counts"]
    assert keys(with_trail())[("human:alice", key_id_of(make, "human:alice"))]["counts"]


def test_export_carries_the_enrolment_evidence_for_verification_elsewhere(people, make, isolated, clock, tmp_path,
                                                                         capsys):
    cfg = tmp_path / "policy.toml"
    cfg.write_text('[policy.approved]\nroles = ["quality-manager"]\n')
    doc = isolated / "release.md"
    doc.write_text("ship it\n")
    make("human:alice").sign(make("human:alice").file_subject(doc), "approved", "fine")
    export = isolated / "signers-export.json"
    assert main(["--sink", f"file:{make.sink}", "signers", "export", str(export)]) == 0
    exported = json.loads(export.read_text())
    assert {r["type"] for r in exported["enrolment_evidence"]["records"]} == {"signoff.key.enrolled"}
    # another machine: only the signature record, the export as the registry, no trail, no signers.json
    copy = isolated / "elsewhere" / "signatures.jsonl"
    copy.parent.mkdir()
    copy.write_text("".join(json.dumps(r) + "\n" for r in records(make, "signoff.signature")))
    other = dict(registry=str(export), evidence=[copy], keys_dir=str(isolated / "elsewhere/keys"),
                 state_dir=str(isolated / "elsewhere/state"))
    report = make(config_path=cfg, **other).verify_file(doc, required=["approved"], record_invalidations=False)
    assert report.ok and report.signatures[0].authorized_role == "quality-manager"
    assert make(**other).check_signers()["evidence"] == "registry export"
    assert main(["--registry", str(export), "--evidence", str(copy), "--config", str(cfg), "verify", str(doc),
                 "--no-record", "--require", "approved"]) == 0
    capsys.readouterr()
    # the embedded records are checked like any other evidence: a forged key in the export does not count
    forged_dir = isolated / "forged"
    forged_dir.mkdir()
    generate_key(forged_dir / "m.key", passphrase=b"attacker-passphrase")
    mallory = load_signer(forged_dir / "m.key", passphrase=b"attacker-passphrase")
    kid, public = load_public_key(forged_dir / "m.key.pub")
    pem = public_pem(public).decode()
    exported["signers"].append({"id": "human:mallory", "name": "Mallory", "role": "quality-manager",
                                "keys": [{"key_id": kid, "public_pem": pem, "enrolled_at": "2020-01-01T00:00:00Z",
                                          "revoked_at": None}]})
    export.write_text(json.dumps(exported))
    so = make(**other)
    signer = so.reload_registry().get("human:mallory")
    request = so.signed_record("signoff.key.enrolled", "enroll", signer=signer, key=mallory, meaning="acknowledged",
                               reason="enrol", envelope_meaning=False, enrolled_at="2020-01-01T00:00:00Z",
                               subject=subject("key", kid, sha256=bytes_hash(pem.encode())),
                               data={"signer": "human:mallory", "name": "Mallory", "role": "quality-manager",
                                     "key_id": kid, "public_pem": pem})
    exported["enrolment_evidence"]["records"].append(request)
    export.write_text(json.dumps(exported))
    assert keys(make(**other))[("human:mallory", kid)]["pending"]


def test_embedded_export_records_are_ignored_when_there_is_a_trail(people, make, isolated, trail, with_trail):
    with_trail("human:alice").import_enrolments()
    registry_path = isolated / "config/aqt/signers.json"
    exported = with_trail().export_registry()
    assert exported["enrolment_evidence"]["source"] == "trail"
    # the agent writes a forged first enrolment into the user's signers.json as "export" records
    forged_key = forge(make, isolated, "human:mallory", "quality-manager")
    forged = [r for r in read_jsonl(make.sink) if r["data"].get("key_id") == forged_key.key_id]
    doc = json.loads(registry_path.read_text())
    doc["enrolment_evidence"] = {"records": forged, "revocations": []}
    registry_path.write_text(json.dumps(doc))
    check = with_trail().check_signers()
    assert check["evidence"] == "trail" and any("not used" in n for n in check["ignored"])
    assert not keys(with_trail())[("human:mallory", forged_key.key_id)]["counts"]


def test_backdated_request_is_pending_not_a_rebootstrap(people, make, isolated):
    """Without a trail the record time is the writer's choice: a request dated before every enrolment must not
    look like one made after all keys were revoked."""
    planted = plant_extra_key(make, isolated, "human:alice", "2025-01-01T00:00:00.000000Z")
    row = keys(make())[("human:alice", planted.key_id)]
    assert row["pending"] and not row["counts"] and not make().check_signers()["rebootstrap"]
