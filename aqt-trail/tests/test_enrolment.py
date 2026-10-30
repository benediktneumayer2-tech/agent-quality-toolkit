"""Registry keys count only when their enrolment record backs them (aqt-signoff's rules).

signers.json is configuration any process of the user can edit. aqt-trail does not depend on aqt-signoff:
with it installed, verify, review sign and status use its reconciliation; without it they say that the keys
rest on the file alone. These tests use aqt-signoff from this repository when it is not installed.
"""

import json
from pathlib import Path

import pytest

from aqt_evidence import generate_key, load_signer
from aqt_evidence.crypto import public_pem

from aqt_trail import signers as signers_module
from aqt_trail.alcoa import alcoa_report
from aqt_trail.client import TrailClient
from aqt_trail.config import DEFAULTS
from aqt_trail.review import ReviewRefused, build_review, load_profile, run_review
from aqt_trail.signers import _signoff_registry as real_signoff_registry
from aqt_trail.signers import check_enrolment, key_file, load_registry, registry_keys
from aqt_trail.state import read_records, service_keys
from aqt_trail.verify import UNCHECKED, review_statuses, signature_status, verify_trail

from conftest import agent, event

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def signoff(monkeypatch, env):
    """aqt-signoff's real enrolment rules: the installed package, else this repository's source tree."""
    try:
        import aqt_signoff  # noqa: F401
    except ImportError:
        source = Path(__file__).resolve().parents[2] / "aqt-signoff" / "src"
        if not (source / "aqt_signoff").is_dir():
            pytest.skip("aqt-signoff is not available")
        monkeypatch.syspath_prepend(str(source))
    assert real_signoff_registry() is not None
    monkeypatch.setattr(signers_module, "_signoff_registry", real_signoff_registry)
    monkeypatch.setattr("aqt_evidence.crypto.SCRYPT_N", 2**10)      # fast keys; each key file records its cost


@pytest.fixture
def trail(server, config, monkeypatch):
    monkeypatch.setenv("AQT_SINK", f"unix:{config.socket_path}")    # aqt-signoff records enrolments in the trail
    return config


def enrol(signer_id: str):
    """``aqt-signoff init`` through its API: key, registry entry and the signoff.key.enrolled record."""
    from aqt_signoff import Signoff, StaticPassphrase, load_settings
    Signoff(load_settings(), authenticator=StaticPassphrase(PASSPHRASE), environ={}, chain=[],
            require_tty=False).init_signer(signer_id, signer_id.split(":")[1].title(), "quality-manager")
    return load_signer(key_file(signer_id), passphrase=PASSPHRASE.encode())


def add_to_registry(signer_id: str, key, env):
    """What a same-user agent can do: write its own key into signers.json (no enrolment record)."""
    path = env / "config" / "aqt" / "signers.json"
    data = json.loads(path.read_text()) if path.exists() else {"version": 1, "signers": []}
    data["signers"] = [s for s in data["signers"] if s["id"] != signer_id] + [{
        "id": signer_id, "name": signer_id.split(":")[1].title(), "role": "quality-manager",
        "keys": [{"key_id": key.key_id, "public_pem": public_pem(key.public_key).decode(),
                  "enrolled_at": "2026-01-01T00:00:00Z", "revoked_at": None}]}]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def review(config, signer, reviewer, registry):
    """A review of the agent's work after the enrolments (an enrolment counts as the signer's activity)."""
    client = TrailClient(config.socket_path)
    since = client.append(event("edit", who=agent()))["time"]
    client.append(event("deploy", who=agent()))
    records = read_records(config.trail_path)
    profile = load_profile("default", dict(DEFAULTS["review"], work_start="00:00", work_end="23:59",
                                           workdays=[1, 2, 3, 4, 5, 6, 7]))
    sheet = run_review(records, profile, log_id="trail_test", since=since)
    return build_review(sheet, records, reviewer_id=reviewer, signer=signer, dispositions={"all": "ok"}, notes={},
                        reason="weekly", conclusion="no concerns", registry=registry)


def verify(config):
    return verify_trail(config.trail_path, keys=service_keys(config), checkpoints=config.checkpoints_path,
                        signer_keys=registry_keys(load_registry()), log_id="trail_test")


def agent_key(tmp_path):
    generate_key(tmp_path / "mal.key")
    return load_signer(tmp_path / "mal.key")


def test_enrolled_reviewer_signs_and_verifies_without_warning(signoff, trail):
    dora = enrol("human:dora")
    assert any(r["type"] == "signoff.key.enrolled" for r in read_records(trail.trail_path))
    TrailClient(trail.socket_path).append(review(trail, dora, "human:dora", load_registry()))
    report = verify(trail)
    assert report.ok and report.reviews == 1, report.problems
    assert not [w for w in report.warnings if "signature" in w or "signers.json" in w]
    assert [status for _, status, _ in review_statuses(read_records(trail.trail_path), signers=load_registry())] \
        == ["valid"]


def test_registry_key_without_enrolment_record_does_not_count(signoff, trail, env, tmp_path, monkeypatch, capsys):
    from aqt_trail import cli
    enrol("human:dora")                                     # dora exists, with her own enrolled key
    mal = agent_key(tmp_path)
    add_to_registry("human:dora", mal, env)                  # the agent puts its key under human:dora
    with pytest.raises(ReviewRefused) as refused:
        review(trail, mal, "human:dora", load_registry())
    assert refused.value.code == "unenrolled_key" and "aqt-signoff signers check" in refused.value.message
    with monkeypatch.context() as patch:                   # the agent builds and signs the review itself
        patch.setattr(signers_module, "_signoff_registry", lambda: None)
        forged = review(trail, mal, "human:dora", load_registry())
    TrailClient(trail.socket_path).append(forged)
    report = verify(trail)
    assert not report.ok and any("not backed by its enrolment record" in p for p in report.signature_problems)
    accurate = next(r for r in alcoa_report(read_records(trail.trail_path), report) if r["attribute"] == "accurate")
    assert accurate["status"] == "fail"
    statuses = review_statuses(read_records(trail.trail_path), signers=load_registry())
    assert [status for _, status, _ in statuses] == ["unknown-key"]
    capsys.readouterr()
    assert cli.main(["--json", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["last_review"] is None


def test_revocation_record_applies_even_when_the_file_says_active(signoff, trail):
    from aqt_signoff import Signoff, StaticPassphrase, load_settings
    dora = enrol("human:dora")
    Signoff(load_settings(), authenticator=StaticPassphrase(PASSPHRASE), environ={}, chain=[],
            require_tty=False).revoke("human:dora", reason="key lost")
    path = load_settings().registry_path
    data = json.loads(path.read_text())
    for key in data["signers"][0]["keys"]:
        key["revoked_at"] = None                            # the file is edited back to "active"
    path.write_text(json.dumps(data))
    checked = load_registry(records=read_records(trail.trail_path))
    assert dora.key_id in checked["human:dora"].revoked_keys and checked.enrolment == "checked"


def test_without_signoff_keys_are_unchecked_and_say_so(trail, env, tmp_path):
    """The same forged registry entry without aqt-signoff installed: never silently valid."""
    mal = agent_key(tmp_path)
    add_to_registry("human:dora", mal, env)
    TrailClient(trail.socket_path).append(review(trail, mal, "human:dora", load_registry()))
    checked = check_enrolment(load_registry(), read_records(trail.trail_path))
    assert checked.enrolment.startswith("aqt-signoff is not installed")
    record = read_records(trail.trail_path)[-1]
    status, detail = signature_status(record, signers=checked)
    assert status == "valid" and UNCHECKED in detail
    report = verify(trail)
    assert any("rest on signers.json alone" in w and "not checked" in w for w in report.warnings)
    accurate = next(r for r in alcoa_report(read_records(trail.trail_path), report) if r["attribute"] == "accurate")
    assert accurate["status"] == "warn"


def test_key_id_that_belongs_to_another_public_key_is_unusable(env, tmp_path):
    dora = agent_key(tmp_path)
    generate_key(tmp_path / "other.key")
    mal = load_signer(tmp_path / "other.key")
    path = env / "config" / "aqt" / "signers.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "signers": [{"id": "human:dora", "name": "Dora", "role": "qa", "keys": [
        {"key_id": dora.key_id, "public_pem": public_pem(mal.public_key).decode(),
         "enrolled_at": "2026-01-01T00:00:00Z", "revoked_at": None}]}]}))
    entry = load_registry()["human:dora"].keys[dora.key_id]
    assert entry.public is None and dora.key_id not in load_registry()["human:dora"].active_keys


# ---- counter-signed enrolment through a real writer (security review round 3) -------------------------------
def signoff_as(signer_id: str | None = None):
    from aqt_signoff import Signoff, StaticPassphrase, load_settings
    settings = load_settings()
    settings.signer = signer_id
    return Signoff(settings, authenticator=StaticPassphrase(PASSPHRASE), environ={}, chain=[], require_tty=False)


def forged_request(config, signer_id: str, key, env, *, client_time: str | None = None):
    """What any same-user process can do: its own key in signers.json and a self-signed enrolment record sent
    through the writer socket (no aqt-signoff command, no terminal)."""
    from aqt_evidence import bytes_hash, new_record, sign_statement, subject
    add_to_registry(signer_id, key, env)
    pem = public_pem(key.public_key).decode()
    statement = {"aqt_signature": "0.1", "record_type": "signoff.key.enrolled",
                 "signer": {"id": signer_id, "name": signer_id.split(":")[1].title(), "role": "quality-manager"},
                 "key": key.key_id, "meaning": "acknowledged", "reason": "enrolled", "tz": "UTC",
                 "signed_at": client_time or "2026-01-01T00:00:00.000000Z", "nonce": "00" * 8,
                 "enrolled_at": client_time or "2026-01-01T00:00:00.000000Z",
                 "subject": subject("key", key.key_id, sha256=bytes_hash(pem.encode()))}
    record = new_record("signoff.key.enrolled", {"kind": "human", "id": signer_id}, "enroll",
                        subject=statement["subject"], time=client_time or "2026-01-01T00:00:00.000000Z",
                        data={"signer": signer_id, "name": statement["signer"]["name"], "role": "quality-manager",
                              "key_id": key.key_id, "public_pem": pem, "signature": sign_statement(statement, key)})
    return TrailClient(config.socket_path).append(record)


def review_since(config, since, signer, reviewer):
    records = read_records(config.trail_path)
    profile = load_profile("default", dict(DEFAULTS["review"], work_start="00:00", work_end="23:59",
                                           workdays=[1, 2, 3, 4, 5, 6, 7]))
    sheet = run_review(records, profile, log_id="trail_test", since=since)
    return build_review(sheet, records, reviewer_id=reviewer, signer=signer, dispositions={"all": "ok"}, notes={},
                        reason="weekly", conclusion="no concerns", registry=load_registry())


def test_self_signed_enrolment_through_the_writer_waits_for_approval(signoff, trail, env, tmp_path):
    enrol("human:dora")                                               # the first signer
    mal = agent_key(tmp_path)
    stored = forged_request(trail, "human:mallory", mal, env)
    assert stored["time"] != "2026-01-01T00:00:00.000000Z"            # the writer's time, not the claimed one
    entry = load_registry(records=read_records(trail.trail_path))["human:mallory"].keys[mal.key_id]
    assert entry.backed is False and "waits for approval" in entry.evidence
    with pytest.raises(ReviewRefused) as refused:
        review(trail, mal, "human:mallory", load_registry())
    assert refused.value.code == "unenrolled_key"
    check = signoff_as().check_signers()
    assert not check["ok"] and [p["signer"] for p in check["pending"]] == ["human:mallory"]


def test_approved_enrolment_counts_from_the_writer_time_of_its_request(signoff, trail, env, tmp_path):
    enrol("human:dora")
    erin = enrol("human:erin")
    info = load_registry(records=read_records(trail.trail_path))["human:erin"].keys[erin.key_id]
    assert info.backed is False
    signoff_as("human:dora").approve_enrolment("human:erin", erin.key_id)
    records = read_records(trail.trail_path)
    request = next(r for r in records if r["type"] == "signoff.key.enrolled" and r["data"]["key_id"] == erin.key_id)
    info = load_registry(records=records)["human:erin"].keys[erin.key_id]
    assert info.backed and info.enrolled_at == request["time"]       # retroactive to the request, writer-stamped
    TrailClient(trail.socket_path).append(review(trail, erin, "human:erin", load_registry()))
    assert verify(trail).ok


def test_verify_accepts_a_keys_own_revocation_and_rotation(signoff, trail):
    enrol("human:dora")
    signoff_as("human:dora").init_signer("human:dora", "", "", add_key=True)     # rotation: old key approves, revoked
    enrol("human:erin")
    signoff_as("human:erin").revoke("human:erin", reason="left")
    report = verify(trail)
    assert report.ok and not report.signature_problems, report.signature_problems
    registry = load_registry(records=read_records(trail.trail_path))
    assert len(registry["human:dora"].active_keys) == 1 and len(registry["human:dora"].revoked_keys) == 1


def test_own_enrolment_is_not_activity_but_approving_someone_else_is(signoff, trail):
    client = TrailClient(trail.socket_path)
    since = client.append(event("edit", who=agent()))["time"]
    dora = enrol("human:dora")                                       # dora's own enrolment, inside the period
    signoff_as("human:dora").init_signer("human:dora", "", "", add_key=True)     # and her own key rotation
    dora = load_signer(key_file("human:dora"), passphrase=PASSPHRASE.encode())
    record = review_since(trail, since, dora, "human:dora")
    assert "human:dora" not in record["data"]["actors_reviewed"]
    client.append(record)
    assert verify(trail).ok
    erin = enrol("human:erin")
    signoff_as("human:dora").approve_enrolment("human:erin", erin.key_id)        # dora approves someone else
    with pytest.raises(ReviewRefused) as refused:
        review_since(trail, since, dora, "human:dora")
    assert refused.value.code == "not_independent"


def test_review_signed_with_the_earlier_actor_list_still_verifies(signoff, trail, monkeypatch):
    from aqt_trail import review as review_module
    dora = enrol("human:dora")
    client = TrailClient(trail.socket_path)
    since = client.append(event("edit", who=agent()))["time"]
    enrol("human:carl")                                              # carl's own enrolment request in the period
    legacy = review_module.scope_actors
    monkeypatch.setattr(review_module, "scope_actors", lambda scope: legacy(scope, legacy=True))
    record = review_since(trail, since, dora, "human:dora")          # as an earlier aqt-trail computed it
    monkeypatch.setattr(review_module, "scope_actors", legacy)
    assert "human:carl" in record["data"]["actors_reviewed"]
    assert "human:carl" not in legacy([r for r in read_records(trail.trail_path) if r["time"] >= since])
    client.append(record)
    assert verify(trail).ok, verify(trail).signature_problems
