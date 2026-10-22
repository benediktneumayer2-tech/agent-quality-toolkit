import json
from datetime import datetime, timedelta, timezone

import pytest

from aqt_evidence import content_hash, generate_key, load_signer, new_record, subject
from aqt_evidence.crypto import public_pem

from aqt_trail.review import QUERIES, ReviewRefused, build_review, load_profile, run_review
from aqt_trail.signers import load_registry, registry_keys
from aqt_trail.config import DEFAULTS
from aqt_trail.state import open_writer, read_records, service_keys
from aqt_trail.verify import verify_trail

from conftest import agent, event, human, observed_stub


class FakeClock:
    def __init__(self, start):
        self.now = start

    def tick(self, minutes=1):
        self.now += timedelta(minutes=minutes)

    def wall(self):
        self.now += timedelta(milliseconds=10)
        return self.now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def mono(self):
        return self.now.timestamp()


@pytest.fixture
def planted(config):
    """A trail with one instance of every risk the default profile looks for."""
    clock = FakeClock(datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc))  # a Tuesday
    w = open_writer(config)
    w.clock, w.monotonic = clock.wall, clock.mono

    def put(record, **observed):
        return w.append(record, observed_stub(**observed))[0]

    authored = put(new_record("change.plan", human("bob"), "edit", subject=subject("file", "plan.md"),
                              meaning="authored", reason="drafted the plan"))
    put(new_record("signoff.signature", human("bob"), "sign", subject=subject("file", "plan.md"),
                   meaning="approved", reason="looks fine", links=[{"rel": "approves", "ref": authored["id"]}]))
    put(new_record("quarantine.released", human("erin"), "release", subject=subject("web-result", "case-1")))
    put(event("pretend-human", who=human("carol")), harness="claude-code", process_chain=["python3", "bash", "claude"])
    for _ in range(3):
        put(new_record("change.receipt", agent(), "run", subject=subject("plan", "plan-1"),
                       data={"argv": ["pytest"], "exit_code": 1, "passed": False}))
    skewed = event("skewed", time="2026-10-20T07:00:00.000000Z")
    put(skewed)
    put(new_record("change.review", human("frank"), "edit", subject=subject("file", "notes.md"), reason="first"))
    put(new_record("change.review", agent("s2"), "edit", subject=subject("file", "notes.md")))
    put(new_record("signoff.invalidation", actor_service(), "invalidated", data={"signature": "rec_x"}))
    clock.now = datetime(2026, 10, 25, 2, 0, tzinfo=timezone.utc)  # Sunday night
    w.monotonic = clock.mono
    put(event("night-work", who=human("gina")))
    w.drain([event("spooled", who=human("hana"))], source="spool.jsonl")
    w.close()
    return config


def actor_service():
    from aqt_evidence import actor
    return actor("service", "service:aqt-signoff")


def profile():
    return load_profile("default", dict(DEFAULTS["review"], timezone="UTC"))


def test_every_default_query_finds_its_planted_risk(planted):
    records = read_records(planted.trail_path)
    sheet = run_review(records, profile(), log_id="trail_test")
    found = {f["query"] for f in sheet["findings"]}
    assert found == set(QUERIES), set(QUERIES) - found
    text = {q: " ".join(f["explanation"] for f in sheet["findings"] if f["query"] == q) for q in QUERIES}
    assert "human:bob" in text["self_approval"]
    assert "claims human human:carol" in text["attribution_mismatch"] and "claude-code" in text["attribution_mismatch"]
    assert sheet["scope"]["to_seq"] == records[-1]["chain"]["seq"]
    assert "human:bob" in sheet["actors_reviewed"] and "service:aqt-trail" not in sheet["actors_reviewed"]


def test_clean_period_has_no_findings_except_anchor(config):
    w = open_writer(config)
    w.append(event("normal", who=agent()), observed_stub(harness="claude-code"))
    w.close()
    sheet = run_review(read_records(config.trail_path), profile(), log_id="t")
    queries = {f["query"] for f in sheet["findings"]}
    assert queries <= {"unanchored_head", "out_of_hours"}


@pytest.fixture
def reviewer(tmp_path):
    generate_key(tmp_path / "dora.key")
    return load_signer(tmp_path / "dora.key")


def _sign(planted, reviewer, sheet, **kw):
    records = read_records(planted.trail_path)
    options = dict(reviewer_id="human:dora", signer=reviewer, dispositions={"all": "ok"}, notes={},
                   reason="periodic review", conclusion="acceptable", registry={})
    options.update(kw)
    return build_review(sheet, records, **options)


def test_sign_review_and_verify_detached_signature(planted, reviewer):
    sheet = run_review(read_records(planted.trail_path), profile(), log_id="trail_test")
    first = sheet["findings"][0]["id"]
    record = _sign(planted, reviewer, sheet, dispositions={"all": "ok", first: "deviation"},
                   notes={first: "open a CAPA"})
    data = record["data"]
    assert record["meaning"] == "reviewed" and record["type"] == "trail.review"
    assert data["head"] == sheet["scope"]["head"] and data["findings"][0]["disposition"] == "deviation"
    statement = data["signature"]["statement"]
    assert statement["subject"]["sha256"] == content_hash({k: v for k, v in data.items() if k != "signature"})
    assert statement["signer"]["id"] == "human:dora" and statement["meaning"] == "reviewed"
    w = open_writer(planted)
    w.append(record, observed_stub())
    w.close()
    keys = {reviewer.key_id: reviewer.public_key}
    report = verify_trail(planted.trail_path, keys=service_keys(planted), signer_keys=keys)
    assert report.ok and report.signatures == 1


@pytest.mark.parametrize("change,code", [
    ({"reviewer_id": "human:bob"}, "not_independent"),
    ({"reviewer_id": "agent:claude-code:s1"}, "not_human"),
])
def test_refusals(planted, reviewer, change, code):
    sheet = run_review(read_records(planted.trail_path), profile(), log_id="trail_test")
    with pytest.raises(ReviewRefused) as caught:
        _sign(planted, reviewer, sheet, **change)
    assert caught.value.code == code


def test_stale_worksheet(planted, reviewer):
    sheet = run_review(read_records(planted.trail_path), profile(), log_id="trail_test")
    sheet["scope"]["head"] = "sha256:" + "1" * 64
    with pytest.raises(ReviewRefused) as caught:
        _sign(planted, reviewer, sheet)
    assert caught.value.code == "stale_worksheet"


def test_dispositions_are_required(planted, reviewer):
    sheet = run_review(read_records(planted.trail_path), profile(), log_id="trail_test")
    with pytest.raises(ValueError, match="needs a disposition"):
        _sign(planted, reviewer, sheet, dispositions={})
    with pytest.raises(ValueError, match="needs a --note"):
        _sign(planted, reviewer, sheet, dispositions={"all": "explained"})


def test_registry_keys_and_revocation(planted, reviewer, env):
    registry = env / "config" / "aqt" / "signers.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    entry = {"key_id": reviewer.key_id, "public_pem": public_pem(reviewer.public_key).decode(),
             "enrolled_at": "2026-10-01T00:00:00Z", "revoked_at": None}
    registry.write_text(json.dumps({"version": 1, "signers": [
        {"id": "human:dora", "name": "Dora Example", "role": "qa-reviewer", "keys": [entry]}]}))
    signers = load_registry()
    assert reviewer.key_id in registry_keys(signers)
    sheet = run_review(read_records(planted.trail_path), profile(), log_id="trail_test")
    record = _sign(planted, reviewer, sheet, registry=signers)
    assert record["data"]["signer_registered"] is True
    assert record["data"]["signature"]["statement"]["signer"] == {"id": "human:dora", "name": "Dora Example",
                                                                  "role": "qa-reviewer"}
    entry["revoked_at"] = "2026-10-15T00:00:00Z"
    registry.write_text(json.dumps({"version": 1, "signers": [
        {"id": "human:dora", "name": "Dora Example", "role": "qa-reviewer", "keys": [entry]}]}))
    with pytest.raises(ReviewRefused) as caught:
        _sign(planted, reviewer, sheet, registry=load_registry())
    assert caught.value.code == "revoked_key"


def test_registry_and_key_directory_honour_the_shared_overrides(env, monkeypatch):
    """AQT_SIGNERS and AQT_KEYS_DIR work as in aqt-signoff and aqt-quarantine."""
    from aqt_trail.signers import key_file, registry_path
    assert registry_path() == env / "config" / "aqt" / "signers.json"
    assert key_file("human:dora") == env / "config" / "aqt" / "keys" / "human-dora.key"
    other = env / "elsewhere" / "signers.json"
    other.parent.mkdir()
    other.write_text(json.dumps({"version": 1, "signers": [{"id": "human:dora", "name": "Dora Example", "keys": []}]}))
    monkeypatch.setenv("AQT_SIGNERS", str(other))
    monkeypatch.setenv("AQT_KEYS_DIR", str(env / "keys-elsewhere"))
    assert registry_path() == other and set(load_registry()) == {"human:dora"}
    assert key_file("human:dora") == env / "keys-elsewhere" / "human-dora.key"
