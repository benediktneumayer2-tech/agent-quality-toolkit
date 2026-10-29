"""Regression tests for the verification side: what verify, review, alcoa and bundles may trust.

Records that a client (an agent) could append, or that an old writer could have stored, are written
straight into the log here, chained and signed with the service key, so the tests do not depend on what
the writer accepts today.
"""

import json

import pytest

from aqt_evidence import (actor, canonical_json, content_hash, generate_key, link, load_signer, new_record,
                          record_hash, sign_record, sign_statement, subject, utc_now)
from aqt_evidence.crypto import public_pem

from aqt_trail import anchors
from aqt_trail.alcoa import alcoa_report
from aqt_trail.config import DEFAULTS
from aqt_trail.export import export_bundle, verify_bundle
from aqt_trail.review import (ReviewRefused, build_review, load_profile, q_attribution_mismatch, q_unanchored_head,
                              run_review, worksheet_digest)
from aqt_trail.signers import build_statement, load_registry, registry_keys
from aqt_trail.state import open_writer, read_records, service_keys
from aqt_trail.verify import verify_trail

from conftest import event, human, observed_stub


# -- helpers -----------------------------------------------------------------------------------------------
def forge(config, *records, observed=None):
    """Append records as the writer would store them (chained, signed with the service key), bypassing it."""
    signer = load_signer(config.key_path)
    lines = config.trail_path.read_bytes().splitlines() if config.trail_path.exists() else []
    last = json.loads(lines[-1]) if lines else None
    seq, prev = (last["chain"]["seq"] + 1, record_hash(last)) if last else (0, "sha256:" + "0" * 64)
    stored = []
    with open(config.trail_path, "ab") as handle:
        for record in records:
            record = dict(record, observed=observed or observed_stub())
            record = sign_record(link(record, seq=seq, prev=prev), signer)
            handle.write(canonical_json(record) + b"\n")
            seq, prev = seq + 1, record_hash(record)
            stored.append(record)
    return stored


class opened:
    """``with opened(config) as w``: a writer that is closed afterwards (``open_writer`` already opens it)."""

    def __init__(self, config):
        self.writer = open_writer(config)

    def __enter__(self):
        return self.writer

    def __exit__(self, *exc):
        self.writer.close()


def put(config, *records, **observed):
    with opened(config) as w:
        return [w.append(record, observed_stub(**observed))[0] for record in records]


def registry(env, *entries):
    """signers.json with (signer id, signer, enrolled_at, revoked_at) entries."""
    path = env / "config" / "aqt" / "signers.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    signers = {}
    for signer_id, key, enrolled, revoked in entries:
        signers.setdefault(signer_id, {"id": signer_id, "name": signer_id.split(":")[1].title(), "role": "qa",
                                       "keys": []})["keys"].append(
            {"key_id": key.key_id, "public_pem": public_pem(key.public_key).decode(), "enrolled_at": enrolled,
             "revoked_at": revoked})
    path.write_text(json.dumps({"version": 1, "signers": list(signers.values())}))
    return load_registry()


@pytest.fixture
def keys(tmp_path):
    made = {}
    for name in ("alice", "bob", "dora"):
        generate_key(tmp_path / f"{name}.key")
        made[name] = load_signer(tmp_path / f"{name}.key")
    return made


def profile():
    return load_profile("default", dict(DEFAULTS["review"], timezone="UTC", work_start="00:00", work_end="23:59",
                                        workdays=[1, 2, 3, 4, 5, 6, 7]))


@pytest.fixture
def worked(config):
    """A short period in which alice acted (so alice may not review it)."""
    put(config, event("edit", who=human("alice"), subject=subject("file", "plan.md")),
        new_record("signoff.signature", human("alice"), "sign", subject=subject("file", "plan.md"),
                   meaning="approved", reason="fine"))
    return config


def verify(config, signers=None):
    return verify_trail(config.trail_path, keys=service_keys(config), checkpoints=config.checkpoints_path,
                        signer_keys=registry_keys(signers) if signers is not None else None, log_id="trail_test")


def sign(config, sheet, signer, reviewer, registry_=None, **kw):
    return build_review(sheet, read_records(config.trail_path), reviewer_id=reviewer, signer=signer,
                        dispositions={"all": "ok"}, notes={}, reason="periodic review", conclusion="ok",
                        registry=registry_ or {}, **kw)


# -- C-2, KEYS-09: the worksheet is recomputed from the trail -----------------------------------------------
@pytest.mark.parametrize("edit", [
    lambda sheet: sheet.update(actors_reviewed=[]),
    lambda sheet: sheet.update(findings=[]),
    lambda sheet: sheet["findings"][0].update(severity="info"),
    lambda sheet: sheet["scope"].update(from_seq=1, count=sheet["scope"]["count"] - 1),
    lambda sheet: sheet["profile"].update(queries=["gaps"]),
])
def test_an_edited_worksheet_is_refused(worked, keys, edit):
    sheet = run_review(read_records(worked.trail_path), profile(), log_id="trail_test")
    assert "human:alice" in sheet["actors_reviewed"] and sheet["findings"]
    edit(sheet)
    with pytest.raises(ReviewRefused) as caught:
        sign(worked, sheet, keys["alice"], "human:alice")
    assert caught.value.code == "worksheet_mismatch"


def test_independence_holds_against_the_trail_not_the_worksheet(worked, keys):
    sheet = run_review(read_records(worked.trail_path), profile(), log_id="trail_test")
    with pytest.raises(ReviewRefused) as caught:
        sign(worked, sheet, keys["alice"], "human:alice")
    assert caught.value.code == "not_independent"
    record = sign(worked, sheet, keys["dora"], "human:dora")
    assert record["data"]["actors_reviewed"] == sheet["actors_reviewed"]
    assert record["data"]["worksheet_sha256"] == worksheet_digest(sheet)


def test_a_review_stays_signable_while_the_trail_grows(worked, keys):
    sheet = run_review(read_records(worked.trail_path), profile(), log_id="trail_test")
    put(worked, event("later", who=human("erin")))
    assert sign(worked, sheet, keys["dora"], "human:dora")["data"]["scope"] == sheet["scope"]


def test_a_worksheet_swapped_after_display_is_refused(worked, keys):
    """AQT-UI-002 (package side): the UI passes the digest of the worksheet it showed."""
    shown = run_review(read_records(worked.trail_path), profile(), log_id="trail_test")
    first = read_records(worked.trail_path)[1]["time"]
    other = run_review(read_records(worked.trail_path), profile(), log_id="trail_test", since=first)  # also valid
    with pytest.raises(ReviewRefused) as caught:
        sign(worked, other, keys["dora"], "human:dora", expected_sha256=worksheet_digest(shown))
    assert caught.value.code == "worksheet_changed"
    assert sign(worked, shown, keys["dora"], "human:dora", expected_sha256=worksheet_digest(shown))


def test_a_broken_trail_cannot_be_reviewed(worked, keys):
    sheet = run_review(read_records(worked.trail_path), profile(), log_id="trail_test")
    records = read_records(worked.trail_path)
    records[0]["reason"] = "edited"
    with pytest.raises(ReviewRefused) as caught:
        build_review(sheet, records, reviewer_id="human:dora", signer=keys["dora"], dispositions={"all": "ok"},
                     notes={}, reason="r", conclusion="c", registry={})
    assert caught.value.code in ("trail_broken", "stale_worksheet")


# -- KEYS-08: the key must belong to the reviewer -------------------------------------------------------------
def test_reviewer_cannot_sign_with_another_signers_key(worked, keys, env):
    signers = registry(env, ("human:alice", keys["alice"], "2026-01-01T00:00:00Z", None))
    sheet = run_review(read_records(worked.trail_path), profile(), log_id="trail_test")
    with pytest.raises(ReviewRefused) as caught:
        sign(worked, sheet, keys["alice"], "human:bob", signers)
    assert caught.value.code == "key_mismatch"
    with pytest.raises(ReviewRefused) as caught:   # with a registry, an unregistered reviewer is refused
        sign(worked, sheet, keys["bob"], "human:bob", signers)
    assert caught.value.code == "unknown_signer"


# -- C-6, AQT-EI-008, KEYS-08, A-9: verify binds review signatures --------------------------------------------
def _review_record(config, signer, reviewer, *, record_type="trail.review", meaning="reviewed", kind="trail-review",
                   actors=None, signed_at=None):
    """A review built by hand, as an agent with a key could build one."""
    records = read_records(config.trail_path)
    last = records[-1]
    scope = {"from_seq": 0, "to_seq": last["chain"]["seq"], "since": None, "until": None, "count": len(records),
             "head": record_hash(last), "head_id": last["id"]}
    data = {"worksheet": "rv_000000000000", "log_id": "trail_test", "scope": scope, "head": scope["head"],
            "actors_reviewed": actors if actors is not None else ["human:alice"], "findings": [], "conclusion": "ok"}
    sub = subject(kind, "rv_000000000000", sha256=content_hash(data))
    statement = build_statement(record_type=record_type, signer={"id": reviewer, "name": "X", "role": "qa"},
                                key=signer.key_id, meaning=meaning, reason="review", subject=sub,
                                signed_at=signed_at or utc_now(), tz="UTC")
    data["signature"] = sign_statement(statement, signer)
    return new_record("trail.review", actor("human", reviewer), "review.signed", subject=sub, reason="review",
                      meaning="reviewed", data=data)


def test_unsigned_review_is_a_problem(worked):
    forge(worked, new_record("trail.review", human("dora"), "review.signed", reason="weekly", meaning="reviewed",
                             data={"findings": [], "conclusion": "ok"}))
    report = verify(worked)
    assert not report.ok and any("trail.review is not signed" in p for p in report.problems)


def test_a_file_approval_is_not_a_review(worked, keys, env):
    signers = registry(env, ("human:dora", keys["dora"], "2026-01-01T00:00:00Z", None))
    forge(worked, _review_record(worked, keys["dora"], "human:dora", record_type="signoff.signature",
                                 meaning="approved", kind="file"))
    report = verify(worked, signers)
    assert not report.ok and any("record type 'signoff.signature'" in p for p in report.problems)


def test_review_with_another_signers_key_or_revoked_key_is_a_problem(worked, keys, env):
    signers = registry(env, ("human:bob", keys["bob"], "2026-01-01T00:00:00Z", None),
                       ("human:dora", keys["dora"], "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"))
    forge(worked, _review_record(worked, keys["bob"], "human:dora"))
    assert any("belongs to human:bob" in p for p in verify(worked, signers).problems)
    forge(worked, _review_record(worked, keys["dora"], "human:dora", signed_at="2026-03-01T00:00:00.000000Z"))
    assert any("revoked" in p for p in verify(worked, signers).problems)


def test_review_by_unregistered_key_is_a_problem_with_a_registry_and_a_warning_without(worked, keys, env):
    forge(worked, _review_record(worked, keys["bob"], "human:bob"))
    without = verify(worked, {})
    assert without.ok and any("review signature(s) not checked" in w for w in without.warnings)
    signers = registry(env, ("human:dora", keys["dora"], "2026-01-01T00:00:00Z", None))
    assert any("not in the signer registry" in p for p in verify(worked, signers).problems)


def test_review_that_hides_the_reviewers_own_activity_is_a_problem(worked, keys, env):
    signers = registry(env, ("human:alice", keys["alice"], "2026-01-01T00:00:00Z", None))
    forge(worked, _review_record(worked, keys["alice"], "human:alice", actors=[]))
    problems = verify(worked, signers).problems
    assert any("actors in scope differ" in p for p in problems)
    assert any("not independent" in p for p in problems)


def test_valid_registered_review_verifies(worked, keys, env):
    signers = registry(env, ("human:dora", keys["dora"], "2026-01-01T00:00:00Z", None))
    sheet = run_review(read_records(worked.trail_path), profile(), log_id="trail_test")
    put(worked, sign(worked, sheet, keys["dora"], "human:dora", signers))
    report = verify(worked, signers)
    assert report.ok and report.reviews == 1 and report.signatures == 1, report.problems
    # aqt-signoff is not installed here: the key could not be checked against an enrolment record, and verify says so
    assert [w for w in report.warnings if "signature" in w] == [
        "1 detached signature(s) rest on signers.json alone: aqt-signoff is not installed, so registry keys were not "
        "checked against their enrolment records"]


def test_detached_statement_naming_another_signer_is_a_problem(worked, keys, env):
    """A-9: a statement signed with bob's registered key but naming alice."""
    signers = registry(env, ("human:bob", keys["bob"], "2026-01-01T00:00:00Z", None))
    statement = build_statement(record_type="signoff.signature", signer={"id": "human:alice", "name": "A", "role": "qa"},
                                key=keys["bob"].key_id, meaning="approved", reason="fine",
                                subject=subject("file", "plan.md", sha256="sha256:" + "1" * 64),
                                signed_at=utc_now(), tz="UTC")
    forge(worked, new_record("signoff.signature", human("alice"), "sign", meaning="approved", reason="fine",
                             data={"signature": sign_statement(statement, keys["bob"])}))
    report = verify(worked, signers)
    assert not report.ok and any("belongs to human:bob" in p for p in report.problems)


# -- A-3: malformed payloads are problems, never crashes -----------------------------------------------------
def test_malformed_anchor_and_review_payloads_are_reported(worked):
    writer_side = {"origin": "writer", "pid": 1, "uid": 0, "gid": 0, "process_chain": [], "processes": [],
                   "harness": None}
    service = actor("service", "service:aqt-trail")
    forge(worked, new_record("trail.anchor", service, "rfc3161", data={"checkpoint": []}), observed=writer_side)
    forge(worked, new_record("trail.anchor", service, "rfc3161", data={"checkpoint": {}, "tsa": "x"}),
          observed=writer_side)
    forge(worked, new_record("trail.review", human("dora"), "review.signed", meaning="reviewed", reason="r",
                             data={"signature": {"statement": {"subject": None, "signer": 5}}}))
    forge(worked, new_record("trail.gap", service, "spool.drained", data={"count": 1}), event("after"))
    report = verify(worked)
    assert not report.ok and report.first_bad_seq is None
    assert sum("malformed checkpoint" in p for p in report.problems) == 2
    assert any("detached signature in data.signature is invalid" in p for p in report.problems)
    records = read_records(worked.trail_path)
    assert alcoa_report(records, report) and run_review(records, profile(), log_id="trail_test")


def test_sig_null_line_is_a_broken_chain_not_a_crash(worked):
    lines = worked.trail_path.read_bytes().splitlines(keepends=True)
    record = json.loads(lines[1])
    record["sig"] = None
    lines[1] = canonical_json(record) + b"\n"
    worked.trail_path.write_bytes(b"".join(lines))
    report = verify(worked)
    assert report.first_bad_seq == 1 and "sig" in report.reason


# -- C-19: the stored bytes are the record -------------------------------------------------------------------
def test_non_canonical_and_duplicate_key_lines_are_refused(worked):
    lines = worked.trail_path.read_bytes().splitlines(keepends=True)
    original = lines[1]
    lines[1] = json.dumps(json.loads(original), indent=None).encode() + b"\n"   # same record, other spacing
    worked.trail_path.write_bytes(b"".join(lines))
    report = verify(worked)
    assert report.first_bad_seq == 1 and "canonical form" in report.reason
    lines[1] = original[:-2] + b',"action":"other"}\n'                           # duplicate key, last wins in json
    worked.trail_path.write_bytes(b"".join(lines))
    report = verify(worked)
    assert report.first_bad_seq == 1 and "duplicate" in report.reason


# -- A-4: only anchors the writer wrote count ----------------------------------------------------------------
def test_client_sent_anchor_does_not_count(worked):
    params = {"unanchored_hours": 24}
    before = read_records(worked.trail_path)
    assert q_unanchored_head(before, before, params)
    forge(worked, new_record("trail.anchor", actor("service", "service:aqt-trail"), "external-head",
                             data={"imprint": "sha256:" + "0" * 64}))
    forged = read_records(worked.trail_path)
    assert q_unanchored_head(forged, forged, params)                      # still unanchored
    report = verify(worked)
    assert any("not written by the writer" in p for p in report.problems)
    enduring = next(r for r in alcoa_report(forged, report) if r["attribute"] == "enduring")
    assert enduring["status"] == "fail" and "ignored" in enduring["detail"]
    with opened(worked) as w:
        anchors.checkpoint(w, tsa_url="test:", test_dir=worked.state / "test-tsa")
    anchored = read_records(worked.trail_path)
    assert not q_unanchored_head(anchored, anchored, dict(params, test_tsa=True))   # TEST ONLY: only in test mode


# -- C-4: ALCOA reflects verification problems ---------------------------------------------------------------
def test_alcoa_original_and_complete_fail_after_truncation(worked):
    put(worked, event("three"), event("four"))
    with opened(worked) as w:
        anchors.save_checkpoint(w, anchors.current_checkpoint(w))
    worked.trail_path.write_bytes(b"".join(worked.trail_path.read_bytes().splitlines(keepends=True)[:2]))
    report = verify(worked)
    status = {r["attribute"]: r["status"] for r in alcoa_report(read_records(worked.trail_path), report)}
    assert status["original"] == "fail" and status["complete"] == "fail"


def test_alcoa_on_a_selection_does_not_fail_an_intact_trail(worked):
    report = verify(worked)
    records = read_records(worked.trail_path)[1:]
    status = {r["attribute"]: r["status"] for r in alcoa_report(records, report)}
    assert status["original"] == "pass" and status["complete"] == "pass"


# -- C-1 (consumer side): attribution needs a complete chain ------------------------------------------------
@pytest.mark.parametrize("observed,severity", [
    ({"chain_status": "complete"}, None),
    ({"chain_status": "partial"}, "minor"),
    ({"chain_status": "unavailable"}, "minor"),
    ({"chain_complete": False}, "minor"),
    ({}, "info"),                                     # written before chain_status existed
    ({"chain_status": "complete", "harness": "claude-code"}, "major"),
])
def test_human_claims_need_a_complete_chain(config, observed, severity):
    put(config, event("decide", who=human("alice")), **observed)
    records = read_records(config.trail_path)
    findings = q_attribution_mismatch(records, records, {})
    assert [f["severity"] for f in findings] == ([severity] if severity else [])
    attributable = next(r for r in alcoa_report(records, verify(config)) if r["attribute"] == "attributable")
    assert attributable["status"] == {None: "pass", "info": "pass", "minor": "warn", "major": "fail"}[severity]


# -- C-10: verify states what is covered ---------------------------------------------------------------------
def test_verify_states_coverage(worked, tmp_path):
    assert any("no external head" in w for w in verify(worked).warnings)
    with opened(worked) as w:
        point = anchors.current_checkpoint(w)
    heads = tmp_path / "heads.jsonl"
    heads.write_text(json.dumps(point) + "\n")
    put(worked, event("after the export"))
    report = verify_trail(worked.trail_path, keys=service_keys(worked), heads=heads, log_id="trail_test")
    assert report.ok and report.covered_seq == point["seq"]
    assert any(f"records seq {point['seq'] + 1}–{report.head_seq} are not covered" in w for w in report.warnings)


# -- C-7, AQT-EI-010: a bundle does not certify itself --------------------------------------------------------
def test_bundle_trust_comes_from_the_caller(worked, keys, env, tmp_path):
    with opened(worked) as w:
        anchors.checkpoint(w, tsa_url="test:", test_dir=worked.state / "test-tsa")
    forge(worked, _review_record(worked, keys["bob"], "human:dora", actors=["human:alice"]))
    bundle = export_bundle(worked, tmp_path / "bundle")
    (bundle / "signers.json").write_text(json.dumps({"version": 1, "signers": [{"id": "human:dora", "keys": [
        {"key_id": keys["bob"].key_id, "public_pem": public_pem(keys["bob"].public_key).decode(),
         "enrolled_at": "2026-01-01T00:00:00Z", "revoked_at": None}]}]}))
    pin = worked.state / "keys" / "service.key.pub"
    report = verify_bundle(bundle, pin_key=pin)
    assert report.anchors_verified == 0 and any("signers.json is not trusted" in w for w in report.warnings)
    assert any("review signature(s) not checked" in w for w in report.warnings)
    test_ca = verify_bundle(bundle, pin_key=pin, test_tsa=True)
    assert test_ca.anchors_verified == 1 and any("TEST ONLY" in w for w in test_ca.warnings)
    trusted = registry(env, ("human:dora", keys["dora"], "2026-01-01T00:00:00Z", None))
    checked = verify_bundle(bundle, pin_key=pin, signers=trusted)
    assert not checked.ok and any("not in the signer registry" in p for p in checked.problems)


# -- A-12: truncation is detected only up to the newest checkpoint kept outside the file ----------------------
def test_verify_states_what_follows_the_newest_checkpoint(worked):
    report = verify(worked)
    assert any("no checkpoints file" in w for w in report.warnings)
    assert any("no checkpoint matches" in w for w in report.warnings)
    with opened(worked) as w:
        anchors.save_checkpoint(w, anchors.current_checkpoint(w))
    put(worked, event("after the checkpoint"))
    report = verify(worked)
    assert report.checkpoint_seq == 1
    assert any("1 record(s) after the newest checkpoint (seq 1)" in w for w in report.warnings)


# -- verification round 2: TEST ONLY anchors and export notes are not anchors unless test mode is chosen -------
def test_test_anchor_requested_by_a_client_counts_only_in_test_mode(server, config, capsys):
    from aqt_trail import cli, tsa
    from aqt_trail.client import TrailClient, request
    from aqt_trail.review import anchored_seq
    TrailClient(config.socket_path).append(event("work", who=human("alice")))
    response = request(config.socket_path, {"op": "checkpoint", "anchor": True, "tsa_url": "test:"})   # any client
    assert response["ok"]
    records = read_records(config.trail_path)
    anchor = records[-1]
    assert anchor["data"]["tsa"]["url"] == "test:" and anchored_seq(anchor) is None
    assert anchored_seq(anchor, test_tsa=True) == anchor["data"]["checkpoint"]["seq"]
    findings = q_unanchored_head(records, records, {"unanchored_hours": 24})
    assert findings and "1 TEST ONLY anchor(s) not counted" in findings[0]["explanation"]
    assert not q_unanchored_head(records, records, {"unanchored_hours": 24, "test_tsa": True})
    report = verify(config)
    enduring = next(r for r in alcoa_report(records, report) if r["attribute"] == "enduring")
    assert enduring["status"] == "fail" and "TEST ONLY" in enduring["detail"]
    other_ca = verify_trail(config.trail_path, keys=service_keys(config), log_id="trail_test",
                            tsa_ca=[tsa.TestTSA().ca_cert])            # a real CA is configured: never a problem
    assert other_ca.ok and any("TEST ONLY authority; not counted" in w for w in other_ca.warnings)
    trusted = verify_trail(config.trail_path, keys=service_keys(config), log_id="trail_test",
                           tsa_ca=tsa.load_ca(config.state / "test-tsa" / "ca.pem"))
    assert trusted.ok and trusted.anchors_verified == 1
    capsys.readouterr()
    assert cli.main(["--json", "status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["last_anchor"] is None and "TEST ONLY" in status["last_test_anchor"]
    assert cli.main(["--json", "status", "--test-tsa"]) == 0
    assert json.loads(capsys.readouterr().out)["last_anchor"] == anchor["time"]


def test_export_note_does_not_make_the_trail_enduring(server, config):
    from aqt_trail.client import TrailClient, request
    TrailClient(config.socket_path).append(event("work", who=human("alice")))
    assert request(config.socket_path, {"op": "checkpoint", "export": True})["ok"]
    records = read_records(config.trail_path)
    assert records[-1]["action"] == "external-head"
    enduring = next(r for r in alcoa_report(records, verify(config)) if r["attribute"] == "enduring")
    assert enduring["status"] == "fail" and "1 exported head(s) noted" in enduring["detail"]


def test_review_run_in_test_mode_records_it_in_the_profile(worked, capsys):
    from aqt_trail import cli
    with opened(worked) as w:
        anchors.checkpoint(w, tsa_url="test:", test_dir=worked.state / "test-tsa")
    sheets = {}
    for flags in ([], ["--test-tsa"]):
        capsys.readouterr()
        assert cli.main(["--json", "review", "run", *flags]) == 0
        sheets[bool(flags)] = json.loads(open(json.loads(capsys.readouterr().out)["worksheet"]).read())
    assert "unanchored_head" in {f["query"] for f in sheets[False]["findings"]}
    assert "unanchored_head" not in {f["query"] for f in sheets[True]["findings"]}
    assert sheets[True]["profile"]["params"]["test_tsa"] is True
    assert sheets[True]["profile"]["differs_from_builtin"]["test_tsa"] == {"value": True, "builtin": False}


# -- verification round 2: the profile's parameters are shown and signed ----------------------------------------
NEUTERED = {"repeated_failures": 100000, "unanchored_hours": 100000, "skew_ms": 100000000}


def test_profile_parameters_are_shown_flagged_and_signed(worked, keys, env, tmp_path):
    from aqt_trail.cli import _describe
    from aqt_trail.review import check_worksheet, worksheet_markdown
    lenient = tmp_path / "evil.toml"
    lenient.write_text('name = "default"\n[params]\nrepeated_failures = 100000\n')
    with pytest.raises(ValueError, match="may not be named 'default'"):
        load_profile(str(lenient), DEFAULTS["review"])
    # a worksheet made in code can still call any parameters 'default': they are shown and signed
    params = dict(profile()["params"], **NEUTERED)
    sheet = run_review(read_records(worked.trail_path), {"name": "default", "queries": profile()["queries"],
                                                         "params": params}, log_id="trail_test")
    markdown = worksheet_markdown(sheet)
    assert "repeated_failures=100000 (built-in 3)" in markdown
    assert "**Differs from the built-in defaults:**" in markdown and "skew_ms" in markdown
    described = _describe(check_worksheet(sheet, read_records(worked.trail_path)))
    assert "WARNING: these parameters differ from the built-in defaults" in described
    assert "unanchored_hours=100000 (built-in 24)" in described
    record = sign(worked, sheet, keys["dora"], "human:dora")
    assert record["data"]["profile_params"] == params
    assert set(NEUTERED) <= set(record["data"]["profile_differs"])
    put(worked, record)
    assert verify(worked).ok
    altered = json.loads(json.dumps(record["data"]))           # a review whose shown parameters are not the profile's
    altered["profile_params"]["repeated_failures"] = 3
    body = {k: v for k, v in altered.items() if k != "signature"}
    sub = subject("trail-review", altered["worksheet"], sha256=content_hash(body))
    statement = build_statement(record_type="trail.review", signer={"id": "human:dora", "name": "D", "role": "qa"},
                                key=keys["dora"].key_id, meaning="reviewed", reason="r", subject=sub,
                                signed_at=utc_now(), tz="UTC")
    altered["signature"] = sign_statement(statement, keys["dora"])
    forge(worked, new_record("trail.review", human("dora"), "review.signed", subject=sub, reason="r",
                             meaning="reviewed", data=altered))
    report = verify(worked)
    assert any("profile parameters do not match its profile hash" in p for p in report.problems)


# -- verification round 2: a signed review counts once; only a valid one shows that a review was done -----------
def test_replayed_review_counts_once(worked, keys, env, capsys):
    from aqt_trail import cli
    from aqt_trail.verify import review_statuses
    sheet = run_review(read_records(worked.trail_path), profile(), log_id="trail_test")
    review = put(worked, sign(worked, sheet, keys["dora"], "human:dora"))[0]
    put(worked, event("much later work", who=human("alice")))
    replay = new_record("trail.review", review["actor"], "review.signed", subject=review["subject"],
                        reason="monthly review incl. later work", meaning="reviewed", data=review["data"],
                        links=review["links"])
    altered = json.loads(json.dumps(review["data"]))
    altered["signature"]["statement"]["reason"] = "signed something else"
    forged = new_record("trail.review", review["actor"], "review.signed", subject=review["subject"], reason="r",
                        meaning="reviewed", data=altered)
    put(worked, replay, forged)
    report = verify(worked)
    assert not report.ok and report.reviews == 2      # the original and the forgery; the copy counts once
    assert any(f"repeats the review signed at seq {review['chain']['seq']}" in p for p in report.problems)
    signers = registry(env, ("human:dora", keys["dora"], "2026-01-01T00:00:00Z", None))
    statuses = {r["id"]: (status, detail)
                for r, status, detail in review_statuses(read_records(worked.trail_path), signers=signers)}
    assert statuses[review["id"]][0] == "valid"
    assert statuses[replay["id"]][0] == "invalid" and "replayed copy" in statuses[replay["id"]][1]
    assert statuses[forged["id"]][0] == "invalid"
    capsys.readouterr()
    assert cli.main(["--json", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["last_review"] == review["time"]
    assert cli.main(["--json", "review", "list"]) == 0
    listed = {row["id"]: row["signature"] for row in json.loads(capsys.readouterr().out)}
    assert listed == {review["id"]: "valid", replay["id"]: "invalid", forged["id"]: "invalid"}


# -- verification round 2: a human claim pushed by an agent through the drain op -----------------------------------
def _drained(config, drainer):
    claimed = event("release.decided", who=human("owner"), meaning="released")
    spooled = {"process_chain": [], "processes": [], "harness": None, "via": "spool", "drained_by": drainer}
    return forge(config, claimed, observed=spooled)[0]


@pytest.mark.parametrize("drainer,state,severity", [
    ({"via": "socket", "harness": "claude-code", "chain_status": "complete", "process_chain": ["python3", "claude"]},
     "agent", "major"),
    ({"via": "socket", "harness": None, "chain_status": "partial", "process_chain": ["python3"]}, "unconfirmed",
     "minor"),
    ({"via": "socket", "harness": None, "chain_status": "complete", "process_chain": ["python3", "bash"]}, None, None),
])
def test_drained_human_claim_is_judged_by_its_drainer(worked, drainer, state, severity):
    from aqt_trail.review import attribution, q_gaps
    stored = _drained(worked, drainer)
    records = read_records(worked.trail_path)
    assert attribution(stored) == state
    found = [f for f in q_attribution_mismatch(records, records, {}) if stored["id"] in f["record_ids"]]
    assert [f["severity"] for f in found] == ([severity] if severity else [])
    if state == "agent":
        assert "drain request from inside claude-code" in found[0]["explanation"]
        attributable = next(r for r in alcoa_report(records, verify(worked)) if r["attribute"] == "attributable")
        assert attributable["status"] == "fail"
    gaps = [f["explanation"] for f in q_gaps(records, records, {}) if stored["id"] in f["record_ids"]]
    assert gaps == ["records delivered through the spool by a drain request (the drainer was observed, the sender "
                    "was not)"]


def test_gap_of_a_drain_request_names_the_drainer(server, config):
    from aqt_trail.client import request
    from aqt_trail.review import q_gaps
    claimed = event("release.decided", who=human("owner"), meaning="released")
    assert request(config.socket_path, {"op": "drain", "records": [claimed], "source": "client spool"})["ok"]
    records = read_records(config.trail_path)
    gap = next(f for f in q_gaps(records, records, {}) if f["severity"] == "major")
    assert "pushed by a drain request from" in gap["explanation"] and "the drainer was observed" in gap["explanation"]
    assert "not observed" not in gap["explanation"].split(";")[0]
