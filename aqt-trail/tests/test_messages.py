"""Message codes next to the English sentences: verify, ALCOA++, signatures, chain status, review."""

import json

import pytest

from aqt_evidence import coded, new_record

from aqt_trail import cli
from aqt_trail.alcoa import alcoa_report
from aqt_trail.observe import chain_status
from aqt_trail.review import ReviewRefused, worksheet_digest
from aqt_trail.state import read_records
from aqt_trail.verify import signature_status

from conftest import event, human
from test_review import _sign, planted, profile, reviewer, run_review  # noqa: F401 - fixtures
from test_tamper import check, lines, trail  # noqa: F401 - fixture


def test_verify_summary_problems_and_warnings_carry_codes(trail):
    config, heads = trail
    intact = check(config)
    assert intact.summary().code == "trail.verify.intact"
    assert {w.code for w in intact.warnings} >= {"trail.verify.key_not_pinned", "trail.verify.not_covered"}
    config.trail_path.write_bytes(b"".join(lines(config)[:3]))
    report = check(config, heads=heads)
    truncated = [p for p in report.problems if getattr(p, "code", "") == "trail.verify.point_truncated"]
    assert truncated and coded(truncated[0])["args"]["label"] == {"code": "trail.verify.label_checkpoint", "args": {}}
    assert report.summary().code == "trail.verify.problems"
    assert report.summary() == f"chain intact (3 records) but: {report.problems[0]}"


def test_break_reason_and_cli_output_stay_the_english_text(trail, capsys):
    config, _ = trail
    data = lines(config)
    config.trail_path.write_bytes(b"".join(data[:2] + [b"\n"] + data[2:]))
    report = check(config)
    assert report.reason == "line 3: empty line" and report.reason.code == "trail.verify.bad_line"
    assert coded(report.reason)["args"] == {"line": 3, "reason": {"code": "trail.verify.line_empty", "args": {}}}
    assert cli.main(["verify"]) == 1
    printed = capsys.readouterr().out.splitlines()
    assert printed[0] == "broken from seq 2: line 3: empty line"
    assert cli.main(["--json", "verify"]) == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "line 3: empty line"


def test_alcoa_details_carry_codes(planted):
    records = read_records(planted.trail_path)
    report = check(planted)
    results = {r["attribute"]: r["detail"] for r in alcoa_report(records, report)}
    assert results["attributable"].code == "aqt.join"
    assert [item.code for item in results["attributable"].args["items"]] == ["trail.alcoa.agent", "trail.alcoa.legacy"]
    assert results["attributable"] == ("1 record(s) claim a human but came from an agent harness; 6 human-claimed "
                                       "record(s) predate observed.chain_status and rest on the absence of agent markers")
    assert results["legible"].code == "trail.alcoa.legible" and results["available"].code == "trail.alcoa.export_unchecked"
    assert all(coded(detail) for detail in results.values())


def test_signature_status_and_chain_status_carry_codes():
    status, detail = signature_status(event("plain", who=human()))
    assert (status, detail, detail.code) == ("unsigned", "no detached signature in data.signature", "trail.signature.none")
    record = new_record("trail.event", human(), "x", reason="r", data={"signature": {"statement": {
        "aqt_signature": "9", "record_type": "other", "signer": {}, "signed_at": "never"}, "alg": "rsa"}})
    status, detail = signature_status(record)
    assert status == "invalid" and detail.code == "aqt.join"
    assert [item.code for item in detail.args["items"]][:2] == ["trail.signature.version", "trail.signature.alg"]
    state, why = chain_status([{"pid": 9, "comm": "x", "start_time": 1}], [], "depth")
    assert (state, why, why.code) == ("partial", "more than 16 ancestors", "trail.observe.too_deep")


def test_review_findings_codes_beside_the_findings_and_refusals(planted, reviewer):
    sheet = run_review(read_records(planted.trail_path), profile(), log_id="trail_test")
    assert set(sheet["finding_codes"]) == {f["id"] for f in sheet["findings"]}
    for finding in sheet["findings"]:
        assert sheet["finding_codes"][finding["id"]] == coded(finding["explanation"])
    without = {key: value for key, value in sheet.items() if key != "finding_codes"}
    assert worksheet_digest(sheet) == worksheet_digest(without)          # not part of what is signed
    shown = json.loads(json.dumps(sheet))
    assert shown["finding_codes"] == sheet["finding_codes"] and _sign(planted, reviewer, shown)
    with pytest.raises(ReviewRefused) as caught:
        _sign(planted, reviewer, sheet, reviewer_id="human:bob")
    assert caught.value.code == "not_independent"
    assert coded(caught.value) == {"code": "trail.refused.not_independent", "args": {"reviewer": "human:bob"}}
