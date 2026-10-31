"""The sentences of the tools reach the page with their message code and parameters beside the English
(``X_code`` / ``X_args``, ``X_codes`` for lists, ``message_code`` / ``message_args`` in decision results and
problem responses), so the German page can show them from static/messages.js."""

from conftest import PASSPHRASE, SIGNER
from test_decisions import case_detail, release
from test_release import body, change_of, finished  # noqa: F401 - fixture

from aqt_ui.config import UiConfig


def test_quarantine_outcome_note_and_problem_carry_codes(trail, held_case, ui_factory):
    client = ui_factory()
    client.login()
    case = case_detail(client, held_case)
    from aqt_quarantine.detectors.heuristics import REASON_CODES
    reasons = {e["reason"] for e in case["evidence"]}
    assert reasons and reasons <= set(REASON_CODES.values()) | {r for r in reasons if "zero-width" in r}
    status, result, _ = release(client, held_case, case["content_sha256"])
    assert status == 200 and result["message_code"] == "quarantine.outcome.released"
    assert result["message_args"] == {"case": held_case, "record": result["record_id"]}
    assert result["message"] == f"release: case {held_case} recorded as {result['record_id']}"
    status, result, _ = client.post("/api/quarantine/nonsense/release", {"reason": "x", "passphrase": PASSPHRASE,
                                                                         "content_sha256": "x", "signer_id": SIGNER})
    assert status == 400 and result["message_code"] == "quarantine.error.case_id"
    assert result["message"] == "not a case id: 'nonsense' (expected Q plus 6 characters)"


def test_trail_check_and_alcoa_carry_codes(trail, ui_factory):
    client = ui_factory()
    client.login()
    client.app.trail.verify_now(wait=True)
    status, data, _ = client.get("/api/trail/status")
    assert status == 200
    check = data["status"]["check"]
    assert check["summary_code"] == "trail.verify.intact" and check["summary"].startswith("intact: ")
    assert len(check["warning_codes"]) == len(check["warnings"]) and all(check["warning_codes"])
    assert {c["code"] for c in check["warning_codes"]} >= {"trail.verify.not_covered"}
    assert data["alcoa"] and all(a["detail_code"] for a in data["alcoa"])
    legible = next(a for a in data["alcoa"] if a["attribute"] == "legible")
    assert legible["detail_code"] == "trail.alcoa.legible" and legible["detail_args"] == {}


def test_change_page_gate_detail_release_summary_and_policy_note(finished, ui_factory):
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    release_state = change_of(client)["plan"]["release"]
    assert release_state["summary_code"] == "signoff.verify.unsigned"
    note = release_state["policy"]
    assert note["note_code"] == "signoff.policy.needs_more" and note["note_args"] == {"n": 1}
    assert note["note"] == "needs 1 more valid signature(s)"
    (finished / ".aqt").mkdir()
    (finished / ".aqt" / "change.toml").write_text('[gate]\nmin_review_independence = "fresh-context"\n')
    reasons = {r["code"]: r for r in change_of(client)["plan"]["reasons"]}
    below = reasons["review_independence_below_policy"]
    assert below["detail"] == "needs fresh-context" and below["detail_code"] == "change.gate.needs_independence"
    assert below["detail_args"] == {"wanted": "fresh-context"}


def test_release_result_carries_its_code(finished, ui_factory):
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    status, result, _ = client.post("/api/change/0/s01/release", body(change_of(client)))
    assert status == 200 and result["message"] == "change s01 released"
    assert (result["message_code"], result["message_args"]) == ("ui.changes.released", {"plan": "s01"})


def test_no_trail_yet_is_a_case_with_the_fix(env, ui_factory):
    client = ui_factory()
    client.login()
    needs = client.get("/api/overview")[1]["needs"]
    entry = next(n for n in needs if n["code"] == "trail_missing")
    assert entry["id"] == "trail:trail_missing" and entry["key"] == "trail_missing" and "aqt setup" in entry["detail"]
