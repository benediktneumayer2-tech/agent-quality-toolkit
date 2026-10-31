"""Second review of the flow (R-e2): Sign released signs only this change's finish record, the page shows
that record, the release state follows what aqt-signoff reads, a bad mirror line degrades one plan, the
guard runs before the signer lookup, and change pages take only plain project and plan parts.

aqt-change's local mirror (``.git/aqt-change/records.jsonl``) can be written by the agent's user; these tests
append to it what such an agent could."""

import json
import re
from pathlib import Path

import pytest
from conftest import PASSPHRASE, SIGNER, trail_records
from test_release import P, body, change_of, finish_project, finished  # noqa: F401 - fixture

from aqt_ui.config import UiConfig
from aqt_ui.guard import Mode

AGENT_PEER = ["curl", "bash", "claude", "systemd"]
STATIC = Path(__file__).resolve().parents[1] / "src" / "aqt_ui" / "static"


def mirror(root: Path) -> Path:
    return root / ".git" / "aqt-change" / "records.jsonl"


def mirror_records(root: Path) -> list[dict]:
    return [json.loads(line) for line in mirror(root).read_bytes().splitlines() if line.strip()]


def append(root: Path, record) -> None:
    with open(mirror(root), "a") as handle:
        handle.write(json.dumps(record) + "\n")


def finish_of(root: Path) -> dict:
    return next(r for r in mirror_records(root) if r["type"] == "change.finish")


def queue(client) -> dict:
    status, data, _ = client.get("/api/overview")
    assert status == 200, data
    return {n["id"]: n for n in data["needs"]}


def other_change(env, monkeypatch) -> Path:
    """A second project with the same plan id s01, finished, then NO-GO after a failing review."""
    from aqt_change.ledger import Ledger
    from aqt_change.review import add_review
    root = finish_project(env / "other", env, monkeypatch)
    monkeypatch.chdir(root)
    add_review(Ledger.open(root), P, reviewer="agent:x:3", independence="different-model", verdict="FAIL",
               reason="broken")
    monkeypatch.chdir(env)
    return root


def refused_without_signature(client, trail, data, code_prefix="ui.release."):
    before = len(trail_records(trail))
    status, result, _ = client.post("/api/change/0/s01/release", body(data))
    assert status == 409 and "nothing was signed" in result["message"], result
    assert result["message_code"] == "ui.release.unbound"
    assert result["message_args"]["why"]["code"].startswith(code_prefix)
    assert not [r for r in trail_records(trail)[before:] if r["type"] == "signoff.signature"]


# -- E2-1: the record signed is this change's change.finish record -------------------------------------------
@pytest.mark.parametrize("forgery", ["own content, other id", "the other change's record"])
def test_a_mirror_line_cannot_redirect_the_release_to_another_change(forgery, finished, trail, env, ui_factory,
                                                                      monkeypatch):
    other = other_change(env, monkeypatch)
    mine, theirs = finish_of(finished), finish_of(other)
    append(finished, {**mine, "id": theirs["id"]} if forgery == "own content, other id" else theirs)
    client = ui_factory(config=UiConfig(projects=[finished, other]))
    client.login()
    data = change_of(client)
    plan = data["plan"]
    assert plan["decision"] == "GO" and plan["finish"] == theirs["id"]           # what the mirror now names
    assert plan["release"]["state"] == "unbound" and plan["finish_record"] is None
    assert plan["finish_problem_code"] in ("ui.release.mirror_differs", "ui.release.other_repository")
    assert [s["state"] for s in data["steps"] if s["id"] == "release"] == ["person"]
    entries = queue(client)
    assert "release:0:s01" in entries and entries["release:0:s01"]["code"] == "finish_unbound"
    refused_without_signature(client, trail, data)
    status, other_data, _ = client.get("/api/change/1/s01?fresh=1")
    assert other_data["plan"]["release"]["state"] == "unreleased"                  # nothing landed on it


def test_a_mirror_line_cannot_point_the_release_at_any_record(finished, trail, ui_factory):
    target = next(r for r in trail_records(trail) if r["type"].startswith("signoff.key"))
    append(finished, {**finish_of(finished), "id": target["id"]})
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    assert data["plan"]["release"]["state"] == "unbound"
    assert data["plan"]["finish_problem_code"] == "ui.release.other_record"
    refused_without_signature(client, trail, data)


def test_an_already_released_record_does_not_make_this_change_released(finished, trail, env, ui_factory,
                                                                       monkeypatch):
    other = finish_project(env / "other", env, monkeypatch)
    client = ui_factory(config=UiConfig(projects=[finished, other]))
    client.login()
    status, other_data, _ = client.get("/api/change/1/s01?fresh=1")
    assert client.post("/api/change/1/s01/release", body(other_data))[0] == 200     # the other change is released
    append(finished, finish_of(other))
    data = change_of(client)
    assert data["plan"]["release"]["state"] == "unbound"
    assert [s["state"] for s in data["steps"] if s["id"] == "release"] == ["person"]
    assert queue(client)["release:0:s01"]["code"] == "finish_unbound"


# -- E2-2: commit, author and time come from the copy that is signed ----------------------------------------
def test_the_page_shows_the_signed_copy_and_refuses_a_rewritten_mirror(finished, trail, ui_factory):
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    signed = next(r for r in trail_records(trail) if r["id"] == data["plan"]["finish"])
    shown = data["plan"]["finish_record"]
    assert shown["commit"] == signed["data"]["commit"] and shown["by"] == signed["actor"]["id"]
    assert shown["sha256"] == data["plan"]["release"]["sha256"]
    lines = []
    for record in mirror_records(finished):
        if record["type"] == "change.finish":
            record = {**record, "actor": {**record["actor"], "id": "human:reviewed-by-alice"},
                      "data": {**record["data"], "commit": "1234567890abcdef1234567890abcdef12345678"}}
        lines.append(json.dumps(record))
    mirror(finished).write_text("\n".join(lines) + "\n")
    data = change_of(client)
    assert data["plan"]["finish_record"] is None and data["plan"]["release"]["state"] == "unbound"
    assert data["plan"]["finish_problem_code"] == "ui.release.mirror_differs"
    refused_without_signature(client, trail, data)


# -- E2-3: the release state follows the files aqt-signoff reads ----------------------------------------------
def test_the_release_state_follows_the_sources_aqt_signoff_reads(signer, env, ui_factory, monkeypatch):
    side = env / "signoff-side.jsonl"
    (env / "config" / "aqt" / "signoff.toml").write_text(f'[paths]\nsink = "file:{side}"\n')
    root = finish_project(env / "project", env, monkeypatch)          # no trail: aqt-change uses the default sink
    client = ui_factory(config=UiConfig(projects=[root]))
    client.login()
    data = change_of(client)
    assert data["plan"]["release"]["state"] == "unreleased"
    status, result, _ = client.post("/api/change/0/s01/release", body(data))
    assert status == 200 and result["ok"], result
    assert change_of(client)["plan"]["release"]["state"] == "released"
    from aqt_signoff import Signoff, StaticPassphrase, load_settings
    so = Signoff(load_settings(), authenticator=StaticPassphrase(PASSPHRASE), environ={}, chain=[], require_tty=False)
    so.withdraw(result["record_id"], "withdrawn: wrong build")
    assert change_of(client)["plan"]["release"]["state"] == "unreleased"


# -- E2-5: one malformed mirror line degrades one plan, the queue stays ------------------------------------------
def test_a_malformed_review_line_does_not_break_the_queue(finished, held_case, trail, ui_factory):
    append(finished, {"type": "change.review", "id": "rec_x", "time": "2026-10-31T00:00:00Z",
                      "actor": {"kind": "agent", "id": "agent:x"},
                      "data": {"plan_id": "s01", "verdict": "PASS", "independence": "none", "reviewer": "agent:x"}})
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    entries = queue(client)
    assert f"quarantine:{held_case}" in entries
    rows = change_of(client)["plan"]["review_records"]
    assert [r["reviewer"] for r in rows if r["id"] == "rec_x"] == ["agent:x"]      # the actor, as a fallback


def test_a_plan_that_cannot_be_read_is_one_error_entry(finished, held_case, trail, ui_factory, monkeypatch):
    def broken(*args, **kwargs):
        raise AttributeError("'str' object has no attribute 'get'")
    monkeypatch.setattr("aqt_ui.views.changes.finish_view", broken)
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    entries = queue(client)
    assert f"quarantine:{held_case}" in entries
    assert entries["gate:0:s01"]["code"] == "plan_error"
    plan = change_of(client)["plan"]
    assert plan["error_code"] == "ui.changes.plan_unreadable" and "AttributeError" in plan["error"]
    assert client.post("/api/change/0/s01/release", body({"plan": {**plan, "release": {"record": "r", "sha256": "s"}}}))[0] == 409


# -- E2-6: the guard runs before the signer lookup ------------------------------------------------------------
DECISIONS = {
    "release": ("/api/change/0/s01/release", {"record": "rec_x", "sha256": "sha256:x", "path": P}, "signoff.refused"),
    "plan": ("/api/changes/plans/approve", {"root": "/tmp/x", "plan_id": "s01", "record": "r", "sha256": "s"},
             "signoff.refused"),
    "action": ("/api/changes/actions/act_000000000000000000000000/approve", {"expected_hash": "sha256:x"},
               "signoff.refused"),
    "capa-approve": ("/api/capa/actions/DEV-0001-A1/approve", {"expected_hash": "sha256:x"}, "signoff.refused"),
    "accept": ("/api/capa/candidates/C-0/accept", {}, "capa.refused"),
}


@pytest.mark.parametrize("name", sorted(DECISIONS))
def test_an_agent_naming_an_unknown_signer_is_refused_and_recorded(name, finished, trail, ui_factory):
    path, extra, refusal_type = DECISIONS[name]
    client = ui_factory(config=UiConfig(projects=[finished]), peer=AGENT_PEER)
    client.login()
    before = len(trail_records(trail))
    status, result, _ = client.post(path, {"reason": "agent try", "passphrase": "x" * 12, "signer_id": "human:nobody",
                                           **extra})
    assert status == 403 and result["reason_code"] in ("agent_context", "agent-context"), result
    refusal = next(r for r in trail_records(trail)[before:] if r["type"] == refusal_type)
    assert refusal["actor"]["id"] == "human:nobody" and "process:claude" in refusal["data"]["agent_markers"]


def test_a_person_naming_an_unknown_signer_is_told_after_the_check(finished, trail, ui_factory):
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    status, result, _ = client.post("/api/change/0/s01/release", {**body(change_of(client)), "signer_id": "human:nobody"})
    assert status in (400, 404) and "nobody" in result["message"]


# -- E2-7 and E2-4: plain project index, plain plan id, safe case pages -----------------------------------------
@pytest.mark.parametrize("project", ["-1", "+0", "0_0", "00000", "1", "%30"])
def test_only_a_plain_index_of_a_configured_project(project, finished, trail, ui_factory):
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    status, data, _ = client.get(f"/api/change/{project}/s01")
    assert status == 400 and data["message_code"] == "ui.changes.no_project", (project, data)
    assert client.get("/api/change/0/s01")[1]["project"] == 0


@pytest.mark.parametrize("plan", ["..", ".", "s%2F01", "s01%3Ffull%3D1", "s01%23x", "%2E%2E"])
def test_only_a_plan_id_in_the_change_address(plan, finished, trail, ui_factory):
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    status, data, _ = client.get(f"/api/change/0/{plan}")
    assert status == 400 and data["message_code"] == "ui.changes.bad_plan_id", (plan, data)


def test_case_pages_with_a_query_fragment_or_dotdot_in_the_id_are_not_served(trail, ui_factory):
    client = ui_factory()
    bad = ["/case/release:..%2Fquarantine%2FQDFA4TF%3Ffull%3D1%26page%3D1%23:x", "/case/plan:0:..", "/case/a%5Cb",
           "/case/plan:0:s01%3Fx", "/change/0/..", "/change/0/s%2F01"]
    for page in bad:
        assert client.get(page, key=False)[0] == 404, page
    for page in ("/case/quarantine:Q7SEGGW", "/case/qualification:aqt-quarantine%2Fheuristics", "/change/0/s01"):
        assert client.get(page, key=False)[0] == 200, page


def test_the_page_builds_change_addresses_from_checked_and_encoded_parts():
    app = (STATIC / "app.js").read_text()
    assert app.count("/api/change/${") == 1, "only changeApi() builds a change API address"
    assert "encodeURIComponent(project)" in app and "PROJECT_PART.test" in app and "PLAN_PART.test" in app
    assert "Object.hasOwn(CASES, kind)" in app and "UNSAFE_CASE_ID.test(id)" in app
    assert not re.search(r"`/change/\$\{project\}", app)


# -- E2-8: display and signing pick the plan by the same rule ---------------------------------------------------
def test_signing_matches_the_plan_shown_by_id_and_path(finished, trail, ui_factory):
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    status, result, _ = client.post("/api/change/0/s01/release", body(data, path="plans/other.md"))
    assert status == 409 and result["message_code"] == "ui.release.other_plan"
    assert client.post("/api/change/0/s01/release", body(data))[0] == 200


# -- E2-10: untrusted strings on the page ---------------------------------------------------------------------
def test_tab_titles_show_hidden_characters_and_ids_are_not_translated():
    app = (STATIC / "app.js").read_text()
    titles = re.findall(r"document\.title = (.+);", app)
    assert titles and all(value.startswith("vis(") for value in titles), titles
    need = app[app.index("function needText"):app.index("function casePath")]
    assert 'key === "attribute" ? t(String(value))' in need and "t(String(value)))" not in need


def test_read_only_still_refuses_sign_released(finished, trail, ui_factory):
    client = ui_factory(config=UiConfig(projects=[finished]), mode=Mode(False, "started with --read-only", explicit=True))
    client.login()
    status, result, _ = client.post("/api/change/0/s01/release", body(change_of(client)))
    assert status == 403 and "--read-only" in result["message"]
