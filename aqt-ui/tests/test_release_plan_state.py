"""Verification of the third review (R-e3, E3V): the finish signed must be this project's own, as aqt-change
finish recorded it in the plan state (history, plan-version link, completed plan), with receipts of this plan
run on this repository's history; open tasks are shown before signing."""

import json
from pathlib import Path

from conftest import trail_records
from test_release import P, body, change_of, finish_project, finished, git  # noqa: F401 - fixture
from test_release_binding import mirror, mirror_records
from test_release_moved_on import out, refused

from aqt_ui.config import UiConfig


def emit(root: Path, monkeypatch, env, record: dict) -> dict:
    from aqt_change.ledger import Ledger
    monkeypatch.chdir(root)
    stored = Ledger.open(root).emit(record)
    monkeypatch.chdir(env)
    return stored


# -- E3V-1: a finish the agent writes itself, with tasks still open --------------------------------------------------
def test_an_agent_written_finish_without_aqt_change_finish_is_refused(trail, signer, env, ui_factory, monkeypatch):
    from aqt_change.actors import current_actor
    from aqt_change.gate import gate
    from aqt_change.ledger import Ledger
    from aqt_evidence import new_record, subject
    root = finish_project(env / "nofinish", env, monkeypatch, finish_it=False, tick=False)   # T01 stays open
    monkeypatch.chdir(root)
    ledger = Ledger.open(root)
    result, state = gate(ledger, P), ledger.plan_state("s01")
    monkeypatch.chdir(env)
    emit(root, monkeypatch, env, new_record(
        "change.finish", current_actor(ledger.config.actor), "finish", subject=subject("plan", "s01", sha256=state["accepted_raw"]),
        data={"plan_ref": "s01", "plan_id": "s01", "path": P, "idempotency_key": "never-finished", "head": ledger.head(),
              "receipts": result["receipts"], "gate": "GO", "tasks": {"done": ["T01"], "open": []}, "waivers": []}))
    client = ui_factory(config=UiConfig(projects=[root]))
    client.login()
    data = change_of(client)
    assert [t["id"] for t in data["plan"]["open_tasks"]] == ["T01"]                  # shown on the Release step
    refused(client, trail, data, {"ui.release.not_in_plan_state", "ui.release.not_completed"})


def test_the_plan_state_must_say_completed(finished, trail, ui_factory):
    state_file = finished / ".git" / "aqt-change" / "plans" / "s01.json"
    state = json.loads(state_file.read_text())
    state_file.write_text(json.dumps({**state, "status": "in_progress"}))
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    assert data["plan"]["decision"] == "GO"
    refused(client, trail, data, {"ui.release.not_completed"})


# -- E3V-2: another project's receipt and finish, identical content, external lifecycle --------------------------
def test_another_projects_finish_and_receipt_are_refused_with_identical_content(trail, signer, env, ui_factory,
                                                                                 monkeypatch):
    from aqt_change.ledger import Ledger
    from aqt_change.review import add_review
    (env / "config" / "aqt").mkdir(parents=True, exist_ok=True)
    (env / "config" / "aqt" / "change.toml").write_text('lifecycle_owner = "external"\n')
    a = finish_project(env / "a", env, monkeypatch)
    b = finish_project(env / "b", env, monkeypatch)
    monkeypatch.chdir(b)
    add_review(Ledger.open(b), P, reviewer="agent:x:3", independence="different-model", verdict="FAIL", reason="x")
    monkeypatch.chdir(env)
    git(a, "fetch", "-q", str(b), "main")
    git(a, "merge", "-q", "-s", "ours", "--allow-unrelated-histories", "-m", "merge", "FETCH_HEAD")
    with open(mirror(a), "a") as handle:
        for record in mirror_records(b):
            if record["type"] in ("change.receipt", "change.finish"):
                handle.write(json.dumps(record) + "\n")
    client = ui_factory(config=UiConfig(projects=[a, b]))
    client.login()
    data = change_of(client)
    theirs = [r for r in mirror_records(b) if r["type"] == "change.finish"][-1]
    assert data["plan"]["finish"] == theirs["id"]
    assert data["plan"]["decision"] == "GO"
    refused(client, trail, data, {"ui.release.not_in_plan_state"})
    status, other, _ = client.get("/api/change/1/s01?fresh=1")
    assert other["plan"]["release"]["state"] == "unreleased"


def test_a_receipt_run_outside_the_plans_history_is_refused(trail, signer, env, ui_factory, monkeypatch):
    """A receipt taken on a history that does not descend from the plan's base commit (here an orphan branch
    with the same files) does not count for the release, even inside the project's own finish."""
    from aqt_change import receipts
    from aqt_change.finish import finish
    from aqt_change.ledger import Ledger
    root = finish_project(env / "orphan", env, monkeypatch, finish_it=False)
    git(root, "checkout", "-q", "--orphan", "elsewhere")
    git(root, "commit", "-qm", "the same files, another history")
    elsewhere = out(root, "rev-parse", "HEAD")
    monkeypatch.chdir(root)
    receipts.run(Ledger.open(root), [], plan_path=P, all_items=True, echo=False)       # run on that history
    monkeypatch.chdir(env)
    git(root, "checkout", "-q", "main")
    monkeypatch.chdir(root)
    finish(Ledger.open(root), P, key="s01-finish", summary="done")
    monkeypatch.chdir(env)
    finish_record = [r for r in mirror_records(root) if r["type"] == "change.finish"][-1]
    run_at = {r["id"]: r["data"]["git"]["head"] for r in mirror_records(root) if r["type"] == "change.receipt"}
    assert [run_at[x] for x in finish_record["data"]["receipts"]] == [elsewhere]
    client = ui_factory(config=UiConfig(projects=[root]))
    client.login()
    data = change_of(client)
    assert data["plan"]["release"]["state"] == "unbound"
    assert data["plan"]["finish_problem_code"] == "ui.release.foreign_receipt"
    assert data["plan"]["decision"] == "GO"
    refused(client, trail, data, {"ui.release.foreign_receipt"})
    assert not [r for r in trail_records(trail) if r["type"] == "signoff.signature"]
