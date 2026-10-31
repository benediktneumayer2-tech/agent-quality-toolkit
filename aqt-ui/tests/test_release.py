"""The change page and "Sign released": the timeline of one plan, the queue entry per plan, and
the release signature over the change.finish record, bound to a fresh GO gate and to the record
shown. Refused when the gate is NO-GO or MANUAL, when the record shown is not the current one,
when this signer already released it, from an agent session, in read-only mode and without the
session key."""

import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import PASSPHRASE, SIGNER, trail_records

from aqt_ui.config import UiConfig
from aqt_ui.guard import Mode

P = "plans/s01.md"
CHECK = """\
import sys
sys.path.insert(0, "src")
import calc
ok = calc.add(2, 3) == 5
print("collected 1 item")
print("1 passed in 0.01s" if ok else "1 failed in 0.01s")
sys.exit(0 if ok else 1)
"""
PLAN = f"""---
tracker:
  schema: 1
  kind: sprint
  id: s01
  implementation: demo
  status: planned
aqt:
  paths:
    - src/**
    - tests/**
---

# Demo change

## Outcome

Add a calculator.

## Scope

Only the calculator.

## Tasks

- [ ] [T01] Implement add

## Verification

- [ ] [V01] Unit check passes `$ {shlex.quote(sys.executable)} tests/check.py`

## Progress Log

## Blockers

## Deviations

## Failures And Learnings

## Decisions

## Linked Git Changes

## Completion
"""


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)


def finish_project(root: Path, env: Path, monkeypatch, *, finish_it: bool = True, tick: bool = True) -> Path:
    """A Git project at ``root`` whose plan s01 was begun, checked (a passing receipt) and finished: the gate is
    GO and the change.finish record waits for a "released" signature."""
    from aqt_change import plans, receipts
    from aqt_change.finish import finish
    from aqt_change.ledger import Ledger
    for sub in ("src", "tests", "plans"):
        (root / sub).mkdir(parents=True)
    (root / "src" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (root / "tests" / "check.py").write_text(CHECK)
    (root / "plans" / "s01.md").write_text(PLAN)
    (root / ".gitignore").write_text("__pycache__/\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(env / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "dev@example.invalid")
    git(root, "config", "user.name", "Example Dev")
    git(root, "add", "-A")
    # A fixed date gives two such projects the same initial commit: aqt-change compares the base commit of a
    # plan id with every begin record of that id in the one trail, and two projects with plan s01 and
    # different bases would be MANUAL (plan_base_mismatch), depending on whether both began in the same second.
    monkeypatch.setenv("GIT_AUTHOR_DATE", "2026-10-01T09:00:00+00:00")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-10-01T09:00:00+00:00")
    git(root, "commit", "-qm", "initial")
    monkeypatch.delenv("GIT_AUTHOR_DATE")
    monkeypatch.delenv("GIT_COMMITTER_DATE")
    monkeypatch.chdir(root)                       # aqt-change resolves plan paths from here (set-up only)
    ledger = Ledger.open(root)
    plans.begin(ledger, P)
    plan = root / P
    if tick:
        plan.write_text(plan.read_text().replace("- [ ] [T01]", "- [x] [T01]"))
    receipts.run(ledger, [], plan_path=P, all_items=True, echo=False)
    if finish_it:
        finish(ledger, P, key="s01-finish", summary="add() done")
    monkeypatch.chdir(env)
    return root


@pytest.fixture
def finished(trail, signer, env, monkeypatch):
    """A finished GO change in a trail (see ``finish_project``)."""
    return finish_project(env / "project", env, monkeypatch)


def change_of(client, fresh=True):
    status, data, _ = client.get(f"/api/change/0/s01{'?fresh=1' if fresh else ''}")
    assert status == 200, data
    return data


def body(data, **extra):
    release = data["plan"]["release"]
    return {"reason": "Approved plan, passing receipts", "passphrase": PASSPHRASE, "signer_id": SIGNER,
            "record": release["record"], "sha256": release.get("sha256", ""), "path": data["plan"]["path"], **extra}


def steps(data):
    return {step["id"]: step["state"] for step in data["steps"]}


def queue(client):
    return {n["id"]: n for n in client.get("/api/overview")[1]["needs"]}


def test_sign_released_on_a_finished_go_change(finished, ui_factory, trail):
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    plan = data["plan"]
    assert plan["decision"] == "GO" and plan["finish"] and plan["release"]["state"] == "unreleased"
    assert steps(data) == {"plan": "open", "checks": "done", "review": "done", "gate": "done",
                           "release": "person"}
    assert [s["id"] for s in data["steps"] if s["current"]] == ["release"]
    assert data["release_policy"] == {"min_signatures": 1, "roles": [], "distinct_from_author": False}
    assert "release:0:s01" in queue(client)                       # "Release to sign"
    status, result, raw = client.post("/api/change/0/s01/release", body(data))
    assert status == 200 and result["ok"] and result["record_type"] == "signoff.signature", result
    signature = next(r for r in trail_records(trail) if r["id"] == result["record_id"])
    assert signature["meaning"] == "released" and signature["subject"]["ref"] == plan["finish"]
    assert signature["subject"]["sha256"] == plan["release"]["sha256"] and PASSPHRASE.encode() not in raw
    after = change_of(client, fresh=False)                        # the cached gate was dropped
    assert after["plan"]["release"]["state"] == "released" and steps(after)["release"] == "done"
    assert after["plan"]["release"]["signatures"][0]["id"] == SIGNER
    assert "release:0:s01" not in queue(client)
    status, result, _ = client.post("/api/change/0/s01/release", body(data))
    assert status == 400 and "already signed this change as released" in result["message"]


def test_release_needs_a_fresh_go_gate(finished, ui_factory, trail):
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    before = len(trail_records(trail))
    (finished / "src" / "calc.py").write_text("def add(a, b):\n    return a + b  # edited after finish\n")
    status, result, _ = client.post("/api/change/0/s01/release", body(data))   # the page still shows GO
    assert status == 409 and "NO-GO" in result["message"] and "receipt_stale" in result["message"]
    assert "nothing was signed" in result["message"].lower()
    assert [r["type"] for r in trail_records(trail)[before:]] == []
    assert steps(change_of(client))["gate"] == "evidence"


def test_release_refused_while_the_gate_is_manual(finished, ui_factory, trail, env, monkeypatch):
    from aqt_change.ledger import Ledger
    from aqt_change.review import add_review
    monkeypatch.chdir(finished)
    add_review(Ledger.open(finished), P, reviewer="agent:x:3", independence="different-model",
               verdict="CONCERNS", reason="one doubt")
    monkeypatch.chdir(env)
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    assert data["plan"]["decision"] == "MANUAL_VERIFY_REQUIRED" and steps(data)["review"] == "person"
    assert "gate:0:s01" in queue(client) and "release:0:s01" not in queue(client)
    status, result, _ = client.post("/api/change/0/s01/release", body(data))
    assert status == 409 and "MANUAL_VERIFY_REQUIRED" in result["message"]


def test_release_signs_only_the_record_shown(finished, ui_factory, trail):
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    before = len(trail_records(trail))
    status, result, _ = client.post("/api/change/0/s01/release", body(data, record="rec_other"))
    assert status == 409 and "not the one shown" in result["message"]
    status, result, _ = client.post("/api/change/0/s01/release", body(data, sha256="sha256:" + "0" * 64))
    assert status == 409 and "changed since it was shown" in result["message"]
    status, result, raw = client.post("/api/change/0/s01/release", body(data, passphrase="wrong-pass-123"))
    assert status == 403 and result["reason_code"] == "auth_failed" and b"wrong-pass-123" not in raw
    assert [r["type"] for r in trail_records(trail)[before:]] == ["signoff.auth.failed"]
    assert client.post("/api/change/1/s01/release", body(data))[0] == 400        # not a configured project


def test_release_follows_the_released_policy(finished, ui_factory, trail, env):
    (env / "config" / "aqt" / "signoff.toml").write_text('[policy.released]\nroles = ["release-manager"]\n')
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    assert data["release_policy"]["roles"] == ["release-manager"]
    status, result, _ = client.post("/api/change/0/s01/release", body(data))
    assert status == 403 and result["reason_code"] == "role_not_allowed"
    assert trail_records(trail)[-1]["type"] == "signoff.refused"


def test_release_refused_from_an_agent_session_read_only_and_without_the_session_key(finished, ui_factory, trail):
    config = UiConfig(projects=[finished])
    client = ui_factory(config=config)
    client.login()
    data = change_of(client)
    before = len(trail_records(trail))
    status, result, _ = client.post("/api/change/0/s01/release", body(data), csrf=False)
    assert status == 403 and "CSRF" in result["message"]
    read_only = ui_factory(config=config, mode=Mode(False, "started with --read-only", explicit=True))
    read_only.login()
    status, result, _ = read_only.post("/api/change/0/s01/release", body(data))
    assert status == 403 and "--read-only" in result["message"]
    assert len(trail_records(trail)) == before
    agent = ui_factory(config=config, peer=["curl", "bash", "claude", "systemd"])
    agent.login()
    status, result, raw = agent.post("/api/change/0/s01/release", body(data))
    assert status == 403 and result["reason_code"] == "agent_context" and PASSPHRASE.encode() not in raw
    refusal = trail_records(trail)[-1]
    assert refusal["type"] == "signoff.refused" and "process:claude" in refusal["data"]["agent_markers"]
    assert change_of(client)["plan"]["release"]["state"] == "unreleased"


def test_one_queue_entry_per_plan_for_its_stop_point(trail, signer, env, ui_factory, monkeypatch):
    """A begun plan whose version waits for approval (the gate requires it) is one entry, not also
    "gate NO-GO"."""
    from test_more_decisions import PLAN as BEGUN_PLAN
    from aqt_change import plans
    from aqt_change.ledger import Ledger
    root = env / "project"
    (root / "src").mkdir(parents=True)
    (root / "plans").mkdir()
    (root / "src" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (root / "plans" / "s01.md").write_text(BEGUN_PLAN)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(env / "gitconfig"))
    (env / "config" / "aqt").mkdir(parents=True, exist_ok=True)
    (env / "config" / "aqt" / "change.toml").write_text("[gate]\nrequire_signed_approval = true\n")
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "dev@example.invalid")
    git(root, "config", "user.name", "Example Dev")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "initial")
    monkeypatch.chdir(root)
    plans.begin(Ledger.open(root), "plans/s01.md")
    monkeypatch.chdir(env)
    client = ui_factory(config=UiConfig(projects=[root]))
    client.login()
    entries = [n for n in client.get("/api/overview")[1]["needs"] if n["view"] == "changes"]
    assert [n["id"] for n in entries] == ["plan:0:s01"] and entries[0]["code"] == "plan_approval"
    assert entries[0]["since"] and entries[0]["args"]["decision"] == "NO-GO"
    data = change_of(client, fresh=False)
    assert [s["id"] for s in data["steps"] if s["current"]] == ["plan"]


def test_case_and_change_pages_are_the_page_shell(trail, ui_factory):
    client = ui_factory()
    for page in ("/health", "/case/quarantine:Q7SEGGW", "/case/plan:0:s01", "/case/trail:alcoa:ALCOA-A1",
                 "/case/qualification:aqt-quarantine%2Fheuristics", "/change/0/s01"):
        status, raw, _ = client.get(page, key=False)
        assert status == 200 and b'<script type="module" src="/static/app.js">' in raw, page
    for page in ("/case/", "/case/a/b", "/change/x/s01", "/change/0/s01/extra", "/cases/x"):
        assert client.get(page, key=False)[0] == 404, page
