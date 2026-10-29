"""The remaining human decisions in the UI: trust a source, approve a plan version, CAPA
(accept, dismiss, approve a corrective action, close), sign an audit-trail review, and the
bundle export. Each decision needs the passphrase, is refused in read-only mode, by the peer
check and without the CSRF token, and is recorded by the owning package."""

import io
import json
import subprocess
import tarfile
from datetime import date, timedelta
from pathlib import Path

import time

import pytest
from conftest import PASSPHRASE, SIGNER, trail_records

from aqt_ui.config import UiConfig
from aqt_ui.guard import Mode

AGENT_PEER = ["curl", "bash", "claude", "systemd"]
REVIEWER = "human:rev-test"
FUTURE = (date.today() + timedelta(days=60)).isoformat()

PLAN = """---
tracker:
  schema: 1
  kind: sprint
  id: s01
  implementation: demo
  status: planned
aqt:
  paths:
    - src/**
---

# Demo change

## Outcome

Add a calculator.

## Scope

Only the calculator.

## Tasks

- [ ] [T01] Implement add

## Verification

- [ ] [V01] Screenshot reviewed

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


def types_after(trail, before: int) -> list[str]:
    return [r["type"] for r in trail_records(trail)[before:]]


# -- set-ups -----------------------------------------------------------------------------------------
@pytest.fixture
def project(trail, env, monkeypatch):
    """A Git project with plan s01 registered and begun (its version waits for approval)."""
    from aqt_change import plans
    from aqt_change.ledger import Ledger
    root = env / "project"
    (root / "src").mkdir(parents=True)
    (root / "plans").mkdir()
    (root / "src" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (root / "plans" / "s01.md").write_text(PLAN)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(env / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "dev@example.invalid")
    git(root, "config", "user.name", "Example Dev")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "initial")
    monkeypatch.chdir(root)                       # aqt-change resolves plan paths from here (set-up only)
    plans.begin(Ledger.open(root), "plans/s01.md")
    monkeypatch.chdir(env)
    return root


def capa_with_identity(*, agent: bool = False):
    """aqt-capa as the configured person, or as a coding agent (the implementer of an action)."""
    from aqt_capa import Capa, load_config
    from aqt_evidence import AgentContext
    context = AgentContext(True, "test", ["env:TEST"], []) if agent else AgentContext(False)
    return Capa(load_config(), guard=lambda: AgentContext(False), context=lambda: context)


@pytest.fixture
def candidates(trail, signer, env):
    """Two CAPA candidates from two refused attempts, and a project root for corrective actions."""
    from aqt_evidence import actor, new_record, open_sink
    agent_home = env / "agent-home"
    agent_home.mkdir()
    (agent_home / "AGENTS.md").write_text("# Agent rules\n")
    config = env / "config" / "aqt"
    config.mkdir(parents=True, exist_ok=True)
    (config / "capa.toml").write_text(f'[project]\nroot = "{agent_home}"\nid = "agents"\n')
    sink = open_sink()
    for attempted in ("release", "trust-source"):
        sink.append(new_record("quarantine.refused", actor("agent", "agent:test:worker-1"), "refused",
                               data={"attempted_action": attempted, "reason_code": "agent_context",
                                     "agent_markers": ["process:claude"]}))
    capa = capa_with_identity()
    found = capa.scan()
    assert len([c for c in found if c["rule"] == "refused"]) == 2, found
    return [c["candidate_id"] for c in capa.candidates()], agent_home


@pytest.fixture
def reviewer(trail):
    """A reviewer whose key counts: made by aqt-quarantine, its enrolment recorded in the trail by
    'aqt-signoff rekey'. Returns the time after the enrolment: a review starts there, since the
    enrolment counts as the reviewer's activity."""
    from aqt_evidence import utc_now
    from aqt_quarantine.config import load_config
    from aqt_quarantine.decisions import create_identity
    from aqt_signoff import Signoff, StaticPassphrase, load_settings
    create_identity(load_config(), signer_id=REVIEWER, name="Robin Review", role="quality-manager",
                    passphrase=lambda _prompt: PASSPHRASE)
    Signoff(load_settings(), authenticator=StaticPassphrase(PASSPHRASE), environ={}, chain=[],
            require_tty=False).rekey(REVIEWER)
    time.sleep(0.01)
    return utc_now()


def body(**extra):
    return {"reason": "Checked in the UI test", "passphrase": PASSPHRASE, "signer_id": SIGNER, **extra}


# -- trust a source ------------------------------------------------------------------------------------
def test_trust_and_revoke_a_source(trail, signer, ui_factory):
    client = ui_factory()
    client.login()
    status, result, raw = client.post("/api/quarantine/sources/trust",
                                      body(domain="Docs.Example.org", expires=FUTURE, subdomains=True))
    assert status == 200 and result["ok"] and result["record_type"] == "quarantine.source.trusted", result
    stored = next(r for r in trail_records(trail) if r["id"] == result["record_id"])
    assert stored["actor"]["id"] == SIGNER and stored["data"]["domain"] == "docs.example.org"
    assert "signature" in stored["data"] and PASSPHRASE.encode() not in raw
    _, data, _ = client.get("/api/quarantine")
    source = next(s for s in data["sources"] if s["domain"] == "docs.example.org")
    assert source["active"] and source["subdomains"] and data["signers"][0]["id"] == SIGNER
    stale = client.post("/api/quarantine/sources/revoke", body(domain="docs.example.org", record="rec_other"))
    assert stale[0] == 409
    status, result, _ = client.post("/api/quarantine/sources/revoke",
                                    body(domain="docs.example.org", record=source["record"]))
    assert status == 200 and result["ok"]
    _, data, _ = client.get("/api/quarantine")
    assert not any(s["domain"] == "docs.example.org" and s["active"] for s in data["sources"])


def test_trust_with_a_wrong_passphrase_is_refused_and_recorded(trail, signer, ui_factory):
    client = ui_factory()
    client.login()
    status, result, raw = client.post("/api/quarantine/sources/trust",
                                      body(domain="docs.example.org", expires=FUTURE, passphrase="wrong-pass-123"))
    assert status == 403 and result["reason_code"] == "auth_failed"
    assert trail_records(trail)[-1]["type"] == "quarantine.refused" and b"wrong-pass-123" not in raw


# -- plan approval ---------------------------------------------------------------------------------------
def approval_of(client):
    _, data, _ = client.get("/api/changes")
    return data["projects"][0]["plans"][0]["approval"]


def test_approve_the_plan_version_shown(project, signer, ui_factory):
    client = ui_factory(config=UiConfig(projects=[project]))
    client.login()
    approval = approval_of(client)
    assert approval["state"] == "unsigned" and approval["record"] and approval["sha256"]
    request = body(root=str(project), plan_id="s01", record=approval["record"], sha256=approval["sha256"])
    assert client.post("/api/changes/plans/approve", {**request, "sha256": "sha256:" + "0" * 64})[0] == 409
    status, result, raw = client.post("/api/changes/plans/approve", {**request, "passphrase": "wrong-pass-123"})
    assert status == 403 and result["reason_code"] == "auth_failed" and b"wrong-pass-123" not in raw
    status, result, raw = client.post("/api/changes/plans/approve", request)
    assert status == 200 and result["ok"] and result["record_type"] == "signoff.signature", result
    assert approval_of(client)["state"] == "signed"            # the cached gate was dropped
    assert client.post("/api/changes/plans/approve", request)[0] == 400       # already approved
    elsewhere = client.post("/api/changes/plans/approve", {**request, "root": "/tmp/not-configured"})
    assert elsewhere[0] == 400


# -- CAPA ------------------------------------------------------------------------------------------------
def test_accept_and_dismiss_candidates_then_close_without_action(candidates, ui_factory, trail):
    (first, second), _ = candidates
    client = ui_factory()
    client.login()
    _, data, _ = client.get("/api/capa")
    assert {c["candidate_id"] for c in data["candidates"]} == {first, second} and data["signers"]
    status, result, raw = client.post(f"/api/capa/candidates/{first}/accept", body(passphrase="wrong-pass-123"))
    assert status == 403 and result["reason_code"] == "auth_failed" and b"wrong-pass-123" not in raw
    assert trail_records(trail)[-1]["type"] == "signoff.auth.failed"
    status, result, _ = client.post(f"/api/capa/candidates/{first}/accept", body())
    assert status == 200 and result["ok"] and result["dev_id"], result
    stored = next(r for r in trail_records(trail) if r["id"] == result["record_id"])
    assert stored["type"] == "capa.deviation" and stored["action"] == "accepted" and stored["actor"]["id"] == SIGNER
    status, result, _ = client.post(f"/api/capa/candidates/{second}/dismiss", body())
    assert status == 200 and result["ok"]
    assert client.get("/api/capa")[1]["counts"]["candidates"] == 0

    dev_id = stored["data"]["dev_id"]
    capa_with_identity().investigate(dev_id, whys=["the agent tried to release its own input"],
                                     factors=["method:no rule"], root_cause="No rule in AGENTS.md",
                                     root_category="instructions")
    _, shown, _ = client.get(f"/api/capa/{dev_id}")
    assert client.post(f"/api/capa/{dev_id}/close", body(version="rec_old", no_action=True))[0] == 409
    status, result, _ = client.post(f"/api/capa/{dev_id}/close", body(version=shown["version"], no_action=True))
    assert status == 200 and result["record_type"] == "capa.closure", result
    assert client.get(f"/api/capa/{dev_id}")[1]["deviation"]["state"] == "closed"


def test_approve_an_implemented_corrective_action(candidates, ui_factory, trail):
    (first, _), agent_home = candidates
    capa = capa_with_identity()
    dev_id = capa.accept(first, reason="needs a rule")["data"]["dev_id"]
    capa.investigate(dev_id, whys=["no rule"], factors=["method:no rule"], root_cause="No rule",
                     root_category="instructions")
    action_id = capa.plan(dev_id, kind="corrective", target="AGENTS.md", description="Add the rule",
                          window_sessions=1)["data"]["action_id"]
    (agent_home / "AGENTS.md").write_text("# Agent rules\n- Never decide quarantine cases.\n")
    capa_with_identity(agent=True).implement(action_id)
    client = ui_factory()
    client.login()
    _, shown, _ = client.get(f"/api/capa/{dev_id}")
    action = shown["actions"][0]
    assert action["state"] == "implemented" and action["approval"]["status"] == "awaiting-approval"
    path = f"/api/capa/actions/{action_id}/approve"
    assert client.post(path, body(expected_hash="sha256:" + "1" * 64))[0] == 409
    status, result, raw = client.post(path, body(expected_hash=action["implemented_hash"], passphrase="wrong-pass-123"))
    assert status == 403 and result["reason_code"] == "auth_failed" and b"wrong-pass-123" not in raw
    status, result, _ = client.post(path, body(expected_hash=action["implemented_hash"]))
    assert status == 200 and result["record_type"] == "signoff.signature", result
    signature = next(r for r in trail_records(trail) if r["id"] == result["record_id"])
    assert signature["subject"]["ref"] == action["implemented_record"] and signature["meaning"] == "approved"
    assert client.get(f"/api/capa/{dev_id}")[1]["actions"][0]["approval"]["status"] == "signed-verified"


# -- audit-trail review and export -----------------------------------------------------------------------
def run_review(client, since=None):
    status, sheet, _ = client.post("/api/trail/review/run", {"since": since} if since else {})
    assert status == 200 and sheet["ok"] and sheet["id"].startswith("rv_"), sheet
    return sheet


def test_sign_a_review_as_an_independent_reviewer(trail, signer, reviewer, ui_factory):
    client = ui_factory()
    client.login()
    # the quality manager decides something, so they act in the period and may not review it
    assert client.post("/api/quarantine/sources/trust", body(domain="docs.example.org", expires=FUTURE))[0] == 200
    sheet = run_review(client, reviewer)
    assert SIGNER in sheet["actors_reviewed"] and REVIEWER not in sheet["actors_reviewed"]
    assert REVIEWER in {s["id"] for s in sheet["signers"]}
    sign = {"head": sheet["scope"]["head"], "worksheet_sha256": sheet["worksheet_sha256"],
            "dispositions": {"all": "ok"}, "notes": {}, "conclusion": "Reviewed in the UI test"}
    path = f"/api/trail/review/{sheet['id']}/sign"
    status, result, _ = client.post(path, body(**sign))
    assert status == 403 and result["reason_code"] == "not_independent"
    assert trail_records(trail)[-1]["type"] == "trail.refused"
    assert client.post(path, body(**{**sign, "head": "sha256:" + "2" * 64}, signer_id=REVIEWER))[0] == 409
    status, result, raw = client.post(path, body(**sign, signer_id=REVIEWER, passphrase="wrong-pass-123"))
    assert status == 403 and result["reason_code"] == "auth_failed" and b"wrong-pass-123" not in raw
    sheet = run_review(client, reviewer)    # the refusals moved the head on; prepare the worksheet again
    status, result, _ = client.post(f"/api/trail/review/{sheet['id']}/sign",
                                    body(**{**sign, "head": sheet["scope"]["head"],
                                            "worksheet_sha256": sheet["worksheet_sha256"]}, signer_id=REVIEWER))
    assert status == 200 and result["record_type"] == "trail.review", result
    review = next(r for r in trail_records(trail) if r["id"] == result["record_id"])
    assert review["actor"]["id"] == REVIEWER and review["data"]["signature"]["statement"]["meaning"] == "reviewed"
    assert client.get("/api/trail/status")[1]["status"]["last_review"] == review["time"]


def test_export_a_bundle_records_nothing_and_works_read_only(trail, ui_factory):
    client = ui_factory(mode=Mode(False, "started with --read-only", explicit=True))
    client.login()
    before = len(trail_records(trail))
    status, raw, response = client.get("/api/trail/export")
    assert status == 200 and response.getheader("Content-Type") == "application/gzip"
    assert "attachment" in response.getheader("Content-Disposition")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        names = archive.getnames()
        manifest = json.load(archive.extractfile(next(n for n in names if n.endswith("MANIFEST.json"))))
    assert any(n.endswith("trail.jsonl") for n in names) and manifest["log_id"] == "trail_ui_test"
    assert len(trail_records(trail)) == before


# -- the same refusals for every new decision ------------------------------------------------------------
DECISIONS = {
    "trust": ("/api/quarantine/sources/trust", {"domain": "docs.example.org", "expires": FUTURE}, "quarantine.refused"),
    "revoke": ("/api/quarantine/sources/revoke", {"domain": "docs.example.org", "record": "rec_x"}, "quarantine.refused"),
    "plan": ("/api/changes/plans/approve", {"root": "/tmp/x", "plan_id": "s01", "record": "r", "sha256": "s"},
             "signoff.refused"),
    "accept": ("/api/capa/candidates/C-0/accept", {}, "capa.refused"),
    "dismiss": ("/api/capa/candidates/C-0/dismiss", {}, "capa.refused"),
    "close": ("/api/capa/DEV-0001/close", {"version": "rec_x"}, "capa.refused"),
    "capa-approve": ("/api/capa/actions/DEV-0001-A1/approve", {"expected_hash": "sha256:x"}, "signoff.refused"),
    "review": ("/api/trail/review/rv_000000000000/sign", {"head": "sha256:x", "dispositions": {"all": "ok"}},
               "trail.refused"),
}


@pytest.mark.parametrize("name", sorted(DECISIONS))
def test_every_decision_is_refused_without_csrf_and_in_read_only_mode(name, trail, signer, ui_factory):
    path, extra, _ = DECISIONS[name]
    client = ui_factory()
    client.login()
    before = len(trail_records(trail))
    status, result, _ = client.post(path, body(**extra), csrf=False)
    assert status == 403 and "CSRF" in result["message"]
    status, result, _ = client.post(path, body(**extra), origin=False)
    assert status == 403 and "Origin" in result["message"]
    read_only = ui_factory(mode=Mode(False, "started with --read-only", explicit=True))
    read_only.login()
    status, result, raw = read_only.post(path, body(**extra))
    assert status == 403 and "--read-only" in result["message"] and PASSPHRASE.encode() not in raw
    assert len(trail_records(trail)) == before


@pytest.mark.parametrize("name", sorted(DECISIONS))
def test_every_decision_from_a_process_under_an_agent_is_refused_and_recorded(name, trail, signer, ui_factory):
    path, extra, refusal_type = DECISIONS[name]
    client = ui_factory(peer=AGENT_PEER)
    client.login()
    before = len(trail_records(trail))
    status, result, raw = client.post(path, body(**extra))
    assert status == 403 and result["ok"] is False, result
    assert refusal_type in types_after(trail, before)
    refusal = next(r for r in trail_records(trail)[before:] if r["type"] == refusal_type)
    assert "process:claude" in refusal["data"]["agent_markers"]
    assert PASSPHRASE.encode() not in raw
