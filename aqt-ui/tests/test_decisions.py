"""Human decisions through the UI against a real trail writer: release, declare threat, stale
views, wrong passphrase, read-only mode and the per-request peer check."""

import io
import os

from conftest import PASSPHRASE, SIGNER, trail_records

from aqt_ui.guard import Mode, startup_mode


class Tty(io.StringIO):
    def isatty(self):
        return True


def journal(env_path):
    from aqt_quarantine.config import load_config
    from aqt_quarantine.store import Store
    config = load_config()
    return list(Store(config.state_dir).records())


def case_detail(client, case_id):
    status, data, _ = client.get(f"/api/quarantine/{case_id}")
    assert status == 200
    return data


def release(client, case_id, sha, *, passphrase=PASSPHRASE, reason="Injection only in an HTML comment; text needed"):
    return client.post(f"/api/quarantine/{case_id}/release",
                       {"reason": reason, "passphrase": passphrase, "content_sha256": sha, "signer_id": SIGNER})


def everything_written(trail, env):
    """Every byte the toolkit wrote under the throw-away state and config dirs."""
    out = b""
    for base in (env / "state", env / "config"):
        for root, _dirs, files in os.walk(base):
            for name in files:
                try:
                    with open(os.path.join(root, name), "rb") as handle:
                        out += handle.read()
                except OSError:
                    pass
    return out


def test_release_end_to_end(trail, held_case, ui_factory, env):
    client = ui_factory()
    client.login()
    status, data, _ = client.get("/api/quarantine")
    assert status == 200 and [c["case_id"] for c in data["cases"]] == [held_case]
    status, overview, _ = client.get("/api/overview")
    assert any(n["ref"] == held_case and n["severity"] == "high" for n in overview["needs"])
    case = case_detail(client, held_case)
    assert case["state"] == "held" and case["signers"][0]["id"] == SIGNER
    marked = [p for w in case["content"]["windows"] for p in w["pieces"] if p.get("mark")]
    assert marked and any("ignore all previous" in p["text"] for p in marked)

    status, result, raw = release(client, held_case, case["content_sha256"])
    assert status == 200 and result["ok"], result
    assert result["record_type"] == "quarantine.released" and result["record_id"].startswith("rec_")
    stored = [r for r in trail_records(trail) if r["id"] == result["record_id"]]
    assert len(stored) == 1, "the decision reached the trail through the writer"
    record = stored[0]
    assert record["actor"]["id"] == SIGNER and "signature" in record["data"]
    assert record["observed"]["pid"] == os.getpid(), "observed as coming from the aqt-ui server process"
    assert case_detail(client, held_case)["state"] == "released"
    status, overview, _ = client.get("/api/overview")
    assert not any(n["ref"] == held_case for n in overview["needs"])

    # the passphrase is nowhere: not in the response, the request log or any file
    assert PASSPHRASE.encode() not in raw
    assert all(PASSPHRASE not in line for line in client.log)
    assert PASSPHRASE.encode() not in everything_written(trail, env)


def test_declare_threat(trail, held_case, ui_factory):
    client = ui_factory()
    client.login()
    case = case_detail(client, held_case)
    status, result, _ = client.post(f"/api/quarantine/{held_case}/threat",
                                    {"reason": "Exfiltration attempt", "passphrase": PASSPHRASE,
                                     "content_sha256": case["content_sha256"], "signer_id": SIGNER})
    assert status == 200 and result["record_type"] == "quarantine.threat.declared"
    assert case_detail(client, held_case)["state"] == "threat"


def test_stale_view_signs_nothing(trail, held_case, ui_factory):
    client = ui_factory()
    client.login()
    before = len(trail_records(trail))
    status, result, _ = release(client, held_case, "sha256:" + "0" * 64)
    assert status == 409 and result["ok"] is False and "nothing was signed" in result["message"]
    assert len(trail_records(trail)) == before
    assert case_detail(client, held_case)["state"] == "held"


def test_wrong_passphrase_is_refused_and_recorded_without_echo(trail, held_case, ui_factory, env):
    client = ui_factory()
    client.login()
    wrong = "not-my-passphrase-41"
    case = case_detail(client, held_case)
    status, result, raw = release(client, held_case, case["content_sha256"], passphrase=wrong)
    assert status == 403 and result["ok"] is False and result["reason_code"] == "auth_failed"
    refused = [r for r in trail_records(trail) if r["type"] == "quarantine.refused"]
    assert refused and refused[-1]["data"]["reason_code"] == "auth_failed"
    assert wrong.encode() not in raw
    assert all(wrong not in line for line in client.log)
    assert wrong.encode() not in everything_written(trail, env)
    assert case_detail(client, held_case)["state"] == "held"


def test_request_from_a_process_under_an_agent_is_refused(trail, held_case, ui_factory):
    client = ui_factory(peer=["curl", "bash", "claude", "systemd"])
    client.login()
    case = case_detail(client, held_case)
    status, result, _ = release(client, held_case, case["content_sha256"])
    assert status == 403 and result["reason_code"] == "agent_context"
    assert "process:claude" in result["markers"]
    refused = [r for r in trail_records(trail) if r["type"] == "quarantine.refused"]
    assert refused[-1]["data"]["agent_markers"] == ["process:claude"]
    assert case_detail(client, held_case)["state"] == "held"


def test_unidentified_peer_is_refused(trail, held_case, ui_factory):
    client = ui_factory(peer=None)
    client.login()
    case = case_detail(client, held_case)
    status, result, _ = release(client, held_case, case["content_sha256"])
    assert status == 403 and result["markers"] == ["peer:unidentified"]


def test_started_inside_an_agent_runs_read_only_and_records_refusals(trail, held_case, ui_factory):
    mode = startup_mode(environ={"CLAUDECODE": "1"}, chain=["python3", "bash", "login"], stdin=Tty())
    assert not mode.decisions and "env:CLAUDECODE" in mode.markers and "claude-code" in mode.reason
    client = ui_factory(mode=mode)
    client.login()
    status, session, _ = client.get("/api/session")
    assert session["mode"]["decisions"] is False and "env:CLAUDECODE" in session["mode"]["reason"]
    case = case_detail(client, held_case)
    status, result, _ = release(client, held_case, case["content_sha256"])
    assert status == 403 and result["reason_code"] == "agent_context"
    refused = [r for r in trail_records(trail) if r["type"] == "quarantine.refused"]
    assert refused[-1]["data"]["agent_markers"] == ["env:CLAUDECODE"]


def test_startup_mode_needs_a_terminal_and_no_agent_markers():
    assert startup_mode(environ={}, chain=["python3", "bash", "login"], stdin=Tty()).decisions
    no_tty = startup_mode(environ={}, chain=["python3", "bash"], stdin=io.StringIO())
    assert not no_tty.decisions and "terminal" in no_tty.reason
    under_codex = startup_mode(environ={}, chain=["python3", "bash", "codex", "systemd"], stdin=Tty())
    assert not under_codex.decisions and "process:codex" in under_codex.markers


def test_explicit_read_only_refuses_without_a_record(trail, held_case, ui_factory):
    client = ui_factory(mode=Mode(False, "started with --read-only", explicit=True))
    client.login()
    before = len(trail_records(trail))
    case = case_detail(client, held_case)
    status, result, _ = release(client, held_case, case["content_sha256"])
    assert status == 403 and "--read-only" in result["message"]
    assert len(trail_records(trail)) == before


def test_read_views_write_no_evidence(trail, held_case, ui_factory, env):
    client = ui_factory()
    client.login()
    before_trail, before_journal = len(trail_records(trail)), len(journal(env))
    case = case_detail(client, held_case)
    for path in ("/api/overview", "/api/trail/records", "/api/trail/status", f"/api/quarantine/{held_case}?full=1",
                 "/api/quarantine?state=all", "/api/changes", "/api/signatures", "/api/capa", "/api/qualifications",
                 f"/api/signatures/verify?sha256={case['content_sha256']}",
                 f"/api/trail/record/{trail_records(trail)[0]['id']}"):
        status, _, _ = client.get(path)
        assert status == 200, path
    assert len(trail_records(trail)) == before_trail
    assert len(journal(env)) == before_journal


def test_approve_a_prepared_action(trail, signer, ui_factory):
    from aqt_evidence import actor
    from aqt_signoff import Signoff, StaticPassphrase
    agent = actor("agent", "agent:test:worker-1", harness="test", session="worker-1")
    so = Signoff.open(authenticator=StaticPassphrase(PASSPHRASE), environ={}, chain=[], require_tty=False)
    prepared = so.actions.prepare("command", "deploy-1", {"argv": ["true"]}, description="no-op deploy", who=agent)
    client = ui_factory()
    client.login()
    status, data, _ = client.get("/api/changes")
    assert [a["id"] for a in data["actions"]] == [prepared["id"]] and data["actions"][0]["status"] == "prepared"
    status, overview, _ = client.get("/api/overview")
    assert any(n["code"] == "action_prepared" for n in overview["needs"])
    stale = client.post(f"/api/changes/actions/{prepared['id']}/approve",
                        {"reason": "ok", "passphrase": PASSPHRASE, "expected_hash": "sha256:" + "1" * 64,
                         "signer_id": SIGNER})
    assert stale[0] == 409
    status, result, raw = client.post(f"/api/changes/actions/{prepared['id']}/approve",
                                      {"reason": "Reviewed the command", "passphrase": PASSPHRASE,
                                       "expected_hash": prepared["action_sha256"], "signer_id": SIGNER})
    assert status == 200 and result["ok"] and result["status"] == "approved", result
    assert result["record_id"] in {r["id"] for r in trail_records(trail) if r["type"] == "signoff.action.approved"}
    assert PASSPHRASE.encode() not in raw


def test_action_approval_from_an_agent_peer_is_recorded_by_signoff(trail, signer, ui_factory):
    from aqt_evidence import actor
    from aqt_signoff import Signoff, StaticPassphrase
    agent = actor("agent", "agent:test:worker-1", harness="test", session="worker-1")
    so = Signoff.open(authenticator=StaticPassphrase(PASSPHRASE), environ={}, chain=[], require_tty=False)
    prepared = so.actions.prepare("command", "deploy-2", {"argv": ["true"]}, who=agent)
    client = ui_factory(peer=["python3", "codex", "systemd"])
    client.login()
    status, result, _ = client.post(f"/api/changes/actions/{prepared['id']}/approve",
                                    {"reason": "self-approval attempt", "passphrase": PASSPHRASE,
                                     "expected_hash": prepared["action_sha256"], "signer_id": SIGNER})
    assert status == 403 and result["reason_code"] == "agent_context"
    refused = [r for r in trail_records(trail) if r["type"] == "signoff.refused"]
    assert refused and refused[-1]["data"]["agent_markers"] == ["process:codex"]
