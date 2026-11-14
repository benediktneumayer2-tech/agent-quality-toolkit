"""The desktop app's setup routes in the core (aqt-ui ``Core.handle``): onboarding, Settings and Projects run
aqt-cli's own checks and steps. Here because they need aqt-cli and aqt-ui together; every test has its own
HOME and XDG folders and a fake ``systemctl --user`` (conftest.env)."""

import json
import os
import subprocess
from pathlib import Path

import pytest
from aqt_signoff.settings import load_settings
from aqt_trail.config import load_config

from aqt_cli import checks
from aqt_ui.config import UiConfig
from aqt_ui.core import Core
from aqt_ui.guard import Guard, Mode
from conftest import LINUX_SYSTEMD, PASSPHRASE

APP = ["aqt-desktop", "gnome-shell", "systemd"]          # the process that started the core: the app
AGENT = ["bash", "claude", "gnome-terminal-server", "systemd"]


def core_for(mode=None, parent=APP):
    mode = mode or Mode(True)
    lines: list[str] = []
    core = Core(UiConfig(), mode, Guard(mode, environ={}, peer_lookup=lambda _c, _s: parent), log=lines.append)
    core.log_lines = lines
    return core


def get(core, route, **query):
    response = core.handle("GET", route, {k: str(v) for k, v in query.items()})
    return response.status, response.body


def post(core, path, body):
    response = core.handle("POST", path, {}, dict(body))
    return response.status, response.body


def enrol_body(**kw):
    return {"name": "Alice Example", "role": "quality-manager", "signer_id": "human:alice-example",
            "passphrase": PASSPHRASE, **kw}


def set_up_machine(core, systemd, start_writer):
    systemd.available = True
    systemd.on_start = start_writer
    for step in ("trail.init", "service", "writer"):
        status, body = post(core, "/api/setup/apply", {"check": step})
        assert status == 200 and body["ok"], (step, body)


def home_text() -> str:
    """Every readable text file under the test HOME and XDG folders."""
    out = []
    for base in {Path(os.environ["HOME"]).parent}:
        for path in base.rglob("*"):
            if path.is_file():
                try:
                    out.append(path.read_text(encoding="utf-8"))
                except (UnicodeDecodeError, OSError):
                    pass
    return "\n".join(out)


def test_a_fresh_machine_needs_setup_and_the_status_is_aqt_status():
    core = core_for()
    status, body = get(core, "/api/setup")
    assert status == 200 and body["needed"] is True and body["trail"] is False and body["signer"] is False
    assert [row["id"] for row in body["checks"]] == [check.id for check in checks.CHECKS]
    rows = {row["id"]: row for row in body["checks"]}
    assert rows["trail.init"]["result"] == "fail" and rows["trail.init"]["can_apply"] is True
    assert rows["signer"]["can_apply"] is False and rows["signer"]["personal"] is True   # the onboarding enrols
    assert body["passphrase_min"] == 12 and body["service"] is None          # the fake systemd is not available
    assert get(core, "/api/overview")[1]["setup"] == {"needed": True, "trail": False, "signer": False, "signers": []}


def test_the_signer_id_is_derived_from_the_name_and_checked_live():
    core = core_for()
    assert get(core, "/api/setup/signer-id", name="Jürgen Müller-Lüdenscheidt")[1]["id"] == \
        "human:juergen-mueller-luedenscheidt"
    found = get(core, "/api/setup/signer-id", name="Bene Test")[1]
    assert found == {**found, "id": "human:bene-test", "valid": True, "taken": False}
    custom = get(core, "/api/setup/signer-id", name="Bene Test", id="Bene Test")[1]
    assert custom["valid"] is False and custom["suggestion"] == "human:bene-test"
    assert get(core, "/api/setup/signer-id", id="bene.t")[1] == {**custom, "id": "human:bene.t", "valid": True,
                                                                 "suggestion": None}


@LINUX_SYSTEMD
def test_onboarding_sets_up_trail_writer_and_signer_and_never_keeps_the_passphrase(systemd, start_writer):
    core = core_for()
    set_up_machine(core, systemd, start_writer)
    assert ("enable", "--now", "aqt-trail") in systemd.calls and checks.unit_path().exists()
    status, body = post(core, "/api/setup/enrol", enrol_body())
    assert status == 200 and body["ok"] and body["signer_id"] == "human:alice-example" and body["counts"] is True
    trail = [json.loads(line) for line in load_config().trail_path.read_text().splitlines()]
    assert any(r["type"] == "signoff.key.enrolled" and r["id"] == body["record_id"] for r in trail)
    assert 'signer = "human:alice-example"' in load_settings().config_path.read_text()      # aqt setup's next step
    for step in ("trail.config",):
        assert post(core, "/api/setup/apply", {"check": step})[1]["ok"]
    status, body = get(core, "/api/setup")
    assert body["needed"] is False and body["signers"] == ["human:alice-example"]
    rows = {row["id"]: row for row in body["checks"]}
    assert all(rows[name]["result"] == "ok" for name in ("trail.init", "service", "writer", "signer", "signoff.config",
                                                         "trail.config")), rows
    assert get(core, "/api/setup/signer-id", id="alice-example")[1]["taken"] is True
    # the setup wrote trail.toml with this computer's time zone: kept on record, so a fresh install is in order
    kept = [r for r in json.loads("[" + ",".join(load_config().trail_path.read_text().splitlines()) + "]")
            if r["type"] == "ui.review_params.kept"]
    assert kept and kept[-1]["after"] == {"timezone": "Europe/Vienna"} and kept[-1]["actor"]["id"] == "human:alice-example"
    assert get(core, "/api/overview")[1]["needs"] == []
    assert PASSPHRASE not in json.dumps(body) and PASSPHRASE not in "\n".join(core.log_lines)
    assert PASSPHRASE not in home_text()
    assert any("aqt-ui decision /api/setup/enrol from pid" in line and "recorded" in line for line in core.log_lines)


@LINUX_SYSTEMD
def test_a_short_passphrase_or_a_bad_id_creates_nothing(systemd, start_writer):
    core = core_for()
    set_up_machine(core, systemd, start_writer)
    status, body = post(core, "/api/setup/enrol", enrol_body(passphrase="short"))
    assert status == 400 and "at least 12 characters" in body["message"] and "short" not in body["message"][-6:]
    status, body = post(core, "/api/setup/enrol", enrol_body(signer_id="Alice Example"))
    assert status == 400 and "human:alice-example" in body["message"]
    assert not load_settings().registry_path.exists() or "alice" not in load_settings().registry_path.read_text()


def test_read_only_and_agent_cores_refuse_every_setup_change(tmp_path, systemd, start_writer):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for core in (core_for(Mode(False, "started with --read-only", explicit=True)), core_for(parent=AGENT)):
        for path, body in (("/api/setup/apply", {"check": "trail.init"}), ("/api/setup/enrol", enrol_body()),
                           ("/api/projects/connect", {"path": str(repo), "items": ["instructions", "ui.project"]})):
            status, answer = post(core, path, body)
            assert status == 403 and answer["ok"] is False, (path, answer)
            assert PASSPHRASE not in json.dumps(answer)
    agent = core_for(parent=AGENT)
    assert post(agent, "/api/setup/apply", {"check": "trail.init"})[1]["reason_code"] == "agent_context"
    assert not load_config().meta_path.exists() and not load_settings().registry_path.exists()
    assert sorted(p.name for p in repo.iterdir()) == [".git"]
    assert not (Path(os.environ["XDG_CONFIG_HOME"]) / "aqt" / "ui.toml").exists()
    assert post(core_for(), "/api/setup/apply", {"check": "signer"})[0] == 400        # personal: only through enrol


def test_project_preview_writes_nothing_and_connect_applies_only_the_chosen_items(tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "CLAUDE.md").write_text("# My project\n")
    core = core_for()
    status, preview = get(core, "/api/projects/preview", path=str(repo))
    assert status == 200 and preview["root"] == str(repo.resolve()) and preview["git"] is True
    items = {item["id"]: item for item in preview["items"]}
    assert set(items) == {"claude.hooks", "claude.deny", "instructions", "change.settings", "ui.project", "git.hook"}
    assert items["claude.hooks"]["can_apply"] and "SessionStart: aqt trail hook claude-code" in items["claude.hooks"]["preview"]
    assert items["instructions"]["backup"] is True and "<!-- aqt:begin -->" in items["instructions"]["preview"]
    assert items["claude.hooks"]["file"] == ".claude/settings.json" and items["claude.hooks"]["backup"] is False
    assert sorted(p.name for p in repo.iterdir()) == [".git", "CLAUDE.md"]               # nothing written yet

    status, done = post(core, "/api/projects/connect",
                        {"path": str(repo), "items": ["claude.hooks", "instructions", "ui.project"]})
    assert status == 200 and done["ok"], done
    settings = json.loads((repo / ".claude" / "settings.json").read_text())
    assert settings["hooks"] and not settings.get("permissions", {}).get("deny")      # deny rules left out
    assert "<!-- aqt:begin -->" in (repo / "CLAUDE.md").read_text()
    assert not (repo / ".aqt" / "change.toml").exists()
    assert any("backup:" in line for line in done["said"])                          # CLAUDE.md was backed up
    rows = {row["id"]: row for row in done["checks"]}
    assert rows["claude.hooks"]["result"] == "ok" and rows["claude.deny"]["result"] == "warn"

    status, listed = get(core, "/api/projects")
    assert status == 200 and [p["root"] for p in listed["projects"]] == [str(repo.resolve())]
    assert core.config.projects and core.changes is not None                       # the core read ui.toml again
    assert listed["can_disconnect"] is False


@pytest.mark.parametrize("path", ["", "relative/dir", "/does/not/exist"])
def test_a_project_folder_must_be_a_full_path_to_a_folder(path):
    status, body = get(core_for(), "/api/projects/preview", path=path)
    assert status == 400 and body["ok"] is False
