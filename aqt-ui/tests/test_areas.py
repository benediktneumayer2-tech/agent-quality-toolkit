"""Navigation by tasks: the areas, the first-run setup and the old addresses are the page shell; the overview
says whether the setup is needed; the page keeps no passphrase. The setup routes themselves need aqt-cli and
are tested there (aqt-cli/tests/test_core_setup.py)."""

import importlib.util
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import PASSPHRASE, SIGNER, trail_records

STATIC = Path(__file__).resolve().parents[1] / "src" / "aqt_ui" / "static"
OLD = ("/health", "/trail", "/quarantine", "/signatures", "/capa", "/qualifications")


def test_areas_setup_and_old_addresses_are_the_page_shell(env, ui_factory):
    client = ui_factory()
    for page in ("/", "/changes", "/projects", "/evidence", "/evidence/trail", "/evidence/signatures",
                 "/evidence/quarantine", "/evidence/capa", "/evidence/qualifications", "/evidence/export",
                 "/settings", "/welcome", *OLD):
        status, raw, _ = client.get(page, key=False)
        assert status == 200 and b'<script type="module" src="/static/app.js">' in raw, page
    for page in ("/evidence/nothing", "/evidence/trail/x", "/setup", "/projects/x"):
        assert client.get(page, key=False)[0] == 404, page


def test_the_page_sends_every_old_view_to_its_new_place():
    app = (STATIC / "app.js").read_text()
    moved = app[app.index("const MOVED = {"):app.index("};", app.index("const MOVED = {"))]
    for old in OLD:
        assert re.search(rf'"{old}": "/(settings|evidence/\w+)"', moved), old
    assert 'history.replaceState(null, "", moved + location.search + location.hash)' in app


def test_the_passphrase_stays_in_page_memory_only():
    app = (STATIC / "app.js").read_text()
    writes = re.findall(r"(?:local|session)Storage\.setItem\(([^,]+),", app)
    assert sorted(writes) == ['"aqt-ui-key"', '"aqt-ui-lang"'], writes
    assert "pendingPass = \"\"" in app                 # dropped once the signing key is made


def test_the_overview_says_whether_setup_is_needed(trail, signer, ui_factory):
    client = ui_factory()
    client.login()
    status, data, _ = client.get("/api/overview")
    assert status == 200 and data["setup"] == {"needed": False, "trail": True, "signer": True, "signers": [signer]}


@pytest.mark.skipif(importlib.util.find_spec("aqt_cli") is not None, reason="aqt-cli is installed here")
def test_without_aqt_cli_the_setup_routes_say_how_to_install_it(env, ui_factory):
    client = ui_factory()
    client.login()
    status, data, _ = client.get("/api/setup")
    assert status == 501 and data["ok"] is False and "agent-quality-toolkit" in data["message"]
    status, data, _ = client.post("/api/setup/apply", {"check": "trail.init"})
    assert status == 501


def test_every_plural_and_either_or_label_has_german():
    """tn(n, one, many) and t(x ? a : b) pass literals the label test above cannot see."""
    app = (STATIC / "app.js").read_text()
    literal = r'"((?:[^"\\]|\\.)*)"'
    used = set()
    for one, many in re.findall(r"\btn\([^,()]*(?:\([^()]*\))?[^,()]*,\s*" + literal + r",\s*" + literal, app):
        used |= {one, many}
    for a, b in re.findall(r"\bt\([^\"()]*\?\s*" + literal + r"\s*:\s*" + literal, app):
        used |= {a, b}
    assert len(used) > 10
    i18n = (STATIC / "i18n.js").read_text()
    start = i18n.index("export const DE")
    keys = set(re.findall(literal + r":\s*", i18n[start:i18n.index("\n};", start)]))
    assert not used - keys, sorted(used - keys)


# -- in-app fixes on the case pages: an external time stamp, keeping the review values, an unknown outcome -----------
def test_add_a_time_stamp_from_the_page(trail, signer, ui_factory, env):
    from aqt_ui.guard import Mode
    client = ui_factory()
    client.login()
    status, data, _ = client.post("/api/trail/anchor", {})
    assert status == 200 and data == {**data, "ok": False, "reason_code": "no_tsa"}
    (env / "config/aqt").mkdir(parents=True, exist_ok=True)
    (env / "config/aqt/trail.toml").write_text('[anchor]\ntsa_url = "test:"\ntest_tsa = true\n')
    for refusing in (ui_factory(mode=Mode(False, "started with --read-only", explicit=True)),
                     ui_factory(peer=["python3", "claude", "systemd"])):
        refusing.login()
        assert refusing.post("/api/trail/anchor", {})[0] == 403
    assert not [r for r in trail_records(trail) if r["type"] == "trail.anchor"]
    client = ui_factory()
    client.login()
    assert client.get("/api/trail/status")[1]["status"]["time_stamps"] is True
    status, data, _ = client.post("/api/trail/anchor", {})
    assert status == 200 and data["ok"] and data["record_id"], data
    assert any(r["id"] == data["record_id"] and r["type"] == "trail.anchor" for r in trail_records(trail))
    assert "unanchored" not in {n["code"] for n in client.get("/api/overview")[1]["needs"]}


def test_keeping_the_review_values_closes_the_case_until_they_change(trail, signer, ui_factory, env):
    (env / "config/aqt").mkdir(parents=True, exist_ok=True)
    toml = env / "config/aqt/trail.toml"
    toml.write_text("[review]\nrepeated_failures = 100000\n")
    client = ui_factory()
    client.login()
    differs = client.get("/api/trail/status")[1]["status"]["review_profile"]["differs_from_builtin"]
    assert "review_params" in {n["code"] for n in client.get("/api/overview")[1]["needs"]}
    stale = {key: {**value, "value": 5} for key, value in differs.items()}
    assert client.post("/api/trail/review-params/keep", {"params": stale})[0] == 409
    status, data, _ = client.post("/api/trail/review-params/keep", {"params": differs})
    assert status == 200 and data["ok"] and data["kept"] == ["repeated_failures"]
    assert "review_params" not in {n["code"] for n in client.get("/api/overview")[1]["needs"]}
    toml.write_text("[review]\nrepeated_failures = 99\n")
    client = ui_factory()
    client.login()
    assert "review_params" in {n["code"] for n in client.get("/api/overview")[1]["needs"]}


def test_record_the_outcome_of_an_action_that_ran_unseen(trail, signer, ui_factory):
    from aqt_evidence import actor
    from aqt_signoff import Signoff, StaticPassphrase
    agent = actor("agent", "agent:test:worker-1", harness="test", session="worker-1")
    so = Signoff.open(authenticator=StaticPassphrase(PASSPHRASE), environ={}, chain=[], require_tty=False)
    view = so.actions.prepare("other", "rotate", {"text": "rotate the certificate"}, who=agent)
    so.actions.approve(view["id"], view["action_sha256"], "ok", signer_id=SIGNER)
    with pytest.raises(RuntimeError):
        with so.actions.claim(view["id"], view["action_sha256"], who=agent):
            raise RuntimeError("connection reset")
    assert so.actions.show(view["id"])["status"] == "unknown"
    client = ui_factory()
    client.login()
    body = {"outcome": "not-applied", "reason": "Checked: the certificate is unchanged", "passphrase": PASSPHRASE,
            "expected_hash": view["action_sha256"], "signer_id": SIGNER}
    assert client.post(f"/api/changes/actions/{view['id']}/resolve", {**body, "expected_hash": "sha256:" + "1" * 64})[0] == 409
    status, result, raw = client.post(f"/api/changes/actions/{view['id']}/resolve", body)
    assert status == 200 and result["ok"] and result["message_code"] == "ui.changes.action_resolved", result
    assert result["record_id"] in {r["id"] for r in trail_records(trail) if r["type"] == "signoff.action.outcome"}
    assert so.actions.show(view["id"])["status"] == "failed" and PASSPHRASE.encode() not in raw


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
def test_the_page_scripts_parse_as_modules(tmp_path):
    """The browser loads app.js as an ES module; a syntax error there leaves an empty window."""
    for name in ("app.js", "i18n.js", "messages.js", "text.js"):
        copy = tmp_path / (Path(name).stem + ".mjs")
        copy.write_text((STATIC / name).read_text(encoding="utf-8"), encoding="utf-8")
        done = subprocess.run(["node", "--check", str(copy)], capture_output=True, text=True, timeout=60)
        assert done.returncode == 0, f"{name}: {done.stderr}"
