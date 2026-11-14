"""Navigation by tasks: the areas, the first-run setup and the old addresses are the page shell; the overview
says whether the setup is needed; the page keeps no passphrase. The setup routes themselves need aqt-cli and
are tested there (aqt-cli/tests/test_core_setup.py)."""

import importlib.util
import re
from pathlib import Path

import pytest

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
