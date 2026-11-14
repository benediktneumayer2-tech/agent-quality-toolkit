"""The desktop app's machines on the page (static/machines.js): every label has German words in the module's
own dictionary, the module parses, the page imports it and the web server serves it, and it puts text into
the page as text only."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[1] / "src" / "aqt_ui" / "static"
LITERAL = r'"((?:[^"\\]|\\.)*)"'


def module() -> str:
    return (STATIC / "machines.js").read_text(encoding="utf-8")


def test_every_machine_label_has_german_words():
    source = module()
    used = set(re.findall(r"\bt\(" + LITERAL, source))
    assert len(used) > 30
    start = source.index("export const MACHINE_DE")
    german = set(re.findall(LITERAL + r":\s*", source[start:source.index("\n};", start)]))
    assert not used - german, sorted(used - german)
    assert not german - used, f"words nothing uses: {sorted(german - used)}"


def test_text_goes_into_the_page_as_text():
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", module())


def test_the_page_imports_the_module_and_the_server_serves_it(trail, ui_factory):
    assert 'from "./machines.js"' in (STATIC / "app.js").read_text(encoding="utf-8")
    client = ui_factory()
    client.login()
    status, body, response = client.get("/static/machines.js")
    assert status == 200 and b"export const MACHINE_DE" in body


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
def test_the_module_parses(tmp_path):
    copy = tmp_path / "machines.mjs"
    copy.write_text(module(), encoding="utf-8")
    done = subprocess.run(["node", "--check", str(copy)], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
