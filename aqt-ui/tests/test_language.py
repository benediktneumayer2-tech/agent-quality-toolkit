"""English and German labels: the dictionary is served like the page's own script, every label
the page passes to t() has a German entry, the choice is remembered in localStorage (inside
try/catch) and English is the default."""

import re
from pathlib import Path

from aqt_ui.server import CSP

STATIC = Path(__file__).resolve().parents[1] / "src" / "aqt_ui" / "static"
LITERAL = r'"((?:[^"\\]|\\.)*)"'


def german_keys(source: str, name: str) -> set[str]:
    start = source.index(f"export const {name}")
    end = source.index("};", start)
    return set(re.findall(LITERAL + r":\s*", source[start:end])) | set(re.findall(r"^\s*(\w+):", source[start:end], re.M))


def test_every_label_has_a_german_entry():
    app = (STATIC / "app.js").read_text()
    used = set(re.findall(r"\bt\(" + LITERAL, app))
    used |= {m for name in ("TRUST_NOTE", "CAPA_NOTE") for m in re.findall(name + r" = " + LITERAL, app)}
    assert len(used) > 300
    missing = used - german_keys((STATIC / "i18n.js").read_text(), "DE")
    assert not missing, sorted(missing)


def test_every_needs_you_entry_and_gate_reason_has_german_words():
    from aqt_ui.views.changes import REASONS
    i18n = (STATIC / "i18n.js").read_text()
    overview = (STATIC.parent / "views" / "overview.py").read_text()
    keys = set(re.findall(r'key="(\w+)"', overview)) | set(re.findall(r'code="(\w+)"', overview))
    keys |= {"case_held", "case_warned", "qualification_expired", "qualification_expiring",
             "qualification_triggered"}                                   # built with f-strings
    missing = keys - german_keys(i18n, "NEEDS")
    assert not missing, sorted(missing)
    assert set(REASONS) <= german_keys(i18n, "REASONS_DE")


def test_english_is_the_default_and_the_choice_is_remembered_safely():
    app = (STATIC / "app.js").read_text()
    assert 'let LANG = "en";' in app
    uses = [m.start() for m in re.finditer(r"localStorage\.", app)]
    assert len(uses) >= 2
    for position in uses:      # every access sits in a try block on the same line
        line = app[app.rindex("\n", 0, position) + 1:app.index("\n", position)]
        assert "try {" in line and "catch" in line, line
    assert '<select class="lang" id="lang"' in (STATIC / "index.html").read_text()


def test_the_dictionary_is_served_as_a_script_of_the_page(trail, ui_factory):
    client = ui_factory()
    client.login()
    status, body, response = client.get("/static/i18n.js")
    assert status == 200 and b"export const DE" in body
    assert response.getheader("Content-Type").startswith("text/javascript")
    assert response.getheader("Content-Security-Policy") == CSP
