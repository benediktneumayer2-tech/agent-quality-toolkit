"""The message catalogue (static/messages.js) covers every message code the packages use.

The packages build coded sentences with ``aqt_evidence.Text(code, template, **args)``; this test finds those
calls in the sources of the monorepo (and the detector reasons, which are plain strings), and checks that each
code has an entry whose English is exactly the package's template, and that every entry has English and
German with the same placeholders."""

from __future__ import annotations

import ast
import json
import re
import string
from pathlib import Path

import pytest

UI = Path(__file__).resolve().parents[1]
CATALOGUE = UI / "src" / "aqt_ui" / "static" / "messages.js"
SOURCES = sorted(UI.parent.glob("aqt-*/src"))
PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def catalogue() -> dict:
    """The ``MESSAGES`` map: a JSON object after ``export const MESSAGES =``, comment lines left out."""
    text = CATALOGUE.read_text(encoding="utf-8")
    body = text.split("export const MESSAGES =", 1)[1].rsplit("};", 1)[0] + "}"
    return json.loads("\n".join(line for line in body.splitlines() if not line.strip().startswith("//")))


def fields(template: str) -> set[str]:
    """Placeholder names of a template; only plain ``{name}`` fields are allowed (no format spec, no conversion)."""
    names = set()
    for _, name, spec, conversion in string.Formatter().parse(template):
        if name is None:
            continue
        assert name.isidentifier() and not spec and not conversion, f"placeholder {{{name}}} in {template!r}"
        names.add(name)
    return names


def package_templates() -> dict[str, str]:
    """``{code: template}`` of every ``Text(code, template, ...)`` call in the packages' sources."""
    found: dict[str, tuple[str, str]] = {}
    for root in SOURCES:
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            for node in ast.walk(tree):
                func = node.func if isinstance(node, ast.Call) else None
                if not (isinstance(func, ast.Name) and func.id == "Text"
                        or isinstance(func, ast.Attribute) and func.attr == "Text"):
                    continue
                where = f"{path.relative_to(UI.parent)}:{node.lineno}"
                code, template = (node.args + [None, None])[:2]
                assert isinstance(code, ast.Constant) and isinstance(code.value, str), f"{where}: code not literal"
                assert isinstance(template, ast.Constant) and isinstance(template.value, str), \
                    f"{where}: template not one string literal"
                keywords = {k.arg for k in node.keywords}
                if None not in keywords:           # no **args: the keywords are exactly the placeholders
                    assert fields(template.value) == keywords, f"{where}: placeholders differ from the arguments"
                previous = found.setdefault(code.value, (template.value, where))
                assert previous[0] == template.value, f"{where}: {code.value} has another template at {previous[1]}"
    return {code: template for code, (template, _) in found.items()}


def detector_templates() -> dict[str, str]:
    """The built-in detectors' span reasons (plain strings: the detectors import nothing heavy)."""
    heuristics = pytest.importorskip("aqt_quarantine.detectors.heuristics")
    onnx = pytest.importorskip("aqt_quarantine.detectors.onnx")
    return {**heuristics.REASON_CODES, "quarantine.detector.model_window": onnx.MODEL_WINDOW}


def test_every_entry_has_english_and_german_with_the_same_placeholders():
    entries = catalogue()
    assert entries
    for code, entry in entries.items():
        assert re.fullmatch(r"[a-z]+(\.[a-z0-9_-]+)+", code), code
        assert set(entry) == {"en", "de"}, code
        assert all(isinstance(entry[k], str) and entry[k].strip() for k in ("en", "de")), code
        assert fields(entry["en"]) == fields(entry["de"]), code
        assert set(PLACEHOLDER.findall(entry["en"])) == fields(entry["en"]), code


def test_every_package_code_has_its_english_template_in_the_catalogue():
    if len(SOURCES) < 2:
        pytest.skip("not in the monorepo: the other packages' sources are not here")
    templates = {**package_templates(), **detector_templates()}
    assert len(templates) > 200
    entries = catalogue()
    missing = sorted(code for code in templates if code not in entries)
    assert not missing, f"codes without a catalogue entry: {missing}"
    differ = sorted(code for code, template in templates.items() if entries[code]["en"] != template)
    assert not differ, f"catalogue English differs from the package template: {differ}"
