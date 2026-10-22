"""Regression: the detector that actually runs (plug-in version, command script) is what gets qualified."""
import json
import shutil
import sys

import pytest

from aqt_evidence import JsonlSink
from aqt_validate import adapters, evidence
from aqt_validate.cli import main
from aqt_validate.config import records
from aqt_validate.decisions import check, qualify
from aqt_validate.detector import run_detector
from aqt_validate.protocol import ProtocolError, configuration_hash, load_protocol
from conftest import FIXTURES, HUMAN, detector_project, write_jsonl, benign_items

ACTOR = {"kind": "human", "id": "human:tester"}
COMMAND = f'command = ["{sys.executable}", "{FIXTURES / "stub_detector.py"}"]'


class Result:
    def __init__(self, score_ppm):
        self.score_ppm, self.spans = score_ppm, []


class VersionedDetector:
    name = "versioned"
    version = "1.0+patterns.aaaa"

    def score(self, text):
        return Result(900_000 if "ignore previous" in text.lower() else len(text) % 1000)


@pytest.fixture
def plugin(monkeypatch):
    class EntryPoint:
        name = "versioned"

        def load(self):
            return VersionedDetector

    monkeypatch.setattr(adapters.metadata, "entry_points",
                        lambda group: [EntryPoint()] if group == "aqt.detectors" else [])
    monkeypatch.setattr(VersionedDetector, "version", "1.0+patterns.aaaa")
    return VersionedDetector


def plugin_protocol(root, pinned=None):
    path = detector_project(root)
    spec = 'id = "versioned"\nplugin = "versioned"'
    text = path.read_text().replace('id = "marker"\nversion = "1.0"\n' + COMMAND, spec)
    if pinned:
        text = text.replace(spec, spec + f'\nversion = "{pinned}"')
    path.write_text(text)
    return load_protocol(path)


def test_plugin_version_is_qualified_and_change_triggers_requalification(aqt_env, plugin):
    protocol = plugin_protocol(aqt_env.tmp / "p")
    sink = JsonlSink(aqt_env.sink)
    evidence.emit(sink, evidence.RUN, ACTOR, "protocol-locked", reason="t",
                  data={"kind": "detector", "protocol": protocol.ref})
    result = run_detector(protocol, split="test", state_dir=aqt_env.state, sink=sink, records=records({}), actor=ACTOR)
    thresholds = json.loads((result.run_dir / "thresholds.json").read_text())
    assert thresholds["detectors"][0]["version"] == "1.0+patterns.aaaa"
    assert "1.0+patterns.aaaa" in (result.run_dir / "report.md").read_text()
    qualify(result.run_dir, decision="approve", reason="ok", sink=sink, records=records({}), human=ACTOR,
            claimed_actor=ACTOR, **HUMAN)
    assert check(protocol, records=records({}), sink=sink, actor=ACTOR).status == "valid"
    plugin.version = "1.0+patterns.bbbb"  # same protocol file, changed detector
    res = check(protocol, records=records({}), sink=sink, actor=ACTOR)
    assert res.status == "requalify" and res.fired[0]["trigger"] == "configuration-changed"


def test_pinned_version_mismatch_fails_clearly(aqt_env, plugin):
    protocol = plugin_protocol(aqt_env.tmp / "p", pinned="1.0+patterns.aaaa")
    configuration_hash(protocol)  # matches: fine
    plugin.version = "1.0+patterns.bbbb"
    with pytest.raises(ProtocolError, match="pins version '1.0\\+patterns.aaaa'.*reports '1.0\\+patterns.bbbb'"):
        run_detector(protocol, split="dev", state_dir=aqt_env.state, sink=JsonlSink(aqt_env.sink),
                     records=[], actor=ACTOR)
    with pytest.raises(ProtocolError, match="pins version"):
        check(protocol, records=[], sink=JsonlSink(aqt_env.sink), actor=ACTOR)


def test_command_script_change_changes_configuration_hash(aqt_env):
    root = aqt_env.tmp / "p"
    path = detector_project(root)
    shutil.copy(FIXTURES / "stub_detector.py", root / "det.py")
    path.write_text(path.read_text().replace(COMMAND, f'command = ["{sys.executable}", "det.py"]'))
    before = configuration_hash(load_protocol(path))
    assert configuration_hash(load_protocol(path)) == before
    (root / "det.py").write_text((root / "det.py").read_text() + "\n# tuned\n")
    assert configuration_hash(load_protocol(path)) != before


def test_callable_module_change_changes_configuration_hash(aqt_env):
    root = aqt_env.tmp / "p"
    path = detector_project(root)
    (root / "mydet.py").write_text("def score(text):\n    return 0.1\n")
    path.write_text(path.read_text().replace(COMMAND, 'callable = "mydet:score"'))
    before = configuration_hash(load_protocol(path))
    (root / "mydet.py").write_text("def score(text):\n    return 0.2\n")
    assert configuration_hash(load_protocol(path)) != before


def test_json_flag_before_or_after_subcommand(aqt_env, capsys):
    data = write_jsonl(aqt_env.tmp / "b.jsonl", benign_items(5, 1, 0))
    assert main(["--json", "data", "stats", str(data)]) == 0
    assert json.loads(capsys.readouterr().out)["items"] == 5
    assert main(["data", "stats", str(data), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["items"] == 5
    assert main(["data", "stats", str(data)]) == 0
    assert capsys.readouterr().out.startswith("5 items")
