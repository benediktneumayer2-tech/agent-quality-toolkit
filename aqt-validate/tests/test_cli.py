"""End-to-end through the command line (and the offline demo)."""
import importlib.util
import json
from pathlib import Path

from aqt_evidence import validate_record
from aqt_validate.cli import main
from conftest import attack_items, benign_items, detector_project, read_records, write_jsonl

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_data_commands(aqt_env, capsys):
    hosts = write_jsonl(aqt_env.tmp / "hosts.jsonl", benign_items(20, 4, 0))
    attacks = write_jsonl(aqt_env.tmp / "attacks.jsonl", attack_items(5, 1))
    assert main(["data", "import", str(attacks), "--format", "generic", "--out", str(aqt_env.tmp / "g.jsonl")]) == 0
    assert main(["data", "compose", "--hosts", str(hosts), "--attacks", str(attacks),
                 "--out", str(aqt_env.tmp / "c.jsonl")]) == 0
    capsys.readouterr()
    assert main(["data", "stats", str(aqt_env.tmp / "c.jsonl"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["by_label"] == {"attack": 5}
    assert main(["data", "stats", str(aqt_env.tmp / "missing.jsonl")]) == 2


def test_protocol_and_detector_flow(aqt_env, capsys):
    protocol = detector_project(aqt_env.tmp / "p")
    assert main(["protocol", "init", "--kind", "reviewer", "--out", str(aqt_env.tmp / "r.toml")]) == 0
    assert "[reviewer]" in (aqt_env.tmp / "r.toml").read_text()
    assert main(["detector", "run", str(protocol)]) == 2  # not locked
    assert "locked protocol" in capsys.readouterr().err
    assert main(["protocol", "lock", str(protocol), "--reason", "agreed", "--json"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert main(["protocol", "lock", str(protocol), "--reason", "again", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["already_locked"] is True
    assert main(["detector", "run", str(protocol), "--json", "--out", str(aqt_env.tmp / "run")]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["conclusion"] == "meets"
    assert main(["report", str(aqt_env.tmp / "run")]) == 0
    assert "Validation report" in capsys.readouterr().out
    # check before qualification: not qualified
    assert main(["check", "--protocol", str(protocol)]) == 1
    # qualification from a non-interactive (or agent) context is refused and recorded
    assert main(["qualify", str(aqt_env.tmp / "run"), "--approve", "--reason", "looks fine"]) == 2
    assert "refused" in capsys.readouterr().err
    recs = read_records(aqt_env.sink)
    assert recs[-1]["type"] == "validate.refused"
    assert all(validate_record(r) == [] for r in recs)
    ids = {r["id"] for r in recs}
    assert all(link["ref"] in ids for r in recs for link in r.get("links", []))
    assert first["record"] in ids
    assert main(["check", "--protocol", str(protocol), "--observed-fp", "5/2"]) == 2


def test_plugins_listing(aqt_env, capsys):
    assert main(["detector", "plugins", "--json"]) == 0
    assert isinstance(json.loads(capsys.readouterr().out)["plugins"], list)


def test_demo_runs_offline(aqt_env, monkeypatch):
    monkeypatch.setenv("AQT_VALIDATE_STATE", str(aqt_env.tmp / "demo-state"))
    spec = importlib.util.spec_from_file_location("aqt_validate_demo", EXAMPLES / "demo.py")
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    assert demo.main(str(aqt_env.tmp / "demo")) == 0
    recs = read_records(aqt_env.tmp / "demo" / "evidence.jsonl")
    types = {r["type"] for r in recs}
    assert {"validate.run", "validate.report", "validate.qualification", "validate.requalification"} <= types
    assert all(validate_record(r) == [] for r in recs)
