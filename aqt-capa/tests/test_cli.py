"""CLI: exit codes, JSON output, the shared human check wired in, file sink from AQT_SINK."""

from __future__ import annotations

import json

import pytest
from aqt_evidence import AgentContext, HumanCheckError, read_jsonl

import aqt_capa.capa as capa_module
from aqt_capa.cli import main
from conftest import append_all, synthetic_evidence


@pytest.fixture
def cli(tmp_path, monkeypatch, capsys):
    root = tmp_path / "project"
    root.mkdir()
    (root / "AGENTS.md").write_text("rules\n")
    sink = tmp_path / "evidence.jsonl"
    other = tmp_path / "other.jsonl"
    append_all(other, synthetic_evidence())
    cfg = tmp_path / "capa.toml"
    cfg.write_text(f'[identity]\nid = "human:qa-lead"\n[project]\nroot = "{root}"\n'
                   f'[evidence]\npaths = ["{other}", "{sink}"]\n[approval]\nallow_self_approval = true\n')
    monkeypatch.setenv("AQT_SINK", f"file:{sink}")
    state = {"agent": False}

    def context():
        return AgentContext(True, "codex", ["env:CODEX_THREAD_ID"]) if state["agent"] else AgentContext(False)

    def guard():
        if state["agent"]:
            raise HumanCheckError(context(), "refused: agent session")
        return context()

    monkeypatch.setattr(capa_module, "detect_agent_context", context)
    monkeypatch.setattr(capa_module, "default_guard", guard)

    def run(*argv):
        code = main(["--config", str(cfg), "--db", str(tmp_path / "capa.db"), *argv])
        out = capsys.readouterr()
        return code, out.out, out.err

    run.state, run.root, run.sink = state, root, sink
    return run


def test_cli_flow_and_exit_codes(cli):
    code, out, _ = cli("--json", "scan")
    assert code == 0
    cands = json.loads(out)
    receipt = next(c for c in cands if c["rule"] == "receipt-failed")
    assert cli("candidate", "accept", receipt["candidate_id"], "--reason", "real failure",
               "--category", "instructions")[0] == 0
    assert cli("candidate", "accept", "C-00000000", "--reason", "x")[0] == 2  # unknown -> usage/runtime
    assert cli("investigate", "DEV-0001", "--why", "a", "--why", "b", "--factor", "method:rule missing",
               "--root-cause", "missing rule", "--root-category", "instructions")[0] == 0
    assert cli("action", "plan", "DEV-0001", "--kind", "corrective", "--target", "AGENTS.md",
               "--description", "add rule", "--window-sessions", "1")[0] == 0
    (cli.root / "AGENTS.md").write_text("rules\n- new\n")
    code, out, _ = cli("action", "implement", "CAPA-0001-1")
    assert code == 0 and "aqt-signoff sign --record" in out

    cli.state["agent"] = True
    code, _, err = cli("action", "approve", "CAPA-0001-1", "--reason", "ok")
    assert code == 1 and "refusal recorded" in err
    cli.state["agent"] = False
    assert cli("action", "approve", "CAPA-0001-1", "--reason", "ok")[0] == 0
    assert cli("action", "verify")[0] == 0
    assert cli("effectiveness", "--check")[0] == 1  # pending: no sessions yet
    assert cli("close", "DEV-0001", "--reason", "x")[0] == 1
    (cli.root / "AGENTS.md").write_text("tampered\n")
    assert cli("action", "verify", "CAPA-0001-1")[0] == 1
    (cli.root / "AGENTS.md").write_text("rules\n- new\n")

    code, out, _ = cli("show", "DEV-0001")
    assert code == 0 and "## Timeline" in out and "CAPA-0001-1" in out
    code, out, _ = cli("--json", "list", "--open")
    assert code == 0 and json.loads(out)[0]["dev_id"] == "DEV-0001"
    code, out, _ = cli("trends", "--since", "30d")
    assert code == 0 and "# CAPA trend review" in out
    code, out, _ = cli("trends", "--format", "json")
    assert json.loads(out)["deviations_in_range"] == 1
    code, out, _ = cli("--json", "rebuild")
    assert code == 0 and json.loads(out)["replayed"] >= 5

    types = {r["type"] for r in read_jsonl(cli.sink)}
    assert {"capa.deviation", "capa.investigation", "capa.action", "capa.refused", "capa.effectiveness"} <= types


def test_cli_usage_errors(cli):
    assert cli("deviation", "new", "--title", "x")[0] == 2  # missing --severity
    assert cli("show", "DEV-0099")[0] == 2
    assert cli("effectiveness", "--extend", "CAPA-0001-1")[0] == 2  # needs --reason


def test_global_options_before_or_after_the_subcommand(cli, tmp_path):
    code, found, _ = cli("scan", "--json")
    assert code == 0 and json.loads(found)
    code, before, _ = cli("--json", "candidate", "list")
    code_after, after, _ = cli("candidate", "list", "--json")
    assert code == code_after == 0 and json.loads(before) == json.loads(after) and json.loads(after)
    # --db given after the subcommand wins; one given before is not reset by the subcommand's defaults
    other = tmp_path / "other.db"
    assert main(["--config", str(tmp_path / "capa.toml"), "list", "--db", str(other), "--json"]) == 0
    third = tmp_path / "third.db"
    assert main(["--config", str(tmp_path / "capa.toml"), "--db", str(third), "list", "--json"]) == 0
    assert other.exists() and third.exists()
