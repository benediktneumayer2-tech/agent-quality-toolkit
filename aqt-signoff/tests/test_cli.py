import json
import sys

import pytest

import aqt_signoff.core
import aqt_signoff.registry
from aqt_signoff.cli import main

from conftest import PASSWORDS


@pytest.fixture
def cli(isolated, monkeypatch, capsys):
    sink = isolated / "evidence.jsonl"

    def remembering(prompt=""):
        for signer, pw in PASSWORDS.items():
            if signer in prompt:
                remembering.last = pw
                return pw
        return remembering.last          # "Repeat the passphrase"

    remembering.last = ""
    monkeypatch.setattr(aqt_signoff.registry.getpass, "getpass", remembering)
    monkeypatch.setattr(aqt_signoff.core, "require_human", lambda **kwargs: None)
    monkeypatch.setenv("AQT_ACTOR", "agent:test:s1")

    def run(*argv, expect=0):
        code = main(["--sink", f"file:{sink}", "--json", *argv])
        out = capsys.readouterr().out
        assert code == expect, out
        return json.loads(out) if out.strip().startswith(("{", "[")) else out

    run.sink = sink
    return run


def test_cli_end_to_end(cli, isolated):
    cli("init", "--id", "human:alice", "--name", "Alice Example", "--role", "quality-manager")
    cli("init", "--id", "human:bob", "--name", "Bob Example", "--role", "developer")
    signers = cli("signers", "list")
    assert [s["id"] for s in signers["signers"]] == ["human:alice", "human:bob"]

    doc = isolated / "report.md"
    doc.write_text("# Report\n")
    signed = cli("sign", "report.md", "--meaning", "approved", "--reason", "fine", "--signer", "human:alice")
    assert signed["type"] == "signoff.signature"
    report = cli("verify", "report.md", "--require", "approved")
    assert report["ok"] and report["signatures"][0]["status"] == "valid"
    cli("verify", "report.md", "--require", "released", expect=1)
    md = cli("manifest", "report.md")
    assert "Alice Example" in md and "approved" in md
    doc.write_text("# Report\nchanged\n")
    report = cli("verify", "report.md", expect=1)
    assert report["signatures"][0]["status"] == "invalidated" and len(report["recorded"]) == 1
    out = isolated / "sig.html"
    cli("manifest", "report.md", "--format", "html", "--out", str(out))
    assert "invalidated" in out.read_text()

    marker = isolated / "ran.txt"
    view = cli("prepare", "--request-key", "k1", "--description", "touch", "--", sys.executable, "-c",
               f"open({str(marker)!r}, 'a').write('x')")
    assert view["preparer"]["id"] == "agent:test:s1"
    cli("approve", view["id"], "--hash", "sha256:" + "1" * 64, "--reason", "x", "--signer", "human:alice", expect=1)
    approved = cli("approve", view["id"], "--hash", view["action_sha256"], "--reason", "reviewed",
                   "--signer", "human:alice", "--valid-for", "1h")
    assert approved["status"] == "approved"
    result = cli("run", view["id"])
    assert result["data"]["outcome"] == "succeeded" and marker.read_text() == "x"
    refused = cli("run", view["id"], expect=1)
    assert refused["code"] == "already_claimed"
    assert cli("status", view["id"])["status"] == "succeeded"
    assert len(cli("list")) == 1

    http = cli("prepare", "--kind", "http", "--request-key", "up", "--method", "PUT", "--url",
               "https://example.invalid/x")
    cli("approve", http["id"], "--hash", http["action_sha256"], "--reason", "ok", "--signer", "human:bob")
    claim = cli("claim", http["id"], "--hash", http["action_sha256"])
    result = cli("outcome", http["id"], "--claim", claim["claim_id"], "--status", "unknown", expect=1)
    assert result["data"]["outcome"] == "unknown"
    resolved = cli("resolve", http["id"], "--as", "succeeded", "--reason", "server shows the file",
                   "--signer", "human:bob")
    assert resolved["status"] == "succeeded"
    assert cli("sync")["delivered"] == []
    from aqt_evidence.cli import main as evidence_main
    assert evidence_main(["conform", str(cli.sink), "--level", "1"]) == 0


def test_cli_refuses_in_agent_session(isolated, monkeypatch, capsys):
    monkeypatch.setenv("CLAUDECODE", "1")
    code = main(["--sink", f"file:{isolated / 'e.jsonl'}", "init", "--id", "human:alice", "--name", "A",
                 "--role", "qm"])
    assert code == 1
    assert "agent session" in capsys.readouterr().err
    record = json.loads((isolated / "e.jsonl").read_text().splitlines()[-1])
    assert record["type"] == "signoff.refused" and record["data"]["reason_code"] == "agent_context"


def test_cli_usage_errors_exit_2(isolated, capsys):
    assert main(["--sink", f"file:{isolated / 'e.jsonl'}", "verify", "missing.md"]) == 2
    assert main(["--sink", f"file:{isolated / 'e.jsonl'}", "sign", "--hash", "nothex", "--meaning", "approved",
                 "--reason", "x"]) == 2


def test_global_options_before_or_after_the_subcommand(cli, isolated, capsys):
    cli("init", "--id", "human:alice", "--name", "Alice Example", "--role", "quality-manager")
    before = main(["--json", "--sink", f"file:{cli.sink}", "signers", "list"])
    listed_before = json.loads(capsys.readouterr().out)
    after = main(["signers", "list", "--json", "--sink", f"file:{cli.sink}"])
    listed_after = json.loads(capsys.readouterr().out)
    assert before == after == 0 and listed_before == listed_after
    assert [s["id"] for s in listed_after["signers"]] == ["human:alice"]
    # a value given before the subcommand is not reset by the subcommand's defaults
    other = isolated / "other-signers.json"
    assert main(["--registry", str(other), "signers", "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["signers"] == []
