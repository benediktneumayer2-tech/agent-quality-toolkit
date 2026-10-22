"""End to end through the CLI: init → serve → hook/import → anchor → review → verify → alcoa → export."""

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from aqt_evidence import generate_key

from aqt_trail import cli
from aqt_trail.state import read_records


def run(*argv, stdin=None, monkeypatch=None):
    return cli.main(list(argv))


@pytest.fixture
def running(env, tmp_path):
    assert cli.main(["init", "--log-id", "trail_cli"]) == 0
    process = subprocess.Popen([sys.executable, "-m", "aqt_trail.cli", "serve"], env=os.environ.copy(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    from aqt_trail.config import load_config
    config = load_config()
    for _ in range(100):
        if config.socket_path.exists():
            break
        time.sleep(0.05)
    else:
        process.kill()
        pytest.fail(process.stderr.read().decode())
    yield config, process
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=10)


def test_end_to_end(running, fixtures, local_fixture, tmp_path, monkeypatch, capsys):
    config, process = running
    # hook event from stdin
    with monkeypatch.context() as patch:  # never monkeypatch.undo(): it would drop the isolated XDG dirs
        patch.setattr(sys, "stdin", type("S", (), {"buffer": open(fixtures / "claude-hook-posttooluse.json", "rb")})())
        assert cli.main(["hook", "claude-code"]) == 0
    # session import is idempotent
    session = local_fixture("claude-session.jsonl")
    assert cli.main(["import", "claude-code", str(session)]) == 0
    assert cli.main(["--json", "import", "claude-code", str(session)]) == 0
    out = capsys.readouterr().out
    assert json.loads(out.strip().splitlines()[-1])[0]["new"] == 0
    assert cli.main(["event", "--action", "release.decided", "--actor", "human:owner", "--reason", "go"]) == 0
    assert cli.main(["checkpoint", "--anchor", "--tsa", "test:"]) == 0
    heads = tmp_path / "heads.jsonl"
    capsys.readouterr()
    assert cli.main(["head", "--export"]) == 0
    heads.write_text(capsys.readouterr().out)
    assert cli.main(["verify", "--test-tsa", "--heads", str(heads)]) == 0
    assert "intact" in capsys.readouterr().out

    # review: run, then sign as an independent human (agent check and passphrase prompt faked)
    assert cli.main(["--json", "review", "run"]) == 0
    sheet = json.loads(capsys.readouterr().out)["worksheet"]
    key = tmp_path / "reviewer.key"
    generate_key(key, passphrase=b"correct horse")
    monkeypatch.setattr(cli, "require_human", lambda: None)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "correct horse")
    assert cli.main(["review", "sign", sheet, "--reviewer", "human:dora", "--key", str(key),
                     "--disposition", "all=ok", "--reason", "weekly review"]) == 0
    # the owner acted in scope, so they may not sign
    assert cli.main(["review", "sign", sheet, "--reviewer", "human:owner", "--key", str(key),
                     "--disposition", "all=ok", "--reason", "self review"]) == 1
    capsys.readouterr()
    assert cli.main(["--json", "review", "list"]) == 0
    reviews = json.loads(capsys.readouterr().out)
    assert len(reviews) == 1 and reviews[0]["reviewer"] == "human:dora"

    assert cli.main(["alcoa", "--format", "md"]) in (0, 1)
    assert "alcoa:attributable" in capsys.readouterr().out
    assert cli.main(["export", "--out", str(tmp_path / "bundle")]) == 0
    assert cli.main(["verify", "--bundle", str(tmp_path / "bundle")]) == 0
    assert cli.main(["report", "--format", "html", "--out", str(tmp_path / "r.html")]) == 0

    process.send_signal(signal.SIGTERM)
    process.wait(timeout=10)
    records = read_records(config.trail_path)
    types = [r["type"] for r in records]
    assert records[0]["action"] == "service.start" and records[-1]["action"] == "service.stop"
    assert "trail.review" in types and "trail.anchor" in types and types.count("trail.import") > 5
    # The shared conformance checker (aqt-spec) accepts the log at level 3: valid payloads, chained,
    # signed by the pinned service key and matched by a checkpoint kept outside the writer.
    from aqt_evidence.cli import main as evidence_main
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(heads.read_text().splitlines()[0])
    assert evidence_main(["conform", str(config.trail_path), "--level", "3", "--key",
                          str(config.state / "keys" / "service.key.pub"), "--checkpoint", str(checkpoint)]) == 0, \
        capsys.readouterr().out
    refusals = [r for r in records if r["type"] == "trail.refused"]
    assert refusals and refusals[-1]["data"]["reason_code"] == "not_independent"
    assert all(r["observed"].get("via") == "socket" or r["observed"].get("origin") == "writer" for r in records)


def test_review_sign_refused_inside_agent_session(env, monkeypatch, capsys, tmp_path):
    assert cli.main(["init"]) == 0
    sheet = tmp_path / "sheet.json"
    sheet.write_text("{}")
    monkeypatch.setenv("CLAUDECODE", "1")
    assert cli.main(["review", "sign", str(sheet), "--reviewer", "human:dora", "--reason", "x"]) == 1
    assert "agent session" in capsys.readouterr().err
    from aqt_trail.client import locked_spool
    with locked_spool() as (entries, _):
        assert entries[-1]["type"] == "trail.refused" and entries[-1]["data"]["reason_code"] == "agent_context"


def test_hook_never_fails_the_agent(env, monkeypatch):
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": type("B", (), {"read": lambda self: b"garbage"})()})())
    assert cli.main(["hook", "claude-code"]) == 0


def test_usage_errors_exit_2(env):
    assert cli.main(["verify"]) in (1, 2)
    assert cli.main(["show", "rec_missing"]) == 2
