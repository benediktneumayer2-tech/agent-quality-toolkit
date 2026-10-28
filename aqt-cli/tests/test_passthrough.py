import json

from aqt_cli import tools
from aqt_cli.cli import main


def test_tool_runs_in_process_with_the_same_arguments_and_exit_code(capsys):
    assert main(["trail", "--json", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["writer"] == "not running"
    assert main(["trail", "show", "rec_missing"]) == 2          # the tool's own runtime error
    assert main(["trail", "no-such-command"]) == 2              # the tool's own usage error
    assert "invalid choice" in capsys.readouterr().err


def test_spec_and_evidence_both_run_aqt_evidence(capsys):
    assert main(["spec", "vectors"]) == 0
    assert "vectors agree" in capsys.readouterr().out
    assert main(["evidence", "vectors", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["failed"] == []


def test_falls_back_to_the_console_script(tmp_path, monkeypatch):
    script = tmp_path / "bin" / "aqt-fake"
    script.parent.mkdir()
    script.write_text(f'#!/bin/sh\necho "$@" > {tmp_path / "args"}\nexit 3\n')
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{script.parent}:/usr/bin:/bin")
    monkeypatch.setitem(tools.TOOLS, "capa", ("aqt_not_importable.cli", "aqt-fake", "aqt-capa"))
    assert main(["capa", "list", "--json"]) == 3
    assert (tmp_path / "args").read_text().strip() == "list --json"


def test_a_missing_tool_prints_its_install_command(monkeypatch, capsys):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setitem(tools.TOOLS, "capa", ("aqt_not_importable.cli", "aqt-not-installed", "aqt-capa"))
    assert main(["capa", "--help"]) == 2
    assert "aqt-capa is not installed" in capsys.readouterr().err and "-e ./aqt-capa" in tools.install_command("aqt-capa")


def test_own_usage(capsys):
    assert main(["--version"]) == 0
    assert "agent-quality-toolkit" in capsys.readouterr().out
    assert main([]) == 2
    assert main(["status", "--bogus"]) == 2
