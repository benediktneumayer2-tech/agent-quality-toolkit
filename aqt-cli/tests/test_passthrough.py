import json
import os
import subprocess
import sys

import pytest

from aqt_cli import __version__, tools
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
    if os.name == "nt":            # a batch file stands in for the console script
        script = tmp_path / "bin" / "aqt-fake.cmd"
        script.parent.mkdir()
        script.write_text(f'@echo %* > "{tmp_path / "args"}"\r\n@exit /b 3\r\n')
        monkeypatch.setenv("PATH", f"{script.parent};{os.environ['SystemRoot']}\\System32")
    else:
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
    assert capsys.readouterr().out.strip() == f"agent-quality-toolkit {__version__} (commands aqt and aqt-toolkit)"
    assert main([]) == 2
    assert main(["status", "--bogus"]) == 2


def test_egress_is_optional_and_says_what_it_needs(monkeypatch, capsys):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setitem(tools.TOOLS, "egress", ("aqt_not_importable.cli", "aqt-not-installed", "aqt-egress"))
    assert main(["egress", "report"]) == 2
    err = capsys.readouterr().err
    assert "aqt-egress is not installed" in err and "-e ./aqt-egress" in err and "Python 3.12" in err


def test_the_second_name_aqt_toolkit_names_itself(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["/somewhere/bin/aqt-toolkit"])
    assert main(["status", "--bogus"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("usage: aqt-toolkit [-h]") and "aqt-toolkit: error:" in err


@pytest.mark.parametrize("route, missing, egress_installed, expected", [
    ("uv-tool", ["aqt-egress"], False, 'uv tool install "agent-quality-toolkit[egress]"'),
    ("uv-tool", ["aqt-capa"], False, "uv tool install agent-quality-toolkit"),
    ("uv-tool", ["aqt-capa"], True, 'uv tool install "agent-quality-toolkit[egress]"'),  # keeps it
    ("pipx", ["aqt-egress"], False, 'pipx install --force "agent-quality-toolkit[egress]"'),
    ("pip", ["aqt-capa", "aqt-ui"], False, "pip install aqt-capa aqt-ui"),
    ("clone", ["aqt-capa"], False, "uv pip install -e ./aqt-capa   (in the repository clone)"),
])
def test_the_install_command_fits_how_the_toolkit_was_installed(monkeypatch, route, missing, egress_installed,
                                                                 expected):
    monkeypatch.setattr(tools, "install_route", lambda: route)
    monkeypatch.setattr(tools, "_installed", lambda dist: egress_installed and dist == "aqt-egress")
    monkeypatch.setattr("sys.version_info", (3, 12, 0))
    assert tools.install_command(*missing).split("   (aqt-egress needs")[0] == expected


def test_egress_on_python_3_11_asks_uv_for_python_3_12(monkeypatch):
    monkeypatch.setattr(tools, "install_route", lambda: "uv-tool")
    monkeypatch.setattr("sys.version_info", (3, 11, 9))
    assert tools.install_command("aqt-egress") == ('uv tool install --python 3.12 '
                                                   '"agent-quality-toolkit[egress]"   (aqt-egress needs Python 3.12 '
                                                   'or newer, bubblewrap)')


def test_the_route_is_read_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.prefix", str(tmp_path))
    (tmp_path / "pipx_metadata.json").write_text("{}")
    assert tools.install_route() == "pipx"
    (tmp_path / "uv-receipt.toml").write_text("[tool]\n")
    assert tools.install_route() == "uv-tool"


def test_the_toolkit_declares_every_tool_command_as_its_package_does():
    """uv tool / pipx link only the toolkit's own scripts; the hooks call aqt-trail etc. by name."""
    from importlib import metadata
    scripts = lambda dist: {ep.name: ep.value for ep in metadata.distribution(dist).entry_points
                            if ep.group == "console_scripts"}
    own = scripts("agent-quality-toolkit")
    assert own.pop("aqt") == own.pop("aqt-toolkit") == "aqt_cli.cli:main"
    expected = {}
    for _module, script, dist in tools.TOOLS.values():
        if dist != "aqt-egress":        # its script cannot depend on the [egress] extra
            expected[script] = scripts(dist)[script]
    assert own == expected and len(own) == 9


def test_aqt_core_speaks_json_lines_on_stdio_and_ends_with_its_input():
    secret = "read-only-passphrase-9"
    requests = [{"id": "s", "method": "GET", "path": "/api/session", "body": None},
                {"id": "d", "method": "POST", "path": "/api/capa/candidates/C1/accept", "body": {"passphrase": secret}}]
    done = subprocess.run([sys.executable, "-m", "aqt_cli.cli", "core", "--stdio", "--read-only"], capture_output=True,
                          input=b"".join(json.dumps(r).encode() + b"\n" for r in requests), timeout=60)
    assert done.returncode == 0, done.stderr.decode()
    lines = [json.loads(line) for line in done.stdout.splitlines()]
    assert lines[0]["event"] == "ready" and lines[0]["body"]["protocol"] == 1
    answers = {line["id"]: line for line in lines[1:]}
    assert len(lines) == 3 and answers["s"]["status"] == 200 and answers["s"]["body"]["version"] == __version__
    assert answers["d"]["status"] == 403 and "--read-only" in answers["d"]["body"]["message"]
    assert secret.encode() not in done.stdout + done.stderr


def test_aqt_core_needs_stdio(capsys):
    assert main(["core"]) == 2
    assert "--stdio" in capsys.readouterr().err
