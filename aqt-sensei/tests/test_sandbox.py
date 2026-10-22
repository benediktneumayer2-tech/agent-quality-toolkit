"""The bwrap command line, profiles, CLI resolution, the Herdr proxy filter and the shim."""

import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from aqt_sensei.config import Config
from aqt_sensei.launch import prepare
from aqt_sensei.sandbox import (Profile, SandboxError, build_argv, herdr_request_allowed, proxy_connection,
                                resolve_cli, resolve_profile, write_shim)

from conftest import pair_up


def binds(argv, flag):
    return [(argv[i + 1], argv[i + 2]) for i, item in enumerate(argv) if item == flag]


def setenv(argv):
    return {argv[i + 1]: argv[i + 2] for i, item in enumerate(argv) if item == "--setenv"}


@pytest.fixture
def pair(bridge, project):
    return pair_up(bridge, project)


def argv_for(pair, paths, config, **kwargs):
    profile = Profile(**{k: v for k, v in pair["profile"].items()})
    return build_argv(pair, profile, paths=paths, config=config, cli_path="/usr/bin/claude", cli_binds=[],
                      environ={"TERM": "xterm", "SECRET_TOKEN": "s3cret", "ANTHROPIC_API_KEY": "k"},
                      home=Path("/home/tester"), **kwargs)


def test_project_read_only_scratch_writable_state_hidden(pair, paths, config):
    argv = argv_for(pair, paths, config)
    assert (pair["project_root"], pair["project_root"]) in binds(argv, "--ro-bind")
    writable = binds(argv, "--bind")
    assert (pair["scratch_dir"], pair["scratch_dir"]) in writable
    assert all(not source.startswith(str(paths.state / "messages")) for source, _ in writable + binds(argv, "--ro-bind"))
    assert all(str(paths.token_file) != source for source, _ in writable + binds(argv, "--ro-bind"))
    own_runtime = str(paths.pair_runtime(pair["id"]))
    assert (own_runtime, own_runtime) in binds(argv, "--ro-bind")
    assert not any(source == str(paths.runtime) for source, _ in binds(argv, "--ro-bind"))
    # project before scratch, so the scratch folder is writable over the read-only project
    assert argv.index(pair["project_root"]) < argv.index(pair["scratch_dir"])
    assert argv.index("--tmpfs") < argv.index(pair["project_root"])


def test_private_home_and_cleared_environment(pair, paths, config):
    argv = argv_for(pair, paths, config)
    home = str(paths.home("claude"))
    assert (home, home) in binds(argv, "--bind")
    assert "--clearenv" in argv
    env = setenv(argv)
    assert env["CLAUDE_CONFIG_DIR"] == home and env["AQT_AGENT_SESSION"] == "1"
    assert env["AQT_SENSEI_SOCKET"] == str(paths.advisor_socket(pair["id"]))
    assert env["HOME"] == "/home/tester" and env["TERM"] == "xterm"
    assert "SECRET_TOKEN" not in env and "ANTHROPIC_API_KEY" not in env
    allowed = argv_for(pair, paths, Config(env_allow=["ANTHROPIC_API_KEY"]))
    assert setenv(allowed)["ANTHROPIC_API_KEY"] == "k"


def test_network_and_command(pair, paths, config):
    argv = argv_for(pair, paths, config)
    assert "--share-net" in argv and "--unshare-all" in argv and "--die-with-parent" in argv
    command = argv[argv.index("--") + 1:]
    assert command[0] == "/usr/bin/claude"
    assert "--permission-mode" in command and "bypassPermissions" in command
    assert command[-2:] == ["--session-id", pair["advisor"]["session"]]
    offline = argv_for({**pair, "network": "none"}, paths, config)
    assert "--share-net" not in offline


def test_herdr_proxy_bind(pair, paths, config):
    argv = argv_for(pair, paths, config, proxy=("/run/x/herdr.sock", "/home/tester/.config/herdr/herdr.sock"))
    assert ("/run/x/herdr.sock", "/home/tester/.config/herdr/herdr.sock") in binds(argv, "--ro-bind")
    env = setenv(argv)
    assert env["HERDR_SOCKET_PATH"] == "/home/tester/.config/herdr/herdr.sock"
    assert env["HERDR_PANE_ID"] == pair["advisor"]["pane_id"]


def test_profiles():
    assert resolve_profile("codex").prompt == "agents-md"
    custom = resolve_profile("myagent --flag 'a b'")
    assert custom.platform == "custom" and custom.command == ["myagent", "--flag", "a b"]
    configured = resolve_profile("mine", {"mine": {"command": ["mine", "{scratch}"], "cost_per_exchange": 5}})
    assert configured.cost_per_exchange == 5
    with pytest.raises(SandboxError):
        resolve_profile("")
    assert resolve_profile("claude").sha256() != resolve_profile("codex").sha256()


def test_resolve_cli_npm_layout(tmp_path):
    root = tmp_path / "npm"
    package = root / "lib" / "node_modules" / "agentx" / "bin"
    package.mkdir(parents=True)
    script = package / "agentx.js"
    script.write_text("#!/usr/bin/env node\n")
    (root / "bin").mkdir()
    os.symlink("../lib/node_modules/agentx/bin/agentx.js", root / "bin" / "agentx")
    found = {"agentx": str(root / "bin" / "agentx"), "node": "/usr/bin/node"}
    path, extra = resolve_cli("agentx", which=found.get)
    assert path == str(root / "bin" / "agentx")
    assert ["--symlink", "../lib/node_modules/agentx/bin/agentx.js", str(root / "bin" / "agentx")] == extra[:3]
    assert ["--ro-bind", str(root / "lib"), str(root / "lib")] == extra[3:6]
    with pytest.raises(SandboxError):
        resolve_cli("missing", which=lambda name: None)


def test_prepare_writes_prompt(pair, paths, config):
    argv = prepare(pair, paths=paths, config=config, resolve=lambda name: ("/usr/bin/claude", []), proxy=False)
    prompt = Path(pair["scratch_dir"]) / ".sensei-prompt.md"
    assert prompt.exists() and pair["project_root"] in prompt.read_text()
    assert "never implement" in prompt.read_text()
    assert argv[0] == config.bwrap


def test_herdr_proxy_filter():
    own = json.dumps({"method": "pane.report_agent", "params": {"pane_id": "w1:p2"}}).encode()
    other = json.dumps({"method": "pane.report_agent", "params": {"pane_id": "w1:p1"}}).encode()
    typing = json.dumps({"method": "pane.send_input", "params": {"pane_id": "w1:p2"}}).encode()
    assert herdr_request_allowed(own, "w1:p2")
    assert not herdr_request_allowed(other, "w1:p2")
    assert not herdr_request_allowed(typing, "w1:p2")
    assert not herdr_request_allowed(b"not json", "w1:p2")


def test_proxy_refuses_input_without_contacting_upstream(short_dir):
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    thread = threading.Thread(target=proxy_connection, args=(right, "w1:p2", str(short_dir / "none.sock")))
    thread.start()
    left.sendall(json.dumps({"method": "pane.send_input", "params": {"pane_id": "w1:p1"}}).encode() + b"\n")
    reply = json.loads(left.recv(65536))
    assert reply["error"]["code"] == "forbidden"
    left.sendall(json.dumps({"method": "pane.report_agent", "params": {"pane_id": "w1:p2"}}).encode() + b"\n")
    assert json.loads(left.recv(65536))["error"]["code"] == "unavailable"
    left.close()
    thread.join(5)


def test_shim_is_stdlib_only_and_talks_to_the_advisor_socket(short_dir, tmp_path):
    shim = write_shim(tmp_path / "bin")
    path = short_dir / "advisor.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    seen = {}

    def answer():
        connection, _ = server.accept()
        seen.update(json.loads(connection.makefile().readline()))
        connection.sendall(b'{"status": "available", "output": "Sent."}\n')
        connection.close()

    thread = threading.Thread(target=answer)
    thread.start()
    env = {"PATH": "/usr/bin:/bin", "AQT_SENSEI_SOCKET": str(path)}
    done = subprocess.run([sys.executable, "-I", str(shim), "reply", "the answer"], env=env,
                          capture_output=True, text=True, timeout=30)
    thread.join(5)
    server.close()
    assert done.returncode == 0 and done.stdout.strip() == "Sent."
    assert seen["op"] == "reply" and seen["text"] == "the answer"
    offline = subprocess.run([sys.executable, "-I", str(shim), "status"],
                             env={"AQT_SENSEI_SOCKET": str(short_dir / "gone.sock")}, capture_output=True, text=True)
    assert offline.returncode == 2 and "offline" in offline.stderr
