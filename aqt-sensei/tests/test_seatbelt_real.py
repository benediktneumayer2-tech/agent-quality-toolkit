"""The advisor sandbox on macOS, for real: sandbox-exec with the generated Seatbelt profile."""

import os
import socket
import subprocess
import threading
from pathlib import Path

import pytest
from aqt_evidence import platform

from aqt_sensei.config import Config
from aqt_sensei.doctor import doctor_profile
from aqt_sensei.launch import prepare
from aqt_sensei.sandbox import resolve_cli, resolve_profile

pytestmark = pytest.mark.skipif(not platform.IS_MACOS, reason="Seatbelt (sandbox-exec) exists only on macOS")

PYTHON = "/usr/bin/python3"


@pytest.fixture
def project(tmp_path):
    folder = tmp_path / "project"
    folder.mkdir()
    (folder / "README").write_text("x")
    return folder


def boxed_pair(paths, project: Path, network: str) -> dict:
    profile = resolve_profile(PYTHON)
    pair_id = f"sp-{network}"
    scratch = project / ".sensei" / pair_id
    scratch.mkdir(parents=True)
    return {"id": pair_id, "backend": "none", "project_root": str(project), "scratch_dir": str(scratch),
            "mode": "confirm", "budget": {}, "network": network, "name": "test",
            "worker": {"pane_id": None}, "advisor": {"pane_id": "p", "platform": "custom", "model": None,
                                                    "session": None},
            "profile": profile.as_dict()}


def run_boxed(paths, project, network, code: str) -> subprocess.CompletedProcess:
    paths.ensure()
    pair = boxed_pair(paths, project, network)
    argv = prepare(pair, paths=paths, config=Config(), command=[PYTHON, "-I", "-c", code], proxy=False,
                   resolve=lambda name: (name, []))
    return subprocess.run(argv, capture_output=True, text=True, timeout=60, cwd=pair["scratch_dir"])


def test_doctor_proves_the_seatbelt_sandbox(paths, project):
    paths.ensure()
    result = doctor_profile("python3", str(project), paths=paths, config=Config(), backend="tmux")
    failed = [c for c in result["checks"] if not c["passed"] and c["name"] not in ("tmux installed",)]
    assert not failed, failed
    assert not list(project.glob(".aqt-sensei-probe"))


def test_writes_outside_the_scratch_folder_and_home_and_reads_of_user_files_fail(paths, project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("s3cret")
    in_tmp = Path(f"/private/tmp/aqt-sensei-probe-{os.getpid()}")
    code = f"""
import os
for path in ({str(project / 'new')!r}, {str(outside / 'new')!r}, {str(in_tmp)!r}):
    try:
        open(path, 'w').close(); print('wrote', path)
    except OSError as error:
        print('refused', error.errno)
try:
    print('read', open({str(outside / 'secret')!r}).read())
except OSError as error:
    print('refused', error.errno)
open(os.path.join(os.environ['TMPDIR'], 'ok'), 'w').close(); print('tmp ok')
"""
    try:
        done = run_boxed(paths, project, "none", code)
        assert done.stdout.split("\n")[:5] == ["refused 1", "refused 1", "refused 1", "refused 1", "tmp ok"], \
            done.stdout + done.stderr
        assert not (project / "new").exists() and not (outside / "new").exists() and not in_tmp.exists()
    finally:
        in_tmp.unlink(missing_ok=True)


def test_a_cli_started_through_a_link_in_a_user_folder_runs(paths, project, tmp_path):
    # Claude Code's installer puts ~/.local/bin/claude -> ~/.local/share/claude/versions/X; both are user folders.
    versions = tmp_path / "share" / "versions"
    versions.mkdir(parents=True)
    cli = versions / "1.0"
    cli.write_text("#!/bin/sh\necho cli-ok\n")
    cli.chmod(0o755)
    bin_folder = tmp_path / "bin"
    bin_folder.mkdir()
    link = bin_folder / "fake-cli"
    link.symlink_to(cli)
    paths.ensure()
    pair = boxed_pair(paths, project, "none")
    argv = prepare(pair, paths=paths, config=Config(), command=[str(link)], proxy=False,
                   resolve=lambda name: resolve_cli(name, which=lambda _: str(link)))
    done = subprocess.run(argv, capture_output=True, text=True, timeout=60, cwd=pair["scratch_dir"])
    assert done.stdout.strip() == "cli-ok", done.stdout + done.stderr


def test_network_none_refuses_and_share_allows_a_tcp_connection(paths, project):
    server = socket.create_server(("127.0.0.1", 0))
    port = server.getsockname()[1]
    def accept():
        try:
            for _ in range(2):
                server.accept()
        except OSError:
            pass
    threading.Thread(target=accept, daemon=True).start()
    code = f"""
import socket
try:
    socket.create_connection(('127.0.0.1', {port}), timeout=5); print('connected')
except OSError as error:
    print('refused', error.errno)
"""
    try:
        assert run_boxed(paths, project, "none", code).stdout.strip() == "refused 1"
        assert run_boxed(paths, project, "share", code).stdout.strip() == "connected"
    finally:
        server.close()
