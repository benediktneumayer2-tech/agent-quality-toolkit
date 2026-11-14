"""``aqt_evidence.pipes``: the Windows named pipe that carries the aqt-trail protocol, without a writer.
A real writer and two clients are tested in aqt-trail (tests/test_windows_pipe.py)."""

import os
import subprocess
import sys
import threading

import pytest

from aqt_evidence import platform

WINDOWS = pytest.mark.skipif(not platform.IS_WINDOWS, reason="named pipes: Windows only")


def test_pipe_addresses():
    assert platform.is_pipe("\\\\.\\pipe\\aqt-trail-1") and platform.is_pipe("//./pipe/aqt-trail-1")
    assert not platform.is_pipe("/run/user/1000/aqt/trail.sock") and not platform.is_pipe("C:\\x\\trail.sock")


@pytest.mark.skipif(platform.IS_WINDOWS, reason="POSIX: a Unix socket in the runtime folder")
def test_the_writer_address_is_a_socket_on_posix(tmp_path):
    assert platform.trail_socket(tmp_path / "trail", {"XDG_RUNTIME_DIR": str(tmp_path / "r")}) == \
        tmp_path / "r" / "aqt" / "trail.sock"


@WINDOWS
def test_the_writer_address_is_a_pipe_per_user_and_trail(tmp_path):
    first, second = platform.trail_socket(tmp_path / "a"), platform.trail_socket(tmp_path / "b")
    assert platform.is_pipe(first) and str(first).startswith("\\\\.\\pipe\\aqt-trail-") and first != second
    assert platform.trail_socket(tmp_path / "a") == first


def _serve(listener, answers):
    """Answer one client: echo its request line with its pid and user."""
    connection = None
    while connection is None:
        connection = listener.accept(timeout=10)
    try:
        connection.settimeout(5)
        request = b""
        while chunk := connection.recv(65536):
            request += chunk
        peer = platform.peer_credentials(connection)
        answers.append((request, peer))
        connection.sendall(b'{"ok": true}\n')
    finally:
        connection.close()


@WINDOWS
def test_request_and_peer_of_another_process(tmp_path):
    from aqt_evidence import pipes
    name = f"\\\\.\\pipe\\aqt-test-{os.getpid()}-{id(tmp_path)}"
    listener = pipes.PipeListener(name)
    try:
        answers = []
        server = threading.Thread(target=_serve, args=(listener, answers))
        server.start()
        client = subprocess.run([sys.executable, "-c", "import os, sys; from aqt_evidence import pipes; "
                                 "print(os.getpid()); print(pipes.request(sys.argv[1], b'{\"op\": \"ping\"}\\n')"
                                 ".decode())", name], capture_output=True, text=True, timeout=60)
        server.join(timeout=30)
        assert client.returncode == 0, client.stderr
        pid, answer = client.stdout.split("\n", 1)
        assert answer.strip() == '{"ok": true}'
        request, peer = answers[0]
        assert request == b'{"op": "ping"}\n'
        assert peer.pid == int(pid) and peer.uid == platform.user_id() and peer.gid is None
        with pytest.raises(FileExistsError):
            pipes.PipeListener(name)            # nobody else can serve the same name
    finally:
        listener.close()
    with pytest.raises(FileNotFoundError):
        pipes.request(name, b"{}\n", timeout=1)


@WINDOWS
def test_nul_is_not_a_terminal():
    with open(os.devnull) as nul:
        assert nul.isatty() and not platform.is_terminal(nul)


@WINDOWS
def test_process_names_without_exe():
    me = platform.process_info(os.getpid())
    assert me.name.lower() == "python" and me.uid == platform.user_id()
    chain = platform.process_chain()
    assert chain[0].pid == os.getpid() and all(not info.name.lower().endswith(".exe") for info in chain)
