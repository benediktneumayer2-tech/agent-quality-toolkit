"""Who is on the other end of a socket: SO_PEERCRED plus /proc.

The bridge never trusts a pane id or role that a caller declares. It reads the
peer's pid, uid and gid from the kernel, walks the process ancestry in /proc,
and compares it with the root processes and terminals of the paired panes.
The description uses the field names of the AQT `observed` object (aqt-spec spec §3.2) and goes
into `data.peer` of the records, because `observed` belongs to the trail writer.
"""

from __future__ import annotations

import hmac
import os
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from aqt_evidence import detect_agent_context

PROC = Path("/proc")


@dataclass
class Peer:
    pid: int
    uid: int
    gid: int
    chain: list[int]            # pids, nearest first (the peer itself first)
    names: list[str]            # command names, nearest first
    start_times: list[int | None]
    tty: str | None             # the peer's stdin if it is a terminal
    environ: dict
    harness: str | None = None
    agent_markers: list[str] | None = None

    def describe(self) -> dict:
        """`data.peer`: same field names as the trail's `observed` object (spec §3.2). As there, fields without a
        value are left out: the peer sends no client time, and a process may be gone before its start time
        is read."""
        processes = [{"pid": pid, "comm": name} if start is None else {"pid": pid, "comm": name, "start_time": start}
                     for pid, name, start in zip(self.chain, self.names, self.start_times)]
        return {"pid": self.pid, "uid": self.uid, "gid": self.gid, "process_chain": self.names,
                "processes": processes, "harness": self.harness, "via": "socket"}


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def _status(pid: int, proc: Path) -> dict:
    text = (proc / str(pid) / "status").read_text(errors="replace")
    return dict(line.split(":\t", 1) for line in text.splitlines() if ":\t" in line)


def _start_time(pid: int, proc: Path) -> int | None:
    try:
        stat = (proc / str(pid) / "stat").read_text()
        return int(stat.rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def _environ(pid: int, proc: Path) -> dict:
    try:
        raw = (proc / str(pid) / "environ").read_bytes()
    except OSError:
        return {}
    pairs = (item.split(b"=", 1) for item in raw.split(b"\0") if b"=" in item)
    return {key.decode(errors="replace"): value.decode(errors="replace") for key, value in pairs}


def _tty(pid: int, proc: Path) -> str | None:
    try:
        target = os.readlink(proc / str(pid) / "fd" / "0")
    except OSError:
        return None
    return target if target.startswith("/dev/pts/") or target.startswith("/dev/tty") else None


def describe_pid(pid: int, uid: int, gid: int, *, proc: Path = PROC, limit: int = 64) -> Peer:
    chain, names, starts, current = [], [], [], pid
    for _ in range(limit):
        try:
            fields = _status(current, proc)
        except OSError:
            break
        chain.append(current)
        names.append(fields.get("Name", "?").strip())
        starts.append(_start_time(current, proc))
        parent = int((fields.get("PPid") or "0").strip() or 0)
        if parent <= 0:
            break
        current = parent
    environ = _environ(pid, proc)
    context = detect_agent_context(environ, chain=names)
    return Peer(pid, uid, gid, chain, names, starts, _tty(pid, proc), environ,
                context.harness, list(context.markers))


def is_descendant(peer: Peer, root_pid: int | None) -> bool:
    return root_pid is not None and root_pid in peer.chain


def token_matches(given: object, expected: str | None) -> bool:
    return isinstance(given, str) and bool(expected) and hmac.compare_digest(given, expected)


def owner_refusal(peer: Peer, *, token_ok: bool, daemon_uid: int, paired: list) -> str | None:
    """None if the peer may act as the owner, else a reason code.

    `paired` holds PaneInfo of every live paired pane (worker and advisor).
    These checks stop an agent in a paired pane, or any process that carries
    agent markers, from deciding for the owner. They do not stop a determined
    same-user process outside the pairs that reads the token (see the threat model).
    """
    if peer.uid != daemon_uid:
        return "uid"
    if not token_ok:
        return "token"
    if any(is_descendant(peer, pane.root_pid) for pane in paired):
        return "paired-pane"
    if peer.agent_markers:
        return "agent-session"
    if peer.tty is None:
        return "no-terminal"
    if any(pane.tty and pane.tty == peer.tty for pane in paired):
        return "paired-terminal"
    return None
