"""Who is on the other end of a socket: SO_PEERCRED plus /proc (on macOS LOCAL_PEERCRED plus sysctl).

The bridge never trusts a pane id or role that a caller declares. It reads the
peer's pid, uid and gid from the kernel, walks the process ancestry in /proc
(through ``aqt_evidence.platform``, which reads the same facts on macOS), and
compares it with the root processes and terminals of the paired panes.
The description uses the field names of the AQT `observed` object (aqt-spec spec §3.2) and goes
into `data.peer` of the records, because `observed` belongs to the trail writer.
"""

from __future__ import annotations

import hmac
import socket
from dataclasses import dataclass
from pathlib import Path

from aqt_evidence import detect_agent_context, platform

PROC: Path | None = None   # None: the system's own process table (/proc on Linux); tests pass a fake tree


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
    peer = platform.peer_credentials(connection)
    return peer.pid, peer.uid, peer.gid


def describe_pid(pid: int, uid: int, gid: int, *, proc: Path | None = PROC, limit: int = 64) -> Peer:
    """The peer and its ancestry up to and including init. ``proc`` reads a Linux-style /proc tree
    at that path instead of asking the system."""
    chain, names, starts, current = [], [], [], pid
    for _ in range(limit):
        info = platform.process_info(current, proc=proc)
        if info is None:
            break
        chain.append(current)
        names.append(info.name)
        starts.append(info.start_time)
        if info.ppid <= 0 or info.ppid == current:
            break
        current = info.ppid
    environ = platform.process_environ(pid, proc=proc) or {}
    context = detect_agent_context(environ, chain=names)
    return Peer(pid, uid, gid, chain, names, starts, platform.process_tty(pid, proc=proc), environ,
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
