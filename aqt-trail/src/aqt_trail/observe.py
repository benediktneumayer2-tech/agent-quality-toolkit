"""Observed attribution: who is on the other end of the socket.

The writer reads the peer's pid, uid and gid from the kernel (``SO_PEERCRED``;
macOS ``LOCAL_PEERPID`` and ``LOCAL_PEERCRED``; Windows: the named pipe's client pid and the
SID of that process's token, recorded as ``sid`` with no ``uid`` or ``gid``) and walks the parent chain
(``/proc``; macOS ``sysctl``; Windows a Toolhelp snapshot, through ``aqt_evidence.platform``).
This is evidence the writer saw, not a claim by the client. ``via`` stays ``socket`` for the
named pipe: it is the writer's local connection on that system. PIDs are reused, so each process
carries its start time (Linux: clock ticks since boot, ``/proc/<pid>/stat`` field
22; macOS and Windows: microseconds since 1970).

``chain_status`` says how far that evidence goes. Finding no agent marker in a
chain only means something when the chain is ``complete``:

- ``unavailable``: no peer pid, the sender's own ``/proc`` entry could not be
  read, or the sender had exited before it was observed (``SO_PEERPIDFD``,
  Linux >= 6.5; it also rules out a reused pid; other systems have no such check);
- ``partial``: an ancestor exited during the walk, the walk hit ``MAX_DEPTH``,
  a parent started after its child (pid reuse), or a process belongs to a
  session whose leader is not among its ancestors: it was reparented to init
  or a subreaper such as the systemd user manager after its parent exited, so
  whoever started it is no longer visible;
- ``complete``: the chain was read up to init and none of the above applies.

A process that detaches into a new session (``setsid``), or one started by a
service manager or an existing terminal server on an agent's request, still
looks ``complete``: the chain is a heuristic, not proof of who acted.
"""

from __future__ import annotations

import os
import select
import socket
from pathlib import Path

from aqt_evidence import Text, platform
from aqt_evidence.session import PROCESS_MARKERS

MAX_DEPTH = 16
CHAIN_STATUSES = ("complete", "partial", "unavailable")
SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)  # Linux >= 6.5


def peer_credentials(connection) -> tuple[int | None, int | str | None, int | None]:
    """(pid, uid, gid) of a connected Unix-socket or named-pipe peer (``aqt_evidence.platform.peer_credentials``)."""
    peer = platform.peer_credentials(connection)
    return peer.pid, peer.uid, peer.gid


def peer_pidfd(connection: socket.socket) -> int | None:
    """A pidfd of the process that connected (Linux >= 6.5), or None where unsupported.
    The caller closes it."""
    if not platform.IS_LINUX:
        return None
    try:
        return connection.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)
    except OSError:
        return None


def _exited(pidfd: int) -> bool:
    """A pidfd becomes readable when its process has exited."""
    try:
        return bool(select.select([pidfd], [], [], 0)[0])
    except (OSError, ValueError):
        return False


def _stat(pid: int, proc: Path | None) -> tuple[str, int, int | None, int] | None:
    """(comm, ppid, start_time, session id or 0) of a process (/proc/<pid>/stat on Linux), or None if gone."""
    info = platform.process_info(pid, proc=proc)
    return None if info is None else (info.name, info.ppid, info.start_time, info.session or 0)


def _reused(start: int | None, child_start: int | None, proc: Path | None) -> bool:
    """Windows only: a "parent" that started after its child holds a reused pid. Windows does not
    re-parent orphans (Linux hands them to init), so every chain there ends at a parent that has
    exited, and its pid may belong to an unrelated process by now."""
    return (platform.IS_WINDOWS and proc is None and start is not None and child_start is not None
            and start > child_start)


def _walk(pid: int, proc: Path | None, limit: int) -> tuple[list[dict], list[int], str]:
    """Chain entries (nearest first), their session ids, and how the walk ended:
    ``top`` (reached init), ``gone`` (a process could not be read) or ``depth``."""
    chain, sessions, current, child_start = [], [], pid, None
    for _ in range(limit):
        info = _stat(current, proc)
        if info is not None and _reused(info[2], child_start, proc):
            info = None     # Windows keeps a dead parent's pid: a later process with that pid is not the parent
        if info is None:
            chain.append({"pid": current, "comm": "?"})  # exited before it could be observed
            return chain, sessions, "gone"
        comm, parent, start, session = info
        child_start = start
        chain.append({"pid": current, "comm": comm} if start is None
                     else {"pid": current, "comm": comm, "start_time": start})
        sessions.append(session)
        if parent <= 1:
            return chain, sessions, "top"
        current = parent
    return chain, sessions, "depth"


def processes(pid: int, *, proc: Path | None = None, limit: int = MAX_DEPTH) -> tuple[list[dict], bool]:
    """Process chain from ``pid`` towards init, nearest first, and whether it reached init."""
    chain, _, end = _walk(pid, proc, limit)
    return chain, end == "top"


def chain_status(chain: list[dict], sessions: list[int], end: str) -> tuple[str, str | None]:
    """(``complete`` | ``partial`` | ``unavailable``, why not complete) for a walk (see the module text)."""
    if not chain or chain[0].get("comm") == "?":
        # the same words on macOS (no /proc there): the catalogue of aqt-ui holds this English template
        return "unavailable", Text("trail.observe.unreadable",
                                   "the sender's /proc entry could not be read (exited or hidden)")
    if end == "gone":
        return "partial", Text("trail.observe.exited", "process {pid} exited before it could be read",
                               pid=chain[-1]["pid"])
    if end == "depth":
        return "partial", Text("trail.observe.too_deep", "more than {n} ancestors", n=MAX_DEPTH)
    for child, parent in zip(chain, chain[1:]):
        if "start_time" in parent and "start_time" in child and parent["start_time"] > child["start_time"]:
            return "partial", Text("trail.observe.pid_reused", "parent {parent} started after its child {child} (pid "
                                   "reused)", parent=parent["pid"], child=child["pid"])
    on_chain = {entry["pid"] for entry in chain}
    for entry, session in zip(chain, sessions):
        if session > 0 and session != entry["pid"] and session not in on_chain:
            return "partial", Text("trail.observe.reparented", "{comm} ({pid}) belongs to session {session}, whose "
                                   "leader is not among its ancestors (reparented after its parent exited)",
                                   comm=entry["comm"], pid=entry["pid"], session=session)
    return "complete", None


def harness_of(chain: list[dict]) -> str | None:
    for entry in chain:
        found = PROCESS_MARKERS.get(entry.get("comm", ""))
        if found:
            return found
    return None


def observe(pid: int | None, uid: int | str | None, gid: int | None, *, via: str = "socket",
            proc: Path | None = None, pidfd: int | None = None) -> dict:
    """Build the writer-owned ``observed`` object (aqt-spec spec §3.2); ``client_time`` is added on append.

    ``pidfd`` (from ``peer_pidfd``) ties the observation to the connecting process: when that process
    has exited by the end of the walk, what /proc showed may belong to another process. ``proc`` reads a
    Linux-style /proc tree at that path instead of asking the system (tests)."""
    chain, sessions, end = _walk(pid, proc, MAX_DEPTH) if pid else ([], [], "gone")
    status, detail = chain_status(chain, sessions, end) if pid else ("unavailable", "no peer pid")
    if pidfd is not None and _exited(pidfd):
        status, detail = "unavailable", "the sender exited before it could be observed"
    # A Windows peer has a SID (a string) in place of uid and gid: observed.sid, and no uid or gid. What the
    # system did not tell (None, or a user name instead of a SID) is left out rather than written as null.
    if isinstance(uid, str):
        who = {"sid": uid} if uid.startswith("S-1-") else {}
    else:
        who = {name: value for name, value in (("uid", uid), ("gid", gid)) if value is not None}
    observed = {
        "pid": pid, **who,
        "process_chain": [entry["comm"] for entry in chain],
        "processes": chain,
        "harness": harness_of(chain),
        "via": via,
        "chain_status": status,
    }
    if detail:
        observed["chain_detail"] = detail
    if pid and end != "top":
        observed["chain_complete"] = False  # kept for older readers; chain_status is the full answer
    return observed


def observe_self() -> dict:
    """``observed`` for records the writer creates itself: no ``via`` (nothing was received),
    ``origin: writer`` instead, plus the writer's own process."""
    observed = observe(os.getpid(), platform.user_id(), None if platform.IS_WINDOWS else os.getgid())
    del observed["via"]
    observed["origin"] = "writer"
    return observed


def unobserved(via: str = "spool") -> dict:
    """``observed`` for spooled records: delivered later, the sender was never observed."""
    return {"process_chain": [], "processes": [], "harness": None, "via": via}


def agent_markers(observed: dict) -> list[str]:
    return [f"process:{entry['comm']}" for entry in observed.get("processes", [])
            if entry.get("comm") in PROCESS_MARKERS]
