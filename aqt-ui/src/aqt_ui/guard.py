"""Who may decide through the UI.

Two checks, both the toolkit's own ``aqt_evidence`` agent detection:

1. **At start** the server runs ``require_human()`` (agent environment markers, agent
   processes in its ancestry, an interactive terminal). If it fails, the server still runs,
   but read-only, and says why.
2. **Per decision request** the server looks up the process on the other end of the
   loopback TCP connection (``/proc/net/tcp`` gives the socket inode, ``/proc/*/fd`` its
   owner) and walks that process's ancestry. A request sent by a process that runs under
   an agent (for example ``curl`` started by ``claude``) is refused like an agent running
   the CLI. A peer that cannot be identified is refused too.

The check is handed to the owning package as its human check, so the package itself
records ``<tool>.refused`` with the markers. Like the CLI checks this is a guard, not a
security boundary: an agent that drives the person's own browser looks like the browser.
The passphrase stays the real control.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from aqt_evidence import AgentContext, HumanCheckError, detect_agent_context, process_chain, require_human


@dataclass
class Mode:
    decisions: bool
    reason: str = ""                    # why decisions are off (shown in the ribbon)
    markers: list[str] = field(default_factory=list)
    context: AgentContext | None = None
    explicit: bool = False              # started with --read-only on purpose

    def as_dict(self) -> dict:
        return {"decisions": self.decisions, "reason": self.reason, "markers": list(self.markers),
                "harness": self.context.harness if self.context else None, "explicit": self.explicit}


def startup_mode(read_only: bool = False, *, environ: dict | None = None, chain: list[str] | None = None,
                 stdin=None) -> Mode:
    """Decisions on only when the start-up human check passes (terminal required)."""
    if read_only:
        return Mode(False, "started with --read-only", explicit=True)
    try:
        context = require_human(environ=environ, chain=chain, stdin=stdin)
    except HumanCheckError as error:
        context = error.context
        if context.is_agent:
            where = f"inside {context.harness}" if context.harness else "inside an agent session"
            reason = (f"Started {where} ({', '.join(context.markers)}). Decisions are off; "
                      "start aqt-ui yourself in a terminal to decide.")
        else:
            reason = "Started without an interactive terminal. Decisions are off; start aqt-ui yourself in a terminal."
        return Mode(False, reason, list(context.markers), context)
    return Mode(True, "", [], context)


# -- the HTTP peer -------------------------------------------------------------------------------------
def _hex_address(host: str, port: int) -> str:
    """``/proc/net/tcp`` notation of an IPv4 address: little-endian hex, then the port."""
    octets = [int(part) for part in host.split(".")]
    return "".join(f"{value:02X}" for value in reversed(octets)) + f":{port:04X}"


def socket_inode(client: tuple[str, int], server: tuple[str, int], *, proc: Path = Path("/proc")) -> int | None:
    """Inode of the client's end of the TCP connection ``client`` -> ``server``."""
    local, remote = _hex_address(*client[:2]), _hex_address(*server[:2])
    try:
        lines = (proc / "net" / "tcp").read_text().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) > 9 and fields[1] == local and fields[2] == remote:
            inode = int(fields[9])
            return inode or None
    return None


def socket_owner(inode: int, *, proc: Path = Path("/proc")) -> int | None:
    """PID of a process that holds the socket ``inode`` (only this user's processes are readable)."""
    target = f"socket:[{inode}]"
    for entry in os.scandir(proc):
        if not entry.name.isdigit():
            continue
        fd_dir = Path(entry.path) / "fd"
        try:
            names = os.listdir(fd_dir)
        except OSError:
            continue
        for name in names:
            try:
                if os.readlink(fd_dir / name) == target:
                    return int(entry.name)
            except OSError:
                continue
    return None


def peer_chain(client: tuple[str, int], server: tuple[str, int], *, proc: Path = Path("/proc")) -> list[str] | None:
    """Process names from the peer up to init, nearest first; ``None`` when the peer is not found."""
    inode = socket_inode(client, server, proc=proc)
    pid = socket_owner(inode, proc=proc) if inode else None
    if pid is None:
        return None
    return process_chain(pid, proc=proc)


PeerLookup = Callable[[tuple, tuple], "list[str] | None"]


class Guard:
    """Builds the human check for one decision request."""

    def __init__(self, mode: Mode, *, environ: dict | None = None, peer_lookup: PeerLookup | None = None):
        self.mode = mode
        self.environ = dict(os.environ if environ is None else environ)
        self.peer_lookup = peer_lookup or peer_chain

    def context(self, client: tuple, server: tuple) -> tuple[AgentContext, str | None]:
        """(context, refusal message or None) for a request from ``client``."""
        if not self.mode.decisions:
            context = self.mode.context or AgentContext(False)
            return context, f"refused: decisions are off in this aqt-ui server. {self.mode.reason}"
        chain = self.peer_lookup(client, server)
        if chain is None:
            context = AgentContext(True, None, ["peer:unidentified"], [])
            return context, ("refused: the process that sent this request could not be identified, so it is "
                             "not known whether it runs inside an agent session")
        # "aqt-ui" stands for this server; detect_agent_context checks everything after it.
        context = detect_agent_context(self.environ, chain=["aqt-ui", *chain])
        if context.is_agent:
            return context, ("refused: this request comes from a process inside an agent session "
                             f"({', '.join(context.markers)}); decide in your own browser")
        return context, None

    def human_check(self, client: tuple, server: tuple) -> Callable[[], AgentContext]:
        """A ``human_check`` callable for the packages: raises ``HumanCheckError`` to refuse."""
        def check() -> AgentContext:
            context, refusal = self.context(client, server)
            if refusal:
                raise HumanCheckError(context, refusal)
            return context
        return check
