"""Is this process running inside an AI agent session?

Human-only decisions (release a quarantined input, approve a CAPA, sign a
review) refuse to run when the caller looks like an agent. The check reads
environment markers that agent harnesses set and the process ancestry from
``/proc``. It is a guard against agents deciding for themselves by accident or
by injected instruction, **not** a security boundary: a same-user process can
clear its environment. Tools say so in their threat model and record every
refusal.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .messages import Text

# Environment variables set by agent harnesses (name -> harness).
ENV_MARKERS = {
    "AQT_AGENT_SESSION": "aqt",          # set by AQT tools when they launch an agent
    "CLAUDECODE": "claude-code",
    "CLAUDE_CODE_ENTRYPOINT": "claude-code",
    "CODEX_SANDBOX": "codex",
    "CODEX_SANDBOX_NETWORK_DISABLED": "codex",
    "CODEX_THREAD_ID": "codex",
    "PI_CODING_AGENT": "pi",
    "GEMINI_CLI": "gemini-cli",
    "AIDER_MODEL": "aider",
    "GOOSE_SESSION_ID": "goose",
    "OPENCODE": "opencode",
}
# Executable names of agent harnesses seen in the process ancestry.
PROCESS_MARKERS = {
    "claude": "claude-code", "codex": "codex", "pi": "pi", "pi-omni": "pi", "aider": "aider",
    "goose": "goose", "opencode": "opencode", "gemini": "gemini-cli", "cursor-agent": "cursor",
    "amp": "amp", "crush": "crush",
}


@dataclass
class AgentContext:
    is_agent: bool
    harness: str | None = None
    markers: list[str] = field(default_factory=list)
    process_chain: list[str] = field(default_factory=list)


def process_chain(pid: int | None = None, *, proc: Path = Path("/proc"), limit: int = 32) -> list[str]:
    """Command names from ``pid`` (default: this process) up to init, nearest first."""
    names, current = [], pid or os.getpid()
    for _ in range(limit):
        try:
            status = (proc / str(current) / "status").read_text(errors="replace")
        except OSError:
            break
        fields = dict(line.split(":\t", 1) for line in status.splitlines() if ":\t" in line)
        names.append(fields.get("Name", "?").strip())
        parent = int(fields.get("PPid", "0").strip() or 0)
        if parent <= 1:
            break
        current = parent
    return names


def detect_agent_context(environ: dict | None = None, *, chain: list[str] | None = None) -> AgentContext:
    environ = os.environ if environ is None else environ
    chain = process_chain() if chain is None else chain
    markers, harness = [], None
    for name, which in ENV_MARKERS.items():
        if environ.get(name):
            markers.append(f"env:{name}")
            harness = harness or which
    for name in chain[1:]:  # skip this process itself
        which = PROCESS_MARKERS.get(name)
        if which:
            markers.append(f"process:{name}")
            harness = harness or which
    return AgentContext(bool(markers), harness, markers, chain)


class HumanCheckError(PermissionError):
    def __init__(self, context: AgentContext, reason: str):
        super().__init__(reason)
        self.context = context


def require_human(*, environ: dict | None = None, chain: list[str] | None = None,
                  require_tty: bool = True, stdin=None) -> AgentContext:
    """Raise ``HumanCheckError`` unless the caller looks like a human at a terminal."""
    context = detect_agent_context(environ, chain=chain)
    if context.is_agent:
        raise HumanCheckError(context, Text("evidence.human.agent_context", "refused: this command looks like it "
                                            "runs inside an agent session ({markers}); run it yourself in a terminal",
                                            markers=", ".join(context.markers)))
    stdin = sys.stdin if stdin is None else stdin
    if require_tty and not (hasattr(stdin, "isatty") and stdin.isatty()):
        raise HumanCheckError(context, Text("evidence.human.no_tty",
                                            "refused: a human decision needs an interactive terminal"))
    return context
