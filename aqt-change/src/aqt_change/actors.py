"""Who is acting: an agent (detected by the shared aqt-spec markers) or a human.

``AQT_ACTOR`` may set the identity but never turns an agent context into a
human one (INTERFACES.md I9/I12). Tests replace ``agent_context``.
"""

from __future__ import annotations

import getpass
import os

from aqt_evidence import AgentContext, actor, detect_agent_context, require_human

SESSION_VARS = ("AQT_AGENT_SESSION", "CLAUDE_SESSION_ID", "CODEX_THREAD_ID", "PI_SESSION_ID", "GOOSE_SESSION_ID")


def agent_context() -> AgentContext:
    return detect_agent_context()


def human_check() -> AgentContext:
    return require_human()


def current_actor(configured: str | None = None, context: AgentContext | None = None) -> dict:
    context = context or agent_context()
    override = os.environ.get("AQT_ACTOR")
    if context.is_agent:
        harness = context.harness or "unknown"
        if override and override.startswith("agent:"):
            ident = override
        else:
            session = next((os.environ[v] for v in SESSION_VARS if os.environ.get(v)), "unknown")
            ident = f"agent:{harness}:{session}"
        return actor("agent", ident, harness=harness)
    ident = override or configured or f"human:{getpass.getuser()}"
    kind = ident.split(":", 1)[0] if ":" in ident else "human"
    if kind not in ("human", "agent", "service"):
        kind = "human"
    return actor(kind, ident)


def is_human(value: dict) -> bool:
    return value.get("kind") == "human"
