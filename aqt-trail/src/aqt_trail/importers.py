"""Turn agent session events into ``trail.import`` records.

Sources: Claude Code hook payloads (stdin), Claude Code transcripts, Codex
rollout JSONL and pi v3 session JSONL. The format knowledge is adapted from
the native history readers of the author's private Agent Platform Next (see
NOTICE); only what is needed for evidence is kept. The formats are
undocumented internals of each CLI and change often.

Full texts are never stored: prompts, tool inputs and outputs are hashed, and
only a short excerpt (masked for obvious secrets, configurable, 0 disables) is
kept. Re-importing is idempotent: each event has ``data.source_hash`` (SHA-256
of the native line plus a part suffix) and a record id derived from it.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aqt_evidence import actor, bytes_hash, new_record, subject, utc_now


class ImportError_(ValueError):
    """The source file cannot be imported safely or is not what it claims to be."""


_VALUE = r"(?:[^\s\\\"',;}]|\\(?!\"))+"  # up to a space, quote (also an escaped one), comma, semicolon or brace
_KEYWORDS = (r"passw(?:or)?d|passphrase|secret|token(?!s)|api[_-]?key|access[_-]?key|private[_-]?key"
             r"|credential")
_SECRETS = [
    # PEM private keys: from BEGIN to END, or to the end of the excerpt when END is cut off
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----|\Z)"),
     "[masked private key]"),
    # well-known token formats
    (re.compile(r"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                r"|glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|xox[abeprs]-[A-Za-z0-9-]{10,}"
                r"|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]{20,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}"
                r"|[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"
                r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})"), "[masked]"),
    # Authorization headers and bearer tokens
    (re.compile(r"(?i)(authorization[\"']?[ \t]*+[:=][ \t]*+[\"']?(?:(?:bearer|basic|token|digest|negotiate)[ \t]++)?)"
                + _VALUE), r"\1[masked]"),
    (re.compile(r"(?i)(?<![A-Za-z0-9_-])(bearer[ \t]++)[A-Za-z0-9._~+/=-]{8,}"), r"\1[masked]"),
    # passwords in URLs (scheme://user:password@host) and in curl -u user:password
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@\"']+:)[^\s@/\"']+(@)"), r"\1[masked]\2"),
    (re.compile(r"(?<![A-Za-z0-9_-])((?:-u|--user)[ \t]++[^\s:\"']+:)[^\s\"']+"), r"\1[masked]"),
]
# NAME=value, NAME: value, "name": "value" and --name value, where NAME contains a keyword
# (DB_PASSWORD, GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY, x-api-key, --password, ...); quoted values also
# with the escaped quotes of a JSON-encoded tool input (\"...\").
_NAME = rf"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]*?(?:{_KEYWORDS})[A-Za-z0-9_.-]*+)"
_QUOTED = re.compile(rf"(?i){_NAME}([\"']?[ \t]*+[:=][ \t]*+)(\\\"[^\"]*\"|\"[^\"]*\"|'[^']*')")
_ASSIGNMENT = re.compile(rf"(?i){_NAME}([\"']?[ \t]*+[:=][ \t]*+[\"']?)({_VALUE})")
_FLAG = re.compile(rf"(?i)(?<![A-Za-z0-9_-])(--?[A-Za-z0-9_-]*?(?:{_KEYWORDS})[A-Za-z0-9_-]*+)([ \t]++)([^\s\"'-][^\s\"']*)")
_MASK_WINDOW = 4096  # characters masked beyond the excerpt limit, so a secret at its end is still masked


def _masked_value(match: re.Match) -> str:
    name, separator, value = match.groups()
    bare = value.strip("\\\"'")
    if not bare or bare.startswith("[masked"):
        return match.group(0)
    quote = '\\"' if value.startswith('\\"') else value[:1] if value[:1] in ("'", '"') else ""
    if quote and len(value) > len(quote):
        return f"{name}{separator}{quote}[masked]{quote}"
    return f"{name}{separator}[masked]"


def mask(text: str) -> str:
    """Mask obvious secrets in an excerpt. A safety net, not a guarantee: set ``excerpt_chars = 0``
    to keep no excerpts at all."""
    for pattern, replacement in _SECRETS:
        text = pattern.sub(replacement, text)
    text = _QUOTED.sub(_masked_value, text)
    text = _ASSIGNMENT.sub(_masked_value, text)
    return _FLAG.sub(_masked_value, text)


def _json_text(value) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def excerpt(value, limit: int) -> str | None:
    if limit <= 0 or value is None:
        return None
    text = " ".join(_json_text(value).split())
    text = mask(text[:limit + _MASK_WINDOW])[:limit]
    return text or None


def value_hash(value) -> str:
    """SHA-256 of a string's UTF-8 bytes, or of compact sorted-key JSON for other values."""
    if isinstance(value, str):
        return bytes_hash(value.encode("utf-8"))
    return bytes_hash(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                                 default=str).encode("utf-8"))


def safe_lines(path: str | os.PathLike) -> list[tuple[int, bytes]]:
    """Complete lines of a regular file owned by the caller (no symlinks, one link)."""
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ImportError_(f"{path}: cannot open ({error.strerror})") from error
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ImportError_(f"{path}: not a regular file owned by you with a single link")
        data = handle.read()
    end = data.rfind(b"\n") + 1  # a partly written last line is left for the next import
    lines, number = [], 0
    for line in data[:end].splitlines():
        number += 1
        if line.strip():
            lines.append((number, line))
    return lines


def _ms(value) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


@dataclass
class Event:
    action: str
    event_id: str
    source_hash: str
    source_time: str | None = None
    fields: dict = field(default_factory=dict)
    subject: dict | None = None


@dataclass
class Session:
    format: str
    harness: str
    id: str | None = None
    version: str | None = None
    model: str | None = None
    events: list[Event] = field(default_factory=list)


def _line_hash(line: bytes, suffix: str = "") -> str:
    return bytes_hash(line + (b"#" + suffix.encode() if suffix else b""))


def to_records(session: Session, *, known: set[str] | None = None) -> tuple[list[dict], int]:
    """Records for the events not yet in ``known`` (source hashes); returns (records, skipped)."""
    known = known if known is not None else set()
    records, skipped = [], 0
    for event in session.events:
        if event.source_hash in known:
            skipped += 1
            continue
        known.add(event.source_hash)
        model = event.fields.pop("_model", None) or session.model
        who = actor("agent", f"agent:{session.harness}:{session.id or 'unknown'}", harness=session.harness,
                    model=model, version=session.version, session=session.id)
        data = {"source": {"format": session.format, "session": session.id, "event_id": event.event_id},
                "source_hash": event.source_hash}
        if event.source_time:
            data["source_time"] = event.source_time
        reserved = {"source", "source_hash", "source_time"}
        clash = reserved & set(event.fields)
        if clash:
            raise ImportError_(f"importer bug: event field(s) {sorted(clash)} would overwrite data.source*")
        data.update({key: value for key, value in event.fields.items() if value is not None})
        record = new_record("trail.import", who, event.action, data=data,
                            subject=event.subject or subject("agent-session", session.id or "unknown"))
        stamp = _ms(event.source_time) or int(time.time() * 1000)
        # Deterministic id (source time + source hash): a re-sent import is idempotent at the writer.
        record["id"] = f"rec_{stamp % (1 << 48):012x}{event.source_hash[7:23]}"
        records.append(record)
    return records, skipped


def _tool_subject(use_id) -> dict | None:
    return subject("tool-call", str(use_id)) if use_id else None


# -- Claude Code hooks ---------------------------------------------------------
HOOK_ACTIONS = {"SessionStart": "session.start", "SessionEnd": "session.end", "UserPromptSubmit": "prompt",
                "PreToolUse": "tool.call", "PostToolUse": "tool.result", "Stop": "stop",
                "SubagentStop": "subagent.stop", "PreCompact": "compaction", "Notification": "notification"}


def claude_hook(raw: bytes, *, excerpt_chars: int = 160) -> Session:
    payload = json.loads(raw)
    if not isinstance(payload, dict) or not payload.get("hook_event_name"):
        raise ImportError_("not a Claude Code hook payload")
    name = payload["hook_event_name"]
    session = Session("claude-code-hook", "claude-code", payload.get("session_id"))
    fields: dict = {"hook_event": name, "cwd": payload.get("cwd"), "permission_mode": payload.get("permission_mode")}
    use_id = payload.get("tool_use_id")
    if "tool_name" in payload:
        tool = {"name": payload.get("tool_name"), "use_id": use_id,
                "input_sha256": value_hash(payload.get("tool_input")),
                "input_excerpt": excerpt(payload.get("tool_input"), excerpt_chars)}
        if "tool_response" in payload:
            response = payload["tool_response"]
            tool["output_sha256"] = value_hash(response)
            if isinstance(response, dict) and isinstance(response.get("is_error"), bool):
                tool["is_error"] = response["is_error"]
        fields["tool"] = {key: value for key, value in tool.items() if value is not None}
    if "prompt" in payload:
        fields["prompt_sha256"] = value_hash(payload["prompt"])
        fields["prompt_excerpt"] = excerpt(payload["prompt"], excerpt_chars)
    # Hook field names that would collide with data.source (format/session/event_id) are renamed.
    for key, target in (("source", "session_source"), ("reason", "end_reason"), ("model", "model")):
        if isinstance(payload.get(key), str):
            fields[target] = payload[key][:200]
    session.events.append(Event(HOOK_ACTIONS.get(name, "hook." + name.lower()), f"hook:{name}:{use_id or ''}",
                                bytes_hash(raw), utc_now(), fields, _tool_subject(use_id)))
    return session


# -- Claude Code transcripts -----------------------------------------------------
def _text_parts(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(part.get("text", "") for part in content if isinstance(part, dict) and part.get("type") == "text")
    return ""


def claude_session(path, *, excerpt_chars: int = 160) -> Session:
    session = Session("claude-code-session", "claude-code")
    tool_names: dict[str, str] = {}
    for number, line in safe_lines(path):
        entry = json.loads(line)
        if not isinstance(entry, dict):
            raise ImportError_(f"line {number}: not an object")
        # Only sessionId names a transcript (session_id is the launch session after /clear).
        if isinstance(entry.get("sessionId"), str):
            if session.id is None:
                session.id = entry["sessionId"].lower()
            elif entry["sessionId"].lower() != session.id:
                raise ImportError_(f"line {number}: transcript mixes sessions")
        if isinstance(entry.get("version"), str):
            session.version = entry["version"][:40]
        kind, when, uid = entry.get("type"), entry.get("timestamp"), entry.get("uuid") or f"line:{number}"
        message = entry.get("message") if isinstance(entry.get("message"), dict) else {}
        if kind == "user" and not entry.get("isMeta") and not entry.get("isCompactSummary"):
            content = message.get("content")
            text = _text_parts(content)
            if text:
                session.events.append(Event("prompt", uid, _line_hash(line, "prompt"), when, {
                    "prompt_sha256": value_hash(text), "prompt_excerpt": excerpt(text, excerpt_chars)}))
            for index, part in enumerate(content if isinstance(content, list) else []):
                if isinstance(part, dict) and part.get("type") == "tool_result":
                    use_id = part.get("tool_use_id")
                    tool = {"name": tool_names.get(use_id), "use_id": use_id,
                            "output_sha256": value_hash(part.get("content", "")),
                            "is_error": part.get("is_error") is True}
                    session.events.append(Event("tool.result", f"{uid}:part:{index}", _line_hash(line, f"part:{index}"),
                                                when, {"tool": {k: v for k, v in tool.items() if v is not None}},
                                                _tool_subject(use_id)))
        elif kind == "assistant":
            model = message.get("model") if isinstance(message.get("model"), str) else None
            if model and model != session.model and not model.startswith("<"):
                session.model = model
                session.events.append(Event("model.change", f"{uid}:model", _line_hash(line, "model"), when,
                                            {"model": model, "_model": model}))
            content = message.get("content") if isinstance(message.get("content"), list) else []
            text = _text_parts(content)
            if text:
                session.events.append(Event("message", f"{uid}:text", _line_hash(line, "text"), when,
                                            {"role": "assistant", "text_sha256": value_hash(text)}))
            for part in content:
                if isinstance(part, dict) and part.get("type") == "tool_use":
                    tool_names[part.get("id")] = part.get("name")
                    tool = {"name": part.get("name"), "use_id": part.get("id"),
                            "input_sha256": value_hash(part.get("input")),
                            "input_excerpt": excerpt(part.get("input"), excerpt_chars)}
                    session.events.append(Event("tool.call", f"{uid}:tool:{part.get('id')}",
                                                _line_hash(line, f"tool:{part.get('id')}"), when,
                                                {"tool": {k: v for k, v in tool.items() if v is not None}},
                                                _tool_subject(part.get("id"))))
        elif kind == "system" and entry.get("subtype") == "compact_boundary":
            session.events.append(Event("compaction", uid, _line_hash(line), when, {}))
        elif kind == "permission-mode" and isinstance(entry.get("permissionMode"), str):
            session.events.append(Event("permission.mode", f"line:{number}", _line_hash(line), when,
                                        {"permission_mode": entry["permissionMode"][:40]}))
        elif kind == "continued-in" and isinstance(entry.get("continuedInSessionId"), str):
            session.events.append(Event("session.continued", f"line:{number}", _line_hash(line), when,
                                        {"continued_in": entry["continuedInSessionId"][:64]}))
    if session.id is None:
        raise ImportError_(f"{path}: no sessionId found; not a Claude Code transcript")
    return session


# -- Codex rollout -------------------------------------------------------------------
def _codex_text(content) -> str:
    if isinstance(content, list):
        return "\n".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
    return content if isinstance(content, str) else ""


def codex_rollout(path, *, excerpt_chars: int = 160) -> Session:
    session = Session("codex-rollout", "codex")
    calls: dict[str, str] = {}
    permission = None
    for number, line in safe_lines(path):
        record = json.loads(line)
        if not isinstance(record, dict) or not isinstance(record.get("payload"), dict):
            raise ImportError_(f"line {number}: not a Codex rollout record")
        kind, payload, when = record.get("type"), record["payload"], record.get("timestamp")
        if session.id is None:
            if kind != "session_meta" or not isinstance(payload.get("id"), str):
                raise ImportError_(f"{path}: rollout does not start with session_meta")
            session.id = payload["id"].lower()
            session.version = str(payload.get("cli_version", ""))[:40] or None
            session.events.append(Event("session.start", "session_meta", _line_hash(line), when,
                                        {"cwd": payload.get("cwd"), "provider": payload.get("model_provider")}))
            continue
        if kind == "turn_context":
            model = payload.get("model")
            if isinstance(model, str) and model != session.model:
                session.model = model
                session.events.append(Event("model.change", f"line:{number}:model", _line_hash(line, "model"), when,
                                            {"model": model, "effort": payload.get("effort"), "_model": model}))
            sandbox = payload.get("sandbox_policy")
            sandbox = sandbox.get("type") if isinstance(sandbox, dict) else sandbox
            current = {"sandbox": sandbox, "approval_policy": payload.get("approval_policy")}
            if current != permission and any(isinstance(v, str) for v in current.values()):
                permission = current
                session.events.append(Event("permission.mode", f"line:{number}:permission",
                                            _line_hash(line, "permission"), when,
                                            {k: v[:40] for k, v in current.items() if isinstance(v, str)}))
        elif kind == "response_item":
            item_type = payload.get("type")
            if item_type == "message" and payload.get("role") in ("user", "assistant"):
                text = _codex_text(payload.get("content"))
                if payload["role"] == "user":
                    session.events.append(Event("prompt", f"line:{number}", _line_hash(line), when, {
                        "prompt_sha256": value_hash(text), "prompt_excerpt": excerpt(text, excerpt_chars)}))
                elif text:
                    session.events.append(Event("message", f"line:{number}", _line_hash(line), when,
                                                {"role": "assistant", "text_sha256": value_hash(text)}))
            elif item_type in ("function_call", "custom_tool_call", "local_shell_call"):
                call_id = payload.get("call_id") or payload.get("id") or f"line:{number}"
                name = ".".join(str(v) for v in (payload.get("namespace"), payload.get("name", "shell")) if v)
                calls[call_id] = name
                arguments = payload.get("arguments", payload.get("input", payload.get("action")))
                session.events.append(Event("tool.call", f"call:{call_id}", _line_hash(line), when, {"tool": {
                    "name": name, "use_id": call_id, "input_sha256": value_hash(arguments),
                    **({"input_excerpt": excerpt(arguments, excerpt_chars)} if excerpt_chars > 0 else {})}},
                    _tool_subject(call_id)))
            elif item_type in ("function_call_output", "custom_tool_call_output"):
                call_id = payload.get("call_id") or f"line:{number}"
                tool = {"name": calls.get(call_id), "use_id": call_id, "output_sha256": value_hash(payload.get("output"))}
                session.events.append(Event("tool.result", f"output:{call_id}", _line_hash(line), when,
                                            {"tool": {k: v for k, v in tool.items() if v is not None}},
                                            _tool_subject(call_id)))
        elif kind == "event_msg":
            event = payload.get("type")
            mapping = {"task_started": "turn.start", "turn_started": "turn.start", "task_complete": "turn.end",
                       "turn_complete": "turn.end", "turn_aborted": "turn.aborted",
                       "thread_rolled_back": "rollback", "session_rolled_back": "rollback"}
            if event in mapping:
                fields = {"turn_id": payload.get("turn_id")}
                if mapping[event] == "rollback" and type(payload.get("num_turns")) is int:
                    fields["turns"] = payload["num_turns"]
                session.events.append(Event(mapping[event], f"line:{number}", _line_hash(line), when, fields))
        elif kind == "compacted":
            session.events.append(Event("compaction", f"line:{number}", _line_hash(line), when, {}))
    if session.id is None:
        raise ImportError_(f"{path}: empty rollout")
    return session


# -- pi sessions ---------------------------------------------------------------------
def pi_session(path, *, excerpt_chars: int = 160) -> Session:
    session = Session("pi-session", "pi")
    tool_names: dict[str, str] = {}
    for number, line in safe_lines(path):
        entry = json.loads(line)
        if not isinstance(entry, dict):
            raise ImportError_(f"line {number}: not an object")
        when = entry.get("timestamp")
        if session.id is None:
            if entry.get("type") != "session" or entry.get("version") != 3 or not isinstance(entry.get("id"), str):
                raise ImportError_(f"{path}: not a pi v3 session (header missing or other version)")
            session.id = entry["id"]
            session.events.append(Event("session.start", "session", _line_hash(line), when, {"cwd": entry.get("cwd")}))
            continue
        kind, entry_id = entry.get("type"), entry.get("id") or f"line:{number}"
        if kind == "model_change":
            session.model = entry.get("modelId")
            session.events.append(Event("model.change", entry_id, _line_hash(line), when, {
                "provider": entry.get("provider"), "model": entry.get("modelId"), "_model": entry.get("modelId")}))
        elif kind == "compaction":
            session.events.append(Event("compaction", entry_id, _line_hash(line), when,
                                        {"tokens_before": entry.get("tokensBefore")
                                         if type(entry.get("tokensBefore")) is int else None}))
        elif kind == "message" and isinstance(entry.get("message"), dict):
            message = entry["message"]
            role, content = message.get("role"), message.get("content")
            parts = content if isinstance(content, list) else [{"type": "text", "text": content}]
            text = "\n".join(str(p.get("text", "")) for p in parts if isinstance(p, dict) and p.get("type") == "text")
            if role == "user":
                session.events.append(Event("prompt", entry_id, _line_hash(line), when, {
                    "prompt_sha256": value_hash(text), "prompt_excerpt": excerpt(text, excerpt_chars)}))
            elif role == "assistant":
                if text:
                    session.events.append(Event("message", f"{entry_id}:text", _line_hash(line, "text"), when,
                                                {"role": "assistant", "text_sha256": value_hash(text)}))
                for part in parts:
                    if isinstance(part, dict) and part.get("type") == "toolCall":
                        tool_names[part.get("id")] = part.get("name")
                        tool = {"name": part.get("name"), "use_id": part.get("id"),
                                "input_sha256": value_hash(part.get("arguments")),
                                "input_excerpt": excerpt(part.get("arguments"), excerpt_chars)}
                        session.events.append(Event("tool.call", f"{entry_id}:tool:{part.get('id')}",
                                                    _line_hash(line, f"tool:{part.get('id')}"), when,
                                                    {"tool": {k: v for k, v in tool.items() if v is not None}},
                                                    _tool_subject(part.get("id"))))
            elif role == "toolResult":
                use_id = message.get("toolCallId")
                tool = {"name": message.get("toolName") or tool_names.get(use_id), "use_id": use_id,
                        "output_sha256": value_hash(content), "is_error": message.get("isError") is True}
                session.events.append(Event("tool.result", entry_id, _line_hash(line), when,
                                            {"tool": {k: v for k, v in tool.items() if v is not None}},
                                            _tool_subject(use_id)))
    if session.id is None:
        raise ImportError_(f"{path}: empty pi session")
    return session


READERS = {"claude-code": claude_session, "codex": codex_rollout, "pi": pi_session}


def known_source_hashes(records) -> set[str]:
    hashes = set()
    for record in records:
        if isinstance(record, dict) and record.get("type") == "trail.import":
            value = (record.get("data") or {}).get("source_hash")
            if isinstance(value, str):
                hashes.add(value)
    return hashes
