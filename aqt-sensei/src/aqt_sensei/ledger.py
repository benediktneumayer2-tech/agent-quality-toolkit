"""The advice ledger: `sensei.*` evidence records written through `open_sink()`.

Texts never go into records: a record carries the sha256 of the text and an
excerpt of at most 280 characters. Owner decisions are record-first (if the
sink refuses, the caller must not apply the decision; an unreachable aqt-trail
spools durably and the decision proceeds); automatic events are
spooled locally and retried, so nothing is silently lost.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from aqt_evidence import SinkError, actor, bytes_hash, canonical_json, new_record, open_sink, subject

EXCERPT = 280
FILE_HASH_LIMIT = 16 * 1024 * 1024
SERVICE = actor("service", "service:aqt-sensei", role="bridge")
HARNESS = {"claude": "claude-code", "codex": "codex", "pi": "pi"}


class LedgerError(RuntimeError):
    pass


def text_hash(text: str) -> str:
    return bytes_hash(text.encode("utf-8"))


def excerpt(text: str, limit: int = EXCERPT) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def file_refs(paths: list[str]) -> list[dict]:
    refs = []
    for path in paths:
        digest = None
        try:
            if os.path.getsize(path) <= FILE_HASH_LIMIT:
                digest = bytes_hash(Path(path).read_bytes())
        except OSError:
            pass
        refs.append({"path": path, "sha256": digest})
    return refs


def agent_actor(pair: dict, role: str) -> dict:
    member = pair[role]
    harness = HARNESS.get(member.get("platform") or "", member.get("platform") or "agent")
    ref = member.get("session") or f"{pair['id']}-{role}"
    return actor("agent", f"agent:{harness}:{ref}", role="worker" if role == "worker" else "advisor",
                 harness=harness, model=member.get("model"), session=member.get("session"))


class Ledger:
    def __init__(self, *, sink_spec: str | None, spool: Path, owner_id: str, owner_display: str | None = None):
        self.sink_spec = sink_spec
        self.spool = Path(spool)
        self.owner = actor("human", owner_id, role="owner", display=owner_display)

    # -- writing
    def _sink(self):
        return open_sink(self.sink_spec)

    def write(self, record: dict) -> dict:
        """Write now or raise LedgerError (for owner decisions: record first)."""
        try:
            return self._sink().append(record)
        except (SinkError, OSError) as error:
            raise LedgerError(f"the evidence sink refused the record: {error}") from error

    def write_or_spool(self, record: dict) -> bool:
        """Write, or keep the record in the local spool; True if written."""
        if self.pending():
            self.drain()
        if not self.pending():
            try:
                self._sink().append(record)
                return True
            except (SinkError, OSError):
                pass
        self.spool.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.spool, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as handle:
            handle.write(canonical_json(record) + b"\n")
        return False

    def pending(self) -> int:
        try:
            return sum(1 for line in self.spool.read_bytes().splitlines() if line.strip())
        except OSError:
            return 0

    def drain(self) -> int:
        """Send spooled records in order; stop at the first failure. Returns how many remain."""
        try:
            lines = [line for line in self.spool.read_bytes().splitlines() if line.strip()]
        except OSError:
            return 0
        sent = 0
        for line in lines:
            try:
                self._sink().append(json.loads(line))
            except (SinkError, OSError, ValueError):
                break
            sent += 1
        rest = lines[sent:]
        temporary = self.spool.with_suffix(".tmp")
        temporary.write_bytes(b"".join(line + b"\n" for line in rest))
        os.replace(temporary, self.spool)
        return len(rest)

    # -- building
    @staticmethod
    def _pair_subject(pair: dict) -> dict:
        return subject("sensei-pair", pair["id"])

    def pair_record(self, pair: dict, action: str, *, by_owner: bool, reason: str | None = None,
                    before: dict | None = None, after: dict | None = None, extra: dict | None = None,
                    peer: dict | None = None) -> dict:
        data = {
            "pair_id": pair["id"], "backend": pair["backend"], "state": pair["state"], "mode": pair["mode"],
            "budget": pair["budget"], "used": pair["used"], "network": pair.get("network"),
            "independence": pair.get("independence"),
            "worker": {k: pair["worker"].get(k) for k in ("pane_id", "platform", "model")},
            "advisor": {k: pair["advisor"].get(k) for k in ("pane_id", "platform", "model", "profile")},
            "profile_sha256": pair.get("profile_sha256"), "sandbox_argv_sha256": pair.get("sandbox_argv_sha256"),
            "project_sha256": text_hash(pair["project_root"]),
        }
        if peer:
            data["peer"] = peer
        data.update(extra or {})
        return new_record("sensei.pair", self.owner if by_owner else SERVICE, action,
                          subject=self._pair_subject(pair), reason=reason, data=data,
                          before={"value": before} if before is not None else None,
                          after={"value": after} if after is not None else None)

    def message_record(self, pair: dict, message: dict, action: str, *, peer: dict | None = None,
                       rendered: str | None = None) -> dict:
        sender = message["from"]
        who = (agent_actor(pair, sender) if sender in ("worker", "advisor")
               else self.owner if sender == "owner" else SERVICE)
        data = {
            "pair_id": pair["id"], "message_id": message["id"], "seq": message["seq"], "from": sender,
            "to": message["to"], "kind": message["kind"], "exchange": message.get("exchange"),
            "state": message["state"], "excerpt": excerpt(message["text"]),
            "files": file_refs(message.get("files") or []), "attempts": message.get("attempts", 0),
            "edited": message.get("edited", False),
        }
        if message.get("digest"):
            data["digest_sha256"] = text_hash(message["digest"])
        if rendered is not None:
            data["rendered_sha256"] = text_hash(rendered)
        if peer:
            data["peer"] = peer
        return new_record("sensei.message", who, action,
                          subject=subject("sensei-message", message["id"], sha256=text_hash(message["text"])),
                          links=[{"rel": "pair", "ref": pair["id"]}], data=data)

    def decision_record(self, pair: dict, message: dict, decision: str, *, reason: str,
                        before_text: str | None = None, peer: dict | None = None) -> dict:
        meaning = {"approve": "approved", "edit": "approved", "discard": "rejected", "forward": "released"}[decision]
        data = {"decision": decision, "message_id": message["id"], "pair_id": pair["id"],
                "kind": message["kind"], "from": message["from"], "to": message["to"]}
        if peer:
            data["peer"] = peer
        before = after = None
        if before_text is not None:
            before = {"sha256": text_hash(before_text), "value": excerpt(before_text)}
            after = {"sha256": text_hash(message["text"]), "value": excerpt(message["text"])}
        action = {"approve": "approved", "edit": "edited", "discard": "discarded", "forward": "forwarded"}[decision]
        return new_record("sensei.decision", self.owner, action,
                          subject=subject("sensei-message", message["id"], sha256=text_hash(message["text"])),
                          reason=reason, meaning=meaning, before=before, after=after,
                          links=[{"rel": "pair", "ref": pair["id"]}], data=data)

    def budget_record(self, pair: dict, action: str, *, by_owner: bool = False, reason: str | None = None,
                      extra: dict | None = None) -> dict:
        data = {"pair_id": pair["id"], "messages_used": pair["used"]["messages"],
                "exchanges_used": pair["used"]["exchanges"], "cost_used": pair["used"]["cost"],
                **pair["budget"], "mode": pair["mode"]}
        data.update(extra or {})
        return new_record("sensei.budget", self.owner if by_owner else SERVICE, action,
                          subject=self._pair_subject(pair), reason=reason, data=data)

    def refused_record(self, claimed: dict, attempted: str, reason_code: str, *, peer: dict | None,
                       markers: list[str] | None, pair_id: str | None = None, message: str | None = None) -> dict:
        data = {"attempted_action": attempted, "reason_code": reason_code, "agent_markers": markers or []}
        if pair_id:
            data["pair_id"] = pair_id
        if peer:
            data["peer"] = peer
        return new_record("sensei.refused", claimed, "refused",
                          subject=subject("sensei-operation", attempted), reason=message, data=data)
