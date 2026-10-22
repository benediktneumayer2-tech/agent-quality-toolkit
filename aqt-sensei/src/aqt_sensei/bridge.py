"""The bridge: pairs, message queue, owner gate, budgets and delivery.

Adapted from the author's private Agent Platform Next Sensei bridge. The poll
(`tick`) delivers the oldest deliverable message to a pane only while the host
reports it idle or done; a busy or blocked receiver is never typed into.

Callers never reach this class directly: the server checks who is calling and
passes the role and the observed peer (`data.peer`) in.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
import uuid
from pathlib import Path

from aqt_evidence import content_hash

from .config import MODES, Budget, Config, Paths
from .hosts import READY, HostError, TerminalHost, strip_ansi
from .ledger import Ledger, LedgerError
from .sandbox import BUILTIN_PROFILES, SandboxError, build_argv, resolve_cli, resolve_profile, write_shim

DIGEST_CHARS = 4000
WORKER_LOG_CHARS = 20000
RECENT_PER_PAIR = 20
MAX_TEXT = 64 * 1024
MAX_ATTEMPTS = 5
TURN_GRACE_SECONDS = 20
START_GRACE_SECONDS = 180
LIVE = ("starting", "active", "paused")
PENDING = ("queued", "awaiting_approval", "held")
VENDOR = {"claude": "anthropic", "codex": "openai"}


class BridgeError(Exception):
    """A request that cannot be carried out; the message goes back to the caller."""


class Refused(BridgeError):
    """A request from a caller that may not do this; recorded as sensei.refused."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------- store

class Store:
    """pairs.json (atomic replace) plus messages/<pair>.jsonl (every version; last wins)."""

    def __init__(self, folder: Path):
        self.folder = Path(folder)
        self.messages_dir = self.folder / "messages"
        self.messages_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.folder, 0o700)
        self.pairs_path = self.folder / "pairs.json"

    def load(self) -> tuple[dict, dict]:
        pairs = {}
        if self.pairs_path.exists():
            for pair in json.loads(self.pairs_path.read_text()).get("pairs", []):
                pairs[pair["id"]] = pair
        messages = {}
        for log in sorted(self.messages_dir.glob("*.jsonl")):
            for line in log.read_text().splitlines():
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict) and record.get("id"):
                    messages[record["id"]] = record
        return pairs, messages

    def versions(self, pair_id: str, message_id: str) -> list[dict]:
        path = self.messages_dir / f"{pair_id}.jsonl"
        out = []
        for line in path.read_text().splitlines() if path.exists() else []:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("id") == message_id:
                out.append(record)
        return out

    def save_pairs(self, pairs: dict) -> None:
        temporary = self.pairs_path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps({"pairs": list(pairs.values())}, ensure_ascii=False, indent=1))
        os.replace(temporary, self.pairs_path)

    def append(self, message: dict) -> None:
        fd = os.open(self.messages_dir / f"{message['pair_id']}.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as handle:
            handle.write(json.dumps(message, ensure_ascii=False) + "\n")


# --------------------------------------------------------------- rendering

def limits_text(pair: dict) -> str:
    budget = pair["budget"]
    parts = [f"{budget[key]} {key.removeprefix('max_')}" for key in ("max_exchanges", "max_messages", "max_cost")
             if budget.get(key)]
    return ", ".join(parts) or "unlimited"


def header(pair: dict, message: dict, exchange: int | None = None) -> str:
    names = {"worker": "Worker", "advisor": "Sensei", "bridge": "Bridge", "owner": "Owner"}
    sender, receiver = names[message["from"]], names[message["to"]]
    if message["kind"] in ("intro", "notice"):
        tag = message["kind"]
    else:
        number = exchange if exchange is not None else message.get("exchange")
        maximum = pair["budget"].get("max_exchanges")
        tag = f"{number}" + (f"/{maximum}" if maximum else "")
    return f"[{sender} → {receiver} · {tag}]"


def render(pair: dict, message: dict, exchange: int | None = None) -> str:
    if message["kind"] == "prompt":  # the owner's own words, without a header
        return message["text"]
    lines = [header(pair, message, exchange), message["text"].strip()]
    if message.get("files"):
        lines += ["", "Files:", *(f"- {path}" for path in message["files"])]
    if message.get("digest"):
        lines += ["", "Worker context (recent pane output):", message["digest"]]
    if message["to"] == "advisor" and message["kind"] != "prompt":
        lines += ["", 'Answer with `sensei reply "…"` (long content in a scratch file, then --file PATH).']
    return "\n".join(lines)


def intro_text(pair: dict) -> str:
    advisor = pair["advisor"]
    who = advisor.get("platform") or "an agent"
    if advisor.get("model"):
        who += f" ({advisor['model']})"
    approval = {"auto": "Messages are delivered automatically within the budget.",
                "confirm": "The owner approves each message before it is delivered.",
                "manual": "The owner forwards each message by hand."}[pair["mode"]]
    return "\n".join([
        f"A sensei is now paired with you: {who}, in the pane next to yours. It advises and plans; it does not implement.",
        f"Mode: {pair['mode']}. {approval} Budget: {limits_text(pair)}.",
        "When to ask: when you are stuck after reassessing your approach, or at the checkpoints of a plan the sensei sent you.",
        "What to send: the intended behaviour, what you tried and what happened, and the specific help you need.",
        'How: run `aqt-sensei ask "…"` (add --file PATH for logs or notes), then end your turn; the answer arrives as '
        "your next message. `aqt-sensei status` shows the pair.",
        "`aqt-sensei` talks to a local socket: if your shell sandbox blocks it, rerun it with escalated permissions.",
        f"The sensei's plans and reports are files in {pair['scratch_dir']}; you can read them there.",
    ])


def clip_tail(text: str, limit: int) -> str:
    text = strip_ansi(text).strip()
    return text if len(text) <= limit else "…" + text[-limit:]


def independence(worker: dict, advisor: dict) -> str:
    def vendor(member):
        model = member.get("model") or ""
        return VENDOR.get(member.get("platform") or "") or (model.split("/", 1)[0] if "/" in model else None)
    if not worker.get("platform") and not worker.get("model"):
        return "unknown"
    if worker.get("model") and worker.get("model") == advisor.get("model"):
        return "same-model"
    if vendor(worker) and vendor(worker) == vendor(advisor):
        return "same-vendor"
    if vendor(worker) and vendor(advisor):
        return "different-vendor"
    return "unknown"


def positive(value, name: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 1:
        raise BridgeError(f"{name} must be a positive whole number")
    return value


# ------------------------------------------------------------------ bridge

class Bridge:
    def __init__(self, *, paths: Paths, config: Config, host: TerminalHost, ledger: Ledger,
                 clock=time.time, launcher_argv=None, resolve=resolve_cli, on_pair=None, on_end=None):
        self.paths, self.config, self.host, self.ledger = paths, config, host, ledger
        self.clock = clock
        self.launcher_argv = launcher_argv or (lambda pair_id: [sys.executable, "-m", "aqt_sensei", "launch",
                                                                "--pair", pair_id])
        self.resolve = resolve
        self.on_pair = on_pair or (lambda pair_id: None)   # the server opens the advisor socket
        self.on_end = on_end or (lambda pair_id: None)
        paths.ensure()
        self.store = Store(paths.state)
        self.pairs, self.messages = self.store.load()
        self.lock = threading.RLock()
        self.panes: dict = {}

    # -- helpers
    def now_ms(self) -> int:
        return int(self.clock() * 1000)

    def _save(self) -> None:
        self.store.save_pairs(self.pairs)

    def _put(self, message: dict) -> None:
        self.messages[message["id"]] = message
        self.store.append(message)

    def pair(self, pair_id) -> dict:
        pair = self.pairs.get(pair_id)
        if not pair:
            raise BridgeError("unknown pair")
        return pair

    def live_pairs(self) -> list[dict]:
        return [pair for pair in self.pairs.values() if pair["state"] in LIVE]

    def paired_panes(self) -> list:
        """PaneInfo of every live paired pane (for the owner checks)."""
        try:
            self.panes = self.host.panes()
        except HostError:
            pass
        out = []
        for pair in self.live_pairs():
            for role in ("worker", "advisor"):
                pane = self.panes.get(pair[role]["pane_id"])
                if pane:
                    out.append(pane)
        return out

    def worker_for(self, chain: list[int], hint: str | None) -> dict:
        """The live pair whose worker pane's root process is an ancestor of the caller."""
        for attempt in range(2):
            for pair in self.live_pairs():
                pane = self.panes.get(pair["worker"]["pane_id"])
                if pane and pane.root_pid is not None and pane.root_pid in chain:
                    if hint and hint != pane.pane_id:
                        raise Refused("the declared pane does not match the calling process", "pane-mismatch")
                    return pair
            if attempt == 0:
                try:
                    self.panes = self.host.panes()
                except HostError:
                    break
        raise Refused("this process does not run in a paired worker pane", "not-paired")

    def _note(self, pair: dict, note: str | None) -> None:
        if pair.get("note") != note:
            pair["note"] = note
            self._save()

    def _cost(self, pair: dict) -> int:
        return int(pair.get("cost_per_exchange") or 0)

    @staticmethod
    def _opens(message: dict) -> bool:
        return message["from"] in ("worker", "advisor") and (
            message["kind"] in ("ask", "send") or message.get("exchange") is None)

    def _limits_hit(self, pair: dict, message: dict) -> list[str]:
        budget, used, hits = pair["budget"], pair["used"], []
        if budget.get("max_messages") and used["messages"] >= budget["max_messages"]:
            hits.append("messages")
        if self._opens(message) and budget.get("max_exchanges") and used["exchanges"] >= budget["max_exchanges"]:
            hits.append("exchanges")
        if budget.get("max_cost") and used["cost"] >= budget["max_cost"]:
            hits.append("cost")
        return hits

    def _fall_back(self, pair: dict, hits: list[str]) -> None:
        pair["mode"] = "confirm"
        pair["note"] = f"Budget reached ({', '.join(hits)}); the pair is back in confirm mode."
        self._save()
        self.ledger.write_or_spool(self.ledger.budget_record(pair, "reached", extra={
            "limits_hit": hits, "fallback_mode": "confirm"}))
        self.host.notify("Sensei budget reached", f"{pair['name']}: {pair['note']}")

    @staticmethod
    def _gated(message: dict) -> bool:
        return message["from"] in ("worker", "advisor") or message["kind"] == "notice"

    def _gate(self, pair: dict, message: dict) -> bool:
        """True if the message may be delivered now; otherwise it waits (held / awaiting_approval)."""
        if not self._gated(message) or message.get("approved"):
            return True
        if pair["mode"] == "manual":
            if message["state"] != "held":
                message["state"] = "held"
                self._put(message)
            return False
        if pair["mode"] == "auto":
            hits = self._limits_hit(pair, message)
            if hits:
                self._fall_back(pair, hits)
        if pair["mode"] == "auto":
            return True
        if message["state"] != "awaiting_approval":
            message["state"] = "awaiting_approval"
            self._put(message)
        return False

    def enqueue(self, pair: dict, sender: str, receiver: str, kind: str, text: str, files=(),
                peer: dict | None = None, **extra) -> dict:
        seq = 1 + max((m["seq"] for m in self.messages.values() if m["pair_id"] == pair["id"]), default=0)
        message = {"id": "m-" + secrets.token_hex(6), "pair_id": pair["id"], "seq": seq, "from": sender,
                   "to": receiver, "kind": kind, "text": text, "files": list(files), "exchange": None,
                   "state": "queued", "created_at_ms": self.now_ms(), "delivered_at_ms": None, "edited": False,
                   "attempts": 0, **extra}
        if kind == "reply" and pair.get("open_ask"):
            message["exchange"] = pair["open_ask"]["exchange"]
            message["reply_to"] = pair["open_ask"]["id"]
            pair["open_ask"] = None
            self._save()
        self._put(message)
        self._gate(pair, message)
        self.ledger.write_or_spool(self.ledger.message_record(pair, message, "enqueued", peer=peer))
        return message

    # ------------------------------------------------------------ agent ops
    def agent_op(self, role: str, pair: dict, request: dict, peer: dict | None) -> dict:
        op = request.get("op")
        with self.lock:
            if pair["state"] not in LIVE:
                raise BridgeError("the pair has ended")
            if role == "worker" and op == "ask":
                return self._agent_message(pair, "worker", "ask", request, peer)
            if role == "advisor" and op in ("reply", "send"):
                return self._agent_message(pair, "advisor", op, request, peer)
            if op == "status":
                return self._status(pair, role)
            if role == "advisor" and op == "worker_log":
                last = request.get("last") if isinstance(request.get("last"), int) else 200
                text = clip_tail(self._capture(pair["worker"]["pane_id"], max(1, min(last, 2000))), WORKER_LOG_CHARS)
                return {"output": text or "The worker pane is not readable right now."}
        raise Refused(f"the {role} may not use {op!r}", "op-not-allowed")

    def _capture(self, pane_id: str, lines: int) -> str:
        try:
            return self.host.capture(pane_id, lines)
        except (HostError, KeyError):
            return ""

    def _agent_message(self, pair: dict, sender: str, kind: str, request: dict, peer: dict | None) -> dict:
        text = request.get("text")
        if not isinstance(text, str) or not text.strip():
            raise BridgeError("the message text is empty")
        if len(text.encode()) > MAX_TEXT:
            raise BridgeError("the message is too long; write it to a file and add --file PATH")
        files = [f for f in request.get("files") or [] if isinstance(f, str)]
        extra = {}
        if kind == "ask":
            extra["digest"] = clip_tail(self._capture(pair["worker"]["pane_id"], 200), DIGEST_CHARS) or None
        receiver = "advisor" if sender == "worker" else "worker"
        message = self.enqueue(pair, sender, receiver, kind, text, files, peer=peer, **extra)
        if message["state"] == "awaiting_approval":
            sent = "Queued for the owner's approval."
        elif message["state"] == "held":
            sent = "Held for the owner, who forwards messages by hand in manual mode."
        elif pair["state"] == "paused":
            sent = "Queued; the pair is paused, so it is delivered when the owner resumes it."
        else:
            sent = f"Sent; it is delivered as soon as the {'sensei' if receiver == 'advisor' else 'worker'} is idle."
        if kind == "ask":
            sent += " End your turn now; the answer arrives as your next message."
        return {"output": sent, "message_id": message["id"], "state": message["state"]}

    def _status(self, pair: dict, role: str) -> dict:
        pending = sum(1 for m in self.messages.values() if m["pair_id"] == pair["id"] and m["state"] in PENDING)
        used = pair["used"]
        lines = [f"Pair {pair['id']} ({pair['name']}): you are the {'sensei' if role == 'advisor' else role}; "
                 f"state {pair['state']}.",
                 f"Mode {pair['mode']}; used {used['exchanges']} exchanges, {used['messages']} messages, "
                 f"cost {used['cost']}; limits: {limits_text(pair)}; pending messages {pending}.",
                 f"Project: {pair['project_root']}", f"Scratch: {pair['scratch_dir']}"]
        if pair.get("note"):
            lines.append(f"Note: {pair['note']}")
        return {"output": "\n".join(lines)}

    # ------------------------------------------------------------ owner ops
    def owner_op(self, request: dict, peer: dict | None) -> dict:
        op = request.get("op")
        handler = getattr(self, f"op_{op}", None) if isinstance(op, str) else None
        if handler is None:
            raise BridgeError(f"unknown operation: {op}")
        with self.lock:
            return handler(request, peer)

    @staticmethod
    def _reason(request: dict) -> str:
        reason = request.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise BridgeError("a reason is required for this decision (--reason)")
        return reason.strip()

    def op_pair(self, request: dict, peer: dict | None) -> dict:
        reason = self._reason(request)
        worker_pane = request.get("worker")
        if not isinstance(worker_pane, str) or not worker_pane:
            raise BridgeError("--worker PANE is required")
        backend = request.get("backend") or self.host.name
        if backend != self.host.name:
            raise BridgeError(f"this bridge runs the {self.host.name} backend, not {backend}")
        if any(worker_pane in (p["worker"]["pane_id"], p["advisor"]["pane_id"]) for p in self.live_pairs()):
            raise BridgeError("this pane already has a sensei")
        root = request.get("project")
        if not isinstance(root, str) or not os.path.isabs(root) or not os.path.isdir(root):
            raise BridgeError("--project must be an existing absolute folder")
        root = os.path.realpath(root)
        mode = request.get("mode") or self.config.default_mode
        if mode not in MODES:
            raise BridgeError("mode must be manual, confirm or auto")
        limits = {key: positive(request.get(key), key) for key in ("max_messages", "max_exchanges", "max_cost")}
        if mode == "auto" and not any(limits.values()):
            limits = self.config.auto_budget.as_dict()
        network = request.get("network") or self.config.network
        if network not in ("share", "none"):
            raise BridgeError("network must be share or none")
        start_with = request.get("start_with") or "worker"
        if start_with not in ("worker", "advisor"):
            raise BridgeError("start_with must be worker or advisor")
        try:
            profile = resolve_profile(request.get("advisor") or "", self.config.profiles)
            cli_path, cli_binds = self.resolve(profile.command[0])
        except SandboxError as error:
            raise BridgeError(str(error)) from error
        self.panes = self.host.panes()
        if worker_pane not in self.panes:
            raise BridgeError(f"worker pane {worker_pane} was not found on the {self.host.name} host")

        pair_id = "sp-" + secrets.token_hex(4)
        scratch_root = Path(os.path.expanduser(self.config.scratch_root))
        scratch = (scratch_root if scratch_root.is_absolute() else Path(root) / scratch_root) / pair_id
        scratch.mkdir(parents=True, exist_ok=True)
        if not (scratch / ".gitignore").exists():
            (scratch / ".gitignore").write_text("*\n")
        worker_info = self.panes[worker_pane]
        worker = {"pane_id": worker_pane, "platform": request.get("worker_platform"),
                  "model": request.get("worker_model"), "session": worker_info.session}
        advisor = {"pane_id": None, "platform": profile.platform, "profile": profile.name,
                   "model": request.get("model"),
                   "session": str(uuid.uuid4()) if profile.platform == "claude" else None}
        pair = {"id": pair_id, "name": request.get("name") or worker_info.title or f"Sensei {pair_id}",
                "backend": self.host.name, "project_root": root, "scratch_dir": str(scratch), "mode": mode,
                "budget": limits, "used": {"messages": 0, "exchanges": 0, "cost": 0},
                "cost_per_exchange": profile.cost_per_exchange, "state": "starting", "note": None,
                "open_ask": None, "turns": {}, "created_at_ms": self.now_ms(), "advisor_seen": False,
                "network": network, "worker": worker, "advisor": advisor,
                "independence": independence(worker, advisor), "profile": profile.as_dict(),
                "profile_sha256": profile.sha256()}
        runtime = self.paths.pair_runtime(pair_id)
        runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_shim(runtime / "bin")
        self.paths.home(profile.platform if profile.platform != "custom" else f"custom-{profile.name}").mkdir(
            parents=True, exist_ok=True, mode=0o700)
        env = {**self.paths.env(), "AQT_AGENT_SESSION": "1"}
        advisor["pane_id"] = self.host.split(worker_pane, str(scratch), env)
        pair["sandbox_argv_sha256"] = content_hash(build_argv(
            pair, profile, paths=self.paths, config=self.config, cli_path=cli_path, cli_binds=cli_binds))
        try:
            self.ledger.write(self.ledger.pair_record(pair, "attached", by_owner=True, reason=reason, peer=peer))
        except LedgerError:
            self._close_quietly(advisor["pane_id"])
            raise
        self.pairs[pair_id] = pair
        self._save()
        self.on_pair(pair_id)
        self.host.set_prompt_pattern(advisor["pane_id"], profile.prompt_pattern)
        worker_profile = BUILTIN_PROFILES.get(worker.get("platform") or "")
        self.host.set_prompt_pattern(worker_pane, worker_profile.get("prompt_pattern") if worker_profile else None)
        try:
            self.host.run(advisor["pane_id"], self.launcher_argv(pair_id))
        except HostError as error:
            pair["state"], pair["note"] = "ended", "The sensei could not be launched."
            self._save()
            self.ledger.write_or_spool(self.ledger.pair_record(pair, "ended", by_owner=False,
                                                               reason=f"launch failed: {error}"))
            self._close_quietly(advisor["pane_id"])
            self.on_end(pair_id)
            raise BridgeError(f"the sensei could not be launched: {error}") from error
        self.enqueue(pair, "bridge", "worker", "intro", intro_text(pair))
        prompt = (request.get("first_prompt") or "").strip()
        if prompt and start_with == "advisor":
            self.enqueue(pair, "owner", "advisor", "prompt", (
                "The owner asks you to plan this work before the worker starts. Write the plan as a file in your "
                'scratch folder and send it to the worker with `sensei send "…" --file PLAN.md`.\n\n' + prompt))
        elif prompt:
            self.enqueue(pair, "owner", "worker", "prompt", prompt)
        return {"pair_id": pair_id, "pair": pair}

    def _close_quietly(self, pane_id: str | None) -> None:
        if pane_id:
            try:
                self.host.close(pane_id)
            except HostError:
                pass

    def op_list(self, request: dict, peer: dict | None) -> dict:
        wanted = request.get("pair_id")
        messages, done = [], {}
        for message in sorted(self.messages.values(), key=lambda m: (m["pair_id"], -m["seq"])):
            if wanted and message["pair_id"] != wanted:
                continue
            if message["state"] in PENDING:
                messages.append(message)
            elif done.get(message["pair_id"], 0) < RECENT_PER_PAIR:
                done[message["pair_id"]] = done.get(message["pair_id"], 0) + 1
                messages.append(message)
        messages.sort(key=lambda m: (m["pair_id"], m["seq"]))
        pairs = [p for p in sorted(self.pairs.values(), key=lambda p: p.get("created_at_ms", 0))
                 if not wanted or p["id"] == wanted]
        return {"pairs": pairs, "messages": messages, "ledger_pending": self.ledger.pending()}

    def _message(self, message_id) -> tuple[dict, dict]:
        message = self.messages.get(message_id)
        if not message:
            raise BridgeError("unknown message")
        return message, self.pair(message["pair_id"])

    def op_show(self, request: dict, peer: dict | None) -> dict:
        message, pair = self._message(request.get("message_id"))
        exchange = message.get("exchange")
        if exchange is None and self._opens(message):
            exchange = pair["used"]["exchanges"] + 1
        texts = []
        for version in self.store.versions(pair["id"], message["id"]):
            if not texts or texts[-1] != version["text"]:
                texts.append(version["text"])
        return {"message": message, "rendered": render(pair, message, exchange), "versions": texts}

    def _decide(self, request: dict, peer: dict | None, decision: str, allowed: tuple) -> dict:
        reason = self._reason(request)
        message, pair = self._message(request.get("message_id"))
        if message["state"] not in allowed:
            if message["state"] == "held" and decision in ("approve", "edit"):
                raise BridgeError("the message is held in manual mode; use forward")
            raise BridgeError(f"the message is {message['state']}")
        updated = dict(message)
        before = None
        if decision in ("approve", "edit"):
            text = request.get("text")
            if isinstance(text, str) and text.strip() and text != message["text"]:
                if len(text.encode()) > MAX_TEXT:
                    raise BridgeError("the edited text is too long")
                decision, before = "edit", message["text"]
                updated.update(text=text, edited=True)
            updated.update(state="queued", approved=True)
        elif decision == "forward":
            updated.update(state="queued", approved=True)
        else:
            updated.update(state="discarded")
        self.ledger.write(self.ledger.decision_record(pair, updated, decision, reason=reason,
                                                      before_text=before, peer=peer))
        updated.update(decided_by=self.ledger.owner["id"], decided_at_ms=self.now_ms(), decision=decision,
                       decision_reason=reason)
        self._put(updated)
        if decision == "discard" and (pair.get("open_ask") or {}).get("id") == message["id"]:
            pair["open_ask"] = None
            self._save()
        return {"message": updated}

    def op_approve(self, request, peer):
        return self._decide(request, peer, "approve", ("awaiting_approval",))

    def op_forward(self, request, peer):
        return self._decide(request, peer, "forward", ("held", "awaiting_approval"))

    def op_discard(self, request, peer):
        return self._decide(request, peer, "discard", PENDING)

    def _live(self, request) -> dict:
        pair = self.pair(request.get("pair_id"))
        if pair["state"] == "ended":
            raise BridgeError("the pair has ended")
        return pair

    def op_mode(self, request, peer):
        reason = self._reason(request)
        pair = self._live(request)
        mode = request.get("mode")
        if mode not in MODES:
            raise BridgeError("mode must be manual, confirm or auto")
        before = pair["mode"]
        if mode == before:
            return {"pair": pair}
        pair_after = {**pair, "mode": mode}
        self.ledger.write(self.ledger.pair_record(pair_after, "updated", by_owner=True, reason=reason,
                                                  before={"mode": before}, after={"mode": mode}, peer=peer))
        pair["mode"] = mode
        if mode == "auto":  # release messages waiting for approval; manual-held ones stay held
            for message in list(self.messages.values()):
                if message["pair_id"] == pair["id"] and message["state"] == "awaiting_approval":
                    self._put({**message, "state": "queued"})
            if (pair.get("note") or "").startswith("Budget reached"):
                pair["note"] = None
        self._save()
        return {"pair": pair}

    def op_budget(self, request, peer):
        reason = self._reason(request)
        pair = self._live(request)
        before = dict(pair["budget"])
        budget = dict(before) if not request.get("clear") else Budget().as_dict()
        for key in ("max_messages", "max_exchanges", "max_cost"):
            if request.get(key) is not None:
                budget[key] = positive(request[key], key)
        add = request.get("add_cost")
        if add is not None and (type(add) is not int or add < 0):
            raise BridgeError("add_cost must be a whole number ≥ 0")
        action = "cost-added" if add and budget == before else "set"
        record_pair = {**pair, "budget": budget, "used": {**pair["used"], "cost": pair["used"]["cost"] + (add or 0)}}
        self.ledger.write(self.ledger.budget_record(record_pair, action, by_owner=True, reason=reason,
                                                    extra={"before": before, "added_cost": add or 0}))
        pair["budget"], pair["used"] = budget, record_pair["used"]
        self._save()
        return {"pair": pair}

    def op_pause(self, request, peer):
        pair = self._live(request)
        reason = request.get("reason") or "paused by the owner"
        self.ledger.write(self.ledger.pair_record({**pair, "state": "paused"}, "paused", by_owner=True,
                                                  reason=reason, peer=peer))
        pair["state"] = "paused"
        self._save()
        return {"pair": pair}

    def op_resume(self, request, peer):
        pair = self._live(request)
        if pair["state"] != "paused":
            return {"pair": pair}
        state = "active" if pair.get("advisor_seen") else "starting"
        reason = request.get("reason") or "resumed by the owner"
        self.ledger.write(self.ledger.pair_record({**pair, "state": state}, "resumed", by_owner=True,
                                                  reason=reason, peer=peer))
        pair["state"], pair["note"] = state, None
        self._save()
        return {"pair": pair}

    def op_end(self, request, peer):
        reason = self._reason(request)
        pair = self.pair(request.get("pair_id"))
        if pair["state"] == "ended":
            return {"pair": pair}
        self.ledger.write(self.ledger.pair_record({**pair, "state": "ended"}, "ended", by_owner=True,
                                                  reason=reason, peer=peer))
        pair["state"], pair["open_ask"], pair["turns"] = "ended", None, {}
        self._save()
        for message in list(self.messages.values()):
            if message["pair_id"] == pair["id"] and message["state"] in PENDING:
                self._put({**message, "state": "discarded"})
        self._close_quietly(pair["advisor"]["pane_id"])
        self.on_end(pair["id"])
        return {"pair": pair}

    def op_record_doctor(self, request, peer):
        """Record a doctor result for a pair (the CLI runs the probe)."""
        pair = self.pair(request.get("pair_id"))
        result = request.get("doctor")
        if not isinstance(result, dict):
            raise BridgeError("doctor result missing")
        checks = [{"name": c.get("name"), "passed": bool(c.get("passed"))} for c in result.get("checks", [])
                  if isinstance(c, dict)]
        self.ledger.write(self.ledger.pair_record(pair, "doctor", by_owner=True, reason="sandbox check",
                                                  extra={"doctor": {"checks": checks,
                                                                    "passed": all(c["passed"] for c in checks)}},
                                                  peer=peer))
        return {"recorded": True}

    # ------------------------------------------------------------- the poll
    def tick(self) -> None:
        try:
            panes = self.host.panes()
        except HostError:
            return
        with self.lock:
            self.panes = panes
            if self.ledger.pending():
                self.ledger.drain()
            for pair in self.live_pairs():
                self._watch(pair)
            for pair in self.live_pairs():
                self._finish_turns(pair)
            for pair in self.live_pairs():
                if pair["state"] in ("starting", "active"):
                    for role in ("worker", "advisor"):
                        self._deliver(pair, role)

    def _watch(self, pair: dict) -> None:
        changed = False
        for role in ("worker", "advisor"):
            member = pair[role]
            pane = self.panes.get(member["pane_id"])
            if pane is None and member.get("session"):  # e.g. after a host restart
                pane = next((p for p in self.panes.values() if p.session == member["session"]), None)
                if pane:
                    pair["turns"].pop(member["pane_id"], None)
                    member["pane_id"], changed = pane.pane_id, True
            if pane is None:
                if pair["state"] != "paused":
                    pair["state"] = "paused"
                    pair["note"] = f"The {role} pane {member['pane_id']} is gone; the pair is paused."
                    self.ledger.write_or_spool(self.ledger.pair_record(pair, "paused", by_owner=False,
                                                                       reason=pair["note"]))
                    changed = True
                continue
            if pane.session and pane.session != member.get("session"):
                member["session"], changed = pane.session, True
        advisor = self.panes.get(pair["advisor"]["pane_id"])
        if pair["state"] == "starting":
            if advisor and advisor.agent:
                pair["state"], pair["advisor_seen"], changed = "active", True, True
                if (pair.get("note") or "").startswith("The sensei has not started"):
                    pair["note"] = None
            elif self.now_ms() - pair["created_at_ms"] > START_GRACE_SECONDS * 1000 and not pair.get("note"):
                pair["note"], changed = "The sensei has not started yet; check its pane.", True
        if changed:
            self._save()

    def _finish_turns(self, pair: dict) -> None:
        for pane_id, turn in list(pair["turns"].items()):
            pane = self.panes.get(pane_id)
            if pane is None:
                del pair["turns"][pane_id]
                self._save()
            elif pane.status in ("working", "blocked"):
                if not turn["working"]:
                    turn["working"] = True
                    self._save()
            elif pane.status in READY and (turn["working"] or self.now_ms() - turn["at_ms"] > TURN_GRACE_SECONDS * 1000):
                del pair["turns"][pane_id]
                self._save()
                if turn.get("ask") and (pair.get("open_ask") or {}).get("id") == turn["ask"]:
                    self._no_reply(pair, turn)

    def _no_reply(self, pair: dict, turn: dict) -> None:
        ask = self.messages.get(turn["ask"])
        exchange = pair["open_ask"]["exchange"]
        pair["open_ask"] = None
        pair["note"] = f"The sensei ended its turn without replying to exchange {exchange}."
        self._save()
        if ask:
            self.ledger.write_or_spool(self.ledger.message_record(pair, {**ask, "state": "no-reply"}, "no-reply"))
        self.enqueue(pair, "bridge", "worker", "notice",
                     f"The sensei ended its turn without replying to exchange {exchange}. Continue without its "
                     "answer, or ask again with a narrower question.")

    def _deliver(self, pair: dict, role: str) -> None:
        member = pair[role]
        pane = self.panes.get(member["pane_id"])
        if member["pane_id"] in pair["turns"] or not pane or not pane.agent or pane.status not in READY:
            return
        if role == "advisor" and pair["state"] != "active":
            return
        waiting = sorted((m for m in self.messages.values()
                          if m["pair_id"] == pair["id"] and m["to"] == role and m["state"] == "queued"),
                         key=lambda m: m["seq"])
        for message in waiting:
            if not self._gate(pair, message):
                continue
            opens = self._opens(message)
            exchange = pair["used"]["exchanges"] + 1 if opens else message.get("exchange")
            text = render(pair, message, exchange)
            try:
                self.host.deliver(member["pane_id"], text)
            except HostError as error:
                message = {**message, "attempts": message.get("attempts", 0) + 1}
                if message["attempts"] >= MAX_ATTEMPTS:
                    message["state"] = "failed"
                    self._note(pair, f"A message to the {role} could not be delivered: {error}")
                    self.ledger.write_or_spool(self.ledger.message_record(pair, message, "failed"))
                self._put(message)
                return
            message = {**message, "exchange": exchange, "state": "delivered", "delivered_at_ms": self.now_ms()}
            if message["from"] in ("worker", "advisor"):
                pair["used"]["messages"] += 1
            if opens:
                pair["used"]["exchanges"] = exchange
                pair["used"]["cost"] += self._cost(pair)
                if message["kind"] == "ask":
                    pair["open_ask"] = {"id": message["id"], "exchange": exchange}
            self._put(message)
            pair["turns"][member["pane_id"]] = {"at_ms": self.now_ms(), "working": False,
                                                "ask": message["id"] if message["kind"] == "ask" else None}
            self._save()
            self.ledger.write_or_spool(self.ledger.message_record(pair, message, "delivered", rendered=text))
            if opens:
                self.ledger.write_or_spool(self.ledger.budget_record(pair, "consumed", extra={"exchange": exchange}))
            if (pair["mode"] == "auto" and message["kind"] == "reply" and not opens
                    and pair["budget"].get("max_exchanges")
                    and pair["used"]["exchanges"] >= pair["budget"]["max_exchanges"]):
                self._fall_back(pair, ["exchanges"])
            return
