"""Trail view: compact record index, background verification, ALCOA++ and writer state.

Reads only. The trail file is parsed incrementally from the last offset into compact rows
(seq, id, type, actor, time, subject); a full record is read from its byte offset on demand.
Verification and the ALCOA++ report run in a background thread at start and on demand and
are cached with the record count they covered.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aqt_evidence import SinkError, spool_file

REASON_CHARS = 200


def _now() -> datetime:
    return datetime.now(UTC)


def parse_time(value) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def compact(record: dict, offset: int, length: int) -> dict:
    """The fields the list, filters and "Needs you" rules need; same keys as a record, so
    ``aqt_trail.export.select`` works on it."""
    who = record.get("actor") if isinstance(record.get("actor"), dict) else {}
    observed = record.get("observed") if isinstance(record.get("observed"), dict) else {}
    sub = record.get("subject") if isinstance(record.get("subject"), dict) else {}
    agent = who.get("agent") if isinstance(who.get("agent"), dict) else {}
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    return {
        "id": record.get("id"), "time": str(record.get("time", "")), "type": str(record.get("type", "")),
        "action": str(record.get("action", "")),
        "actor": {"id": who.get("id", ""), "kind": who.get("kind", ""), "display": who.get("display"),
                  "agent": {"session": agent.get("session")} if agent else None},
        "subject": {"kind": sub.get("kind"), "ref": sub.get("ref")} if sub else None,
        "chain": {"seq": (record.get("chain") or {}).get("seq")},
        "observed": {"harness": observed.get("harness"), "via": observed.get("via"),
                     "chain": (observed.get("process_chain") or [])[:6]},
        "meaning": record.get("meaning"),
        "reason": str(record.get("reason") or "")[:REASON_CHARS],
        "reason_code": data.get("reason_code") if str(record.get("type", "")).endswith(".refused") else None,
        "signed": isinstance(data.get("signature"), dict),
        "_off": offset, "_len": length,
    }


class TrailIndex:
    """Incremental, append-only reader of one trail file."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.rows: list[dict] = []
        self.offset = 0
        self.identity: tuple | None = None
        self.unreadable: str | None = None
        self.lock = threading.Lock()

    def refresh(self) -> list[dict]:
        with self.lock:
            try:
                info = self.path.stat()
            except FileNotFoundError:
                self.rows, self.offset, self.identity = [], 0, None
                return self.rows
            identity = (info.st_ino, info.st_dev)
            if identity != self.identity or info.st_size < self.offset:
                self.rows, self.offset, self.identity = [], 0, identity   # new or rewritten file
            if info.st_size == self.offset:
                return self.rows
            with open(self.path, "rb") as handle:
                handle.seek(self.offset)
                position = self.offset
                for line in handle:
                    if not line.endswith(b"\n"):
                        break                       # a record being written; read it next time
                    if line.strip():
                        try:
                            record = json.loads(line)
                            self.rows.append(compact(record, position, len(line)))
                        except ValueError:
                            self.unreadable = f"byte {position}: line is not valid JSON"
                    position += len(line)
                self.offset = position
            return self.rows

    def full(self, row: dict) -> dict:
        with open(self.path, "rb") as handle:
            handle.seek(row["_off"])
            return json.loads(handle.read(row["_len"]))

    def find(self, key: str) -> dict | None:
        rows = self.refresh()
        for row in rows:
            if row["id"] == key or str(row["chain"].get("seq")) == key:
                return self.full(row)
        return None


def public_row(row: dict) -> dict:
    return {key: value for key, value in row.items() if not key.startswith("_")}


class TrailView:
    def __init__(self):
        from aqt_trail.config import load_config
        self.config = load_config()
        self.index = TrailIndex(self.config.trail_path)
        self.check: dict | None = None          # last verification + ALCOA++ result
        self.running = False
        self._lock = threading.Lock()

    # -- writer and spool --------------------------------------------------------------------------
    def writer(self) -> dict:
        from aqt_trail.client import request
        state = {"socket": str(self.config.socket_path), "running": False, "head_seq": None}
        try:
            response = request(self.config.socket_path, {"op": "head"}, timeout=1.5)
            state.update(running=bool(response.get("ok")), head_seq=response.get("seq"))
        except (SinkError, OSError, ValueError):
            pass
        state["spooled"] = _count_lines(spool_file())
        return state

    # -- verification ----------------------------------------------------------------------------------
    def verify_now(self, wait: bool = False) -> bool:
        """Start a full verification in the background; False if one is already running."""
        with self._lock:
            if self.running:
                return False
            self.running = True
        thread = threading.Thread(target=self._verify, daemon=True, name="aqt-ui-verify")
        thread.start()
        if wait:
            thread.join()
        return True

    def _verify(self) -> None:
        started = time.monotonic()
        try:
            self.check = self._run_check()
        except Exception as error:  # noqa: BLE001 - shown in the UI, never crashes the server
            self.check = {"ok": False, "error": f"{type(error).__name__}: {error}", "checked_at": _stamp(),
                          "count": 0, "alcoa": []}
        finally:
            if self.check is not None:
                self.check["seconds"] = round(time.monotonic() - started, 2)
            self.running = False

    def _run_check(self) -> dict:
        from aqt_trail.alcoa import alcoa_report, export_dry_run
        from aqt_trail.signers import load_registry, registry_keys
        from aqt_trail.state import read_records, service_keys
        from aqt_trail.tsa import load_ca
        from aqt_trail.verify import verify_trail
        config = self.config
        if not config.trail_path.exists():
            return {"ok": False, "missing": True, "checked_at": _stamp(), "count": 0, "alcoa": [],
                    "summary": f"no trail at {config.state}", "problems": [], "warnings": []}
        try:
            signer_keys = registry_keys(load_registry())
        except (ValueError, OSError):
            signer_keys = {}
        ca_path = config.section("anchor").get("tsa_ca")
        log_id = config.meta()["log_id"] if config.meta_path.exists() else None
        report = verify_trail(config.trail_path, keys=service_keys(config), checkpoints=config.checkpoints_path,
                              tsa_ca=load_ca(ca_path) if ca_path else None, signer_keys=signer_keys, log_id=log_id)
        records = read_records(config.trail_path) if report.first_bad_seq is None else []
        alcoa = []
        if records:
            params = config.section("review")
            alcoa = alcoa_report(records, report, skew_ms=int(params["skew_ms"]),
                                 unanchored_hours=int(params["unanchored_hours"]),
                                 export_check=lambda: export_dry_run(config))
        return {"ok": report.ok, "summary": report.summary(), "count": report.count, "head_seq": report.head_seq,
                "head": report.head, "first_bad_seq": report.first_bad_seq, "reason": report.reason,
                "problems": report.problems, "warnings": report.warnings, "log_id": log_id,
                "signatures": report.signatures, "anchors": report.anchors, "checked_at": _stamp(), "alcoa": alcoa}

    # -- status band -----------------------------------------------------------------------------------
    def status(self) -> dict:
        rows = self.index.refresh()
        anchors = [row for row in rows if row["type"] == "trail.anchor"]
        reviews = [row for row in rows if row["type"] == "trail.review"]
        check = self.check
        if not self.config.trail_path.exists():
            state = "missing"
        elif check is None or check.get("error"):
            state = "unverified"
        elif check.get("first_bad_seq") is not None:
            state = "broken"
        elif not check.get("ok"):
            state = "problems"
        else:
            state = "intact"
        unverified = max(0, len(rows) - (check or {}).get("count", 0)) if state in ("intact", "problems") else 0
        return {
            "state": state, "records": len(rows), "head_seq": rows[-1]["chain"]["seq"] if rows else None,
            "path": str(self.config.trail_path), "log_id": (check or {}).get("log_id"),
            "check": {k: v for k, v in (check or {}).items() if k != "alcoa"} or None,
            "verifying": self.running, "appended_since_check": unverified,
            "last_anchor": anchors[-1]["time"] if anchors else None,
            "last_review": reviews[-1]["time"] if reviews else None,
            "writer": self.writer(), "unreadable": self.index.unreadable,
        }

    def alcoa(self) -> list[dict]:
        return list((self.check or {}).get("alcoa") or [])

    # -- list ------------------------------------------------------------------------------------------
    def records(self, *, since=None, until=None, type=None, actor=None, action=None, subject=None, session=None,
                limit: int = 300, before: int | None = None) -> dict:
        from aqt_trail.export import select
        rows = self.index.refresh()
        chosen = select(rows, since=since or None, until=until or None, type=type or None, actor=actor or None,
                        action=action or None, subject=subject or None, session=session or None)
        if before is not None:
            chosen = [row for row in chosen if (row["chain"].get("seq") or 0) < before]
        newest = list(reversed(chosen))[:limit]
        types = sorted({row["type"] for row in rows})
        return {"total": len(chosen), "rows": [public_row(row) for row in newest], "types": types,
                "more": len(chosen) > limit}

    def record(self, key: str) -> dict | None:
        record = self.index.find(key)
        if record is None:
            return None
        observed = record.get("observed") or {}
        claimed = record.get("actor") or {}
        mismatch = claimed.get("kind") == "human" and bool(observed.get("harness"))
        return {"record": record, "claimed": claimed, "observed": observed, "attribution_mismatch": mismatch}

    def refusals_since(self, hours: int = 24) -> list[dict]:
        cutoff = _now() - timedelta(hours=hours)
        out = []
        for row in self.index.refresh():
            if row["type"].endswith(".refused"):
                moment = parse_time(row["time"])
                if moment and moment >= cutoff:
                    out.append(public_row(row))
        return out


def _count_lines(path: Path) -> int:
    try:
        with open(path, "rb") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def _stamp() -> str:
    return _now().strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = ["TrailIndex", "TrailView", "compact", "parse_time"]
