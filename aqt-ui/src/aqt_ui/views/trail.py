"""Trail view: compact record index, background verification, ALCOA++ and writer state.

Reads only. The trail file is parsed incrementally from the last offset into compact rows
(seq, id, type, actor, time, subject); a full record is read from its byte offset on demand.
Verification and the ALCOA++ report run in a background thread at start and on demand.

A verification result holds only for the bytes it covered: before each check the file's
identity, size and a SHA-256 of its content are noted, and the status shows "changed" instead
of "intact" as soon as the file was replaced, truncated or those bytes were modified. Records
appended after them count as not yet verified.

An audit-trail review is signed over the worksheet this server prepared and showed: the
worksheet stays in memory with its digest (``aqt_trail.review.worksheet_digest``), which the page
sends back and aqt-trail checks again (``expected_sha256``), so editing the saved
``worksheet.json`` in between changes nothing that is signed.

The record inspector shows how far the writer's observation confirms a human claim, in the
review's words (``aqt_trail.review.attribution``: agent, unconfirmed, legacy, human; a spooled
record's sender was not observed, and ``observed.drained_by`` names who drained it), and a
detached signature only with its ``signature_status`` against the signer registry.

"Last anchor" counts only RFC 3161 anchors the writer wrote whose token covers its checkpoint
(``aqt_trail.review.anchored_seq``); "last review" only reviews whose signature is valid against
the signer registry (``aqt_trail.verify.signature_status``), each signed statement once. A client
record of either type that claims more does not move them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable

from aqt_evidence import SinkError, spool_file

from . import NotFound, Stale, UsageProblem, fingerprint, refusal_text

REASON_CHARS = 200
PAGE = 100          # records per page in the Trail view
MAX_PAGE = 500
KEEP_SHEETS = 20    # worksheets kept for signing, newest


def _now() -> datetime:
    return datetime.now(UTC)


def parse_time(value) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def attribution(record: dict) -> dict | None:
    """How well the writer's observation backs a human claim, or None for records that make none.

    ``state`` is aqt-trail's ``attribution``: ``agent``, ``unconfirmed``, ``legacy`` or ``human``. A
    human claim delivered through the spool was not observed at all: ``unconfirmed``, or ``agent``
    when ``observed.drained_by`` shows that an agent harness drained it."""
    from aqt_trail.review import attribution as trail_attribution
    who = record.get("actor") if isinstance(record.get("actor"), dict) else {}
    observed = record.get("observed") if isinstance(record.get("observed"), dict) else {}
    drained = observed.get("drained_by") if isinstance(observed.get("drained_by"), dict) else None
    state = trail_attribution(record)
    if state is None and who.get("kind") == "human" and observed.get("via") == "spool":
        state = "agent" if drained and drained.get("harness") else "unconfirmed"
    if state is None:
        return None
    return {"state": state, "via": observed.get("via"), "chain_status": observed.get("chain_status"),
            "harness": observed.get("harness") or (drained or {}).get("harness"), "drained": drained is not None}


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
                     "chain": (observed.get("process_chain") or [])[:6], "chain_status": observed.get("chain_status"),
                     "drained_by": (observed.get("drained_by") or {}).get("harness")
                     if isinstance(observed.get("drained_by"), dict) else None},
        "attribution": (attribution(record) or {}).get("state"),
        "meaning": record.get("meaning"),
        "reason": str(record.get("reason") or "")[:REASON_CHARS],
        "reason_code": data.get("reason_code") if str(record.get("type", "")).endswith(".refused") else None,
        "reason_text": refusal_text(data.get("reason_code")) if str(record.get("type", "")).endswith(".refused")
        else None,
        "signed": isinstance(data.get("signature"), dict),
        "_off": offset, "_len": length,
    }


class TrailIndex:
    """Incremental, append-only reader of one trail file."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.unreadable: str | None = None
        self.lock = threading.Lock()
        self._reset(None)

    def invalidate(self) -> None:
        """Read the whole file again on the next refresh (its content changed under the index)."""
        with self.lock:
            version = self.version
            self._reset(None)
            self.version = version + 1

    def _reset(self, identity: tuple | None) -> None:
        """Forget everything (new or rewritten file). The aggregates below are kept up to date
        row by row, so no request has to walk the whole list for them."""
        self.rows: list[dict] = []
        self.offset = 0
        self.identity = identity
        self.types: set[str] = set()
        self.last_time: dict[str, str] = {}      # last record time per tool prefix ("trail.", ...)
        self.last_anchor: str | None = None       # time of the newest anchor that counts (anchored_seq)
        self.reviews: list[dict] = []             # trail.review rows; their signatures are checked on use
        self.refused: list[dict] = []
        self.by_id: dict[str, int] = {}          # record id -> position in rows
        self.version = 0                          # grows with every change of rows

    def _add(self, row: dict) -> None:
        kind = row["type"]
        self.by_id[str(row["id"])] = len(self.rows)
        self.rows.append(row)
        self.types.add(kind)
        self.last_time[kind.split(".", 1)[0] + "."] = row["time"]
        if row.get("_anchored"):
            self.last_anchor = row["time"]
        elif kind == "trail.review":
            self.reviews.append(row)
        if kind.endswith(".refused"):
            self.refused.append(row)

    def refresh(self) -> list[dict]:
        from aqt_trail.review import anchored_seq
        with self.lock:
            try:
                info = self.path.stat()
            except FileNotFoundError:
                if self.identity is not None or self.rows:
                    self._reset(None)
                    self.version += 1
                return self.rows
            identity = (info.st_ino, info.st_dev)
            if identity != self.identity or info.st_size < self.offset:
                version = self.version
                self._reset(identity)                   # new or rewritten file
                self.version = version + 1
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
                            row = compact(record, position, len(line))
                            if row["type"] == "trail.anchor":
                                row["_anchored"] = _counts_as_anchor(record, anchored_seq)
                            self._add(row)
                        except ValueError:
                            self.unreadable = f"byte {position}: line is not valid JSON"
                    position += len(line)
                if position != self.offset:
                    self.version += 1
                self.offset = position
            return self.rows

    def full(self, row: dict) -> dict:
        with open(self.path, "rb") as handle:
            handle.seek(row["_off"])
            return json.loads(handle.read(row["_len"]))

    def find(self, key: str) -> dict | None:
        rows = self.refresh()
        position = self.by_id.get(key)
        if position is None and key.isdigit():
            seq = int(key)       # seq usually equals the position; fall back to a scan otherwise
            if seq < len(rows) and rows[seq]["chain"].get("seq") == seq:
                position = seq
            else:
                position = next((i for i, row in enumerate(rows) if row["chain"].get("seq") == seq), None)
        return self.full(rows[position]) if position is not None else None


def detached_signature(record: dict) -> dict | None:
    """The detached statement in ``data.signature`` with its ``signature_status`` against the signer
    registry (``valid``, ``invalid``, ``revoked``, ``unknown-key``, ``unbound``), or None."""
    from aqt_trail.signers import load_registry
    from aqt_trail.verify import signature_status
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    block = data.get("signature")
    if not isinstance(block, dict):
        return None
    statement = block.get("statement") if isinstance(block.get("statement"), dict) else {}
    signer = statement.get("signer") if isinstance(statement.get("signer"), dict) else {}
    try:
        signers = load_registry()
    except (ValueError, OSError):
        signers = {}
    try:
        status, detail = signature_status(record, signers=signers)
    except Exception as error:  # noqa: BLE001 - a malformed statement is shown as invalid, never crashes
        status, detail = "invalid", f"cannot be checked: {type(error).__name__}"
    return {"status": status, "detail": detail, "meaning": statement.get("meaning"), "signer": signer.get("id"),
            "key": block.get("key"), "signed_at": statement.get("signed_at")}


def _counts_as_anchor(record: dict, anchored_seq) -> bool:
    try:
        return anchored_seq(record) is not None
    except Exception:  # noqa: BLE001 - a malformed anchor never counts and never breaks the index
        return False


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
        self._snapshot_lock = threading.Lock()
        self._selection: tuple = (None, [])     # (key, rows) of the last filtered selection
        self._sheets: dict[str, tuple[str, dict]] = {}   # worksheet id -> (digest, sheet) prepared here
        self._review_cache: tuple = (None, None)         # (index version, registry, rows) -> last review time

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
        snapshot = take_snapshot(config.trail_path)        # the bytes this result is about
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
        result = {"ok": report.ok, "summary": report.summary(), "count": report.count, "head_seq": report.head_seq,
                  "head": report.head, "first_bad_seq": report.first_bad_seq, "reason": report.reason,
                  "problems": report.problems, "warnings": report.warnings, "log_id": log_id,
                  "signatures": report.signatures, "anchors": report.anchors, "checked_at": _stamp(), "alcoa": alcoa,
                  "_snapshot": snapshot}
        changed = snapshot_change(config.trail_path, snapshot)
        if changed:                                        # changed while it was being verified
            snapshot["changed"] = f"{changed} while it was being verified"
        return result

    def changed_since_check(self, check: dict | None) -> str | None:
        """Why the last result no longer describes the trail file, or None while it still does."""
        snapshot = (check or {}).get("_snapshot")
        if not snapshot:
            return None
        with self._snapshot_lock:
            if not snapshot.get("changed"):
                snapshot["changed"] = snapshot_change(self.config.trail_path, snapshot)
                if snapshot["changed"]:
                    self.index.invalidate()                # rows and offsets may no longer match the file
            return snapshot["changed"]

    # -- status band -----------------------------------------------------------------------------------
    def status(self) -> dict:
        check = self.check
        changed = self.changed_since_check(check) if self.config.trail_path.exists() else None
        rows = self.index.refresh()
        if not self.config.trail_path.exists():
            state = "missing"
        elif check is None or check.get("error"):
            state = "unverified"
        elif changed:
            state = "changed"
        elif check.get("first_bad_seq") is not None:
            state = "broken"
        elif not check.get("ok"):
            state = "problems"
        else:
            state = "intact"
        unverified = 0
        if state in ("intact", "problems"):            # records after the bytes the check covered
            covered = ((check or {}).get("_snapshot") or {}).get("size", 0)
            for row in reversed(rows):
                if row["_off"] < covered:
                    break
                unverified += 1
        return {
            "state": state, "records": len(rows), "head_seq": rows[-1]["chain"]["seq"] if rows else None,
            "path": str(self.config.trail_path), "log_id": (check or {}).get("log_id"),
            "check": {k: v for k, v in (check or {}).items() if k != "alcoa" and not k.startswith("_")} or None,
            "changed": changed, "verifying": self.running, "appended_since_check": unverified,
            "last_anchor": self.index.last_anchor, "last_review": self.last_review(),
            "writer": self.writer(), "unreadable": self.index.unreadable,
        }

    def last_review(self) -> str | None:
        """Time of the newest ``trail.review`` whose signature is ``valid`` against the signer
        registry. A statement copied into a later record counts once, at its first record."""
        from aqt_evidence import content_hash
        from aqt_trail.signers import load_registry, registry_path
        from aqt_trail.verify import signature_status
        rows = list(self.index.reviews)
        key = (self.index.version, len(rows), fingerprint(registry_path()))
        if self._review_cache[0] == key:
            return self._review_cache[1]
        try:
            signers = load_registry()
        except (ValueError, OSError):
            signers = {}
        seen, last = set(), None
        for row in rows:
            try:
                record = self.index.full(row)
                digest = content_hash(record["data"]["signature"]["statement"])
                valid = signature_status(record, signers=signers)[0] == "valid"
            except Exception:  # noqa: BLE001 - a malformed review never counts and never breaks the page
                continue
            if valid and digest not in seen:
                last = row["time"]
            seen.add(digest)
        self._review_cache = (key, last)
        return last

    def alcoa(self) -> list[dict]:
        return list((self.check or {}).get("alcoa") or [])

    # -- list ------------------------------------------------------------------------------------------
    def records(self, *, since=None, until=None, type=None, actor=None, action=None, subject=None, session=None,
                limit: int = PAGE, offset: int = 0, before: int | None = None) -> dict:
        """One page of the (filtered) records, newest first. ``offset`` counts from the newest
        match; ``before`` (a seq) is the older cursor form. A filtered selection is cached until
        the trail grows, so paging through it does not filter 50,000 rows again."""
        rows = self.index.refresh()
        filters = (since or None, until or None, type or None, actor or None, action or None, subject or None,
                   session or None)
        if any(filters):
            key = (self.index.version, filters)
            if self._selection[0] != key:
                from aqt_trail.export import select
                names = ("since", "until", "type", "actor", "action", "subject", "session")
                self._selection = (key, select(rows, **dict(zip(names, filters))))
            chosen = self._selection[1]
        else:
            chosen = rows
        if before is not None:
            cut = len(chosen)
            while cut and (chosen[cut - 1]["chain"].get("seq") or 0) >= before:
                cut -= 1
            chosen = chosen[:cut]
        limit = max(1, min(int(limit), MAX_PAGE))
        total = len(chosen)
        offset = max(0, min(int(offset), max(total - 1, 0)))
        end = total - offset
        page = chosen[max(0, end - limit):end][::-1]
        return {"total": total, "rows": [public_row(row) for row in page], "types": sorted(self.index.types),
                "offset": offset, "limit": limit, "more": end - limit > 0}

    def record(self, key: str) -> dict | None:
        record = self.index.find(key)
        if record is None:
            return None
        observed = record.get("observed") or {}
        claimed = record.get("actor") or {}
        state = attribution(record)
        return {"record": record, "claimed": claimed, "observed": observed, "attribution": state,
                "attribution_mismatch": bool(state and state["state"] == "agent"),
                "signature": detached_signature(record)}

    def refusals_since(self, hours: int = 24) -> list[dict]:
        self.index.refresh()
        cutoff = _now() - timedelta(hours=hours)
        out = []
        for row in reversed(self.index.refused):
            moment = parse_time(row["time"])
            if moment and moment >= cutoff:
                out.append(public_row(row))
            elif moment and moment < cutoff - timedelta(hours=1):
                break                                 # older than the window (allowing some clock skew)
        return out[::-1]

    # -- audit-trail review and export (the CLI's review run / review sign / export) ----------------------
    def review_run(self, *, since: str | None = None, until: str | None = None) -> dict:
        """``aqt-trail review run``: risk queries over the period, saved as a worksheet. Writes no evidence."""
        from aqt_trail.review import load_profile, run_review, save_worksheet, worksheet_digest, worksheet_markdown
        from aqt_trail.state import read_records
        config = self.config
        if not config.trail_path.exists():
            raise UsageProblem("there is no trail to review yet")
        profile = load_profile("default", config.section("review"))
        try:
            sheet = run_review(read_records(config.trail_path), profile, log_id=config.meta()["log_id"],
                               since=since or None, until=until or None, trail=str(config.trail_path))
        except ValueError as error:
            raise UsageProblem(str(error)) from error
        path = save_worksheet(sheet, self.reviews_dir())
        shown = json.loads(json.dumps(sheet))           # exactly what the page receives
        digest = worksheet_digest(shown)
        with self._lock:
            self._sheets[shown["id"]] = (digest, shown)
            while len(self._sheets) > KEEP_SHEETS:
                self._sheets.pop(next(iter(self._sheets)))
        return {**shown, "path": str(path), "markdown": worksheet_markdown(shown), "worksheet_sha256": digest}

    def reviews_dir(self) -> Path:
        """Where worksheets go, as ``aqt-trail review run`` chooses: ``<state>/reviews`` when it is
        writable, else the user's own ``$XDG_STATE_HOME/aqt/trail-reviews`` (separate-user mode)."""
        from aqt_evidence import state_dir
        target = self.config.state / "reviews"
        if os.access(target if target.exists() else self.config.state, os.W_OK):
            return target
        return state_dir() / "trail-reviews"

    def worksheet(self, sheet_id: str) -> dict:
        if not re.fullmatch(r"rv_[0-9a-f]{12}", sheet_id or ""):
            raise UsageProblem("not a worksheet id")
        path = self.reviews_dir() / sheet_id / "worksheet.json"
        if not path.exists():
            raise NotFound(f"no worksheet {sheet_id}")
        return json.loads(path.read_text())

    def review_sign(self, sheet_id: str, *, shown_head: str, dispositions: dict, notes: dict, reason: str,
                    conclusion: str, passphrase: str, signer_id: str, human_check: Callable,
                    shown_sha256: str = "") -> dict:
        """``aqt-trail review sign``: same checks and the same records as the CLI. A refusal is
        recorded as ``trail.refused``; the reviewer must not be an actor of the reviewed period.
        Signed is the worksheet this server prepared and showed (``shown_sha256`` is its digest),
        never a worksheet read back from disk; aqt-trail recomputes it from the trail, checks that
        digest again (``expected_sha256``) and, with the service keys, that the trail verifies."""
        from aqt_evidence import HumanCheckError, load_signer
        from aqt_trail.review import ReviewRefused, build_review
        from aqt_trail.signers import key_file, load_registry
        from aqt_trail.state import service_keys
        config = self.config
        reviewer = str(signer_id or "")
        try:
            human_check()
        except HumanCheckError as error:
            return self._refuse_review(reviewer, "agent_context", str(error), list(error.context.markers))
        with self._lock:
            digest, sheet = self._sheets.get(sheet_id, (None, None))
        same = bool(shown_sha256) and digest is not None and hmac.compare_digest(digest.encode(), shown_sha256.encode())
        if not same or not shown_head or sheet["scope"]["head"] != shown_head:
            raise Stale("the worksheet is not the one shown; nothing was signed. Prepare the worksheet again.")
        key_path = key_file(reviewer)
        if not key_path.exists():
            raise UsageProblem(f"no key at {key_path}; enrol the reviewer with aqt-signoff init")
        encrypted = b"ENCRYPTED" in key_path.read_bytes()     # as the CLI: ask only for a protected key
        try:
            signer = load_signer(key_path, passphrase=passphrase.encode() if encrypted else None)
        except (ValueError, TypeError) as error:
            return self._refuse_review(reviewer, "auth_failed", f"could not unlock the key: {error}")
        records = read_all(config.trail_path)
        try:
            record = build_review(sheet, records, reviewer_id=reviewer, signer=signer,
                                  dispositions={str(k): str(v) for k, v in (dispositions or {}).items()},
                                  notes={str(k): str(v).strip() for k, v in (notes or {}).items() if str(v).strip()},
                                  reason=reason, conclusion=conclusion or "audit trail reviewed; dispositions as listed",
                                  registry=load_registry(), tz=config.section("review")["timezone"],
                                  log_id=config.meta()["log_id"] if config.meta_path.exists() else None,
                                  keys=service_keys(config), expected_sha256=digest)
        except ReviewRefused as refused:
            return self._refuse_review(reviewer, refused.code, refused.message)
        except ValueError as error:
            raise UsageProblem(str(error)) from error
        stored = self._send(record)
        with self._lock:
            self._sheets.pop(sheet_id, None)              # signed once
        return {"ok": True, "message": f"review {record['id']} signed by {reviewer}", "record_id": record["id"],
                "record_type": "trail.review", "time": (stored or record).get("time")}

    def _send(self, record: dict) -> dict | None:
        from aqt_trail.client import TrailClient, TrailRefused
        try:
            return TrailClient(self.config.socket_path, timeout=5.0).append(record)
        except TrailRefused as error:
            raise UsageProblem(f"the trail refused the record: {error}") from error

    def _refuse_review(self, reviewer: str, code: str, message: str, markers: list[str] | None = None) -> dict:
        from aqt_trail.review import refusal_record
        record = refusal_record(reviewer, code, message, markers)
        try:
            self._send(record)
        except (UsageProblem, SinkError, OSError):
            pass
        return {"ok": False, "message": f"refused: {message}", "reason_code": code, "reason_text": refusal_text(code),
                "markers": markers or [], "record_id": record["id"]}

    def export(self) -> tuple[str, bytes]:
        """``aqt-trail export --tar``: a verification bundle, built in a temporary folder and sent as a file."""
        from aqt_trail.export import export_bundle
        if not self.config.trail_path.exists():
            raise UsageProblem("there is no trail to export yet")
        stamp = _now().strftime("%Y%m%dT%H%M%SZ")
        log_id = self.config.meta()["log_id"] if self.config.meta_path.exists() else "trail"
        name = re.sub(r"[^A-Za-z0-9._-]", "_", f"aqt-trail-bundle-{log_id}-{stamp}")
        with tempfile.TemporaryDirectory(prefix="aqt-ui-export-") as folder:
            archive = export_bundle(self.config, Path(folder) / name, tar=True)
            return archive.name, archive.read_bytes()


def _prefix_sha256(path: Path, size: int) -> str | None:
    """SHA-256 of the first ``size`` bytes of ``path``; None when the file is shorter."""
    digest, left = hashlib.sha256(), size
    with open(path, "rb") as handle:
        while left:
            chunk = handle.read(min(left, 1 << 20))
            if not chunk:
                return None
            digest.update(chunk)
            left -= len(chunk)
    return "sha256:" + digest.hexdigest()


def take_snapshot(path: Path) -> dict:
    """Identity, size and content hash of the trail file now: what a verification result is about."""
    info = os.stat(path)
    digest = _prefix_sha256(path, info.st_size)
    after = os.stat(path)
    same = (after.st_ctime_ns, after.st_size) == (info.st_ctime_ns, info.st_size)
    return {"dev": info.st_dev, "ino": info.st_ino, "size": info.st_size, "sha256": digest,
            "confirmed": (info.st_ctime_ns, info.st_size) if same else None, "changed": None}


def snapshot_change(path: Path, snapshot: dict) -> str | None:
    """None while the file still starts with the snapshot's bytes, else what happened. The
    content is hashed again only when the file's ctime or size moved since the last look."""
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return "the trail file was removed"
    except OSError as error:
        return f"the trail file cannot be read ({error.strerror})"
    if (info.st_dev, info.st_ino) != (snapshot["dev"], snapshot["ino"]):
        return "the trail file was replaced by another file"
    if info.st_size < snapshot["size"]:
        return "the trail file was truncated"
    key = (info.st_ctime_ns, info.st_size)
    if key == snapshot.get("confirmed"):
        return None
    try:
        digest = _prefix_sha256(path, snapshot["size"])
        again = os.stat(path)
    except OSError as error:
        return f"the trail file cannot be read ({error.strerror})"
    if digest != snapshot["sha256"]:
        return "records covered by the check were modified"
    if (again.st_dev, again.st_ino, again.st_ctime_ns) == (info.st_dev, info.st_ino, info.st_ctime_ns):
        snapshot["confirmed"] = key
    return None


def read_all(path: Path) -> list[dict]:
    """The trail itself, strictly parsed as ``aqt-trail review sign`` reads it (up to an unreadable line)."""
    from aqt_trail.verify import load_lines
    return load_lines(path)[0] if Path(path).exists() else []


def _count_lines(path: Path) -> int:
    try:
        with open(path, "rb") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def _stamp() -> str:
    return _now().strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = ["TrailIndex", "TrailView", "compact", "parse_time"]
