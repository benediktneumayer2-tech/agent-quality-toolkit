"""The local ledger: working state next to the authoritative evidence sink.

Location: ``AQT_CHANGE_STATE``; else ``<git-dir>/aqt-change/``; else
``$XDG_STATE_HOME/aqt/change/<16 hex of the root path>/``. Contents:
``plans/<id>.json``, ``objects/<sha>`` (accepted plan snapshots),
``logs/<sha>`` (receipt output), ``attempts/<plan>/<key>.json`` (finish
phases) and ``records.jsonl`` (a mirror of every record this tool wrote).

The mirror is writable by the agent's user. When records go to an aqt-trail writer,
``TrailCheck`` decides which receipts and reviews of the mirror the trail log confirms.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterable, Iterator

from aqt_evidence import (SinkError, canonical_json, evidence_sources, open_sink, record_content_hash, resolve_sink,
                          spool_file, state_dir)

from .config import Config, load_config
from .errors import ChangeError, usage
from .gitio import Git, walk_fingerprint


ID_TOKEN = re.compile(rb"rec_[0-9a-f]{28}")
CHECKED_TYPES = ("change.receipt", "change.review")
TRUST_NOGO = ("absent", "mismatch")       # the trail contradicts the mirror: NO-GO
TRUST_TEXT = {
    "absent": "not in the aqt-trail log (written only to the local mirror or a sink file, or spooled while the "
              "writer was down: run the commands again with the writer running)",
    "mismatch": "differs from the record with the same id in the aqt-trail log",
    "unattributed": "reached the aqt-trail log through the spool, without an observed sender; run the commands "
                    "again with the writer running",
    "unreadable": "cannot be checked: records go to an aqt-trail writer but no trail log is readable "
                  "(set AQT_EVIDENCE to its trail.jsonl)",
}


def trail_logs(environ: dict | None = None) -> tuple[bool, list[Path]]:
    """(a trail is in use, its log files). A trail is in use when a trail log exists or records go to an
    aqt-trail writer (``resolve_sink()`` kind ``unix``); ``AQT_SINK=file:`` does not switch the check off
    while a log exists (an agent sets its own environment). The log is each ``AQT_EVIDENCE`` entry named
    ``trail.jsonl``, else ``trail.jsonl`` in the trail state directory; the sink file and the spool never
    count (anyone with the agent's rights can write them)."""
    environ = os.environ if environ is None else environ
    side = {state_dir() / "evidence.jsonl", spool_file()}
    sink = environ.get("AQT_SINK", "")
    if sink.startswith("file:"):
        side.add(Path(sink[5:]))
    logs = [path for path in evidence_sources(environ) if path.name == "trail.jsonl" and path not in side] \
        if environ.get("AQT_EVIDENCE") else []
    if not logs:
        plain = {key: value for key, value in environ.items() if key not in ("AQT_EVIDENCE", "AQT_SINK")}
        logs = [path for path in evidence_sources(plain) if path not in side]
    try:
        writer = resolve_sink(environ)["kind"] == "unix"
    except SinkError:
        writer = False
    return writer or bool(logs), logs


class TrailCheck:
    """Which receipts and reviews of the local mirror the aqt-trail log confirms.

    ``status(record)``: ``ok`` (no trail in use, or the log holds the same record, by id and content
    hash, received from a socket client), ``absent``, ``mismatch``, ``unattributed`` (only a copy that
    came through the spool) or ``unreadable`` (a trail is in use, but no log can be read).
    """

    def __init__(self, records: Iterable[dict], environ: dict | None = None):
        self.in_use, self.logs = trail_logs(environ)
        self.readable: list[Path] = []
        self.found: dict[str, list[tuple[str, str | None]]] = {}
        if self.in_use:
            wanted = {r["id"] for r in records if r.get("type") in CHECKED_TYPES and isinstance(r.get("id"), str)}
            for path in self.logs:
                try:
                    self._scan(path, wanted)
                except OSError:
                    continue
                self.readable.append(path)

    def _scan(self, path: Path, wanted: set[str]) -> None:
        with open(path, "rb") as handle:
            for line in handle:
                if not wanted.intersection(token.decode() for token in ID_TOKEN.findall(line)):
                    continue
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict) or record.get("id") not in wanted:
                        continue
                    observed = record.get("observed") if isinstance(record.get("observed"), dict) else {}
                    copy = (record_content_hash(record), observed.get("via"))
                except (ValueError, TypeError, RecursionError):
                    continue
                self.found.setdefault(record["id"], []).append(copy)

    def status(self, record: dict) -> str:
        if not self.in_use:
            return "ok"
        if not self.readable:
            return "unreadable"
        copies = self.found.get(record.get("id"))
        if not copies:
            return "absent"
        try:
            mine = record_content_hash(record)
        except (ValueError, TypeError):
            return "mismatch"
        routes = [via for sha, via in copies if sha == mine]
        if not routes:
            return "mismatch"
        return "ok" if "socket" in routes else "unattributed"

    def summary(self) -> dict:
        return {"checked": self.in_use, "logs": [str(path) for path in self.readable]}


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def write_json(path: Path, value: dict) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n")


def read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except ValueError as error:
        raise ChangeError("ledger_corrupt", f"cannot read ledger file {path}: {error}", exit_code=2) from error


class Ledger:
    def __init__(self, root: Path, state: Path, git: Git | None, config: Config):
        self.root, self.state, self.git, self.config = root, state, git, config

    @classmethod
    def open(cls, root: str | os.PathLike | None = None, state: str | os.PathLike | None = None,
             config: Config | None = None) -> "Ledger":
        start = Path(root or os.getcwd()).resolve()
        if not start.is_dir():
            raise usage("root_invalid", f"not a directory: {start}")
        git = Git.discover(start)
        top = git.root.resolve() if git else start
        config = config or load_config()
        if state or os.environ.get("AQT_CHANGE_STATE"):
            target = Path(state or os.environ["AQT_CHANGE_STATE"])
        elif git:
            target = git.git_dir() / "aqt-change"
        else:
            key = hashlib.sha256(str(top).encode()).hexdigest()[:16]
            target = state_dir() / "change" / key
        return cls(top, target, git, config)

    # --- paths ---------------------------------------------------------------

    def rel(self, path: str | os.PathLike) -> str:
        full = Path(path)
        full = (full if full.is_absolute() else Path(os.getcwd()) / full).resolve()
        try:
            return full.relative_to(self.root).as_posix()
        except ValueError as error:
            raise usage("path_outside_root", f"{path} is outside the project root {self.root}") from error

    def abs(self, rel: str) -> Path:
        return self.root / rel

    # --- plan state ----------------------------------------------------------

    def plan_state(self, plan_id: str) -> dict | None:
        return read_json(self.state / "plans" / f"{plan_id}.json")

    def save_plan_state(self, plan_id: str, value: dict) -> None:
        write_json(self.state / "plans" / f"{plan_id}.json", value)

    def plan_states(self) -> list[dict]:
        folder = self.state / "plans"
        if not folder.is_dir():
            return []
        return [state for path in sorted(folder.glob("*.json")) if (state := read_json(path))]

    # --- content-addressed objects -----------------------------------------------

    def put_object(self, kind: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        path = self.state / kind / digest
        if not path.exists():
            atomic_write(path, data)
        return "sha256:" + digest

    def get_object(self, kind: str, sha: str) -> bytes | None:
        path = self.state / kind / sha.removeprefix("sha256:")
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    # --- records -----------------------------------------------------------------

    def emit(self, record: dict) -> dict:
        """Append to the configured sink (authoritative) and then to the local mirror."""
        try:
            stored = open_sink().append(record)
        except SinkError as error:
            raise ChangeError("sink_failed", f"evidence sink refused the record: {error}", exit_code=2) from error
        stored = stored if isinstance(stored, dict) else record
        mirror = self.state / "records.jsonl"
        mirror.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(mirror, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                handle.write(canonical_json(stored) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
        return stored

    def records(self, type: str | None = None, plan_id: str | None = None) -> Iterator[dict]:
        mirror = self.state / "records.jsonl"
        if not mirror.exists():
            return
        with open(mirror, "rb") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if type and record.get("type") != type:
                    continue
                if plan_id and (record.get("data") or {}).get("plan_id") != plan_id:
                    continue
                yield record

    def record(self, record_id: str) -> dict | None:
        return next((r for r in self.records() if r.get("id") == record_id), None)

    def trail_check(self) -> TrailCheck:
        return TrailCheck(self.records())

    # --- working tree --------------------------------------------------------------

    def head(self) -> str | None:
        return self.git.head() if self.git else None

    def fingerprint(self, exclude_paths: list[str]) -> str:
        globs = list(self.config.fingerprint_exclude)
        excluded = set(exclude_paths)
        if self.git:
            return self.git.fingerprint(excluded, globs)
        return walk_fingerprint(self.root, excluded, globs)
