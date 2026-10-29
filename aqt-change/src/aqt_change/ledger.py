"""The local ledger: working state next to the authoritative evidence sink.

Location: ``AQT_CHANGE_STATE``; else ``<git-dir>/aqt-change/``; else
``$XDG_STATE_HOME/aqt/change/<16 hex of the root path>/``. Contents:
``plans/<id>.json``, ``objects/<sha>`` (accepted plan snapshots),
``logs/<sha>`` (receipt output), ``attempts/<plan>/<key>.json`` (finish
phases) and ``records.jsonl`` (a mirror of every record this tool wrote).

The mirror is writable by the agent's user. When records go to an aqt-trail writer,
``TrailCheck`` decides which receipts and reviews of the mirror the trail log confirms. Where the
trail is comes from the caller's environment, which the agent sets; so the check also stays on when
the project requires a trail (``require_trail`` in ``.aqt/change.toml``) or when earlier records of
the mirror came back from a writer.
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

from .config import PROJECT_FILE, Config, load_config, parse_project_settings
from .errors import ChangeError, usage
from .gitio import COMMIT_RE, Git, walk_fingerprint


ID_TOKEN = re.compile(rb"rec_[0-9a-f]{28}")
CHECKED_TYPES = ("change.receipt", "change.review")
TRUST_NOGO = ("absent", "mismatch", "required")   # the trail contradicts the mirror, or is required: NO-GO
TRAIL_REQUIRED = (f"the project requires an aqt-trail log (require_trail in {PROJECT_FILE}) and none is found in "
                  "this environment: run the command where the trail is (the owner's shell or CI), start the "
                  "writer (aqt-trail serve), or set AQT_EVIDENCE to its trail.jsonl")
TRUST_TEXT = {
    "absent": "not in the aqt-trail log (written only to the local mirror or a sink file, or spooled while the "
              "writer was down: run the commands again with the writer running)",
    "mismatch": "differs from the record with the same id in the aqt-trail log",
    "unattributed": "reached the aqt-trail log through the spool, without an observed sender; run the commands "
                    "again with the writer running",
    "unreadable": "cannot be checked: records go to an aqt-trail writer, or earlier records of this project "
                  "came back from one, but no trail log is readable here (run the command where the trail is, "
                  "or set AQT_EVIDENCE to its trail.jsonl)",
    "required": "cannot be checked: " + TRAIL_REQUIRED,
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
    came through the spool), ``unreadable`` (a trail is in use, but no log can be read) or ``required``
    (the same while the project requires a trail: NO-GO).

    A trail is in use when ``trail_logs()`` says so, when ``required`` is true, or when a record of
    ``records`` came back from a writer (it carries a ``chain``): the environment alone cannot switch
    the check off.
    """

    def __init__(self, records: Iterable[dict], environ: dict | None = None, required: bool = False):
        records = list(records)
        found_in_use, self.logs = trail_logs(environ)
        self.required = bool(required)
        self.history = any(isinstance(r.get("chain"), dict) for r in records if isinstance(r, dict))
        self.in_use = found_in_use or self.required or self.history
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
            return "required" if self.required else "unreadable"
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

    @property
    def missing(self) -> bool:
        """The project requires a trail, but no trail log is readable here."""
        return self.required and not self.readable

    def summary(self) -> dict:
        return {"checked": self.in_use, "logs": [str(path) for path in self.readable], "required": self.required}


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
        self._settings: dict | None = None

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
        return TrailCheck(self.records(), required=self.project_settings()["require_trail"])

    # --- project settings ------------------------------------------------------------

    def project_settings(self) -> dict:
        """The committed project settings (``.aqt/change.toml``): the strictest of the copy in the working
        tree, at HEAD and at the base commit of each plan in progress, so neither an uncommitted edit nor a
        commit during a plan switches a setting off. ``require_trail_from`` names the copies that set it."""
        if self._settings is None:
            copies = []
            if (self.root / PROJECT_FILE).is_file():
                copies.append((PROJECT_FILE, (self.root / PROJECT_FILE).read_bytes()))
            if self.git:
                bases = {s.get("base_commit") for s in self.plan_states() if s.get("status") == "in_progress"}
                revs = ["HEAD", *sorted(b for b in bases if isinstance(b, str) and COMMIT_RE.match(b))]
                copies += [(f"{rev}:{PROJECT_FILE}", text) for rev, text in self.git.file_at(revs, PROJECT_FILE)]
            required = [where for where, text in copies
                        if parse_project_settings(text.decode("utf-8", "replace"), where)["require_trail"]]
            self._settings = {"require_trail": bool(required), "require_trail_from": required}
        return self._settings

    # --- working tree --------------------------------------------------------------

    def head(self) -> str | None:
        return self.git.head() if self.git else None

    def snapshot(self) -> dict[str, str] | None:
        """The working tree's blob ids (``Git.worktree_blobs()``; None without Git), to compute several
        fingerprints and the hidden-change check from one read of the tree."""
        return self.git.worktree_blobs() if self.git else None

    def fingerprint(self, exclude_paths: list[str], snapshot: dict[str, str] | None = None) -> str:
        globs = list(self.config.fingerprint_exclude)
        excluded = set(exclude_paths)
        if self.git:
            return self.git.fingerprint(excluded, globs, snapshot)
        return walk_fingerprint(self.root, excluded, globs)
