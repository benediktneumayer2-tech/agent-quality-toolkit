"""The local ledger: working state next to the authoritative evidence sink.

Location: ``AQT_CHANGE_STATE``; else ``<git-dir>/aqt-change/``; else
``$XDG_STATE_HOME/aqt/change/<16 hex of the root path>/``. Contents:
``plans/<id>.json``, ``objects/<sha>`` (accepted plan snapshots),
``logs/<sha>`` (receipt output), ``attempts/<plan>/<key>.json`` (finish
phases) and ``records.jsonl`` (a mirror of every record this tool wrote).

The mirror is writable by the agent's user. When records go to an aqt-trail writer,
``TrailCheck`` decides which receipts and reviews of the mirror the trail log confirms. Where the
trail is comes from the caller's environment, which the agent sets; so the check also stays on when
the project requires a trail (``require_trail`` or ``trail_keys`` in ``.aqt/change.toml``) or when earlier
records of the mirror came back from a writer. With ``trail_keys`` a log copy counts only when it carries a
valid signature by a pinned service key, so a log the agent wrote itself does not confirm anything.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterable, Iterator

from aqt_evidence import (SinkError, Text, canonical_json, evidence_sources, load_public_key, open_sink,
                          record_content_hash, resolve_sink, spool_file, state_dir, verify_record_signatures)

from .config import INDEPENDENCE, PROJECT_FILE, Config, load_config, parse_project_settings
from .errors import ChangeError, usage
from .gitio import COMMIT_RE, Git, _digest, walk_blobs
from .globs import matches_any
from .plan import STABLE_ID


ID_TOKEN = re.compile(rb"rec_[0-9a-f]{28}")
CHECKED_TYPES = ("change.receipt", "change.review")
TRUST_NOGO = ("absent", "mismatch", "unsigned", "required")   # the trail contradicts the mirror, or is required
TRAIL_REQUIRED = Text("change.gate.trail_required", "the project requires an aqt-trail log (require_trail or "
                      "trail_keys in {file}) and none is found in this environment (with trail_keys, only a log whose "
                      "keys/ folder holds a pinned service key counts): run the command where the trail is (the "
                      "owner's shell or CI), start the writer (aqt-trail serve), or set AQT_EVIDENCE to its "
                      "trail.jsonl", file=PROJECT_FILE)
TRUST_TEXT = {
    "absent": Text("change.trust.absent", "not in the aqt-trail log (written only to the local mirror or a sink "
                   "file, or spooled while the writer was down: run the commands again with the writer running)"),
    "mismatch": Text("change.trust.mismatch", "differs from the record with the same id in the aqt-trail log"),
    "unsigned": Text("change.trust.unsigned", "is in the trail log, but without a valid signature by a service key "
                     "pinned in trail_keys ({file}): that log was not written by the project's trail writer",
                     file=PROJECT_FILE),
    "unattributed": Text("change.trust.unattributed", "reached the aqt-trail log through the spool, without an "
                         "observed sender; run the commands again with the writer running"),
    "unreadable": Text("change.trust.unreadable", "cannot be checked: records go to an aqt-trail writer, or earlier "
                       "records of this project came back from one, but no trail log is readable here (run the "
                       "command where the trail is, or set AQT_EVIDENCE to its trail.jsonl)"),
    "required": Text("change.trust.required", "cannot be checked: {why}", why=TRAIL_REQUIRED),
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

    ``keys`` (pinned service key ids, ``trail_keys``; None: nothing pinned) makes the trail required, and a
    log counts only when ``keys/*.pub`` next to it holds a pinned key (its key id is a hash of the key, so
    the file's place does not matter); a copy then confirms a record only with a valid signature by that
    key, else the status is ``unsigned`` (NO-GO).
    """

    def __init__(self, records: Iterable[dict], environ: dict | None = None, required: bool = False,
                 keys: Iterable[str] | None = None):
        records = list(records)
        found_in_use, self.logs = trail_logs(environ)
        self.pinned = None if keys is None else sorted(set(keys))
        self.required = bool(required) or self.pinned is not None
        self.history = any(isinstance(r.get("chain"), dict) for r in records if isinstance(r, dict))
        self.in_use = found_in_use or self.required or self.history
        self.readable: list[Path] = []
        self.found: dict[str, list[tuple[str, str | None, bool]]] = {}
        if self.in_use:
            wanted = {r["id"] for r in records if r.get("type") in CHECKED_TYPES and isinstance(r.get("id"), str)}
            for path in self.logs:
                public = self._pinned_keys(path)
                if public is not None and not public:
                    continue                              # no pinned key next to this log: it cannot confirm
                try:
                    self._scan(path, wanted, public)
                except OSError:
                    continue
                self.readable.append(path)

    def _pinned_keys(self, log: Path) -> dict | None:
        """{key id: public key} of the pinned keys in ``keys/*.pub`` next to ``log`` (None: nothing pinned)."""
        if self.pinned is None:
            return None
        found = {}
        try:
            candidates = sorted((log.parent / "keys").glob("*.pub"))
        except OSError:
            return {}
        for path in candidates:
            try:
                kid, public = load_public_key(path)
            except (OSError, ValueError):
                continue
            if kid in self.pinned:
                found[kid] = public
        return found

    def _scan(self, path: Path, wanted: set[str], public: dict | None = None) -> None:
        with open(path, "rb") as handle:
            for line in handle:
                if not wanted.intersection(token.decode() for token in ID_TOKEN.findall(line)):
                    continue
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict) or record.get("id") not in wanted:
                        continue
                    observed = record.get("observed") if isinstance(record.get("observed"), dict) else {}
                    signed = public is None or any(ok for _, ok in verify_record_signatures(record, public))
                    copy = (record_content_hash(record), observed.get("via"), signed)
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
        same = [(via, signed) for sha, via, signed in copies if sha == mine]
        if not same:
            return "mismatch"
        routes = [via for via, signed in same if signed]
        if not routes:
            return "unsigned"
        return "ok" if "socket" in routes else "unattributed"

    def confirmed_bases(self, plan_id: str, begins: Iterable[tuple[Path | None, dict]]) -> set[str]:
        """The base commits that copies of the plan's ``begin``/``baseline`` records (``Ledger.begin_records()``)
        in a readable log name, received over the socket and, with ``trail_keys``, signed by a pinned key."""
        found = set()
        for path, record in begins:
            if path is None or path not in self.readable or record["data"].get("plan_id") != plan_id:
                continue
            observed = record.get("observed") if isinstance(record.get("observed"), dict) else {}
            if observed.get("via") != "socket":
                continue
            if self.pinned is not None:
                try:
                    if not any(ok for _, ok in verify_record_signatures(record, self._pinned_keys(path) or {})):
                        continue
                except (ValueError, TypeError, RecursionError):
                    continue
            found.add(record["data"]["base_commit"])
        return found

    @property
    def missing(self) -> bool:
        """The project requires a trail, but no trail log is readable here."""
        return self.required and not self.readable

    def summary(self) -> dict:
        found = {"checked": self.in_use, "logs": [str(path) for path in self.readable], "required": self.required}
        if self.pinned is not None:
            found["keys"] = list(self.pinned)
        return found


def begin_base(record) -> str | None:
    """The base commit a ``change.plan.reconciled`` ``begin`` or ``baseline`` record names (None: not one)."""
    if not isinstance(record, dict) or record.get("type") != "change.plan.reconciled" \
            or record.get("action") not in ("begin", "baseline"):
        return None
    data = record.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("plan_id"), str):
        return None
    base = data.get("base_commit")
    return base if isinstance(base, str) and COMMIT_RE.match(base) else None


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
        self._settings: dict[str, dict] = {}
        self._begins: list[tuple[Path | None, dict]] | None = None

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

    def trail_check(self, plan_id: str | None = None) -> TrailCheck:
        settings = self.project_settings(plan_id)
        return TrailCheck(self.records(), required=settings["require_trail"], keys=settings["trail_keys"])

    # --- base commits of plans ----------------------------------------------------

    def begin_records(self) -> list[tuple[Path | None, dict]]:
        """Every ``begin``/``baseline`` record that names a base commit (``begin_base``): ``(None, record)`` from
        the local mirror and ``(log, record)`` for each copy in a trail log (``trail_logs()``, every copy: a
        record only adds a base commit, it cannot remove one)."""
        if self._begins is None:
            found: list[tuple[Path | None, dict]] = [(None, r) for r in self.records("change.plan.reconciled")
                                                     if begin_base(r)]
            for path in trail_logs()[1]:
                try:
                    with open(path, "rb") as handle:
                        for line in handle:
                            if b'"change.plan.reconciled"' not in line or b'"base_commit"' not in line:
                                continue
                            try:
                                record = json.loads(line)
                            except (ValueError, RecursionError):
                                continue
                            if begin_base(record):
                                found.append((path, record))
                except OSError:
                    continue
            self._begins = found
        return self._begins

    def plan_bases(self, plan_id: str) -> list[str]:
        """The plan's base commits that exist in this repository: the plan state's (``base_commit`` in
        ``plans/<id>.json``, which the agent can edit) and every one its ``begin``/``baseline`` records name."""
        if not self.git:
            return []
        state = self.plan_state(plan_id) if STABLE_ID.match(plan_id) else None
        bases = {(state or {}).get("base_commit")}
        bases |= {r["data"]["base_commit"] for _, r in self.begin_records() if r["data"]["plan_id"] == plan_id}
        return sorted(self.git.existing_commits({b for b in bases if isinstance(b, str) and COMMIT_RE.match(b)}))

    def base_problem(self, plan_id: str, trail: TrailCheck) -> dict | None:
        """``plan_base_mismatch`` when the plan state's base commit is not one the plan's records name: ``nogo``
        when the trail log confirms other base commits for the plan (``TrailCheck.confirmed_bases``), else (only
        the local mirror disagrees) a manual check; also a manual check when a log records several base commits
        for the plan (a made-up second begin record). The base commit decides the scope diff and which copies of
        the project settings count, so an edited one could hide a commit that removed them. None: they agree."""
        if not self.git:
            return None
        state = self.plan_state(plan_id) if STABLE_ID.match(plan_id) else None
        base = (state or {}).get("base_commit")
        begins = self.begin_records()
        confirmed = self.git.existing_commits(trail.confirmed_bases(plan_id, begins))
        local = self.git.existing_commits({r["data"]["base_commit"] for path, r in begins
                                           if path is None and r["data"]["plan_id"] == plan_id})
        where_state = self.state / "plans" / f"{plan_id}.json"
        for recorded, nogo in ((confirmed, True), (local, False)):
            if recorded and (base not in recorded or len(recorded) > 1):
                args = {"state": where_state, "base": base, "recorded": ", ".join(sorted(recorded))}
                detail = Text("change.gate.plan_base_mismatch_trail", "the plan state {state} names base commit "
                              "{base}, but the aqt-trail log records {recorded} for this plan; a changed base commit "
                              "can hide commits from the scope check and the project settings check (restore the "
                              "one the plan began with)", **args) if nogo else \
                    Text("change.gate.plan_base_mismatch_mirror", "the plan state {state} names base commit {base}, "
                         "but the local mirror records {recorded} for this plan; a changed base commit can hide "
                         "commits from the scope check and the project settings check (restore the one the plan "
                         "began with)", **args)
                return {"code": "plan_base_mismatch", "nogo": nogo and base not in recorded, "detail": detail}
        return None

    # --- project settings ------------------------------------------------------------

    def project_settings(self, plan_id: str | None = None) -> dict:
        """The committed project settings (``.aqt/change.toml``): the strictest of the copy in the working
        tree, at HEAD, at every base commit (``plan_bases``) of each plan in progress and of ``plan_id`` (the plan
        being judged, whatever its state), and at every commit since such a base that changed the file, so neither
        an uncommitted edit, nor a commit during a plan, nor an edited base commit in the plan state switches a
        setting off. ``require_trail``: a copy sets it or pins ``trail_keys`` (``require_trail_from`` names those
        copies); ``trail_keys``: the keys every pinning copy names (None when no copy pins any); ``gate``: each
        policy value at its strictest; ``fingerprint_exclude`` and ``always_allowed_paths`` (which loosen checks):
        only the globs every copy names. A copy that cannot be read refuses (``config_invalid``), except one at a
        commit between a base and HEAD, which is left out."""
        key = plan_id or ""
        if key not in self._settings:
            copies = []
            if (self.root / PROJECT_FILE).is_file():
                copies.append((PROJECT_FILE, (self.root / PROJECT_FILE).read_bytes(), True))
            if self.git:
                plans = {s.get("plan_id") for s in self.plan_states() if s.get("status") == "in_progress"}
                plans |= {plan_id} if plan_id else set()
                bases = sorted({base for p in plans if isinstance(p, str) for base in self.plan_bases(p)})
                revs = ["HEAD", *bases]
                later = sorted({c for base in bases for c in self.git.commits_touching(base, PROJECT_FILE)} - set(revs))
                copies += [(f"{rev}:{PROJECT_FILE}", text, True) for rev, text in self.git.file_at(revs, PROJECT_FILE)]
                copies += [(f"{rev}:{PROJECT_FILE}", text, False) for rev, text in self.git.file_at(later, PROJECT_FILE)]
            parsed = []
            for where, text, strict in copies:
                try:
                    parsed.append((where, parse_project_settings(text.decode("utf-8", "replace"), where)))
                except ChangeError:
                    if strict:
                        raise
            required = [where for where, found in parsed if found["require_trail"] or found["trail_keys"]]
            pins = [set(found["trail_keys"]) for _, found in parsed if found["trail_keys"]]
            ranks = ("none", *INDEPENDENCE)
            gates = [found["gate"] for _, found in parsed]
            gate = {"require_signed_approval": any(g.get("require_signed_approval") for g in gates),
                    "warnings_block": any(g.get("warnings_block") for g in gates),
                    "min_review_independence": max((g.get("min_review_independence", "none") for g in gates),
                                                   key=ranks.index, default="none")}
            def common(lists: list[list[str]]) -> list[str]:
                return sorted(set.intersection(*map(set, lists))) if lists else []

            self._settings[key] = {
                "require_trail": bool(required), "require_trail_from": required,
                "trail_keys": sorted(set.intersection(*pins)) if pins else None, "gate": gate,
                "fingerprint_exclude": common([found["fingerprint_exclude"] for _, found in parsed]),
                "always_allowed_paths": common([g.get("always_allowed_paths", []) for g in gates])}
        return self._settings[key]

    # --- working tree --------------------------------------------------------------

    def head(self) -> str | None:
        return self.git.head() if self.git else None

    def snapshot(self) -> dict[str, str] | None:
        """The working tree's blob ids (``Git.worktree_blobs()``; None without Git), to compute several
        fingerprints and the hidden-change check from one read of the tree."""
        return self.git.worktree_blobs() if self.git else None

    def fingerprint(self, exclude_paths: list[str], snapshot: dict[str, str] | None = None,
                    scope: list[str] | None = None, tracked: set[str] | None = None,
                    plan_id: str | None = None) -> str:
        """The tree fingerprint without ``exclude_paths`` (the plan file, a run's JUnit file) and the paths the
        project's ``fingerprint_exclude`` names (``project_settings(plan_id)``). The user's ``fingerprint_exclude``
        leaves out only untracked files outside ``scope`` (the plan's paths), so the agent's environment cannot
        hide the tested code. ``tracked``: the tracked paths, if already known (``Git.tracked()``)."""
        project = list(self.project_settings(plan_id)["fingerprint_exclude"])
        user, scope = list(self.config.fingerprint_exclude), list(scope or [])
        excluded = set(exclude_paths)
        if self.git:
            blobs = self.git.worktree_blobs() if snapshot is None else snapshot
            if user:
                tracked = self.git.tracked() if tracked is None else tracked
                excluded |= {path for path in blobs if path not in tracked and not matches_any(path, scope)
                             and matches_any(path, user)}
            return self.git.fingerprint(excluded, project, blobs)
        tree = walk_blobs(self.root)
        excluded |= {path for path in tree if not matches_any(path, scope) and matches_any(path, user)}
        return _digest(tree, excluded, project)
