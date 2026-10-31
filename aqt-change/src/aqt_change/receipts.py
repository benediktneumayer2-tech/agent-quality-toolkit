"""Receipts: the runner executes the command and records what it observed.

A receipt is *fresh* while the plan basis hash and the tree fingerprint it
recorded still match the current state, and *passing* when the command exited 0
and, where counts could be parsed, nothing failed and at least one test ran.
When a trail is in use, a fresh passing receipt counts only if the trail log
confirms it (``ledger.TrailCheck``); otherwise its item is ``unverified``.
A run that changed the fingerprinted tree (``command_modified_worktree``) does not
count by itself: its item lists it under ``modified`` (gate MANUAL, finish refuses)
until a later run of the same command leaves the tree unchanged.
Commands run with a fresh Python bytecode cache (``execute``; the receipt's ``env.python_bytecode``).
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from aqt_evidence import Text, bytes_hash, new_record, subject, text_join

from . import antigaming
from .actors import current_actor
from .errors import refused, usage
from .globs import matches_any
from .ledger import TRUST_NOGO, TRUST_TEXT, Ledger, TrailCheck
from .plan import Plan, basis_hash, command_text
from .plans import read_plan, require_valid, status

PYTEST_SUMMARY = re.compile(r"^(?:=+\s+)?(?P<parts>\d+ [a-z]+(?:, \d+ [a-z]+)*) in [\d.]+s(?:\s*\([^)]*\))?(?:\s+=+)?\s*$")
PART = re.compile(r"(\d+) ([a-z]+)")
UNITTEST_RAN = re.compile(r"^Ran (\d+) tests? in ")
UNITTEST_RESULT = re.compile(r"^(OK|FAILED)(?: \((?P<detail>[^)]*)\))?\s*$")
JUNIT_LIMIT = 50 * 1024 * 1024
KEYS = {"passed": "passed", "failed": "failed", "error": "errors", "errors": "errors", "skipped": "skipped",
        "xfailed": "xfailed", "xpassed": "xpassed", "deselected": "deselected"}


def utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_counts(text: str) -> dict:
    lines = text.splitlines()[-60:]
    for line in reversed(lines):
        match = PYTEST_SUMMARY.match(line.strip())
        if match:
            counts = {"source": "pytest"}
            for number, word in PART.findall(match.group("parts")):
                key = KEYS.get(word)
                if key:
                    counts[key] = counts.get(key, 0) + int(number)
            counts["total"] = sum(counts.get(k, 0) for k in ("passed", "failed", "errors", "skipped",
                                                             "xfailed", "xpassed"))
            return counts
    ran = next((UNITTEST_RAN.match(l) for l in reversed(lines) if UNITTEST_RAN.match(l)), None)
    result = next((UNITTEST_RESULT.match(l.strip()) for l in reversed(lines) if UNITTEST_RESULT.match(l.strip())), None)
    if ran and result:
        counts = {"source": "unittest", "total": int(ran.group(1))}
        detail = result.group("detail") or ""
        for key, value in re.findall(r"(\w+)=(\d+)", detail):
            name = {"failures": "failed", "errors": "errors", "skipped": "skipped",
                    "expected failures": "xfailed"}.get(key, key)
            counts[name] = int(value)
        counts["passed"] = counts["total"] - counts.get("failed", 0) - counts.get("errors", 0) - counts.get("skipped", 0)
        return counts
    return {}


def parse_junit(path: Path) -> dict:
    if path.stat().st_size > JUNIT_LIMIT:
        raise ValueError("JUnit file is larger than 50 MB")
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else []
    suites += [s for s in root.iter("testsuite") if s is not root]
    leaves = [s for s in suites if not any(child.tag == "testsuite" for child in s)]
    counts = {"source": "junit", "total": 0, "failed": 0, "errors": 0, "skipped": 0}
    for suite in leaves:
        counts["total"] += int(suite.get("tests", 0) or 0)
        counts["failed"] += int(suite.get("failures", 0) or 0)
        counts["errors"] += int(suite.get("errors", 0) or 0)
        counts["skipped"] += int(suite.get("skipped", suite.get("disabled", 0)) or 0)
    counts["passed"] = counts["total"] - counts["failed"] - counts["errors"] - counts["skipped"]
    return counts


def judge(exit_code: int, outcome: str, counts: dict) -> bool:
    if outcome != "completed" or exit_code != 0:
        return False
    if counts:
        return counts.get("failed", 0) == 0 and counts.get("errors", 0) == 0 and counts.get("total", 0) > 0
    return True


def _tail(data: bytes, lines: int) -> str | None:
    if lines <= 0:
        return None
    text = data.decode("utf-8", "replace").splitlines()[-lines:]
    joined = "\n".join(text)
    return joined[-4000:]


def _env_summary(argv: list[str]) -> dict:
    digest = hashlib.sha256()
    for key in sorted(os.environb):
        digest.update(key + b"=" + os.environb[key] + b"\0")
    executable = shutil.which(argv[0]) if argv else None
    return {"platform": platform.platform(terse=True), "python": platform.python_version(),
            "executable": executable, "env_sha256": "sha256:" + digest.hexdigest(), "python_bytecode": "fresh"}


def _pump(stream, sink, echo) -> None:
    for chunk in iter(lambda: stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536), b""):
        sink.write(chunk)
        if echo is not None:
            echo.write(chunk)
            echo.flush()


def execute(argv: list[str], cwd: Path, timeout: int | None, echo: bool) -> dict:
    """Run ``argv`` in ``cwd``. Python reads and writes bytecode only in a fresh, empty cache directory
    (``PYTHONPYCACHEPREFIX``, removed afterwards), so ``.pyc`` files already in the tree (``__pycache__/``,
    which ``.gitignore`` usually hides from the fingerprint) cannot stand in for the source under test."""
    pycache = tempfile.mkdtemp(prefix="aqt-change-pycache-")
    try:
        return _execute(argv, cwd, timeout, echo, {**os.environ, "PYTHONPYCACHEPREFIX": pycache})
    finally:
        shutil.rmtree(pycache, ignore_errors=True)


def _execute(argv: list[str], cwd: Path, timeout: int | None, echo: bool, env: dict) -> dict:
    out_file = tempfile.TemporaryFile()
    err_file = tempfile.TemporaryFile()
    started, start_clock = utc_stamp(), time.monotonic()
    outcome, exit_code = "completed", 0
    try:
        process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.DEVNULL, start_new_session=True, env=env)
    except OSError as error:
        err_file.write(f"aqt-change: cannot start command: {error}\n".encode())
        outcome, exit_code = "error", 127
        process = None
    if process:
        threads = [threading.Thread(target=_pump, args=(process.stdout, out_file,
                                                        sys.stdout.buffer if echo else None), daemon=True),
                   threading.Thread(target=_pump, args=(process.stderr, err_file,
                                                        sys.stderr.buffer if echo else None), daemon=True)]
        for thread in threads:
            thread.start()
        try:
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            outcome = "timeout"
            _kill(process)
            exit_code = process.wait()
        except KeyboardInterrupt:
            outcome = "interrupted"
            _kill(process)
            exit_code = process.wait()
        for thread in threads:
            thread.join(timeout=5)
    duration = int((time.monotonic() - start_clock) * 1000)
    out_file.seek(0)
    err_file.seek(0)
    return {"exit_code": int(exit_code), "outcome": outcome, "started": started, "ended": utc_stamp(),
            "duration_ms": duration, "stdout": out_file.read(), "stderr": err_file.read(),
            "start_epoch": time.time() - duration / 1000}


def _kill(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _resolve_targets(plan: Plan | None, item: str | None, argv: list[str], all_items: bool) -> list[tuple[str | None, list[str]]]:
    if all_items:
        if plan is None:
            raise usage("plan_required", "--all needs --plan")
        targets = [(i.id, cmd) for i in plan.verification for cmd in i.commands]
        if not targets:
            raise refused("no_declared_commands", "the plan declares no verification commands (`$ …`)")
        return targets
    if item:
        if plan is None:
            raise usage("plan_required", "--item needs --plan")
        found = plan.item(item)
        if not found:
            raise usage("item_unknown", f"no item {item} in the plan")
        if not found.commands:
            raise refused("item_manual", f"{item} declares no command; use 'aqt-change attest'")
        if not argv:
            return [(item, cmd) for cmd in found.commands]
        if argv not in found.commands:
            raise refused("command_mismatch", f"command does not match the command declared for {item}",
                          declared=[command_text(c) for c in found.commands])
        return [(item, argv)]
    if not argv:
        raise usage("command_required", "give a command after --, or --item / --all")
    if plan is not None:
        matched = [(i.id, argv) for i in plan.verification if argv in i.commands]
        if matched:
            return matched
    return [(None, argv)]


def run(ledger: Ledger, argv: list[str], *, plan_path: str | None = None, item: str | None = None,
        all_items: bool = False, junit: str | None = None, timeout: int | None = None,
        echo: bool = True) -> list[dict]:
    plan, rel = None, None
    if plan_path:
        rel, plan = read_plan(ledger, plan_path)
        require_valid(plan, rel)
        state = status(ledger, rel)
        if state["state"] == "unregistered":
            raise refused("plan_unregistered", f"{rel} is not registered; run 'aqt-change plan add' or 'begin'")
    targets = _resolve_targets(plan, item, argv, all_items)
    receipts = []
    for item_id, command in targets:
        receipts.append(_run_one(ledger, command, plan, rel, item_id, junit, timeout, echo))
    return receipts


def _run_one(ledger, argv, plan, rel, item_id, junit, timeout, echo) -> dict:
    excludes = [rel] if rel else []
    scope = plan.declared_paths if plan else []
    if junit:
        # the JUnit file stays out of the fingerprint only as an untracked file outside the plan's paths: the
        # caller names it, so it must not hide tested code
        target = ledger.rel(junit)
        if not matches_any(target, scope) and not (ledger.git and target in ledger.git.tracked()):
            excludes.append(target)
    plan_id = plan.id if plan else None
    before = ledger.fingerprint(excludes, scope=scope, plan_id=plan_id)
    result = execute(argv, ledger.root, timeout or ledger.config.timeout_seconds, echo)
    snapshot = ledger.snapshot()
    after = ledger.fingerprint(excludes, snapshot, scope=scope, plan_id=plan_id)
    counts = parse_counts(result["stdout"].decode("utf-8", "replace") + "\n" +
                          result["stderr"].decode("utf-8", "replace"))
    warnings = []
    junit_sha = None
    if junit:
        path = ledger.abs(ledger.rel(junit))
        if not path.exists():
            warnings.append({"code": "junit_missing", "path": ledger.rel(junit)})
        elif path.stat().st_mtime < result["start_epoch"] - 1:
            warnings.append({"code": "junit_stale", "path": ledger.rel(junit),
                             "detail": "JUnit file is older than the run; counts ignored"})
        else:
            try:
                counts = parse_junit(path)
                junit_sha = bytes_hash(path.read_bytes())
            except (ValueError, ET.ParseError) as error:
                warnings.append({"code": "junit_unreadable", "path": ledger.rel(junit), "detail": str(error)[:200]})
    if before != after:
        warnings.append({"code": "command_modified_worktree",
                         "detail": "the working tree changed while the command ran"})
    hidden = [h for h in ledger.git.hidden_changes(snapshot) if h["state"] != "sparse"] if ledger.git else []
    if hidden:
        warnings.append({"code": "hidden_worktree_change", "detail": hidden_text(hidden)})
    if plan is not None and ledger.git:
        base = (ledger.plan_state(plan.id) or {}).get("base_commit") or plan.base_commit
        warnings += antigaming.scan(ledger.git, base, set(excludes))
    passed = judge(result["exit_code"], result["outcome"], counts)
    outcome = result["outcome"]
    outcome = ("passed" if passed else "failed") if outcome == "completed" else outcome
    streams = {}
    for name in ("stdout", "stderr"):
        data = result[name]
        sha = ledger.put_object("logs", data)
        entry = {"sha256": sha, "bytes": len(data)}
        tail = _tail(data, ledger.config.excerpt_lines)
        if tail:
            entry["tail"] = tail
        streams[name] = entry
    head = ledger.head()
    data = {
        "plan_id": plan.id if plan else None, "plan_ref": plan.id if plan else None, "item": item_id,
        "kind": "run", "argv": list(argv), "command": command_text(argv), "cwd": ".",
        "exit_code": result["exit_code"], "passed": passed, "outcome": outcome,
        "started": result["started"], "ended": result["ended"], "duration_ms": result["duration_ms"],
        "stdout": streams["stdout"], "stderr": streams["stderr"], "counts": counts,
        "junit_sha256": junit_sha,
        "git": {"head": head, "dirty": bool(ledger.git and ledger.git.is_dirty(set(excludes)))} if ledger.git else None,
        "tree_fingerprint": after, "tree_fingerprint_before": before, "fingerprint_excludes": excludes,
        "plan_basis_hash": basis_hash(plan) if plan else None,
        "plan_raw_hash": plan.raw_hash if plan else None,
        "env": _env_summary(argv), "warnings": warnings,
    }
    record = new_record(
        "change.receipt", current_actor(ledger.config.actor), "run",
        subject=subject("plan-item", f"{plan.id}#{item_id}") if plan and item_id
        else subject("command", command_text(argv)[:200]),
        data={k: v for k, v in data.items() if v is not None or k in ("plan_basis_hash", "plan_id", "plan_ref", "item")})
    return ledger.emit(record)


def attest(ledger: Ledger, plan_path: str, item: str, evidence: list[str], reason: str) -> dict:
    if not reason or not reason.strip():
        raise usage("reason_required", "attest needs --reason")
    rel, plan = read_plan(ledger, plan_path)
    require_valid(plan, rel)
    if status(ledger, rel)["state"] == "unregistered":
        raise refused("plan_unregistered", f"{rel} is not registered")
    found = plan.item(item)
    if not found or found.section != "verification":
        raise usage("item_unknown", f"no verification item {item}")
    if found.commands:
        raise refused("item_has_command", f"{item} declares a command; use 'aqt-change run --item {item}'")
    files = []
    for path in evidence:
        relpath = ledger.rel(path)
        try:
            files.append({"path": relpath, "sha256": bytes_hash(ledger.abs(relpath).read_bytes())})
        except FileNotFoundError as error:
            raise usage("evidence_missing", f"evidence file not found: {relpath}") from error
    who = current_actor(ledger.config.actor)
    data = {"plan_id": plan.id, "plan_ref": plan.id, "item": item, "kind": "manual", "argv": [],
            "exit_code": 0, "passed": True, "outcome": "attested", "counts": {}, "evidence": files,
            "tree_fingerprint": ledger.fingerprint([rel], scope=plan.declared_paths, plan_id=plan.id),
            "fingerprint_excludes": [rel],
            "plan_basis_hash": basis_hash(plan), "plan_raw_hash": plan.raw_hash,
            "attested_by": who.get("kind"), "started": utc_stamp()}
    record = new_record("change.receipt", who, "attest", subject=subject("plan-item", f"{plan.id}#{item}"),
                        reason=reason.strip(), meaning="verified", data=data)
    return ledger.emit(record)


HIDDEN_FIX = Text("change.gate.hidden_fix", "for skip-worktree / assume-unchanged run git update-index "
                  "--no-skip-worktree / --no-assume-unchanged; for stat-cache remove core.fsmonitor or a relaxed "
                  "core.checkStat / core.trustctime and touch the files")


def listing(items: list[str], limit: int = 20) -> str:
    """``items`` as one line, at most ``limit`` of them."""
    shown = ", ".join(items[:limit])
    return Text("change.list.more", "{items} and {n} more", items=shown, n=len(items) - limit) \
        if len(items) > limit else shown


def hidden_text(hidden: list[dict], limit: int = 20) -> str:
    """``Git.hidden_changes()`` as one line."""
    return listing([f"{h['path']} ({h['flag']}, {h['state']})" for h in hidden], limit)


def trust_note(entry: dict) -> str:
    """Why the receipts of an ``unverified`` item do not count."""
    return text_join("; ", [Text("change.gate.receipt_trust", "{receipt} {trust}", receipt=u["receipt"],
                                 trust=TRUST_TEXT[u["trust"]]) for u in entry.get("untrusted", [])])


def trust_blocks(entry: dict) -> bool:
    """True when the trail contradicts a receipt of the item (NO-GO rather than MANUAL)."""
    return any(u["trust"] in TRUST_NOGO for u in entry.get("untrusted", []))


# --- evaluation ------------------------------------------------------------------

class Freshness:
    """Caches the working tree's blob ids, the fingerprints per exclude set and the trail check during
    one evaluation."""

    def __init__(self, ledger: Ledger, plan_id: str | None = None):
        self.ledger, self.plan_id = ledger, plan_id         # plan_id: whose project settings apply
        self.cache: dict[tuple, str] = {}
        self._trail: TrailCheck | None = None
        self._snapshot: dict[str, str] | None = None
        self._tracked: set[str] | None = None

    def of(self, plan_id: str) -> "Freshness":
        """This cache for the plan ``plan_id`` (itself, or a copy sharing the snapshot of the working tree)."""
        if plan_id == self.plan_id:
            return self
        other = Freshness(self.ledger, plan_id)
        other._snapshot, other._tracked = self.snapshot, self._tracked
        mine, theirs = self.ledger.project_settings(self.plan_id), self.ledger.project_settings(plan_id)
        if all(mine[key] == theirs[key] for key in ("require_trail", "trail_keys")):
            other._trail = self.trail                       # the same trail check: read the log once
        return other

    @property
    def snapshot(self) -> dict[str, str] | None:
        if self._snapshot is None:
            self._snapshot = self.ledger.snapshot()
        return self._snapshot

    def hidden(self) -> list[dict]:
        """``Git.hidden_changes()`` of the cached snapshot ([] without Git)."""
        return self.ledger.git.hidden_changes(self.snapshot) if self.ledger.git else []

    @property
    def trail(self) -> TrailCheck:
        if self._trail is None:
            self._trail = self.ledger.trail_check(self.plan_id)
        return self._trail

    def fingerprint(self, excludes: list[str], scope: list[str] | None = None) -> str:
        """``Ledger.fingerprint`` of the cached snapshot; ``scope``: the plan's paths."""
        key = (tuple(sorted(excludes)), tuple(scope or ()))
        if key not in self.cache:
            if self._tracked is None and self.ledger.git and self.ledger.config.fingerprint_exclude:
                self._tracked = self.ledger.git.tracked()
            self.cache[key] = self.ledger.fingerprint(list(key[0]), self.snapshot, scope=list(key[1]),
                                                      tracked=self._tracked, plan_id=self.plan_id)
        return self.cache[key]

    def is_fresh(self, receipt: dict, basis: str, scope: list[str] | None = None) -> bool:
        data = receipt.get("data") or {}
        return (data.get("plan_basis_hash") == basis
                and data.get("tree_fingerprint") == self.fingerprint(data.get("fingerprint_excludes") or [], scope))


def modified_worktree(receipt: dict) -> bool:
    """True when the receipt's run changed the fingerprinted tree (before and after differ)."""
    data = receipt.get("data") or {}
    before = data.get("tree_fingerprint_before")
    return (before is not None and before != data.get("tree_fingerprint")) or any(
        isinstance(w, dict) and w.get("code") == "command_modified_worktree" for w in data.get("warnings") or [])


def evaluate(ledger: Ledger, plan: Plan, freshness: Freshness | None = None) -> dict[str, dict]:
    """Verification items -> {state: ok|unverified|stale|failed|missing, commands: [...], ...}.

    ``unverified``: the latest receipt is fresh and passing, but a trail is in use and does not
    confirm it; ``untrusted`` lists those receipts with their ``TrailCheck`` status. ``modified``: the
    ``ok`` receipts whose run changed the working tree (``modified_worktree()``)."""
    freshness = freshness.of(plan.id) if freshness else Freshness(ledger, plan.id)
    basis = basis_hash(plan)
    scope = plan.declared_paths
    receipts = [r for r in ledger.records("change.receipt", plan.id)]
    result = {}
    rank = {"ok": 0, "unverified": 1, "stale": 2, "failed": 3, "missing": 4}
    for item in plan.verification:
        mine = [r for r in receipts if r["data"].get("item") == item.id]
        entry = {"id": item.id, "checked": item.checked, "manual": item.manual, "text": item.text,
                 "commands": [], "state": "ok", "untrusted": [], "modified": []}

        def trusted(latest: dict) -> bool:
            trust = freshness.trail.status(latest)
            if trust != "ok":
                entry["untrusted"].append({"receipt": latest["id"], "trust": trust})
            return trust == "ok"

        if item.manual:
            attests = [r for r in mine if r["data"].get("kind") == "manual"]
            latest = attests[-1] if attests else None
            if not latest:
                state = "missing"
            elif not freshness.is_fresh(latest, basis, scope):
                state = "stale"
            else:
                state = "ok" if trusted(latest) else "unverified"
            entry.update(state=state, receipt=latest["id"] if latest else None,
                         attested_by=latest["data"].get("attested_by") if latest else None)
        else:
            worst = "ok"
            for argv in item.commands:
                runs = [r for r in mine if r["data"].get("kind") == "run" and r["data"].get("argv") == argv]
                latest = runs[-1] if runs else None
                if not latest:
                    state = "missing"
                elif not freshness.is_fresh(latest, basis, scope):
                    state = "stale"
                elif not latest["data"].get("passed"):
                    state = "failed"
                else:
                    state = "ok" if trusted(latest) else "unverified"
                modified = state == "ok" and modified_worktree(latest)
                if modified:
                    entry["modified"].append(latest["id"])
                entry["commands"].append({"argv": argv, "command": command_text(argv), "state": state,
                                          "modified_worktree": modified,
                                          "receipt": latest["id"] if latest else None,
                                          "counts": latest["data"].get("counts") if latest else None,
                                          "outcome": latest["data"].get("outcome") if latest else None})
                worst = max(worst, state, key=lambda s: rank[s])
            entry["state"] = worst
        result[item.id] = entry
    return result
