"""SQLite working index.

The index is *derived*: every state change is first an evidence record, and
``apply()`` folds a stored ``capa.*`` record into the index. Live commands and
``rebuild`` use the same function, so a rebuilt index equals the live one.
Undecided scan candidates are the only index content without a record; the
next scan recreates them.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from aqt_evidence import iter_evidence

from .util import parse_time

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY, type TEXT NOT NULL, action TEXT NOT NULL, time TEXT NOT NULL,
    dev_id TEXT, action_id TEXT, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deviations (
    dev_id TEXT PRIMARY KEY, num INTEGER NOT NULL, title TEXT NOT NULL, description TEXT,
    severity TEXT NOT NULL, category TEXT NOT NULL, source_type TEXT, source_ref TEXT,
    subject_ref TEXT, candidate_id TEXT, occurred_at TEXT NOT NULL, opened_at TEXT NOT NULL, opened_by TEXT NOT NULL,
    due TEXT, state TEXT NOT NULL, closed_at TEXT, basis TEXT);
CREATE TABLE IF NOT EXISTS links (dev_id TEXT NOT NULL, rel TEXT NOT NULL, ref TEXT NOT NULL,
    PRIMARY KEY (dev_id, rel, ref));
CREATE TABLE IF NOT EXISTS candidates (
    candidate_id TEXT PRIMARY KEY, key TEXT UNIQUE NOT NULL, rule TEXT NOT NULL,
    source_type TEXT NOT NULL, source_ref TEXT NOT NULL, time TEXT NOT NULL, title TEXT NOT NULL,
    severity TEXT NOT NULL, category TEXT NOT NULL, session TEXT, status TEXT NOT NULL,
    dev_id TEXT, decided_record TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS investigations (
    record_id TEXT PRIMARY KEY, dev_id TEXT NOT NULL, status TEXT NOT NULL, time TEXT NOT NULL,
    json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY, dev_id TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL,
    description TEXT NOT NULL, path TEXT NOT NULL, before_sha256 TEXT, after_sha256 TEXT,
    criterion TEXT NOT NULL, state TEXT NOT NULL, planned_record TEXT, implemented_record TEXT,
    implemented_hash TEXT, implementer TEXT, approved_record TEXT, approved_at TEXT, approver TEXT);
CREATE TABLE IF NOT EXISTS evaluations (
    record_id TEXT PRIMARY KEY, action_id TEXT NOT NULL, kind TEXT NOT NULL, time TEXT NOT NULL,
    result TEXT, json TEXT NOT NULL);
"""

CAPA_TYPES = ("capa.deviation", "capa.investigation", "capa.action", "capa.effectiveness",
              "capa.closure", "capa.refused")


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ------------------------------------------------------------------ queries
    def q(self, sql: str, *args) -> list[sqlite3.Row]:
        return self.db.execute(sql, args).fetchall()

    def one(self, sql: str, *args) -> sqlite3.Row | None:
        return self.db.execute(sql, args).fetchone()

    def is_empty(self) -> bool:
        return self.one("SELECT 1 FROM records LIMIT 1") is None

    def next_dev_num(self) -> int:
        row = self.one("SELECT MAX(num) AS n FROM deviations")
        return (row["n"] or 0) + 1

    def next_action_seq(self, dev_id: str) -> int:
        row = self.one("SELECT MAX(seq) AS n FROM actions WHERE dev_id = ?", dev_id)
        return (row["n"] or 0) + 1

    def deviation(self, dev_id: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM deviations WHERE dev_id = ?", dev_id)

    def action(self, action_id: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM actions WHERE action_id = ?", action_id)

    def record(self, record_id: str) -> dict | None:
        row = self.one("SELECT json FROM records WHERE id = ?", record_id)
        return json.loads(row["json"]) if row else None

    def latest_evaluation(self, action_id: str) -> dict | None:
        row = self.one("SELECT json FROM evaluations WHERE action_id = ? AND kind = 'evaluated' "
                       "ORDER BY time DESC, record_id DESC LIMIT 1", action_id)
        return json.loads(row["json"]) if row else None

    def extensions(self, action_id: str) -> list[dict]:
        return [json.loads(r["json"]) for r in self.q(
            "SELECT json FROM evaluations WHERE action_id = ? AND kind = 'extended' ORDER BY time, record_id",
            action_id)]

    # ------------------------------------------------------------- candidates
    def upsert_candidate(self, cand: dict) -> bool:
        """Insert a new candidate; returns False when its key is already known."""
        if self.one("SELECT 1 FROM candidates WHERE key = ?", cand["key"]):
            return False
        self.db.execute(
            "INSERT INTO candidates (candidate_id, key, rule, source_type, source_ref, time, title, severity,"
            " category, session, status) VALUES (?,?,?,?,?,?,?,?,?,?, 'open')",
            (cand["candidate_id"], cand["key"], cand["rule"], cand["source_type"], cand["source_ref"],
             cand["time"], cand["title"], cand["severity"], cand["category"], cand.get("session")))
        self.db.commit()
        return True

    def candidate(self, candidate_id: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM candidates WHERE candidate_id = ?", candidate_id)

    # ------------------------------------------------------------------ apply
    def apply(self, record: dict) -> None:
        """Fold one stored ``capa.*`` record into the index (idempotent by record id)."""
        if record.get("type") not in CAPA_TYPES:
            return
        if self.one("SELECT 1 FROM records WHERE id = ?", record["id"]):
            return
        data = record.get("data") or {}
        kind, action, time = record["type"], record["action"], record["time"]
        dev_id, action_id = data.get("dev_id"), data.get("action_id")
        self.db.execute("INSERT INTO records (id, type, action, time, dev_id, action_id, json) VALUES (?,?,?,?,?,?,?)",
                        (record["id"], kind, action, time, dev_id, action_id, json.dumps(record, sort_keys=True)))
        handler = getattr(self, "_" + kind.split(".", 1)[1], None)
        if handler:
            handler(record, action, data)
        self.db.commit()

    def _deviation(self, record: dict, action: str, data: dict) -> None:
        if action in ("opened", "accepted"):
            source = data.get("source") or {}
            self.db.execute(
                "INSERT OR REPLACE INTO deviations (dev_id, num, title, description, severity, category, source_type,"
                " source_ref, subject_ref, candidate_id, occurred_at, opened_at, opened_by, due, state)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'open')",
                (data["dev_id"], int(data["dev_id"].split("-")[1]), data["title"], data.get("description"),
                 data["severity"], data["category"], source.get("type"), source.get("ref"),
                 data.get("subject_ref"), (data.get("candidate") or {}).get("candidate_id"),
                 (data.get("candidate") or {}).get("time") or record["time"], record["time"],
                 record["actor"]["id"], data.get("due")))
            for link in record.get("links", []):
                self.db.execute("INSERT OR IGNORE INTO links VALUES (?,?,?)", (data["dev_id"], link["rel"], link["ref"]))
            cand = data.get("candidate")
            if cand:
                self._decide_candidate(cand, "accepted", record, data["dev_id"])
        elif action == "dismissed":
            self._decide_candidate(data["candidate"], "dismissed", record, None)
        elif action == "classified":
            after = data.get("after") or {}
            for column in ("severity", "category"):
                if after.get(column):
                    self.db.execute(f"UPDATE deviations SET {column} = ? WHERE dev_id = ?", (after[column], data["dev_id"]))
            for ref in data.get("recurrence_of", []):
                self.db.execute("INSERT OR IGNORE INTO links VALUES (?,?,?)", (data["dev_id"], "recurrence-of", ref))

    def _decide_candidate(self, cand: dict, status: str, record: dict, dev_id: str | None) -> None:
        existing = self.one("SELECT 1 FROM candidates WHERE key = ?", cand["key"])
        if not existing:
            self.db.execute(
                "INSERT INTO candidates (candidate_id, key, rule, source_type, source_ref, time, title, severity,"
                " category, session, status) VALUES (?,?,?,?,?,?,?,?,?,?, 'open')",
                (cand["candidate_id"], cand["key"], cand["rule"], cand["source_type"], cand["source_ref"],
                 cand["time"], cand["title"], cand["severity"], cand["category"], cand.get("session")))
        self.db.execute("UPDATE candidates SET status = ?, dev_id = ?, decided_record = ?, reason = ? WHERE key = ?",
                        (status, dev_id, record["id"], record.get("reason"), cand["key"]))

    def _investigation(self, record: dict, action: str, data: dict) -> None:
        status = "draft" if action == "drafted" else "recorded"
        self.db.execute("INSERT INTO investigations VALUES (?,?,?,?,?)",
                        (record["id"], data["dev_id"], status, record["time"], json.dumps(data, sort_keys=True)))
        if status == "recorded":
            self.db.execute("UPDATE deviations SET state = 'investigated' WHERE dev_id = ? AND state = 'open'",
                            (data["dev_id"],))

    def _action(self, record: dict, action: str, data: dict) -> None:
        target = data.get("target") or {}
        if action == "planned":
            self.db.execute(
                "INSERT INTO actions (action_id, dev_id, seq, kind, description, path, before_sha256, criterion,"
                " state, planned_record) VALUES (?,?,?,?,?,?,?,?, 'planned', ?)",
                (data["action_id"], data["dev_id"], int(data["action_id"].rsplit("-", 1)[1]), data["kind"],
                 data["description"], target["path"], target.get("before_sha256"),
                 json.dumps(data["effectiveness_criterion"], sort_keys=True), record["id"]))
            self.db.execute("UPDATE deviations SET state = 'actions' WHERE dev_id = ? AND state != 'closed'",
                            (data["dev_id"],))
        elif action == "implemented":
            from aqt_evidence import record_content_hash
            self.db.execute(
                "UPDATE actions SET state = 'implemented', after_sha256 = ?, implemented_record = ?,"
                " implemented_hash = ?, implementer = ?, approved_record = NULL, approved_at = NULL, approver = NULL"
                " WHERE action_id = ?",
                (target.get("after_sha256"), record["id"], record_content_hash(record), record["actor"]["id"],
                 data["action_id"]))
        elif action == "approved":
            self.db.execute("UPDATE actions SET state = 'approved', approved_record = ?, approved_at = ?, approver = ?"
                            " WHERE action_id = ?", (record["id"], record["time"], record["actor"]["id"],
                                                     data["action_id"]))
        elif action == "cancelled":
            self.db.execute("UPDATE actions SET state = 'cancelled' WHERE action_id = ?", (data["action_id"],))

    def _effectiveness(self, record: dict, action: str, data: dict) -> None:
        self.db.execute("INSERT INTO evaluations VALUES (?,?,?,?,?,?)",
                        (record["id"], data["action_id"], action, record["time"], data.get("result"),
                         json.dumps(data, sort_keys=True)))

    def _closure(self, record: dict, action: str, data: dict) -> None:
        self.db.execute("UPDATE deviations SET state = 'closed', closed_at = ?, basis = ? WHERE dev_id = ?",
                        (record["time"], data.get("basis"), data["dev_id"]))

    # ---------------------------------------------------------------- rebuild
    def rebuild(self, paths: list[Path] | None) -> int:
        """Drop everything and replay ``capa.*`` records from the evidence files."""
        for table in ("records", "deviations", "links", "candidates", "investigations", "actions", "evaluations"):
            self.db.execute(f"DELETE FROM {table}")
        self.db.commit()
        paths = None if paths is None else [p for p in paths if Path(p).exists()]
        records = [r for r in iter_evidence(paths) if isinstance(r, dict) and r.get("type") in CAPA_TYPES]
        records.sort(key=lambda r: parse_time(r["time"]))  # stable: file order breaks ties
        for record in records:
            self.apply(record)
        return len(records)

    def snapshot(self) -> dict:
        """Index content that must survive a rebuild (used by tests and ``rebuild --check``)."""
        tables = {
            "deviations": "SELECT * FROM deviations ORDER BY dev_id",
            "links": "SELECT * FROM links ORDER BY dev_id, rel, ref",
            "investigations": "SELECT * FROM investigations ORDER BY record_id",
            "actions": "SELECT * FROM actions ORDER BY action_id",
            "evaluations": "SELECT * FROM evaluations ORDER BY record_id",
            "decided_candidates": "SELECT key, status, dev_id, decided_record FROM candidates"
                                  " WHERE status != 'open' ORDER BY key",
        }
        return {name: [dict(row) for row in self.q(sql)] for name, sql in tables.items()}
