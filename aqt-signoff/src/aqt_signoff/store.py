"""SQLite working index: approved actions (with the claim lock) and undelivered records.

The index is not the authority: claims re-verify the signed approvals it holds.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    request_key_sha256 TEXT NOT NULL,
    version INTEGER NOT NULL,
    spec TEXT NOT NULL,
    action_sha256 TEXT NOT NULL,
    preparer TEXT NOT NULL,
    prepared_record TEXT NOT NULL,
    status TEXT NOT NULL,
    approvals TEXT NOT NULL DEFAULT '[]',
    rejection TEXT,
    claim_id TEXT,
    claimed_at TEXT,
    claim_record TEXT,
    outcome TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending (
    record_id TEXT PRIMARY KEY,
    record TEXT NOT NULL,
    error TEXT,
    created_at TEXT NOT NULL
);
"""

JSON_COLUMNS = ("spec", "preparer", "approvals", "rejection", "outcome")


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists()
        self.db = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        self.db.row_factory = sqlite3.Row
        if new:
            os.chmod(self.path, 0o600)
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def transaction(self):
        """``BEGIN IMMEDIATE``: one writer at a time, so check-then-update is atomic."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    def action(self, action_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        return decode(row) if row else None

    def actions(self, status: str | None = None) -> list[dict]:
        rows = self.db.execute("SELECT * FROM actions ORDER BY created_at, id").fetchall()
        return [decode(row) for row in rows]

    def add_pending(self, record: dict, error: str, now: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO pending (record_id, record, error, created_at) VALUES (?,?,?,?)",
                        (record["id"], json.dumps(record), error, now))

    def pending(self) -> list[dict]:
        return [json.loads(row["record"]) for row in
                self.db.execute("SELECT record FROM pending ORDER BY created_at, record_id")]

    def drop_pending(self, record_id: str) -> None:
        self.db.execute("DELETE FROM pending WHERE record_id=?", (record_id,))


def decode(row: sqlite3.Row) -> dict:
    value = dict(row)
    for column in JSON_COLUMNS:
        if value.get(column) is not None:
            value[column] = json.loads(value[column])
    return value


def encode(value) -> str:
    return json.dumps(value, sort_keys=True)
