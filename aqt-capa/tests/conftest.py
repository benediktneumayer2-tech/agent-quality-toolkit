"""Shared fixtures: isolated XDG dirs, synthetic evidence (INTERFACES I5/I6), a temp git repo, a CAPA instance."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from aqt_evidence import AgentContext, JsonlSink, actor, new_record, subject

from aqt_capa.capa import Capa
from aqt_capa.config import Config
from aqt_capa.store import Store

HUMAN = "human:qa-lead"
AGENT = actor("agent", "agent:claude-code:s-001", harness="claude-code", session="s-001")


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    for name in ("AQT_SINK", "AQT_EVIDENCE", "AQT_ACTOR", "AQT_CAPA_DB", "AQT_AGENT_SESSION"):
        monkeypatch.delenv(name, raising=False)


def rec(type_, action, *, data=None, who=AGENT, **kw):
    return new_record(type_, who, action, data=data, **kw)


def synthetic_evidence() -> list[dict]:
    """One record per scanned source, with the I6 field names."""
    receipt = rec("change.receipt", "run", data={
        "argv": ["pytest", "-q"], "exit_code": 1, "passed": False, "plan_basis_hash": "sha256:" + "1" * 64,
        "tree_fingerprint": "sha256:" + "2" * 64, "counts": {"failed": 2}})
    passing = rec("change.receipt", "run", data={
        "argv": ["pytest", "-q"], "exit_code": 0, "passed": True, "plan_basis_hash": "sha256:" + "1" * 64,
        "tree_fingerprint": "sha256:" + "3" * 64, "counts": {}})
    review = rec("change.review", "review", data={
        "verdict": "FAIL", "independence": "fresh-context", "diff_sha256": "sha256:" + "4" * 64,
        "findings": [{"severity": "high", "text": "missing input validation"}]})
    threat = rec("quarantine.threat.declared", "declare-threat", who=actor("human", HUMAN), reason="injection",
                 data={"case_id": "QC-0001", "band": "hold", "score_ppm": 910_000,
                       "source": {"tool": "WebFetch", "ref": "https://example.test/page", "domain": "example.test"}})
    held = rec("quarantine.held", "hold", data={"case_id": "QC-0001", "band": "hold", "score_ppm": 910_000,
                                                "source": {"tool": "WebFetch", "ref": "x", "domain": "example.test"}})
    refused = rec("quarantine.refused", "refused", data={
        "attempted_action": "release", "reason_code": "agent-context", "agent_markers": ["env:CLAUDECODE"]})
    review_ok = rec("trail.review", "review", who=actor("human", "human:auditor"), data={
        "head": "sha256:" + "5" * 64,
        "findings": [{"query": "self-approval", "severity": "high", "record_ids": ["rec_x"], "disposition": "deviation"},
                     {"query": "out-of-hours", "severity": "low", "record_ids": [], "disposition": "ok"}]})
    return [receipt, passing, review, held, threat, refused, review_ok]


def append_all(path: Path, records: list[dict]) -> None:
    sink = JsonlSink(path)
    for r in records:
        sink.append(r)


def git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.test",
           "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.test", "GIT_CONFIG_GLOBAL": "/dev/null"}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout


@pytest.fixture
def repo(tmp_path) -> Path:
    """A throwaway git repository (in tmp) with one agent commit and its revert."""
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    (path / "a.txt").write_text("one\n")
    git(path, "add", "a.txt")
    git(path, "commit", "-q", "-m", "initial")
    (path / "a.txt").write_text("two\n")
    git(path, "commit", "-q", "-am", "agent change\n\nCo-Authored-By: Example Agent <agent@example.test>")
    git(path, "revert", "--no-edit", "HEAD")
    return path


class Env:
    """A configured project: evidence files, control file, CAPA factory with an injectable caller."""

    def __init__(self, tmp_path: Path):
        self.root = tmp_path / "project"
        self.root.mkdir()
        (self.root / "AGENTS.md").write_text("# Agent rules\n\n- Run the tests.\n")
        self.others = tmp_path / "others.jsonl"
        self.sink_path = tmp_path / "capa-evidence.jsonl"
        self.others.touch()
        self.sink_path.touch()
        self.db = tmp_path / "state" / "capa.db"
        self.is_agent = False

    def config(self, **kw) -> Config:
        cfg = Config(identity_id=HUMAN, identity_role="quality", project_root=self.root, db_path=self.db,
                     evidence_paths=[self.others, self.sink_path])
        for k, v in kw.items():
            setattr(cfg, k, v)
        return cfg

    def context(self) -> AgentContext:
        if self.is_agent:
            return AgentContext(True, "claude-code", ["env:CLAUDECODE"], [])
        return AgentContext(False)

    def guard(self) -> AgentContext:
        from aqt_evidence import HumanCheckError
        ctx = self.context()
        if ctx.is_agent:
            raise HumanCheckError(ctx, "refused: looks like an agent session")
        return ctx

    def capa(self, **kw) -> Capa:
        cfg = self.config(**kw)
        return Capa(cfg, store=Store(cfg.db_path), sink=JsonlSink(self.sink_path), evidence=cfg.evidence_paths,
                    guard=self.guard, context=self.context)

    def add(self, records: list[dict]) -> None:
        append_all(self.others, records)


@pytest.fixture
def env(tmp_path) -> Env:
    return Env(tmp_path)


def sessions(n: int, start: int = 100) -> list[dict]:
    return [rec("trail.import", "import", who=actor("agent", f"agent:claude-code:s-{i}", harness="claude-code",
                                                     session=f"s-{i}"), data={"tool": "Bash"})
            for i in range(start, start + n)]


__all__ = ["AGENT", "HUMAN", "append_all", "git", "rec", "sessions", "subject", "synthetic_evidence"]
