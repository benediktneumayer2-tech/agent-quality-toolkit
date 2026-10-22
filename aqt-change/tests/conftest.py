"""Shared fixtures: an isolated environment and a temporary Git project with a plan.

Everything is synthetic and offline. Agent detection is replaced so results do
not depend on whether the tests themselves run inside an agent session.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from aqt_evidence import AgentContext

from aqt_change import actors
from aqt_change.ledger import Ledger

PY = shlex.quote(sys.executable)

CHECK_SCRIPT = """\
import sys
sys.path.insert(0, "src")
import calc
ok = calc.add(2, 3) == 5
print("collected 1 item")
print("1 passed in 0.01s" if ok else "1 failed in 0.01s")
sys.exit(0 if ok else 1)
"""

PLAN = f"""---
tracker:
  schema: 1
  kind: sprint
  id: s01
  implementation: demo
  status: planned
aqt:
  paths:
    - src/**
    - tests/**
---

# Demo change

## Outcome

Add a calculator.

## Scope

Only the calculator.

## Tasks

- [ ] [T01] Implement add
- [ ] [T02] Document add

## Verification

- [ ] [V01] Unit check passes `$ {PY} tests/check.py`
- [ ] [V02] Screenshot reviewed

## Progress Log

## Blockers

## Deviations

## Failures And Learnings

## Decisions

## Linked Git Changes

## Completion
"""


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    for name in ("AQT_SINK", "AQT_EVIDENCE", "AQT_ACTOR", "AQT_CHANGE_STATE", "AQT_CHANGE_CONFIG",
                 "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(name, raising=False)
    env = tmp_path / "env"
    monkeypatch.setenv("XDG_STATE_HOME", str(env / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(env / "config"))
    monkeypatch.setenv("AQT_SINK", f"file:{env / 'evidence.jsonl'}")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(env / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setattr(actors, "agent_context", lambda: AgentContext(False))
    monkeypatch.setattr(actors, "human_check", lambda: AgentContext(False))
    return env


@pytest.fixture
def evidence_file(isolated) -> Path:
    return isolated / "evidence.jsonl"


@pytest.fixture
def project(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "plans").mkdir()
    (root / "src" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (root / "tests" / "check.py").write_text(CHECK_SCRIPT)
    (root / "plans" / "s01.md").write_text(PLAN)
    (root / ".gitignore").write_text("__pycache__/\n")
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "dev@example.invalid")
    git(root, "config", "user.name", "Example Dev")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "initial")
    monkeypatch.chdir(root)
    return root


@pytest.fixture
def ledger(project) -> Ledger:
    return Ledger.open(project)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def edit(path: Path, old: str, new: str) -> None:
    text = read(path)
    assert old in text, old
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
