"""Hook entry points: Claude Code (``TaskCompleted``, ``Stop``, ``SubagentStop``) and git ``commit-msg``.

Claude Code protocol: exit 0 allows, exit 2 blocks and shows stderr to the agent.
The hooks never run tests; they only read the ledger.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import sys
from pathlib import Path

from .errors import ChangeError
from .gitio import trailers
from .ledger import TRUST_NOGO, TRUST_TEXT, Ledger
from .plans import STATES_OK, active_plans, status
from .receipts import Freshness, evaluate, hidden_text, trust_note

ID_REF = re.compile(r"\[([A-Za-z][A-Za-z0-9._-]{0,127})\]")
SNIPPET = {
    "hooks": {
        "TaskCompleted": [{"hooks": [{"type": "command", "command": "aqt-change hook claude-code"}]}],
        "Stop": [{"hooks": [{"type": "command", "command": "aqt-change hook claude-code"}]}],
        "SubagentStop": [{"hooks": [{"type": "command", "command": "aqt-change hook claude-code"}]}],
    }
}
GIT_SHIM = "#!/bin/sh\n# installed by aqt-change: checks AQT-* commit trailers\nexec {python} -m aqt_change.cli hook commit-msg \"$1\"\n"


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _not_ok(plan_id: str, item_id: str, entry: dict, ticked: bool = False) -> str:
    lead = f"{plan_id} {item_id} is ticked but has" if ticked else f"{plan_id} {item_id}:"
    text = f"{lead} no fresh passing receipt ({entry['state']})"
    return text + (f": {trust_note(entry)}" if entry["state"] == "unverified" else "")


def claude_code(payload: dict, ledger: Ledger | None = None) -> tuple[int, str]:
    """Return (exit code, message). 2 blocks."""
    event = payload.get("hook_event_name", "")
    if ledger is None:
        try:
            ledger = Ledger.open(payload.get("cwd") or os.getcwd())
        except ChangeError:
            return 0, ""
    plans = active_plans(ledger)
    if not plans:
        return 0, ""
    freshness = Freshness(ledger)
    problems: list[str] = []
    if event == "TaskCompleted":
        referenced = set()
        for text in _strings({k: v for k, v in payload.items() if k not in ("transcript_path", "cwd")}):
            referenced |= set(ID_REF.findall(text))
        checked = False
        for rel, plan in plans:
            wanted = [item for item in plan.verification if item.id in referenced]
            if not wanted:
                continue
            checked = True
            items = evaluate(ledger, plan, freshness)
            for item in wanted:
                entry = items[item.id]
                if entry["state"] != "ok":
                    problems.append(_not_ok(plan.id, item.id, entry))
    elif event in ("Stop", "SubagentStop"):
        checked = True
        for rel, plan in plans:
            state = status(ledger, rel)["state"]
            if state not in STATES_OK:
                problems.append(f"{plan.id}: plan edits are {state}; run 'aqt-change reconcile {rel} --kind … --reason …'")
            items = evaluate(ledger, plan, freshness)
            for item in plan.verification:
                if item.checked and items[item.id]["state"] != "ok":
                    problems.append(_not_ok(plan.id, item.id, items[item.id], ticked=True))
    else:
        return 0, ""
    hidden = [h for h in ledger.git.hidden_changes() if h["state"] != "sparse"] if (checked and ledger.git) else []
    if hidden:
        problems.append("Git is told to ignore working-tree changes, so receipts do not test what would be "
                        "committed (git update-index --no-skip-worktree / --no-assume-unchanged): "
                        + hidden_text(hidden))
    if not problems:
        return 0, ""
    hint = "Run 'aqt-change run --plan <plan> --item <ID>' (or --all) to record receipts."
    message = "aqt-change: completion is not evidenced:\n- " + "\n- ".join(problems) + "\n" + hint
    if event in ("Stop", "SubagentStop") and payload.get("stop_hook_active"):
        return 0, message + "\n(not blocking again: stop_hook_active; 'aqt-change finish' will still refuse)"
    return 2, message


def commit_msg(ledger: Ledger, message_file: str, require: bool = False) -> tuple[int, str]:
    text = Path(message_file).read_text(encoding="utf-8", errors="replace")
    text = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    pairs = trailers(text)
    aqt = [(k, v) for k, v in pairs if k.startswith("AQT-")]
    problems = []
    if not aqt:
        if require and active_plans(ledger):
            return 1, "aqt-change: a plan is in progress; commits need an AQT-Plan trailer (or use 'aqt-change finish')"
        return 0, ""
    known = {k: [v for kk, v in aqt if kk == k] for k in {k for k, _ in aqt}}
    plan_ids = []
    for value in known.get("AQT-Plan", []):
        plan_id = value.split(" ")[0]
        plan_ids.append(plan_id)
        if not ledger.plan_state(plan_id):
            problems.append(f"AQT-Plan names unknown plan {plan_id}")
    if len(known.get("AQT-Plan", [])) != 1:
        problems.append("exactly one AQT-Plan trailer is required")
    receipts = {r["id"]: r for r in ledger.records("change.receipt")}
    trail = ledger.trail_check() if known.get("AQT-Receipts") else None
    for value in known.get("AQT-Receipts", []):
        for receipt_id in [p.strip() for p in value.split(",") if p.strip()]:
            receipt = receipts.get(receipt_id)
            if not receipt:
                problems.append(f"unknown receipt {receipt_id}")
            elif not receipt["data"].get("passed"):
                problems.append(f"receipt {receipt_id} did not pass")
            elif trail and (trust := trail.status(receipt)) in TRUST_NOGO:
                problems.append(f"receipt {receipt_id} {TRUST_TEXT[trust]}")
    for value in known.get("AQT-Finish", []):
        if "/" not in value or (plan_ids and value.split("/")[0] not in plan_ids):
            problems.append(f"AQT-Finish {value!r} must be <plan-id>/<key> of the AQT-Plan")
    if problems:
        return 1, "aqt-change: commit trailers rejected:\n- " + "\n- ".join(problems)
    return 0, ""


def install_git_hook(ledger: Ledger) -> Path:
    if not ledger.git:
        raise ChangeError("git_required", "not a Git repository", exit_code=2)
    hooks = ledger.git.hooks_dir()
    target = hooks / "commit-msg"
    if target.exists():
        raise ChangeError("hook_exists", f"{target} already exists; add 'aqt-change hook commit-msg \"$1\"' to it "
                          "yourself", exit_code=1)
    hooks.mkdir(parents=True, exist_ok=True)
    target.write_text(GIT_SHIM.format(python=shlex.quote(sys.executable)), encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


def snippet() -> str:
    return json.dumps(SNIPPET, indent=2)
