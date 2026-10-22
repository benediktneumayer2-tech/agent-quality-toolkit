"""Plan files: Project Tracker Next sprint Markdown plus an optional ``aqt:`` block.

The parser is line based. It knows front matter, ``##`` sections, fenced code,
task items ``- [ ] [T01] text`` and timestamped events ``### <ts> — <title>``.
Patterns adapted from Project Tracker Next (``content/markdown_parser.py``).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from aqt_evidence import bytes_hash, content_hash

from . import frontmatter

TASK_RE = re.compile(
    r"^(?P<indent>\s*)[-+*]\s+\[(?P<checked>[ xX])\]\s+"
    r"(?:\[(?P<task_id>[A-Za-z][A-Za-z0-9_-]*)\]\s+)?(?P<text>.*)$"
)
STABLE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,127}$")
EVENT_RE = re.compile(r"^###\s+(?P<timestamp>\d{4}-\d{2}-\d{2}(?:[T ][^—]+?)?)\s+—\s+(?P<title>.+?)\s*$")
COMMAND_RE = re.compile(r"`\$ ([^`]+)`")
EVENT_SECTIONS = {
    "progress log": "progress", "progress": "progress", "blockers": "blocker",
    "deviations": "deviation", "failures and learnings": "failure", "failures & learnings": "failure",
    "failures": "failure", "decisions": "decision",
}
ITEM_SECTIONS = {"tasks": "tasks", "verification": "verification"}
COMPLETION = "completion"
LIFECYCLE_KEYS = ("status", "started_at", "completed_at", "git")
IDENTITY_KEYS = ("schema", "kind", "id", "implementation")
STRUCTURE_KEYS = ("schema", "kind", "id", "implementation", "sequence", "depends_on", "owners")
ACTIVE = {"in_progress", "blocked"}
TERMINAL = {"completed", "failed", "cancelled", "superseded"}
STATUSES = {"draft", "planned", *ACTIVE, *TERMINAL}


@dataclass
class Item:
    section: str
    id: str | None
    checked: bool
    text: str
    line: int
    commands: list[list[str]] = field(default_factory=list)

    @property
    def manual(self) -> bool:
        return not self.commands


@dataclass
class Event:
    category: str
    timestamp: str
    title: str
    body: str

    def identity(self) -> str:
        return content_hash({"c": self.category, "t": self.timestamp, "h": self.title, "b": self.body})


@dataclass
class Plan:
    text: str
    front: dict
    body: str
    body_offset: int
    title: str
    items: list[Item]
    events: list[Event]
    sections: list[tuple[str, int, int]]  # (lower-case name, first body line index, end index)
    errors: list[str]

    @property
    def tracker(self) -> dict:
        value = self.front.get("tracker")
        return value if isinstance(value, dict) else {}

    @property
    def aqt(self) -> dict:
        value = self.front.get("aqt")
        return value if isinstance(value, dict) else {}

    @property
    def id(self) -> str | None:
        value = self.tracker.get("id")
        return str(value) if value is not None else None

    @property
    def status(self) -> str | None:
        value = self.tracker.get("status")
        return str(value) if value is not None else None

    @property
    def base_commit(self) -> str | None:
        git = self.tracker.get("git")
        return str(git.get("base_commit")) if isinstance(git, dict) and git.get("base_commit") else None

    @property
    def tasks(self) -> list[Item]:
        return [item for item in self.items if item.section == "tasks"]

    @property
    def verification(self) -> list[Item]:
        return [item for item in self.items if item.section == "verification"]

    def item(self, item_id: str) -> Item | None:
        return next((item for item in self.items if item.id == item_id), None)

    @property
    def declared_paths(self) -> list[str]:
        paths = self.aqt.get("paths")
        return [str(p) for p in paths] if isinstance(paths, list) else []

    @property
    def raw_hash(self) -> str:
        return bytes_hash(self.text.encode("utf-8"))

    @property
    def lifecycle(self) -> dict:
        return {key: self.tracker.get(key) for key in LIFECYCLE_KEYS}


def parse_plan(text: str) -> Plan:
    errors: list[str] = []
    try:
        front_text, body = frontmatter.split(text)
        front = frontmatter.parse(front_text) if front_text is not None else {}
    except frontmatter.FrontMatterError as error:
        front_text, body, front = None, text, {}
        errors.append(f"front matter: {error}")
    body_offset = 0 if front_text is None else front_text.count("\n") + 2
    lines = body.splitlines()
    sections: list[tuple[str, int, int]] = []
    items: list[Item] = []
    events: list[Event] = []
    title = ""
    fence = None
    current = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            marker = stripped[:3]
            fence = None if fence == marker else (fence or marker)
            continue
        if fence:
            continue
        if line.startswith("# ") and not title:
            title = line[2:].strip()
        if line.startswith("## "):
            if current:
                sections.append((current[0], current[1], index))
            current = (line[3:].strip().lower(), index + 1)
            continue
        if current is None:
            continue
        name = current[0]
        if name in ITEM_SECTIONS:
            match = TASK_RE.match(line)
            if match:
                item = Item(ITEM_SECTIONS[name], match.group("task_id"), match.group("checked") in "xX",
                            match.group("text").strip(), body_offset + index + 1)
                for raw in COMMAND_RE.findall(item.text):
                    try:
                        argv = shlex.split(raw)
                    except ValueError as error:
                        errors.append(f"line {item.line}: declared command cannot be parsed: {error}")
                        continue
                    if argv:
                        item.commands.append(argv)
                items.append(item)
    if current:
        sections.append((current[0], current[1], len(lines)))
    for name, start, end in sections:
        category = EVENT_SECTIONS.get(name)
        if not category:
            continue
        entry = None
        body_lines: list[str] = []
        for line in lines[start:end]:
            match = EVENT_RE.match(line)
            if match:
                if entry:
                    events.append(Event(category, entry[0], entry[1], "\n".join(body_lines).strip()))
                entry, body_lines = (match.group("timestamp").strip(), match.group("title").strip()), []
            elif entry:
                body_lines.append(line.rstrip())
        if entry:
            events.append(Event(category, entry[0], entry[1], "\n".join(body_lines).strip()))
    plan = Plan(text, front, body, body_offset, title, items, events, sections, errors)
    _validate(plan)
    return plan


def _validate(plan: Plan) -> None:
    if not plan.tracker:
        plan.errors.append("front matter needs a 'tracker:' block")
        return
    if not plan.id or not STABLE_ID.match(plan.id):
        plan.errors.append("tracker.id is missing or not a stable ID")
    if plan.status is not None and plan.status not in STATUSES:
        plan.errors.append(f"tracker.status {plan.status!r} is not a known status")
    seen: set[str] = set()
    for item in plan.items:
        if not item.id:
            plan.errors.append(f"line {item.line}: {item.section} item needs a stable ID like [T01]")
            continue
        if item.id in seen:
            plan.errors.append(f"line {item.line}: duplicate item ID {item.id}")
        seen.add(item.id)
    paths = plan.aqt.get("paths")
    if paths is not None and not isinstance(paths, list):
        plan.errors.append("aqt.paths must be a list of globs")


def _section_of(plan: Plan, index: int) -> str | None:
    for name, start, end in plan.sections:
        if start <= index < end:
            return name
    return None


def basis_hash(plan: Plan) -> str:
    """Hash of the plan's normal form: check marks masked, lifecycle fields, the
    Completion section and event section contents removed. Ticking boxes and
    appending events therefore leave it unchanged."""
    front = {key: value for key, value in plan.front.items()}
    if isinstance(front.get("tracker"), dict):
        front["tracker"] = {k: v for k, v in front["tracker"].items() if k not in LIFECYCLE_KEYS}
    lines = plan.body.splitlines()
    out: list[str] = []
    for index, line in enumerate(lines):
        section = _section_of(plan, index)
        if section == COMPLETION or section in EVENT_SECTIONS:
            continue
        if section in ITEM_SECTIONS:
            match = TASK_RE.match(line)
            if match:
                line = line[: match.start("checked")] + " " + line[match.end("checked"):]
        out.append(line.rstrip())
    while out and not out[-1]:
        out.pop()
    return content_hash({"front": front, "body": "\n".join(out)})


def structure(plan: Plan) -> dict[str, Any]:
    """The structured meaning used to tell editorial from semantic changes."""
    return {
        "tracker": {key: plan.tracker.get(key) for key in STRUCTURE_KEYS},
        "aqt": plan.aqt,
        "items": [[item.section, item.id, item.text] for item in plan.items],
    }


def item_diff(old: Plan, new: Plan) -> dict[str, list[str]]:
    before = {item.id: item for item in old.items if item.id}
    after = {item.id: item for item in new.items if item.id}
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "changed": sorted(key for key in set(before) & set(after)
                          if (before[key].text, before[key].section) != (after[key].text, after[key].section)),
    }


def command_text(argv: list[str]) -> str:
    return shlex.join(argv)


# --- writing -------------------------------------------------------------------

def set_tracker(text: str, **updates: Any) -> str:
    """Rewrite the front matter with updated ``tracker`` keys (None removes a key)."""
    front_text, body = frontmatter.split(text)
    front = frontmatter.parse(front_text or "")
    tracker = dict(front.get("tracker") or {})
    for key, value in updates.items():
        if value is None:
            tracker.pop(key, None)
        else:
            tracker[key] = value
    front["tracker"] = tracker
    return frontmatter.join(front, body)


def tick_items(text: str, ids: set[str]) -> str:
    lines = text.split("\n")
    in_items = False
    fence = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            fence = None if fence == stripped[:3] else (fence or stripped[:3])
            continue
        if fence:
            continue
        if line.startswith("## "):
            in_items = line[3:].strip().lower() in ITEM_SECTIONS
            continue
        if in_items:
            match = TASK_RE.match(line)
            if match and match.group("task_id") in ids and match.group("checked") == " ":
                lines[index] = line[: match.start("checked")] + "x" + line[match.end("checked"):]
    return "\n".join(lines)


def append_completion(text: str, entry: str) -> str:
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if line.startswith("## ") and line[3:].strip().lower() == COMPLETION:
            end = next((j for j in range(index + 1, len(lines)) if lines[j].startswith("## ")), len(lines))
            while end > index + 1 and not lines[end - 1].strip():
                end -= 1
            block = ["", *entry.rstrip("\n").split("\n")]
            lines[end:end] = block
            result = "\n".join(lines)
            return result if result.endswith("\n") else result + "\n"
    return text.rstrip("\n") + "\n\n## Completion\n\n" + entry.rstrip("\n") + "\n"


TEMPLATE = """---
tracker:
  schema: 1
  kind: sprint
  id: {id}
  implementation: {implementation}
  status: planned
aqt:
  paths: []
---

# {title}

## Outcome

{follows}
## Scope

## Tasks

<!-- Add work tasks as: - [ ] [T01] Description -->

## Verification

<!-- Add checks as: - [ ] [V01] Unit tests pass `$ python -m pytest -q` -->

## Progress Log

## Blockers

## Deviations

## Failures And Learnings

## Decisions

## Linked Git Changes

## Completion
"""


def new_plan_text(plan_id: str, title: str, implementation: str, follows: str | None = None) -> str:
    if not STABLE_ID.match(plan_id):
        raise ValueError("plan id must be a stable ID (letters, digits, . _ -)")
    note = f"Follow-up of `{follows}`.\n\n" if follows else ""
    return TEMPLATE.format(id=plan_id, title=title, implementation=implementation, follows=note)
