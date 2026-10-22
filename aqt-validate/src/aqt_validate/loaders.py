"""Loaders that turn public benchmark files into generic attack (or benign) items.

The benchmarks are read from paths the user provides (a clone or a downloaded file); no
benchmark text ships with this package. Supported layouts:

- ``bipia``: a BIPIA clone (``benchmark/{text,code}_attack_{train,test}.json``: category ->
  list of payloads) or one such file. BIPIA's own train/test become dev/test. With
  ``what="benign"``: the clean contexts in ``benchmark/{email,table,code}/test.jsonl``.
- ``injecagent``: an InjecAgent clone (``data/attacker_cases_{dh,ds}.jsonl``) or one file;
  ``Attacker Instruction`` is the payload, non-empty ``Attacker Tools`` means ``agent_action``.
- ``llmail``: a JSON array or JSONL export of LLMail-Inject submissions with ``subject``
  and ``body`` (parquet must be converted by the user).
- ``agentdojo``: an AgentDojo clone; injection goals are read from
  ``src/agentdojo/default_suites/*/*/injection_tasks.py`` and attack templates (strings
  containing ``{goal}``) from ``src/agentdojo/attacks/*.py``, both with ``ast`` (no import).
- ``generic``: JSONL already in the generic format (validated, passed through).
"""

from __future__ import annotations

import ast
import json
import random
from pathlib import Path

from .data import DataError, read_items, sha256_text

FORMATS = ("generic", "bipia", "injecagent", "llmail", "agentdojo")


def _attack(family: str, payload: str, *, category: str, goal: str | None = None, template: str | None = None,
            source: str, license: str, split: str | None = None) -> dict:
    item = {"label": "attack", "text": payload, "family": family, "category": category,
            "payload": sha256_text(payload), "goal": goal or sha256_text(payload), "source": source,
            "license": license}
    if template:
        item["template"] = template
    if split:
        item["split"] = split
    return item


def _number(items: list[dict], family: str) -> list[dict]:
    seen: dict[str, int] = {}
    for item in items:
        base = f"{family}:{item['payload'][7:19]}"
        seen[base] = seen.get(base, 0) + 1
        item["id"] = base if seen[base] == 1 else f"{base}-{seen[base]}"
    return items


def load(fmt: str, src: str | Path, *, what: str = "attacks", version: str = "unknown",
         license: str = "MIT", seed: int = 36, templates_per_goal: int = 2) -> list[dict]:
    src = Path(src)
    if not src.exists():
        raise DataError(f"{src}: not found")
    if fmt == "generic":
        return read_items(src)
    source = f"{fmt}@{version}"
    if fmt == "bipia":
        return load_bipia(src, what=what, source=source, license=license)
    if what != "attacks":
        raise DataError(f"format {fmt} provides attack items only")
    if fmt == "injecagent":
        return load_injecagent(src, source=source, license=license)
    if fmt == "llmail":
        return load_llmail(src, source=source, license=license)
    if fmt == "agentdojo":
        return load_agentdojo(src, source=source, license=license, seed=seed, templates_per_goal=templates_per_goal)
    raise DataError(f"unknown format {fmt!r}; choose one of {', '.join(FORMATS)}")


# --------------------------------------------------------------------------- BIPIA

def load_bipia(src: Path, *, what: str, source: str, license: str) -> list[dict]:
    if what == "benign":
        files = [src] if src.is_file() else sorted((src / "benchmark").glob("*/test.jsonl"))
        if not files:
            raise DataError(f"{src}: no benchmark/*/test.jsonl contexts found")
        items = []
        for path in files:
            kind = path.parent.name if src.is_dir() else path.stem
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
                if not line.strip():
                    continue
                row = json.loads(line)
                context = row.get("context")
                if context is None:
                    continue
                text = context if isinstance(context, str) else json.dumps(context, ensure_ascii=False)
                items.append({"id": f"bipia-{kind}:{n}", "label": "benign", "text": text, "family": f"bipia-{kind}",
                              "category": "benign", "source": source, "license": license})
        return items
    if src.is_file():
        files = [src]
    else:
        files = sorted((src / "benchmark").glob("*_attack_*.json"))
    if not files:
        raise DataError(f"{src}: no benchmark/*_attack_*.json files found")
    items = []
    for path in files:
        stem = path.stem  # text_attack_test
        kind = "code" if stem.startswith("code") else "text"
        split = "dev" if stem.endswith("train") else "test" if stem.endswith("test") else None
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise DataError(f"{path}: expected an object of category -> list of payloads")
        for category, payloads in sorted(data.items()):
            for payload in payloads:
                if isinstance(payload, str) and payload.strip():
                    items.append(_attack(f"bipia-{kind}", payload, category=category, source=source,
                                         license=license, split=split))
    return _number(items, "bipia")


# --------------------------------------------------------------------------- InjecAgent

def load_injecagent(src: Path, *, source: str, license: str) -> list[dict]:
    files = [src] if src.is_file() else sorted((src / "data").glob("attacker_cases_*.jsonl"))
    if not files:
        raise DataError(f"{src}: no data/attacker_cases_*.jsonl files found")
    items, seen = [], set()
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            payload = row.get("Attacker Instruction")
            if not isinstance(payload, str) or not payload.strip() or payload in seen:
                continue
            seen.add(payload)
            tools = row.get("Attacker Tools") or []
            items.append(_attack("injecagent", payload, category="agent_action" if tools else "task_hijack",
                                 template=row.get("Attack Type") or None, source=source, license=license))
    return _number(items, "injecagent")


# --------------------------------------------------------------------------- LLMail-Inject

def load_llmail(src: Path, *, source: str, license: str) -> list[dict]:
    raw = src.read_text(encoding="utf-8")
    try:
        rows = json.loads(raw)
        if isinstance(rows, dict):
            rows = rows.get("data") or rows.get("rows") or [rows]
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    items, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        body = row.get("body")
        if not isinstance(body, str) or not body.strip():
            continue
        subject = row.get("subject") or ""
        text = f"{subject}\n\n{body}" if subject else body
        if text in seen:
            continue
        seen.add(text)
        category = str(row.get("scenario") or row.get("level") or "email")
        items.append(_attack("llmail", text, category=category, source=source, license=license))
    if not items:
        raise DataError(f"{src}: no rows with a non-empty body")
    return _number(items, "llmail")


# --------------------------------------------------------------------------- AgentDojo

def _string_value(node, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue) and isinstance(value.value, (ast.Name, ast.Attribute)):
                key = ast.unparse(value.value).split(".")[-1]
                if key not in constants:
                    return None
                parts.append(constants[key])
            else:
                return None
        return "".join(parts)
    return None


def _constants(body, known: dict[str, str] | None = None) -> dict[str, str]:
    out = dict(known or {})
    for node in body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = _string_value(node.value, out)
            if value is not None:
                out[node.targets[0].id] = value
    return out


def agentdojo_goals(root: Path) -> list[tuple[str, bool]]:
    """``(goal, needs_tool_call)`` for every injection task found."""
    files = sorted((root / "src/agentdojo/default_suites").glob("*/*/injection_tasks.py"))
    if not files:
        raise DataError(f"{root}: no src/agentdojo/default_suites/*/*/injection_tasks.py found "
                        "(AgentDojo layout changed? use the generic format)")
    goals = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module_constants = _constants(tree.body)
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            constants = _constants(cls.body, module_constants)
            goal = constants.get("GOAL")
            if goal is None:
                continue
            empty = None
            for node in cls.body:
                if isinstance(node, ast.FunctionDef) and node.name == "ground_truth":
                    returns = [r for r in ast.walk(node) if isinstance(r, ast.Return)]
                    empty = bool(returns) and all(isinstance(r.value, ast.List) and not r.value.elts for r in returns)
            goals.append((goal, not empty))
    return sorted(set(goals))


def agentdojo_templates(root: Path) -> dict[str, str]:
    files = sorted((root / "src/agentdojo/attacks").glob("*.py"))
    templates: dict[str, str] = {}
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            name = cls.name
            found = None
            for node in ast.walk(cls):
                if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "name" for t in node.targets):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        name = node.value.value
                if found is None and isinstance(node, ast.Constant) and isinstance(node.value, str) \
                        and "{goal}" in node.value and "{tools}" not in node.value and "{task}" not in node.value:
                    found = node.value
            if found and found not in templates.values():
                templates[name] = found
    if not templates:
        raise DataError(f"{root}: no attack templates with {{goal}} found in src/agentdojo/attacks/")
    return templates


class _Keep(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def load_agentdojo(root: Path, *, source: str, license: str, seed: int, templates_per_goal: int) -> list[dict]:
    goals = agentdojo_goals(root)
    templates = agentdojo_templates(root)
    rng = random.Random(seed)
    names = sorted(templates)
    items = []
    for goal, needs_tool in goals:
        chosen = names if templates_per_goal <= 0 else rng.sample(names, min(templates_per_goal, len(names)))
        for name in chosen:
            payload = templates[name].format_map(_Keep(goal=goal, user="the user", model="the AI language model"))
            items.append(_attack("agentdojo", payload, category="agent_action" if needs_tool else "task_hijack",
                                 goal=sha256_text(goal), template=name, source=source, license=license))
    return _number(items, "agentdojo")
