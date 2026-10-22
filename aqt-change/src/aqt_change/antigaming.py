"""Heuristic checks for weakened tests in the diff since the plan's base commit.

They produce *warnings*, never proof (idea from dunnit; no code reused).
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from .gitio import Git

SKIP_PATTERNS = [
    (re.compile(r"@pytest\.mark\.(skip|skipif|xfail)\b"), "pytest marker"),
    (re.compile(r"\bpytest\.(skip|xfail)\("), "pytest call"),
    (re.compile(r"@unittest\.(skip|skipIf|skipUnless|expectedFailure)\b"), "unittest decorator"),
    (re.compile(r"\b(it|describe|test)\.(skip|only)\("), "JavaScript test modifier"),
    (re.compile(r"\b(xit|xdescribe|fit|fdescribe)\("), "JavaScript test modifier"),
]
ASSERT_RE = re.compile(r"(^|\s)assert\b|\bself\.assert\w*\(|\bexpect\(|\bassert\w*\(")
TEST_DEF_RE = re.compile(r"^\s*(async\s+)?def\s+test\w*\s*\(|^\s*(it|test)\s*\(")
CONFIG_FILES = {"pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", "conftest.py", "noxfile.py",
                "jest.config.js", "jest.config.ts", "vitest.config.ts", "vitest.config.js", "package.json"}
CONFIG_RE = re.compile(r"addopts|--deselect|(^|\s)-k\s|collect_ignore|testpaths|norecursedirs|testPathIgnorePatterns"
                       r"|testMatch|\"test\"\s*:")


def is_test_file(path: str) -> bool:
    pure = PurePosixPath(path)
    name = pure.name
    return (name.startswith("test_") and name.endswith(".py")) or name.endswith("_test.py") \
        or name == "conftest.py" or "tests" in pure.parts or "__tests__" in pure.parts \
        or re.search(r"\.(test|spec)\.[jt]sx?$", name) is not None


def scan(git: Git | None, base: str | None, exclude: set[str] = frozenset()) -> list[dict]:
    if not git or not base:
        return []
    diff = git.diff_text(base, exclude)
    added: dict[str, list[tuple[int, str]]] = {}
    removed: dict[str, list[str]] = {}
    path = None
    line_no = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = line[4:]
            path = target[2:] if target.startswith("b/") else None
            continue
        if line.startswith("--- "):
            continue
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            line_no = int(match.group(1)) if match else 0
            continue
        if path is None and line.startswith("-"):
            continue
        if line.startswith("+"):
            added.setdefault(path, []).append((line_no, line[1:]))
            line_no += 1
        elif line.startswith("-") and path:
            removed.setdefault(path, []).append(line[1:])
    for untracked in git.untracked():
        if untracked in exclude or not (is_test_file(untracked) or PurePosixPath(untracked).name in CONFIG_FILES):
            continue
        try:
            text = (git.root / untracked).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        added.setdefault(untracked, []).extend((n, l) for n, l in enumerate(text.splitlines(), 1))
    warnings: list[dict] = []
    for file, lines in sorted(added.items()):
        if file is None:
            continue
        for number, text in lines:
            for pattern, label in SKIP_PATTERNS:
                if pattern.search(text):
                    warnings.append({"code": "skip_added", "path": file, "line": number,
                                     "detail": f"{label}: {text.strip()[:120]}"})
                    break
    for file in sorted(set(added) | set(removed)):
        if file is None:
            continue
        plus = [t for _, t in added.get(file, [])]
        minus = removed.get(file, [])
        name = PurePosixPath(file).name
        if is_test_file(file):
            lost = sum(bool(ASSERT_RE.search(t)) for t in minus) - sum(bool(ASSERT_RE.search(t)) for t in plus)
            if lost > 0:
                warnings.append({"code": "asserts_removed", "path": file, "detail": f"{lost} assertion line(s) net removed"})
            gone = sum(bool(TEST_DEF_RE.search(t)) for t in minus) - sum(bool(TEST_DEF_RE.search(t)) for t in plus)
            if gone > 0:
                warnings.append({"code": "tests_removed", "path": file, "detail": f"{gone} test definition(s) net removed"})
        if name in CONFIG_FILES:
            touched = [t for t in plus + minus if CONFIG_RE.search(t)]
            if touched:
                warnings.append({"code": "test_config_changed", "path": file,
                                 "detail": touched[0].strip()[:120]})
    for status, file in git.changed_since(base):
        if status == "D" and is_test_file(file) and file not in exclude:
            warnings.append({"code": "test_file_deleted", "path": file, "detail": "test file deleted"})
    return warnings
