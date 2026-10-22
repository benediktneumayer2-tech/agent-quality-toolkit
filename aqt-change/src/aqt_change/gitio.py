"""Git access through the ``git`` CLI with argument lists (no shell, no remotes).

Exact-path commit rules adapted from the author's Project Tracker Next (see NOTICE):
files only, unrelated staged paths abort, hooks and identity are never bypassed.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path

from .errors import ChangeError, refused
from .globs import matches_any

COMMIT_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
TRAILER_RE = re.compile(r"^(?P<key>[A-Za-z0-9-]+):\s*(?P<value>.*)$")


class Git:
    def __init__(self, root: Path):
        self.root = Path(root)

    def run(self, *args: str, input: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
        result = subprocess.run(["git", "-C", str(self.root), *args], input=input, capture_output=True,
                                env=env)
        if check and result.returncode != 0:
            raise ChangeError("git_failed", f"git {args[0]} failed: "
                              f"{result.stderr.decode('utf-8', 'replace').strip()}",
                              details={"args": list(args)}, exit_code=2)
        return result

    def text(self, *args: str) -> str:
        return self.run(*args).stdout.decode("utf-8", "replace")

    @staticmethod
    def discover(start: Path) -> "Git | None":
        try:
            result = subprocess.run(["git", "-C", str(start), "rev-parse", "--show-toplevel"],
                                    capture_output=True, text=True)
        except OSError:
            return None
        if result.returncode != 0:
            return None
        return Git(Path(result.stdout.strip()))

    def git_dir(self) -> Path:
        return Path(self.text("rev-parse", "--absolute-git-dir").strip())

    def hooks_dir(self) -> Path:
        value = self.text("rev-parse", "--git-path", "hooks").strip()
        path = Path(value)
        return path if path.is_absolute() else self.root / path

    def head(self) -> str | None:
        result = self.run("rev-parse", "--verify", "-q", "HEAD^{commit}", check=False)
        if result.returncode != 0:
            return None
        return result.stdout.decode().strip() or None

    def branch(self) -> str | None:
        result = self.run("symbolic-ref", "--short", "-q", "HEAD", check=False)
        if result.returncode != 0:
            return None
        return result.stdout.decode().strip() or None

    def is_dirty(self, exclude: set[str] = frozenset()) -> bool:
        return any(path not in exclude for _, path in self.status_entries())

    # --- content fingerprint ---------------------------------------------------

    def status_entries(self) -> list[tuple[str, str]]:
        """(XY, path) for changed and untracked files; renames yield both paths."""
        raw = self.run("status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
        parts = raw.split(b"\0")
        entries, index = [], 0
        while index < len(parts):
            part = parts[index]
            index += 1
            if not part:
                continue
            code, path = part[:2].decode(), part[3:].decode("utf-8", "surrogateescape")
            entries.append((code, path))
            if code[0] in "RC":
                if index < len(parts) and parts[index]:
                    entries.append(("D ", parts[index].decode("utf-8", "surrogateescape")))
                index += 1
        return entries

    def head_tree(self) -> dict[str, str]:
        if not self.head():
            return {}
        raw = self.run("ls-tree", "-r", "-z", "--full-tree", "HEAD").stdout
        tree = {}
        for entry in raw.split(b"\0"):
            if not entry:
                continue
            meta, path = entry.split(b"\t", 1)
            tree[path.decode("utf-8", "surrogateescape")] = meta.split()[2].decode()
        return tree

    def hash_paths(self, paths: list[str]) -> dict[str, str]:
        if not paths:
            return {}
        data = "\n".join(paths).encode("utf-8", "surrogateescape") + b"\n"
        out = self.run("hash-object", "--stdin-paths", input=data).stdout.decode().split()
        return dict(zip(paths, out))

    def fingerprint(self, exclude_paths: set[str], exclude_globs: list[str]) -> str:
        tree = self.head_tree()
        changed = []
        for _code, path in self.status_entries():
            full = self.root / path
            if full.is_dir():
                continue  # submodule or nested repository: keep the recorded commit
            if full.is_file():
                changed.append(path)
            else:
                tree.pop(path, None)
        tree.update(self.hash_paths(changed))
        return _digest(tree, exclude_paths, exclude_globs)

    # --- diffs -----------------------------------------------------------------

    def changed_since(self, base: str) -> list[tuple[str, str]]:
        """(status, path) between ``base`` and the working tree, plus untracked files."""
        raw = self.run("diff", "--name-status", "-z", "--no-renames", base).stdout.split(b"\0")
        result = []
        for index in range(0, len(raw) - 1, 2):
            status, path = raw[index].decode(), raw[index + 1].decode("utf-8", "surrogateescape")
            if status:
                result.append((status[0], path))
        for path in self.untracked():
            result.append(("A", path))
        return sorted(set(result), key=lambda item: item[1])

    def untracked(self) -> list[str]:
        raw = self.run("ls-files", "--others", "--exclude-standard", "-z").stdout
        return [p.decode("utf-8", "surrogateescape") for p in raw.split(b"\0") if p]

    def diff_text(self, base: str, exclude: set[str] = frozenset()) -> str:
        args = ["diff", "-U0", "--no-ext-diff", "--no-color", base, "--", "."]
        args += [f":(exclude){path}" for path in sorted(exclude)]
        return self.run(*args).stdout.decode("utf-8", "replace")

    def diff_sha256(self, base: str, exclude: set[str] = frozenset()) -> str:
        args = ["diff", "--binary", "--no-ext-diff", "--no-color", base, "--", "."]
        args += [f":(exclude){path}" for path in sorted(exclude)]
        digest = hashlib.sha256(self.run(*args).stdout)
        untracked = sorted(p for p in self.untracked() if p not in exclude)
        for path, blob in sorted(self.hash_paths(untracked).items()):
            digest.update(f"\0untracked {blob} {path}".encode("utf-8", "surrogateescape"))
        return "sha256:" + digest.hexdigest()

    # --- commits -----------------------------------------------------------------

    def staged_paths(self) -> list[str]:
        raw = self.run("diff", "--cached", "--name-only", "-z").stdout
        return [p.decode("utf-8", "surrogateescape") for p in raw.split(b"\0") if p]

    def check_paths(self, paths: list[str]) -> list[str]:
        clean = []
        tracked = set(self.head_tree())
        for path in paths:
            normal = Path(path).as_posix()
            if (not path or path.startswith("-") or Path(path).is_absolute() or ".." in Path(path).parts
                    or normal.startswith(".git/") or normal == ".git" or any(c in path for c in "*?[")):
                raise refused("git_path_invalid", f"not an exact project-relative file path: {path!r}")
            full = self.root / normal
            if full.is_dir():
                raise refused("git_path_invalid", f"directories are not allowed: {path}")
            if not full.exists() and normal not in tracked:
                raise refused("git_path_invalid", f"path does not exist and is not tracked: {path}")
            clean.append(normal)
        return sorted(set(clean))

    def preflight_commit(self, paths: list[str]) -> list[str]:
        clean = self.check_paths(paths)
        unrelated = [p for p in self.staged_paths() if p not in clean]
        if unrelated:
            raise refused("git_staged_scope_conflict", "unrelated staged paths would enter the commit; "
                          "unstage them first", paths=unrelated[:20])
        return clean

    def commit_exact_paths(self, paths: list[str], message: str) -> str:
        clean = self.preflight_commit(paths)
        self.run("add", "-A", "--", *clean)
        result = self.run("commit", "-q", "-F", "-", input=message.encode("utf-8"), check=False)
        if result.returncode != 0:
            raise ChangeError("git_commit_failed", "git commit failed (hook, identity or nothing to commit): "
                              + (result.stderr or result.stdout).decode("utf-8", "replace").strip()[-800:],
                              exit_code=1)
        head = self.head()
        assert head
        return head

    def message(self, commit: str) -> str:
        return self.text("log", "-1", "--format=%B", commit)

    def log(self, base: str | None, limit: int = 500) -> list[tuple[str, str]]:
        args = ["log", f"-{limit}", "--format=%H%x00%B%x1e"]
        if base:
            args.append(f"{base}..HEAD")
        elif not self.head():
            return []
        out = self.text(*args)
        commits = []
        for chunk in out.split("\x1e"):
            chunk = chunk.strip("\n")
            if "\x00" in chunk:
                sha, body = chunk.split("\x00", 1)
                commits.append((sha.strip(), body))
        return commits


def trailers(message: str) -> list[tuple[str, str]]:
    """Key/value trailers from the last paragraph of a commit message."""
    paragraphs = [p for p in message.strip().split("\n\n") if p.strip()]
    if len(paragraphs) < 2:
        return []
    found = []
    for line in paragraphs[-1].splitlines():
        match = TRAILER_RE.match(line.strip())
        if not match:
            return []
        found.append((match.group("key"), match.group("value").strip()))
    return found


def _digest(tree: dict[str, str], exclude_paths: set[str], exclude_globs: list[str]) -> str:
    digest = hashlib.sha256()
    for path in sorted(tree):
        if path in exclude_paths or matches_any(path, exclude_globs):
            continue
        digest.update(f"{tree[path]} {path}\n".encode("utf-8", "surrogateescape"))
    return "sha256:" + digest.hexdigest()


SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache", ".mypy_cache", ".aqt"}


def walk_fingerprint(root: Path, exclude_paths: set[str], exclude_globs: list[str]) -> str:
    """Fingerprint for a directory without Git: SHA-256 of every file's content."""
    tree = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            try:
                tree[rel] = hashlib.sha256(full.read_bytes()).hexdigest()
            except OSError:
                continue
    return _digest(tree, exclude_paths, exclude_globs)
