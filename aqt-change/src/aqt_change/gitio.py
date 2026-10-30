"""Git access through the ``git`` CLI with argument lists (no shell, no remotes).

Exact-path commit rules adapted from the author's Project Tracker Next (see NOTICE):
files only, unrelated staged paths abort, hooks and identity are never bypassed.

Calls run with ``SAFE_CONFIG``: Git looks at the files themselves instead of trusting an fsmonitor
hook, the untracked cache or a relaxed stat check (only the hidden-change check also asks Git with the
repository's own settings, to find what they hide). The fingerprint and the hidden-change check do not
trust the index's stat data at all: they hash every tracked file's content. Untracked files count unless the
repository's own tracked ``.gitignore`` files ignore them: ``.git/info/exclude``, ``core.excludesFile`` and an
untracked ``.gitignore`` are local rules a clean checkout does not have, so they do not hide a file from the
fingerprint.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .errors import ChangeError, refused
from .globs import matches_any

SAFE_CONFIG = ("-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.checkStat=default",
               "-c", "core.trustctime=true", "-c", "core.ignoreStat=false")
TOOL_DIRS = (".venv", ".tox", ".nox", ".pytest_cache", ".mypy_cache", ".ruff_cache")   # names no import can use
COMMIT_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
TRAILER_RE = re.compile(r"^(?P<key>[A-Za-z0-9-]+):\s*(?P<value>.*)$")


class Git:
    def __init__(self, root: Path):
        self.root = Path(root)
        self._object_format: str | None = None

    def run(self, *args: str, input: bytes | None = None, check: bool = True,
            safe: bool = True) -> subprocess.CompletedProcess:
        """``git -C root args``; ``safe=False`` leaves out ``SAFE_CONFIG`` (the repository's own view)."""
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"}
        result = subprocess.run(["git", *(SAFE_CONFIG if safe else ()), "-C", str(self.root), *args], input=input,
                                capture_output=True, env=env)
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

    def status_entries(self, safe: bool = True) -> list[tuple[str, str]]:
        """(XY, path) for changed and untracked files; renames yield both paths. ``safe=False``: as
        ``git status`` shows them with the repository's own settings."""
        raw = self.run("status", "--porcelain=v1", "-z", "--untracked-files=all", safe=safe).stdout
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

    def head_entries(self) -> dict[str, tuple[str, str]]:
        """{path: (mode, object id)} of HEAD's tree."""
        if not self.head():
            return {}
        raw = self.run("ls-tree", "-r", "-z", "--full-tree", "HEAD").stdout
        tree = {}
        for entry in raw.split(b"\0"):
            if not entry:
                continue
            meta, path = entry.split(b"\t", 1)
            fields = meta.split()
            tree[path.decode("utf-8", "surrogateescape")] = (fields[0].decode(), fields[2].decode())
        return tree

    def head_tree(self) -> dict[str, str]:
        return {path: oid for path, (_mode, oid) in self.head_entries().items()}

    def hash_paths(self, paths: list[str]) -> dict[str, str]:
        if not paths:
            return {}
        data = "\n".join(paths).encode("utf-8", "surrogateescape") + b"\n"
        out = self.run("hash-object", "--stdin-paths", input=data).stdout.decode().split()
        return dict(zip(paths, out))

    def _link_blob(self, target: bytes) -> str:
        """Git's blob id for a symbolic link (the link text), in the repository's object format."""
        if self._object_format is None:
            self._object_format = self.run("rev-parse", "--show-object-format", check=False).stdout.decode().strip()
        digest = hashlib.new("sha256" if self._object_format == "sha256" else "sha1")
        digest.update(b"blob %d\0" % len(target) + target)
        return digest.hexdigest()

    def file_at(self, revs: list[str], path: str) -> list[tuple[str, bytes]]:
        """(rev, content) for each commit in ``revs`` whose tree has ``path`` as a file."""
        if not revs:
            return []
        out = self.run("cat-file", "--batch", input="".join(f"{rev}:{path}\n" for rev in revs).encode()).stdout
        found, pos = [], 0
        for rev in revs:
            end = out.index(b"\n", pos)
            header, pos = out[pos:end].split(), end + 1
            if len(header) == 3 and header[2].isdigit():      # "<oid> <type> <size>", then the content
                size = int(header[2])
                if header[1] == b"blob":
                    found.append((rev, out[pos:pos + size]))
                pos += size + 1
        return found

    def existing_commits(self, revs: set[str]) -> set[str]:
        """The commit ids of ``revs`` (full ids, ``COMMIT_RE``) that name a commit in this repository."""
        revs = sorted(rev for rev in revs if isinstance(rev, str) and COMMIT_RE.match(rev))
        if not revs:
            return set()
        out = self.run("cat-file", "--batch-check", input="".join(f"{rev}^{{commit}}\n" for rev in revs).encode())
        return {rev for rev, line in zip(revs, out.stdout.decode().splitlines())
                if len(line.split()) == 3 and line.split()[1] == "commit"}

    def commits_touching(self, base: str, path: str) -> list[str]:
        """Commits in ``base..HEAD`` that change ``path`` (every one, also on merged side branches)."""
        if not self.head():
            return []
        return self.text("rev-list", "--full-history", f"{base}..HEAD", "--", path).split()

    def index_entries(self) -> dict[str, tuple[str, str, str]]:
        """{path: (tag, mode, object id)} of the stage-0 index entries (``ls-files -v -s``; tag ``S``
        is skip-worktree, a lowercase tag assume-unchanged). Unmerged paths are left out."""
        raw = self.run("ls-files", "-v", "-s", "-z").stdout
        found = {}
        for entry in raw.split(b"\0"):
            if len(entry) < 3 or b"\t" not in entry:
                continue
            meta, path = entry.split(b"\t", 1)
            fields = meta.split()
            if len(fields) < 4 or fields[3] != b"0":
                continue
            found[path.decode("utf-8", "surrogateescape")] = (fields[0].decode(), fields[1].decode(),
                                                               fields[2].decode())
        return found

    def tracked(self) -> set[str]:
        """Paths in HEAD or in the index."""
        return set(self.head_entries()) | set(self.index_entries())

    def flagged_entries(self) -> dict[str, tuple[str, str]]:
        """Tracked paths whose index entry tells Git not to look at the working tree
        (``update-index --skip-worktree`` or ``--assume-unchanged``): {path: (flag, index blob)}.
        ``git status`` and ``git diff`` do not show changes to these files."""
        return {path: ("skip-worktree" if tag == "S" else "assume-unchanged", oid)
                for path, (tag, _mode, oid) in self.index_entries().items() if tag == "S" or tag.islower()}

    def worktree_blobs(self) -> dict[str, str]:
        """{path: blob id} of every tracked (HEAD or index) file and every untracked file the repository's
        ``.gitignore`` files do not ignore (also those only local rules ignore, ``local_ignored()``), as it is
        in the working tree, from its content: neither the stat cache nor an fsmonitor hook nor an index flag
        nor a local ignore rule decides what is looked at. Symbolic links count by their link text,
        submodules by HEAD's recorded commit; missing files are left out."""
        head, index = self.head_entries(), self.index_entries()
        blobs, files = {}, []
        for path in sorted(set(head) | set(index) | set(self.untracked(repository_rules=True))):
            full = self.root / path
            if head.get(path, ("",))[0] == "160000":
                if path in index or full.is_dir():
                    blobs[path] = head[path][1]       # submodule: keep the recorded commit
            elif full.is_symlink():
                blobs[path] = self._link_blob(os.readlink(os.fsencode(full)))
            elif full.is_file():
                files.append(path)
        blobs.update(self.hash_paths(files))
        return blobs

    def hidden_changes(self, blobs: dict[str, str] | None = None) -> list[dict]:
        """Tracked files whose working-tree content differs from the index although ``git status``, with
        the repository's own settings, does not report them: changes hidden from ``status``, ``diff`` and
        ``add``. ``flag`` says why Git does not look: ``skip-worktree`` / ``assume-unchanged`` (index flags;
        for these a missing file counts too, ``state`` ``missing``, or ``sparse`` for a skip-worktree file
        of a sparse checkout), or ``stat-cache`` (an fsmonitor hook, a relaxed ``core.checkStat`` /
        ``core.trustctime`` or edited index data make Git believe the file is unchanged).
        ``blobs``: a ``worktree_blobs()`` result."""
        blobs = self.worktree_blobs() if blobs is None else blobs
        index = self.index_entries()
        reported = {path for code, path in self.status_entries(safe=False) if code[1] != " "}
        hidden, sparse = [], None
        for path, (tag, mode, oid) in sorted(index.items()):
            flagged = tag == "S" or tag.islower()
            flag = ("skip-worktree" if tag == "S" else "assume-unchanged") if flagged else "stat-cache"
            if mode == "160000" or (path in reported and not flagged):
                continue                              # submodule, or a change Git shows anyway
            if path in blobs:
                if blobs[path] != oid:
                    hidden.append({"path": path, "flag": flag, "state": "modified"})
                continue
            if not flagged:
                continue                              # deleted or replaced: git status reports it
            if tag == "S" and sparse is None:
                sparse = self.run("config", "--bool", "core.sparseCheckout", check=False).stdout.strip() == b"true"
            state = "sparse" if tag == "S" and sparse else "missing"
            hidden.append({"path": path, "flag": flag, "state": state})
        return hidden

    def left_out(self, blobs: dict[str, str], committed: set[str], declared: list[str],
                 exclude_globs: list[str]) -> list[dict]:
        """Files whose working-tree content (``blobs``, a ``worktree_blobs()`` result) a commit of HEAD plus
        the ``committed`` paths would not hold: a tracked file that differs from HEAD (state ``modified``,
        ``deleted``, or ``added`` to the index only) inside the ``declared`` globs or covered by the
        fingerprint (not matched by ``exclude_globs``), and an untracked file inside the declared globs
        (``untracked``, or ``ignored locally`` when only local ignore rules hide it). Untracked files outside
        the declared scope may stay out (the scope check reports them). Index-flagged files and submodules
        are left to ``hidden_changes()``."""
        head, index = self.head_entries(), self.index_entries()
        local, left = None, []
        for path in sorted(set(head) | set(index) | set(blobs)):
            if path in committed:
                continue
            in_scope = bool(declared) and matches_any(path, declared)
            if path in head or path in index:
                tag, mode, _oid = index.get(path, ("H", head.get(path, ("",))[0], ""))
                if tag == "S" or tag.islower() or "160000" in (mode, head.get(path, ("",))[0]):
                    continue
                if not in_scope and matches_any(path, exclude_globs):
                    continue
                want, have = blobs.get(path), head.get(path, ("", None))[1]
                if want != have:
                    left.append({"path": path, "state": "deleted" if want is None else
                                 ("modified" if have else "added")})
            elif in_scope:
                local = set(self.local_ignored()) if local is None else local
                left.append({"path": path, "state": "ignored locally" if path in local else "untracked"})
        return left

    def fingerprint(self, exclude_paths: set[str], exclude_globs: list[str],
                    blobs: dict[str, str] | None = None) -> str:
        """Content fingerprint of the working tree: the blob id of every tracked and untracked file
        (``worktree_blobs()``). When Git sees every change and no local ignore rule hides a file, this equals
        the earlier value (HEAD's blobs, with the files ``git status`` reports replaced by their content), so
        older receipts stay fresh."""
        return _digest(self.worktree_blobs() if blobs is None else blobs, exclude_paths, exclude_globs)

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

    def untracked(self, repository_rules: bool = False) -> list[str]:
        """Untracked files that are not ignored. ``repository_rules``: only the repository's own rules ignore
        (``repository_excludes()``), not ``.git/info/exclude``, ``core.excludesFile`` or a ``.gitignore`` that
        is itself untracked."""
        if not repository_rules:
            return self._others("--exclude-standard")
        return self._others(excludes=self.repository_excludes())

    def _others(self, *args: str, excludes: bytes | None = None) -> list[str]:
        """``git ls-files --others`` with ``args``; ``excludes``: patterns for ``--exclude-from``."""
        if excludes is None:
            raw = self.run("ls-files", "--others", "-z", *args).stdout
        else:
            with tempfile.NamedTemporaryFile(prefix="aqt-change-excludes-") as handle:
                handle.write(excludes)
                handle.flush()
                raw = self.run("ls-files", "--others", "-z", f"--exclude-from={handle.name}", *args).stdout
        return [p.decode("utf-8", "surrogateescape") for p in raw.split(b"\0") if p]

    def repository_excludes(self) -> bytes:
        """The patterns of every tracked (HEAD or index) ``.gitignore``, as it is in the working tree, rewritten
        relative to the top of the tree (``_anchored``), root first and deeper files later, so that one
        ``--exclude-from`` list ignores what these files ignore together; then those of an untracked
        ``.gitignore`` directly in a tool's cache or environment folder (``TOOL_DIRS``: pytest, mypy, ruff and
        ``venv``/uv write one that ignores the whole folder). Any other untracked ``.gitignore`` (one that ignores
        itself is invisible to ``git status``) is a local rule like ``.git/info/exclude``."""
        names = [p for p in self.tracked() if p == ".gitignore" or p.endswith("/.gitignore")]
        rules = self._read_ignores(sorted(names, key=lambda p: (p.count("/"), p)))
        tools = self._others("--", *(f":(glob)**/{name}/.gitignore" for name in TOOL_DIRS), excludes=rules)
        return rules + self._read_ignores(sorted(tools, key=lambda p: (p.count("/"), p)))

    def _read_ignores(self, paths: list[str]) -> bytes:
        lines = []
        for path in paths:
            full = self.root / path
            if full.is_symlink() or not full.is_file():
                continue                                  # Git does not read a .gitignore through a link
            directory = path[:-len(".gitignore")].rstrip("/").encode("utf-8", "surrogateescape")
            lines += _anchored(directory, full.read_bytes())
        return b"".join(line + b"\n" for line in lines)

    def local_ignored(self) -> list[str]:
        """Untracked files that only local rules ignore (``.git/info/exclude``, ``core.excludesFile``, by
        default ``$XDG_CONFIG_HOME/git/ignore``, or an untracked ``.gitignore``): invisible to ``git status``,
        but present for a test run, and absent from a clean checkout."""
        return sorted(set(self.untracked(repository_rules=True)) - set(self.untracked()))

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


def _trim(pattern: bytes) -> bytes:
    """Git's ``trim_trailing_spaces``: trailing spaces go unless a backslash escapes them."""
    last_space, index = None, 0
    while index < len(pattern):
        char = pattern[index:index + 1]
        if char == b" ":
            last_space = index if last_space is None else last_space
        elif char == b"\\":
            index += 1
            if index >= len(pattern):
                return pattern
            last_space = None
        else:
            last_space = None
        index += 1
    return pattern if last_space is None else pattern[:last_space]


def _anchored(directory: bytes, text: bytes) -> list[bytes]:
    """The patterns of the ``.gitignore`` in ``directory`` (b"" for the top) rewritten for an exclude list read
    relative to the top, with the same meaning (gitignore(5)): a pattern with a slash at the start or in the
    middle is relative to ``directory``, one without matches at any depth below it."""
    if text.startswith(b"\xef\xbb\xbf"):
        text = text[3:]                                   # Git skips a UTF-8 byte order mark
    prefix = b"/" + re.sub(rb"([*?\[\\])", rb"\\\1", directory) + b"/" if directory else b""
    found = []
    for line in text.split(b"\n"):
        line = _trim(line[:-1] if line.endswith(b"\r") else line)
        if not line or line.startswith(b"#"):
            continue
        negate = line.startswith(b"!")
        body = line[1:] if negate else line
        if not prefix:
            found.append(line)
            continue
        must_be_dir = body.endswith(b"/")
        core = body[:-1] if must_be_dir else body
        if not core:
            continue
        core = core[1:] if core.startswith(b"/") else (core if b"/" in core else b"**/" + core)
        found.append((b"!" if negate else b"") + prefix + core + (b"/" if must_be_dir else b""))
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
    return _digest(walk_blobs(root), exclude_paths, exclude_globs)


def walk_blobs(root: Path) -> dict[str, str]:
    """{path: SHA-256 of the content} of every file below ``root`` (without Git; ``SKIP_DIRS`` left out)."""
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
    return tree
