#!/usr/bin/env python3
"""Point the links and images of every package README at GitHub, for the project pages on PyPI.

PyPI shows each package's README as its project page, where a link relative to the repository leads
nowhere. The release build runs this in its own checkout before `uv build`: every relative link and
image in the README that a package's pyproject.toml names becomes an absolute URL at one tag or
commit (files and folders on github.com, images on raw.githubusercontent.com). The READMEs in the
repository keep their relative links.

Rewritten: inline links and images `[text](path)`, `![alt](path)`, reference definitions
`[label]: path` and HTML `href="path"` / `src="path"`. Left alone: code blocks and code spans,
absolute URLs, `mailto:` and other schemes, and links to a heading of the same page (`#…`).

Usage: scripts/pypi_readmes.py --ref REF [--check] [--root DIR]
  --ref REF    tag or commit the links point to, for example v0.2.0
  --check      write nothing; only report what would change and fail if a relative link would remain
  --root DIR   the repository (default: the one this script is in)
Exit 0 when every relative link was (or can be) rewritten; 1 when a link points outside the repository
or at a missing file, or a relative link would remain (nothing is written then); 2 for a usage error.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import quote, unquote

REPOSITORY = "benediktneumayer2-tech/agent-quality-toolkit"
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")

FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})")
CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`).*?(?<!`)\1(?!`)", re.S)
INLINE = re.compile(r"\]\(\s*(<[^>\n]*>|[^\s()<>]+)")           # ](dest  or  ](<dest>
REFERENCE = re.compile(r"^[ ]{0,3}\[[^\]\n]+\]:[ \t]*(<[^>\n]*>|\S+)", re.M)
HTML_ATTR = re.compile(r"""<[A-Za-z][^>]*?\b(href|src)\s*=\s*(["'])(.*?)\2""", re.S)
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def is_relative(dest: str) -> bool:
    return bool(dest) and not SCHEME.match(dest) and not dest.startswith(("#", "//"))


def protected_ranges(text: str) -> list[tuple[int, int]]:
    """Character ranges of fenced code blocks and code spans, where nothing is rewritten."""
    ranges: list[tuple[int, int]] = []
    pos, fence, fence_start, prose_start = 0, None, 0, 0
    for line in text.splitlines(keepends=True):
        match = FENCE.match(line)
        if fence is None and match:
            ranges += [(m.start(), m.end()) for m in CODE_SPAN.finditer(text, prose_start, pos)]
            fence, fence_start = match.group(1), pos
        elif fence is not None and match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence) \
                and not line.strip()[len(match.group(1)):].strip():
            ranges.append((fence_start, pos + len(line)))
            fence, prose_start = None, pos + len(line)
        pos += len(line)
    if fence is not None:                                    # an unclosed fence runs to the end
        ranges.append((fence_start, len(text)))
    else:
        ranges += [(m.start(), m.end()) for m in CODE_SPAN.finditer(text, prose_start)]
    return ranges


def is_image_link(text: str, close: int) -> bool:
    """Whether the `]` at `close` ends the alt text of an image, i.e. its `[` follows a `!`."""
    depth = 0
    for i in range(close, -1, -1):
        if text[i] == "]" and (i == 0 or text[i - 1] != "\\"):
            depth += 1
        elif text[i] == "[" and (i == 0 or text[i - 1] != "\\"):
            depth -= 1
            if depth == 0:
                return i > 0 and text[i - 1] == "!"
    return False


def destinations(text: str):
    """(start, end, destination, is_image) of every link destination outside code."""
    ranges = protected_ranges(text)
    inside = lambda i: any(a <= i < b for a, b in ranges)
    found = []
    for m in INLINE.finditer(text):
        if not inside(m.start()):
            found.append((m.start(1), m.end(1), m.group(1), is_image_link(text, m.start())))
    for m in REFERENCE.finditer(text):
        if not inside(m.start()):
            found.append((m.start(1), m.end(1), m.group(1), m.group(1).strip("<>").lower().endswith(IMAGE_SUFFIXES)))
    for m in HTML_ATTR.finditer(text):
        if not inside(m.start()):
            found.append((m.start(3), m.end(3), m.group(3), m.group(1).lower() == "src"))
    return sorted(found)


def absolute(dest: str, readme_dir: str, root: Path, ref: str, image: bool) -> str:
    """The absolute URL for a relative destination; ValueError when it cannot be rewritten."""
    bracketed = dest.startswith("<") and dest.endswith(">")
    raw = dest[1:-1] if bracketed else dest
    path, suffix = re.match(r"([^?#]*)(.*)", raw, re.S).groups()
    joined = path.lstrip("/") if path.startswith("/") else posixpath.join(readme_dir, path)
    target = posixpath.normpath(unquote(joined)) if joined else readme_dir
    if target == ".." or target.startswith("../") or posixpath.isabs(target):
        raise ValueError("points outside the repository")
    on_disk = root / target
    if not on_disk.exists():
        raise ValueError("points at a missing file")
    target = "" if target == "." else target
    quoted, ref_q = quote(target), quote(ref, safe="")
    if image and on_disk.is_file():
        url = f"https://raw.githubusercontent.com/{REPOSITORY}/{ref_q}/{quoted}"
    else:
        kind = "tree" if on_disk.is_dir() else "blob"
        url = f"https://github.com/{REPOSITORY}/{kind}/{ref_q}" + (f"/{quoted}" if quoted else "")
    url += suffix
    return f"<{url}>" if bracketed else url


def rewrite(text: str, readme_dir: str, root: Path, ref: str) -> tuple[str, int, list[str]]:
    """The rewritten text, the number of rewritten links and the problems (one line each)."""
    out, last, changed, problems = [], 0, 0, []
    for start, end, dest, image in destinations(text):
        if not is_relative(dest.strip("<>")):
            continue
        line = text.count("\n", 0, start) + 1
        try:
            new = absolute(dest, readme_dir, root, ref, image)
        except ValueError as error:
            problems.append(f"line {line}: {dest} {error}")
            continue
        out += [text[last:start], new]
        last, changed = end, changed + 1
    out.append(text[last:])
    result = "".join(out)
    left = [d for _s, _e, d, _i in destinations(result) if is_relative(d.strip("<>"))]
    problems += [f"a relative link would remain: {d}" for d in left if not any(d in p for p in problems)]
    return result, changed, problems


def package_readmes(root: Path) -> list[Path]:
    """The README of every package, as its pyproject.toml names it (`readme = "…"` or `{file = "…"}`)."""
    readmes = []
    for project in sorted(root.glob("*/pyproject.toml")):
        readme = tomllib.loads(project.read_text(encoding="utf-8")).get("project", {}).get("readme")
        if isinstance(readme, dict):
            readme = readme.get("file")
        if isinstance(readme, str) and readme.lower().endswith(".md"):
            readmes.append(project.parent / readme)
    return readmes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--ref", required=True, help="tag or commit, for example v0.2.0")
    parser.add_argument("--check", action="store_true", help="write nothing; fail if a relative link would remain")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    readmes = package_readmes(root)
    if not readmes:
        print(f"no package READMEs found under {root}", file=sys.stderr)
        return 2
    results, failed = [], False
    for readme in readmes:
        name = readme.relative_to(root).as_posix()
        text = readme.read_text(encoding="utf-8")
        new, changed, problems = rewrite(text, posixpath.dirname(name), root, args.ref)
        for problem in problems:
            print(f"{name}: {problem}", file=sys.stderr)
        failed = failed or bool(problems)
        results.append((readme, name, text, new, changed))
    if failed:
        print("relative links remain; nothing written", file=sys.stderr)
        return 1
    for readme, name, text, new, changed in results:
        if new != text and not args.check:
            readme.write_text(new, encoding="utf-8")
        verb = "would rewrite" if args.check else "rewrote"
        print(f"{name}: {verb} {changed} link{'s' * (changed != 1)}" if changed else f"{name}: no relative links")
    return 0


if __name__ == "__main__":
    sys.exit(main())
