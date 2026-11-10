#!/usr/bin/env python3
"""Collect the notes of one version from every package's CHANGELOG.md, for the GitHub release.

Each CHANGELOG.md needs a section `## <version> — <date>` (or `## [<version>]`); it runs to the next `## `
heading. A section still marked "unreleased" counts as missing unless --allow-unreleased (dry runs).

Usage: scripts/release_notes.py VERSION [--allow-unreleased] [--root DIR]
Prints Markdown on standard output; exits 1 when a package has no section for VERSION.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

UMBRELLA = "agent-quality-toolkit"


def section(changelog: str, version: str) -> tuple[str, str] | None:
    """(heading, body) of the section for `version`, or None."""
    heading = re.compile(rf"^##[ \t]+\[?v?{re.escape(version)}\]?(?=[\s\]]|$).*$", re.M)
    match = heading.search(changelog)
    if not match:
        return None
    following = re.compile(r"^##[ \t]", re.M).search(changelog, match.end())
    body = changelog[match.end():following.start() if following else len(changelog)].strip("\n")
    lines, fence = [], False
    for line in body.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            fence = not fence
        if not fence and re.match(r"#{3,5}[ \t]", line):      # ### Added -> #### Added under the package heading
            line = "#" + line
        lines.append(line)
    return match.group(0), "\n".join(lines).rstrip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("version", help="for example 0.2.0")
    parser.add_argument("--allow-unreleased", action="store_true", help="accept sections marked unreleased")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    packages = []
    for project in sorted(root.glob("*/pyproject.toml")):
        name = tomllib.loads(project.read_text(encoding="utf-8")).get("project", {}).get("name")
        if name:
            packages.append((name != UMBRELLA, name, project.parent / "CHANGELOG.md"))
    out, problems = [f"All packages of the Agent Quality Toolkit, released together as {args.version}."], []
    for _order, name, changelog in sorted(packages):
        found = section(changelog.read_text(encoding="utf-8"), args.version) if changelog.is_file() else None
        if found is None:
            problems.append(f"{changelog.relative_to(root)}: no section for {args.version}")
            continue
        heading, body = found
        if "unreleased" in heading.lower() and not args.allow_unreleased:
            problems.append(f"{changelog.relative_to(root)}: the {args.version} section is still marked unreleased")
            continue
        out += ["", f"## {name} {args.version}", "", body or "No changes."]
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
