#!/usr/bin/env python3
"""Check that every package has the same version, and that a release tag names exactly that version.

All packages are released together under one version (tag `v<version>`, for example v0.2.0).

Usage: scripts/check_versions.py [--tag TAG] [--root DIR]
Prints the version and exits 0 when all packages agree (and the tag is `v` + that version);
exits 1 otherwise, naming each package and its version.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path


def package_versions(root: Path) -> dict[str, str]:
    """{distribution name: version} of every package folder with a pyproject.toml."""
    versions = {}
    for project in sorted(root.glob("*/pyproject.toml")):
        meta = tomllib.loads(project.read_text(encoding="utf-8")).get("project", {})
        if "name" in meta:
            versions[meta["name"]] = str(meta.get("version", "(dynamic or missing)"))
    return versions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--tag", help="the release tag, for example v0.2.0")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args(argv)
    versions = package_versions(args.root.resolve())
    if not versions:
        print(f"no packages found under {args.root}", file=sys.stderr)
        return 1
    found = sorted(set(versions.values()))
    if len(found) != 1:
        print("the packages have different versions:", file=sys.stderr)
        for name, version in versions.items():
            print(f"  {name} {version}", file=sys.stderr)
        return 1
    version = found[0]
    if args.tag is not None and args.tag != f"v{version}":
        print(f"tag {args.tag} does not match the package version {version} (expected tag v{version})",
              file=sys.stderr)
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
