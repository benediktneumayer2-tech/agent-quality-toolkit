#!/usr/bin/env python3
"""Check that every package has the same version, and that a release tag names exactly that version.

All packages are released together under one version (tag `v<version>`, for example v0.2.0). The root
CITATION.cff, which Zenodo reads for the DOI record, must carry the same version, and on a tag a release date.
So must the desktop app (aqt-desktop/src-tauri: `tauri.conf.json` names its installers and updates, `Cargo.toml`
its program).

Usage: scripts/check_versions.py [--tag TAG] [--root DIR]
Prints the version and exits 0 when all packages agree (and the tag is `v` + that version);
exits 1 otherwise, naming each package and its version.
"""

from __future__ import annotations

import argparse
import json
import re
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


def citation(root: Path) -> dict[str, str]:
    """The top-level ``version`` and ``date-released`` of the root CITATION.cff (empty if there is none)."""
    path = root / "CITATION.cff"
    if not path.is_file():
        return {}
    fields = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r'^(version|date-released):\s*["\']?([^"\'\s#]+)', line)
        if match:
            fields[match.group(1)] = match.group(2)
    return fields


def app_versions(root: Path) -> dict[str, str]:
    """The desktop app's version in tauri.conf.json and Cargo.toml (empty if there is no app)."""
    app = root / "aqt-desktop" / "src-tauri"
    versions = {}
    conf = app / "tauri.conf.json"
    if conf.is_file():
        versions["aqt-desktop/src-tauri/tauri.conf.json"] = str(
            json.loads(conf.read_text(encoding="utf-8")).get("version", "(missing)"))
    cargo = app / "Cargo.toml"
    if cargo.is_file():
        package = tomllib.loads(cargo.read_text(encoding="utf-8")).get("package", {})
        versions["aqt-desktop/src-tauri/Cargo.toml"] = str(package.get("version", "(missing)"))
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
    cff = citation(args.root.resolve())
    if cff:
        versions["CITATION.cff"] = cff.get("version", "(missing)")
    versions.update(app_versions(args.root.resolve()))
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
    if args.tag is not None and cff and "date-released" not in cff:
        print("CITATION.cff has no date-released: set it to the release date (RELEASING.md, step 2)", file=sys.stderr)
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
