#!/usr/bin/env python3
"""The files of a release: sign the desktop app's updates, write its update manifest, and SHA256SUMS.

The release workflow puts the Python packages and every platform's desktop installers into one folder and runs
this script on it:

1. **Sign**, only when TAURI_SIGNING_PRIVATE_KEY is set (the updater key, a repository secret; its password in
   TAURI_SIGNING_PRIVATE_KEY_PASSWORD): every file the app updates itself from gets a signature from
   `tauri signer sign --app-version <version>`, which also binds it to this version.
2. **latest.json**, the update manifest the app reads, only when there are signatures: one entry per platform and
   bundle type with the signature and the file's address in the release. The macOS updates (`.app.tar.gz`) stay
   in the release only then; without a manifest nothing reads them.
3. **SHA256SUMS** of every file (`sha256sum -c SHA256SUMS` checks a download).

Usage: scripts/desktop_release.py DIR --version X.Y.Z [--repo OWNER/NAME] [--tag-run]
--tag-run (a tag push): also fail when the app checks for updates (its config has the updater's public key) but
there is no key to sign them, so that the release would have no manifest.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "aqt-desktop"
REPO = "benediktneumayer2-tech/agent-quality-toolkit"
# The files the app updates itself from, by the names the build scripts give them, and their key in latest.json:
# the updater looks for "<os>-<arch>-<bundle type>" of the running app (tauri-plugin-updater).
UPDATES = {
    "aqt-desktop_{v}_amd64.AppImage": "linux-x86_64-appimage",
    "aqt-desktop_{v}_amd64.deb": "linux-x86_64-deb",
    "aqt-desktop_{v}_arm64.app.tar.gz": "darwin-aarch64-app",
    "aqt-desktop_{v}_x86_64.app.tar.gz": "darwin-x86_64-app",
    "aqt-desktop_{v}_x64-setup.exe": "windows-x86_64-nsis",
}


class Refused(Exception):
    pass


def public_key(conf: Path = APP / "src-tauri" / "tauri.conf.json") -> str:
    """The updater's public key in the app config ("" while updates are off)."""
    config = json.loads(conf.read_text(encoding="utf-8"))
    return str(config.get("plugins", {}).get("updater", {}).get("pubkey", "")).strip()


def key_id(text: str, what: str) -> bytes:
    """The 8-byte key id of a minisign public key or signature, as Tauri writes them (base64 of the minisign file)."""
    try:
        lines = base64.b64decode(text, validate=True).decode().splitlines()
        blob = base64.b64decode(lines[1], validate=True)
    except (binascii.Error, UnicodeDecodeError, IndexError) as error:
        raise Refused(f"{what} is not a minisign key or signature in base64 ({error})") from None
    if len(blob) < 10:
        raise Refused(f"{what} is too short for a minisign key or signature")
    return blob[2:10]


def desktop_files(folder: Path, version: str) -> list[Path]:
    """The desktop app's files; each must carry the release's version in its name."""
    files = sorted(p for p in folder.iterdir() if p.is_file() and p.name.startswith("aqt-desktop_"))
    stale = [p.name for p in files if not p.name.startswith(f"aqt-desktop_{version}_")]
    if stale:
        raise Refused(f"desktop files of another version than {version}: {', '.join(stale)}")
    return files


def sign(folder: Path, version: str, tauri: Path) -> list[Path]:
    """Sign each update file present; returns the signature files."""
    if not tauri.is_file():
        raise Refused(f"{tauri} is missing: run 'npm ci' in aqt-desktop first")
    signatures = []
    for pattern in UPDATES:
        path = folder / pattern.format(v=version)
        if path.is_file():
            subprocess.run([str(tauri), "signer", "sign", "--app-version", version, str(path)], check=True,
                           stdout=subprocess.DEVNULL)
            signatures.append(path.with_name(path.name + ".sig"))
    return signatures


def manifest(folder: Path, version: str, repo: str, pubkey: str) -> dict | None:
    """latest.json from the signature files in the folder, or None when there are none. With a public key, each
    signature must be made by its key: a wrong key would make every update fail on the users' machines."""
    platforms = {}
    for pattern, platform in UPDATES.items():
        name = pattern.format(v=version)
        sig = folder / f"{name}.sig"
        if not sig.is_file():
            continue
        if not (folder / name).is_file():
            raise Refused(f"{sig.name} has no {name} beside it")
        signature = sig.read_text(encoding="utf-8").strip()
        if pubkey and key_id(signature, sig.name) != key_id(pubkey, "the app's public key"):
            raise Refused(f"{sig.name} is not signed by the key whose public key is in tauri.conf.json")
        platforms[platform] = {"signature": signature,
                               "url": f"https://github.com/{repo}/releases/download/v{version}/{name}"}
    if not platforms:
        return None
    return {
        "version": version,
        "notes": f"Agent Quality Toolkit {version}: https://github.com/{repo}/releases/tag/v{version}",
        "pub_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platforms": platforms,
    }


def sha256sums(folder: Path) -> str:
    lines = []
    for path in sorted(p for p in folder.iterdir() if p.is_file() and p.name != "SHA256SUMS"):
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        lines.append(f"{digest.hexdigest()}  {path.name}\n")
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("folder", type=Path, help="the release's files: Python packages and desktop installers")
    parser.add_argument("--version", required=True)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY") or REPO)
    parser.add_argument("--tag-run", action="store_true", help="a tag push: refuse a release without a manifest "
                                                               "when the app checks for updates")
    parser.add_argument("--config", type=Path, default=APP / "src-tauri" / "tauri.conf.json")
    parser.add_argument("--tauri", type=Path, default=APP / "node_modules" / ".bin" / "tauri")
    args = parser.parse_args(argv)
    folder, version = args.folder, args.version
    try:
        desktop_files(folder, version)
        pubkey = public_key(args.config)
        if os.environ.get("TAURI_SIGNING_PRIVATE_KEY"):
            signed = sign(folder, version, args.tauri)
            print(f"signed {len(signed)} update file(s) for {version}")
            if not pubkey:
                print("note: the app config has no updater public key, so this version's app does not check for "
                      "updates; the manifest serves the apps that do")
        elif pubkey and args.tag_run:
            raise Refused("the app checks for updates (tauri.conf.json has the updater's public key), but "
                          "TAURI_SIGNING_PRIVATE_KEY is not set: this release would have no latest.json "
                          "(RELEASING.md, Updates of the desktop app)")
        else:
            print("TAURI_SIGNING_PRIVATE_KEY is not set: nothing is signed")
        found = manifest(folder, version, args.repo, pubkey)
        if found:
            (folder / "latest.json").write_text(json.dumps(found, indent=2) + "\n", encoding="utf-8")
            print(f"latest.json: {', '.join(found['platforms'])}")
        else:
            print("no signatures: no latest.json, and the .app.tar.gz files are left out")
            for tarball in folder.glob("*.app.tar.gz"):      # macOS updates: of use only with a manifest
                tarball.unlink()
        for sig in folder.glob("*.sig"):                     # the manifest carries the signatures
            sig.unlink()
    except (Refused, subprocess.CalledProcessError, OSError, ValueError) as error:
        print(f"desktop_release: {error}", file=sys.stderr)
        return 1
    sums = sha256sums(folder)
    (folder / "SHA256SUMS").write_text(sums, encoding="utf-8")
    print(f"SHA256SUMS: {len(sums.splitlines())} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
