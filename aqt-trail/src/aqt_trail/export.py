"""Export bundles (archive copy with checksums) and legible reports."""

from __future__ import annotations

import html
import json
import os
import shutil
import tarfile
from pathlib import Path

from aqt_evidence import bytes_hash, load_public_key, record_hash, utc_now

from .config import Config
from .signers import load_registry, registry_keys, registry_path
from .state import service_keys
from .tsa import load_ca
from .verify import TrailReport, load_lines, verify_trail

VERIFY_TEXT = """# Verifying this bundle

This bundle is a complete copy of an aqt-trail audit trail.

1. Check the files against `MANIFEST.json` (SHA-256 of each file), then run
   `aqt-trail verify --bundle .` (needs `aqt-trail`), or with only `aqt-spec`:
   `aqt-evidence verify trail.jsonl --key keys/<service key>.pub --require-signature`.
2. Compare the head in `MANIFEST.json` with head copies you stored elsewhere
   (`aqt-trail verify --bundle . --heads my-heads.jsonl`).
3. RFC 3161 tokens are in the `trail.anchor` records (`data.tsa.token_b64`); each covers
   the 32-byte head hash and can also be checked with
   `openssl ts -verify -digest <head hex> -in token.der -token_in -CAfile <TSA CA>`.

A file named `*.TEST-ONLY.pem` belongs to the built-in test time-stamp authority and
proves nothing about real time.
"""


def export_bundle(config: Config, out: str | os.PathLike, *, tar: bool = False) -> Path:
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"{out} exists and is not empty")
    (out / "keys").mkdir(parents=True, exist_ok=True)
    files = {"trail.jsonl": config.trail_path, "checkpoints.jsonl": config.checkpoints_path}
    for pub in sorted((config.state / "keys").glob("*.pub")):
        files[f"keys/{pub.name}"] = pub
    if registry_path().exists():
        files["signers.json"] = registry_path()
    ca = config.section("anchor").get("tsa_ca")
    if ca and Path(ca).exists():
        files["tsa-ca.pem"] = Path(ca)
    test_ca = config.state / "test-tsa" / "ca.pem"
    if test_ca.exists():
        files["tsa-ca.TEST-ONLY.pem"] = test_ca
    digests = {}
    for name, source in files.items():
        if source.exists():
            shutil.copyfile(source, out / name)
            digests[name] = bytes_hash((out / name).read_bytes())
    (out / "VERIFY.md").write_text(VERIFY_TEXT)
    digests["VERIFY.md"] = bytes_hash((out / "VERIFY.md").read_bytes())
    records, _ = load_lines(out / "trail.jsonl") if (out / "trail.jsonl").exists() else ([], None)
    meta = config.meta()
    manifest = {"aqt_bundle": "0.1", "log_id": meta["log_id"], "created": utc_now(),
                "head_seq": records[-1]["chain"]["seq"] if records else None,
                "head": record_hash(records[-1]) if records else None,
                "key_ids": sorted(service_keys(config)), "files": digests}
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    if tar:
        archive = out.with_suffix(".tar.gz")
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(out, arcname=out.name)
        return archive
    return out


def verify_bundle(directory: str | os.PathLike, *, heads=None, pin_key=None) -> TrailReport:
    directory = Path(directory)
    manifest = json.loads((directory / "MANIFEST.json").read_text())
    problems = []
    for name, digest in manifest["files"].items():
        path = directory / name
        if not path.exists():
            problems.append(f"{name} listed in MANIFEST.json is missing")
        elif bytes_hash(path.read_bytes()) != digest:
            problems.append(f"{name} does not match MANIFEST.json")
    keys = dict(load_public_key(p) for p in sorted((directory / "keys").glob("*.pub")))
    if pin_key:
        keys = dict([load_public_key(pin_key)])
    ca = []
    for name in ("tsa-ca.pem", "tsa-ca.TEST-ONLY.pem"):
        if (directory / name).exists():
            ca += load_ca(directory / name)
    signer_keys = registry_keys(load_registry(directory / "signers.json")) if (directory / "signers.json").exists() else {}
    report = verify_trail(directory / "trail.jsonl", keys=keys, checkpoints=directory / "checkpoints.jsonl",
                          heads=heads, tsa_ca=ca or None, signer_keys=signer_keys, log_id=manifest.get("log_id"),
                          pinned=bool(pin_key))
    if manifest.get("head") and report.head != manifest["head"]:
        problems.append("the trail head differs from MANIFEST.json")
    if problems:
        report.problems = problems + report.problems
        report.ok = False
    return report


# -- legible views ---------------------------------------------------------------------
def select(records, *, since=None, until=None, actor=None, type=None, action=None, subject=None, session=None):
    out = []
    for record in records:
        if since and record["time"] < since or until and record["time"] > until:
            continue
        if actor and record["actor"].get("id") != actor:
            continue
        if type and not (record.get("type") == type or record.get("type", "").startswith(type.rstrip("*"))
                         and type.endswith("*")):
            continue
        if action and record.get("action") != action:
            continue
        if subject and (record.get("subject") or {}).get("ref") != subject:
            continue
        if session and ((record["actor"].get("agent") or {}).get("session") != session):
            continue
        out.append(record)
    return out


COLUMNS = ("seq", "time", "type", "action", "actor", "observed", "subject", "meaning", "reason")


def row(record) -> dict:
    observed = record.get("observed") or {}
    chain = " ← ".join(observed.get("process_chain", [])[:5])
    return {"seq": str(record.get("chain", {}).get("seq", "")), "time": record.get("time", ""),
            "type": record.get("type", ""), "action": record.get("action", ""), "actor": record["actor"].get("id", ""),
            "observed": f"{observed.get('via', '')}: {chain}" if chain else observed.get("via", ""),
            "subject": (record.get("subject") or {}).get("ref", ""), "meaning": record.get("meaning", ""),
            "reason": record.get("reason", "")}


def render_markdown(records, *, title: str, summary: str) -> str:
    lines = [f"# {title}", "", f"Verification: **{summary}**", "", f"{len(records)} record(s).", "",
             "| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
    for record in records:
        values = row(record)
        lines.append("| " + " | ".join(values[c].replace("|", "/").replace("\n", " ") for c in COLUMNS) + " |")
    return "\n".join(lines) + "\n"


def render_html(records, *, title: str, summary: str) -> str:
    head = "".join(f"<th>{c}</th>" for c in COLUMNS)
    body = "\n".join("<tr>" + "".join(f"<td>{html.escape(row(r)[c])}</td>" for c in COLUMNS) + "</tr>"
                     for r in records)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{ --bg: #fff; --fg: #1d1d1f; --line: #d8d8dc; --muted: #6b6b72; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg: #141416; --fg: #ececf0; --line: #3a3a40; --muted: #a0a0a8; }} }}
body {{ background: var(--bg); color: var(--fg); font: 14px/1.45 system-ui, sans-serif; margin: 16px; }}
table {{ border-collapse: collapse; width: 100%; }} th, td {{ border-bottom: 1px solid var(--line);
padding: 4px 6px; text-align: left; vertical-align: top; }} th {{ color: var(--muted); }}
.wrap {{ overflow-x: auto; }}
</style></head><body>
<h1>{html.escape(title)}</h1><p>Verification: <strong>{html.escape(summary)}</strong></p>
<p>{len(records)} record(s).</p>
<div class="wrap"><table><thead><tr>{head}</tr></thead><tbody>
{body}
</tbody></table></div></body></html>
"""
