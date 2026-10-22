"""``aqt-signoff``: signatures with meaning and approved actions.

Exit codes: 0 ok; 1 check failed or refused; 2 usage or runtime error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from aqt_evidence import SinkError

from .core import Signoff, VerifyReport
from .errors import SignoffError, UsageError
from .manifest import local_time, render
from .settings import load_settings

_DURATION = re.compile(r"^(\d+)(ms|s|m|h|d)$")
_UNITS = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}


def duration_ms(text: str) -> int:
    match = _DURATION.match(text or "")
    if not match:
        raise UsageError(f"duration {text!r} must look like 90s, 30m, 24h or 7d")
    return int(match.group(1)) * _UNITS[match.group(2)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aqt-signoff", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", help="config TOML (default $XDG_CONFIG_HOME/aqt/signoff.toml)")
    parser.add_argument("--registry", help="signer registry (default $XDG_CONFIG_HOME/aqt/signers.json)")
    parser.add_argument("--keys-dir", help="key directory (default $XDG_CONFIG_HOME/aqt/keys)")
    parser.add_argument("--state-dir", help="state directory (default $XDG_STATE_HOME/aqt/signoff)")
    parser.add_argument("--sink", help="evidence sink, file:PATH or unix:PATH (default AQT_SINK)")
    parser.add_argument("--evidence", action="append", help="JSONL evidence file to read; repeatable")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a signer with a passphrase-protected key")
    p.add_argument("--id", required=True, help="signer id, e.g. human:alice")
    p.add_argument("--name", default="", help="printed name")
    p.add_argument("--role", default="", help="role, e.g. quality-manager")
    p.add_argument("--add-key", action="store_true", help="new key for an existing signer (old key revoked)")

    signers = sub.add_parser("signers", help="list or export the signer registry")
    signers_sub = signers.add_subparsers(dest="signers_command", required=True)
    signers_sub.add_parser("list")
    export = signers_sub.add_parser("export")
    export.add_argument("file", nargs="?")

    p = sub.add_parser("revoke", help="revoke a signer's active key")
    p.add_argument("signer")
    p.add_argument("--reason", required=True)
    p.add_argument("--compromised-since", help="RFC 3339 time; signatures from then on show 'revoked'")
    p.add_argument("--lost", action="store_true", help="key or passphrase lost: record the revocation unsigned")

    def subject_args(p, *, hash_ok=True):
        group = p.add_mutually_exclusive_group(required=True)
        group.add_argument("file", nargs="?", help="file to sign or verify")
        group.add_argument("--record", help="evidence record id")
        if hash_ok:
            group.add_argument("--hash", dest="sha256", help="sha256:<hex> of an externally hashed artefact")

    p = sub.add_parser("sign", help="sign a file, record or hash with a meaning")
    subject_args(p)
    p.add_argument("--meaning", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--signer")
    p.add_argument("--kind", default="hash", help="subject kind with --hash")
    p.add_argument("--ref", help="subject reference with --hash")
    p.add_argument("--author", action="append", default=[], help="author id for the two-person rule; repeatable")

    p = sub.add_parser("verify", help="verify the signatures over a file, record or hash")
    subject_args(p)
    p.add_argument("--require", action="append", default=[], metavar="MEANING",
                   help="fail unless the policy for MEANING is met; repeatable")
    p.add_argument("--no-record", action="store_true", help="do not record detected invalidations")

    p = sub.add_parser("invalidate", help="withdraw one of your signatures")
    p.add_argument("signature", help="signature record id")
    p.add_argument("--reason", required=True)

    p = sub.add_parser("manifest", help="render the signature block")
    subject_args(p, hash_ok=False)
    p.add_argument("--format", choices=("md", "html"), default="md")
    p.add_argument("--out")

    p = sub.add_parser("prepare", help="propose an action for approval")
    p.add_argument("--kind", choices=("command", "http", "other"), default="command")
    p.add_argument("--request-key", help="idempotency key (same key + same action returns the same action)")
    p.add_argument("--description", default="")
    p.add_argument("--payload", help="file whose bytes the approval binds by hash")
    p.add_argument("--method", help="http: method")
    p.add_argument("--url", help="http: URL")
    p.add_argument("--header", action="append", default=[], help="http: header name (values are not stored)")
    p.add_argument("--text", help="other: free-text description of the effect")
    p.add_argument("--revise", help="new version of an existing action (earlier approvals no longer apply)")
    p.add_argument("argv", nargs=argparse.REMAINDER, help="command: -- ARGV...")

    p = sub.add_parser("show", help="show an action, its hash and its state")
    p.add_argument("action")
    p = sub.add_parser("status", help="short state of an action")
    p.add_argument("action")
    p = sub.add_parser("list", help="list actions")
    p.add_argument("--status")

    for name in ("approve", "reject"):
        p = sub.add_parser(name, help=f"{name} the exact action hash")
        p.add_argument("action")
        p.add_argument("--hash", required=True, dest="sha256")
        p.add_argument("--reason", required=True)
        p.add_argument("--signer")
        if name == "approve":
            p.add_argument("--valid-for", help="approval lifetime, e.g. 24h")

    p = sub.add_parser("claim", help="claim an approved action before executing it yourself")
    p.add_argument("action")
    p.add_argument("--hash", required=True, dest="sha256")
    p.add_argument("--payload")

    p = sub.add_parser("outcome", help="report the outcome of a claimed action")
    p.add_argument("action")
    p.add_argument("--claim", required=True)
    p.add_argument("--status", required=True, choices=("succeeded", "failed", "unknown"))
    p.add_argument("--evidence-text", help="short evidence note (e.g. provider id)")

    p = sub.add_parser("run", help="claim and run an approved command action once")
    p.add_argument("action")
    p.add_argument("--timeout", help="e.g. 10m")
    p.add_argument("--payload")

    p = sub.add_parser("resolve", help="close an unknown outcome after checking the external state")
    p.add_argument("action")
    p.add_argument("--as", dest="as_", required=True, choices=("succeeded", "not-applied"))
    p.add_argument("--reason", required=True)
    p.add_argument("--signer")

    sub.add_parser("sync", help="deliver records that could not reach the sink")
    return parser


def make_signoff(args) -> Signoff:
    settings = load_settings(config=args.config, registry=args.registry, keys_dir=args.keys_dir,
                             state_dir=args.state_dir, sink=args.sink, evidence=args.evidence)
    return Signoff(settings)


def _out(args, value, text: str) -> None:
    print(json.dumps(value, indent=2, sort_keys=True) if args.json else text)


def _report_text(report: VerifyReport) -> str:
    lines = [f"{report.subject.get('ref')}  {report.subject.get('sha256')}", report.summary()]
    for s in report.signatures:
        lines.append(f"  [{s.status}] {s.meaning} by {s.name} ({s.signer_id}, {s.role}) "
                     f"at {local_time(s.signed_at, s.tz)}: {s.reason}" + (f" — {s.detail}" if s.detail else ""))
    for meaning, result in report.policies.items():
        lines.append(f"  policy {meaning}: {'met' if result.met else 'NOT met'} "
                     f"({result.count}/{result.policy.min_signatures}) {result.note}".rstrip())
    for rid in report.recorded:
        lines.append(f"  recorded invalidation {rid}")
    return "\n".join(lines)


def _action_text(view: dict) -> str:
    spec = view["spec"]
    lines = [f"{view['id']} v{view['version']}  [{view['status']}] {view['detail']}".rstrip(),
             f"  hash:        {view['action_sha256']}",
             f"  kind:        {spec['kind']}",
             f"  description: {spec.get('description') or '-'}",
             f"  spec:        {json.dumps(spec['spec'], sort_keys=True)}",
             f"  payload:     {spec.get('payload_sha256') or '-'}",
             f"  prepared by: {view['preparer'].get('id')}"]
    for a in view["approvals"]:
        lines.append(f"  approved by {a['signer']} at {a['signed_at']}"
                     + (f" (until {a['expires_at']})" if a["expires_at"] else "") + f": {a['reason']}")
    if view["claim_id"]:
        lines.append(f"  claim:       {view['claim_id']} at {view['claimed_at']}")
    if view["outcome"]:
        lines.append(f"  outcome:     {view['outcome'].get('outcome')} ({view['outcome'].get('basis')})")
    return "\n".join(lines)


def _subject(so: Signoff, args) -> tuple[dict, list[str]]:
    if args.file:
        return so.file_subject(args.file), []
    if args.record:
        subject, record = so.record_subject(args.record)
        return subject, [record["actor"]["id"]] if isinstance(record.get("actor"), dict) else []
    if not args.sha256.startswith("sha256:") or len(args.sha256) != 71:
        raise UsageError("--hash must be sha256:<64 hex>")
    return {"kind": args.kind, "ref": args.ref or args.sha256, "sha256": args.sha256}, []


def _read(path: str | None) -> bytes | None:
    return Path(path).read_bytes() if path else None


def run(args) -> int:
    so = make_signoff(args)
    cmd = args.command
    if cmd == "init":
        record = so.init_signer(args.id, args.name, args.role, add_key=args.add_key)
        _out(args, record, f"enrolled {args.id} with key {record['data']['key_id']}\n"
                           f"registry: {so.settings.registry_path}\nkey:      {so.registry.key_path(args.id)}")
        return 0
    if cmd == "signers":
        data = so.registry.as_dict()
        if args.signers_command == "export":
            text = json.dumps(data, indent=2, sort_keys=True) + "\n"
            if args.file:
                Path(args.file).write_text(text, encoding="utf-8")
                print(f"wrote {args.file}")
            else:
                print(text, end="")
            return 0
        lines = []
        for s in data["signers"]:
            for k in s["keys"]:
                lines.append(f"{s['id']}  {s['name']} ({s['role']})  {k['key_id']}  "
                             f"{'revoked ' + k['revoked_at'] if k['revoked_at'] else 'active'}")
        _out(args, data, "\n".join(lines) or "no signers")
        return 0
    if cmd == "revoke":
        record = so.revoke(args.signer, args.reason, compromised_since=args.compromised_since, lost=args.lost)
        _out(args, record, f"revoked {record['data']['key_id']} at {record['data']['revoked_at']}")
        return 0
    if cmd == "sign":
        subject, authors = _subject(so, args)
        record = so.sign(subject, args.meaning, args.reason, signer_id=args.signer, authors=authors + args.author)
        _out(args, record, f"signed {subject['ref']} as {args.meaning}: {record['id']}")
        return 0
    if cmd in ("verify", "manifest"):
        required = getattr(args, "require", [])
        record_inv = cmd == "verify" and not args.no_record
        if args.file:
            report = so.verify_file(args.file, required=required, record_invalidations=record_inv)
        elif args.record:
            report = so.verify_record(args.record, required=required, record_invalidations=record_inv)
        else:
            report = so.verify_hash(args.sha256, required=required)
        if cmd == "manifest":
            text = render(report, args.format)
            if args.out:
                Path(args.out).write_text(text, encoding="utf-8")
                print(f"wrote {args.out}")
            else:
                print(text, end="")
            return 0
        _out(args, report.as_dict(), _report_text(report))
        return 0 if report.ok else 1
    if cmd == "invalidate":
        record = so.withdraw(args.signature, args.reason)
        _out(args, record, f"withdrew {args.signature}: {record['id']}")
        return 0
    if cmd == "prepare":
        argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        if args.kind == "command":
            spec = {"argv": argv}
        elif args.kind == "http":
            spec = {"method": args.method, "url": args.url, "headers": args.header}
        else:
            spec = {"text": args.text or args.description}
        view = so.actions.prepare(args.kind, args.request_key, spec, description=args.description,
                                  payload=_read(args.payload), revise=args.revise)
        _out(args, view, _action_text(view))
        return 0
    if cmd in ("show", "status"):
        view = so.actions.show(args.action)
        _out(args, view, _action_text(view) if cmd == "show" else f"{view['status']} {view['detail']}".rstrip())
        return 0
    if cmd == "list":
        views = so.actions.list(args.status)
        _out(args, views, "\n".join(f"{v['id']} v{v['version']} [{v['status']}] {v['spec'].get('description') or ''}"
                                    for v in views) or "no actions")
        return 0
    if cmd == "approve":
        view = so.actions.approve(args.action, args.sha256, args.reason, signer_id=args.signer,
                                  valid_for_ms=duration_ms(args.valid_for) if args.valid_for else None)
        _out(args, view, _action_text(view))
        return 0
    if cmd == "reject":
        view = so.actions.reject(args.action, args.sha256, args.reason, signer_id=args.signer)
        _out(args, view, _action_text(view))
        return 0
    if cmd == "claim":
        claim = so.actions.claim(args.action, args.sha256, payload=_read(args.payload))
        _out(args, {"action_id": claim.action_id, "claim_id": claim.claim_id, "record": claim.record["id"]},
             f"claimed {claim.action_id}: {claim.claim_id}\nrun the effect once, then report it with "
             f"'aqt-signoff outcome {claim.action_id} --claim {claim.claim_id} --status ...'")
        return 0
    if cmd in ("outcome", "run"):
        if cmd == "outcome":
            record = so.actions.report_outcome(args.action, args.claim, args.status,
                                               extra={"evidence": args.evidence_text} if args.evidence_text else None)
        else:
            record = so.actions.run(args.action, timeout_ms=duration_ms(args.timeout) if args.timeout else None,
                                    payload=_read(args.payload))
        data = record["data"]
        text = f"{args.action}: {data['outcome']} ({data['basis']})"
        if data.get("excerpt"):
            text += "\n" + data["excerpt"].rstrip()
        if not record["_delivered"]:
            text += f"\nwarning: the record could not reach the sink ({record['_error']}); run 'aqt-signoff sync'"
        _out(args, record, text)
        if not record["_delivered"]:
            return 2
        return 0 if data["outcome"] == "succeeded" else 1
    if cmd == "resolve":
        view = so.actions.resolve(args.action, args.as_, args.reason, signer_id=args.signer)
        _out(args, view, _action_text(view))
        return 0
    if cmd == "sync":
        result = so.sync()
        _out(args, result, f"delivered {len(result['delivered'])}, still pending {len(result['failed'])}")
        return 0 if not result["failed"] else 2
    raise UsageError(f"unknown command {cmd}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except SignoffError as error:
        if args.json:
            print(json.dumps({"ok": False, "code": error.code, "message": str(error), **error.details}))
        else:
            print(f"error ({error.code}): {error}", file=sys.stderr)
        return error.exit
    except SinkError as error:
        print(f"error (sink): {error}; the operation was not completed", file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
