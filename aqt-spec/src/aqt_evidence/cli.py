"""``aqt-evidence``: validate, hash, verify and check conformance of evidence record files."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from pathlib import Path

from .chain import verify_chain
from .conformance import conformance, read_strict
from .crypto import generate_key, load_public_key
from .record import record_hash, validate_record
from .sink import SinkError, read_jsonl
from .vectors import run_all


def _keys(paths):
    return dict(load_public_key(path) for path in paths or [])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aqt-evidence", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="check every record's envelope")
    validate.add_argument("file")
    hashes = sub.add_parser("hash", help="print each record's hash")
    hashes.add_argument("file")
    verify = sub.add_parser("verify", help="verify a chained file (and signatures with --key)")
    verify.add_argument("file")
    verify.add_argument("--key", action="append", help="public key PEM; repeatable")
    verify.add_argument("--require-signature", action="store_true")
    verify.add_argument("--json", action="store_true")
    keygen = sub.add_parser("keygen", help="create an Ed25519 key pair (PATH and PATH.pub)")
    keygen.add_argument("path")
    keygen.add_argument("--passphrase", action="store_true", help="encrypt the private key")
    conform = sub.add_parser("conform", help="highest conformance level (1 valid, 2 chained, 3 signed + anchored)")
    conform.add_argument("file")
    conform.add_argument("--level", type=int, choices=(1, 2, 3), default=1, help="target level (default 1)")
    conform.add_argument("--key", action="append", help="pinned public key PEM; repeatable (L3)")
    conform.add_argument("--checkpoint", action="append", help="checkpoint JSON file kept outside the writer (L3)")
    conform.add_argument("--no-payloads", action="store_true", help="skip payload schema checks")
    conform.add_argument("--json", action="store_true")
    vectors = sub.add_parser("vectors", help="run the conformance test vectors against this library")
    vectors.add_argument("dir", nargs="?", help="vector folder (default: the packaged vectors)")
    vectors.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.command == "validate":
            bad = 0
            for number, record in enumerate(read_jsonl(args.file), 1):
                for problem in validate_record(record):
                    bad += 1
                    print(f"record {number}: {problem}")
            print("valid" if not bad else f"{bad} problem(s)")
            return 0 if not bad else 1
        if args.command == "hash":
            for record in read_jsonl(args.file):
                print(record.get("id"), record_hash(record))
            return 0
        if args.command == "verify":
            keys = _keys(args.key) if args.key else None
            result = verify_chain(read_jsonl(args.file), keys=keys, require_signature=args.require_signature)
            if args.json:
                print(json.dumps(result.__dict__))
            else:
                print(result.summary())
                for warning in result.warnings:
                    print("warning:", warning)
            return 0 if result.ok else 1
        if args.command == "conform":
            records, problems = read_strict(args.file)
            checkpoints = [json.loads(Path(path).read_text(encoding="utf-8")) for path in args.checkpoint or []]
            result = conformance(records, args.level, keys=_keys(args.key) if args.key else None,
                                 checkpoints=checkpoints, check_payloads=not args.no_payloads,
                                 parse_problems=problems)
            if args.json:
                print(json.dumps(result.as_dict()))
            else:
                print(result.summary())
                for problem in result.problems[:20]:
                    print("problem:", problem)
                for warning in result.warnings:
                    print("warning:", warning)
            return 0 if result.ok else 1
        if args.command == "vectors":
            results = run_all(Path(args.dir) if args.dir else None)
            failed = [result for result in results if not result.ok]
            if args.json:
                print(json.dumps({"count": len(results), "failed": [
                    {"file": r.file, "mismatches": r.mismatches} for r in failed]}))
            else:
                for result in failed:
                    print(f"FAIL {result.file}: {'; '.join(result.mismatches)}")
                print(f"{len(results) - len(failed)} of {len(results)} vectors agree")
            return 0 if not failed else 1
        if args.command == "keygen":
            passphrase = getpass.getpass("Passphrase: ").encode() if args.passphrase else None
            print(generate_key(args.path, passphrase=passphrase))
            return 0
    except (OSError, SinkError, ValueError, KeyError, ImportError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
