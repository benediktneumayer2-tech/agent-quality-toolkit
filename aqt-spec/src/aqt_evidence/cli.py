"""``aqt-evidence``: validate, hash, verify and check conformance of evidence record files."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from pathlib import Path

from .canonical import CanonicalError, parse_json, parse_record
from .chain import ChainResult, verify_chain
from .conformance import conformance, read_strict
from .crypto import generate_key, load_public_key
from .record import record_hash, validate_record
from .sink import RecordLineError, SinkError, read_jsonl
from .vectors import run_all


def _keys(paths):
    return dict(load_public_key(path) for path in paths or [])


def _verify_file(path, *, keys=None, require_signature: bool = False) -> ChainResult:
    """Verify a stored chained JSON-lines log: every line strictly parsed and canonical
    (``read_jsonl(strict=True)``), then the chain (and signatures with ``keys``). An unreadable
    line breaks the chain at the seq it would have had."""
    bad: list[RecordLineError] = []

    def records():
        try:
            yield from read_jsonl(path, strict=True)
        except RecordLineError as error:
            bad.append(error)

    result = verify_chain(records(), keys=keys, require_signature=require_signature)
    if result.ok and bad:
        return ChainResult(False, result.count, result.head_seq, result.head_hash, result.count,
                           f"line {bad[0].line}: {bad[0].reason}", result.warnings)
    return result


def _checkpoint(path):
    try:
        return parse_json(Path(path).read_bytes())
    except CanonicalError as error:
        raise ValueError(f"checkpoint {path}: {error}") from error


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
    verify.add_argument("--require-signature", action="store_true",
                        help="every record needs a valid signature by a --key")
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
            with open(args.file, "rb") as handle:
                lines = [line for line in handle if line.strip()]
            for number, line in enumerate(lines, 1):
                try:
                    problems = validate_record(parse_record(line))
                except CanonicalError as error:  # strict parsing (spec §4)
                    problems = [str(error)]
                for problem in problems:
                    bad += 1
                    print(f"record {number}: {problem}")
            print("valid" if not bad else f"{bad} problem(s)")
            return 0 if not bad else 1
        if args.command == "hash":
            for record in read_jsonl(args.file):
                print(record.get("id"), record_hash(record))
            return 0
        if args.command == "verify":
            if args.require_signature and not args.key:
                parser.error("--require-signature needs the pinned public key: add --key PEM")
            keys = _keys(args.key) if args.key else None
            result = _verify_file(args.file, keys=keys, require_signature=args.require_signature)
            if args.json:
                print(json.dumps(result.__dict__))
            else:
                print(result.summary())
                for warning in result.warnings:
                    print("warning:", warning)
            return 0 if result.ok else 1
        if args.command == "conform":
            records, problems = read_strict(args.file)
            checkpoints = [_checkpoint(path) for path in args.checkpoint or []]
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
