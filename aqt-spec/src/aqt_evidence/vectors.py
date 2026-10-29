"""Run the conformance test vectors (``vectors/``) against this library.

Each vector is one JSON file with ``kind``, ``input`` or ``input_text`` and
``expect``; see ``vectors/README.md``. Another implementation runs the same
files against its own code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .canonical import CanonicalError, canonical_json, content_hash, parse_json, parse_record
from .chain import checkpoint_matches, verify_chain, verify_checkpoint
from .crypto import public_key_from_raw, verify_record_signatures, verify_statement
from .record import record_content_hash, record_hash, validate_record
from .schemas import data_dir


def vector_dir() -> Path:
    return data_dir("vectors")


def load_keys(directory: Path | None = None) -> dict[str, dict]:
    """Named test keys; each entry gains ``key_id`` and ``public`` (an Ed25519PublicKey)."""
    directory = directory or vector_dir()
    keys = json.loads((directory / "keys.json").read_text(encoding="utf-8"))["keys"]
    for entry in keys.values():
        entry["key_id"], entry["public"] = public_key_from_raw(bytes.fromhex(entry["public_hex"]))
    return keys


def load_vectors(directory: Path | None = None) -> list[dict]:
    directory = directory or vector_dir()
    vectors = []
    for path in sorted(directory.glob("*/*.json")):
        vector = json.loads(path.read_text(encoding="utf-8"))
        vector["_file"] = str(path.relative_to(directory))
        vectors.append(vector)
    return vectors


@dataclass
class VectorResult:
    name: str
    file: str
    mismatches: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.mismatches


def _schema_valid(record) -> bool | None:
    try:
        from .schemas import validate_schema
        return not validate_schema(record, "envelope")
    except ImportError:
        return None


def _same(mismatches: list[str], what: str, got, expected) -> None:
    if got != expected:
        mismatches.append(f"{what}: got {got!r}, expected {expected!r}")


def run_vector(vector: dict, keys: dict[str, dict]) -> VectorResult:
    result = VectorResult(vector.get("name", "?"), vector.get("_file", "?"))
    expect, out = vector["expect"], result.mismatches
    pinned = {keys[name]["key_id"]: keys[name]["public"] for name in vector.get("pinned_keys", [])}
    kind = vector["kind"]
    if kind == "canonical":
        try:
            value = parse_json(vector["input_text"])
            canonical = canonical_json(value).decode("utf-8")
        except CanonicalError as error:
            _same(out, "error", True, expect.get("error", False))
            if not expect.get("error"):
                out.append(f"unexpected error: {error}")
            return result
        _same(out, "error", False, expect.get("error", False))
        _same(out, "canonical", canonical, expect.get("canonical"))
        _same(out, "sha256", content_hash(value), expect.get("sha256"))
    elif kind == "record":
        if "input_text" in vector:
            try:
                record = parse_record(vector["input_text"])
            except CanonicalError:
                _same(out, "valid", False, expect["valid"])
                return result
        else:
            record = vector["input"]
        errors = validate_record(record)
        _same(out, "valid", not errors, expect["valid"])
        if "schema_valid" in expect:
            schema_valid = _schema_valid(record)
            if schema_valid is not None:
                _same(out, "schema_valid", schema_valid, expect["schema_valid"])
        if not errors:
            for what, function in (("record_hash", record_hash), ("content_hash", record_content_hash)):
                if what in expect:
                    _same(out, what, function(record), expect[what])
            if "canonical" in expect:
                _same(out, "canonical", canonical_json(record).decode("utf-8"), expect["canonical"])
            if "signatures" in expect:
                got = [[key, ok] for key, ok in verify_record_signatures(record, pinned)]
                _same(out, "signatures", got, expect["signatures"])
    elif kind == "chain":
        chain = verify_chain(vector["input"], keys=pinned or None,
                             require_signature=expect.get("require_signature", False))
        _same(out, "ok", chain.ok, expect["ok"])
        _same(out, "first_bad_seq", chain.first_bad_seq, expect.get("first_bad_seq"))
        if chain.ok:
            _same(out, "head_seq", chain.head_seq, expect.get("head_seq"))
            _same(out, "head_hash", chain.head_hash, expect.get("head_hash"))
    elif kind == "log":
        records, bad_line = [], None
        for number, line in enumerate(vector["input_text"].encode("utf-8").split(b"\n"), 1):
            if not line.strip():
                continue
            try:
                records.append(parse_record(line))
            except CanonicalError:
                bad_line = number
                break
        chain = verify_chain(records, keys=pinned or None, require_signature=expect.get("require_signature", False))
        _same(out, "ok", chain.ok and bad_line is None, expect["ok"])
        _same(out, "first_bad_line", bad_line, expect.get("first_bad_line"))
        if chain.ok and bad_line is None:
            _same(out, "head_hash", chain.head_hash, expect.get("head_hash"))
    elif kind == "checkpoint":
        checkpoint = vector["input"]["checkpoint"]
        _same(out, "valid", verify_checkpoint(checkpoint, pinned), expect["valid"])
        if "matches" in expect:
            _same(out, "matches", checkpoint_matches(checkpoint, vector["input"]["records"]), expect["matches"])
    elif kind == "statement":
        signed = vector["input"]["signature"]
        _same(out, "valid", verify_statement(signed, pinned), expect["valid"])
        if "target" in vector["input"]:
            subject_hash = signed["statement"]["subject"]["sha256"]
            for name in ("target", "stored_target"):
                if name in vector["input"]:
                    _same(out, f"{name} content_hash matches subject",
                          record_content_hash(vector["input"][name]) == subject_hash, expect[f"{name}_matches"])
    else:
        out.append(f"unknown vector kind {kind!r}")
    return result


def run_all(directory: Path | None = None) -> list[VectorResult]:
    directory = directory or vector_dir()
    keys = load_keys(directory)
    return [run_vector(vector, keys) for vector in load_vectors(directory)]
