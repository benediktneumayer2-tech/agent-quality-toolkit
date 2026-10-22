#!/usr/bin/env python3
"""Generate the conformance test vectors in ``vectors/``.

Deterministic: fixed IDs, times and the RFC 8032 test keys (Ed25519 signatures
are deterministic), so regeneration is byte-identical. Expected outcomes
(valid/invalid, first broken seq, signature results) are written by hand here;
hashes and canonical bytes come from the reference library. After writing, the
script checks every vector against the library.

Usage: ``python scripts/gen_vectors.py [--check]``
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aqt_evidence import (GENESIS, canonical_json, content_hash, link, make_checkpoint,  # noqa: E402
                          record_content_hash, record_hash, sign_record, sign_statement, signer_from_seed)
from aqt_evidence.vectors import load_keys, run_vector  # noqa: E402

OUT = ROOT / "vectors"
# RFC 8032 section 7.1, TEST 1 and TEST 2. Published keys: TEST ONLY, never use them for real evidence.
KEYS = {
    "rfc8032-test1": {
        "seed_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    },
    "rfc8032-test2": {
        "seed_hex": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public_hex": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    },
}
SIGNER = signer_from_seed(bytes.fromhex(KEYS["rfc8032-test1"]["seed_hex"]))
OTHER = signer_from_seed(bytes.fromhex(KEYS["rfc8032-test2"]["seed_hex"]))
vectors: list[dict] = []


def rid(n: int) -> str:
    return f"rec_019a0f3c2b00{n:016x}"


def ts(n: int) -> str:
    return f"2026-10-21T12:00:{n:02d}.000000Z"


ALICE = {"kind": "human", "id": "human:alice", "role": "quality-manager", "display": "Alice Example"}
AGENT = {"kind": "agent", "id": "agent:claude-code:s-0001",
         "agent": {"harness": "claude-code", "model": "example-model", "session": "s-0001"}}
TRAIL = {"kind": "service", "id": "service:aqt-trail"}


def minimal(n: int, **extra) -> dict:
    return {"aqt": "0.1", "id": rid(n), "type": "trail.event", "time": ts(n), "actor": AGENT,
            "action": f"step-{n}", **extra}


def add(category: str, name: str, kind: str, description: str, expect: dict, *, input=None,
        input_text: str | None = None, pinned_keys: list[str] | None = None) -> None:
    vector = {"name": name, "category": category, "kind": kind, "description": description}
    if pinned_keys:
        vector["pinned_keys"] = pinned_keys
    if input_text is not None:
        vector["input_text"] = input_text
    else:
        vector["input"] = input
    vector["expect"] = expect
    vectors.append(vector)


def chain_of(records: list[dict], signer=None, start_prev: str = GENESIS) -> list[dict]:
    out, prev = [], start_prev
    for seq, record in enumerate(records):
        record = link(record, seq=seq, prev=prev)
        if signer:
            record = sign_record(record, signer)
        out.append(record)
        prev = record_hash(record)
    return out


# --- canonical -----------------------------------------------------------------------------------
def canonical_ok(name: str, description: str, text: str) -> None:
    value = json.loads(text)
    add("canonical", name, "canonical", description,
        {"error": False, "canonical": canonical_json(value).decode("utf-8"), "sha256": content_hash(value)},
        input_text=text)


def canonical_error(name: str, description: str, text: str) -> None:
    add("canonical", name, "canonical", description, {"error": True}, input_text=text)


canonical_ok("key-order", "Object keys are sorted by code point at every level; whitespace is removed.",
             '{ "b": 1, "a": 2, "c": { "z": true, "y": null } }')
canonical_ok("unicode-raw", "Non-ASCII string content is written as raw UTF-8, not escaped.",
             '{"text": "Gr\\u00fc\\u00dfe \\u20ac \\ud834\\udd1e"}')
canonical_ok("escapes", "Quote, backslash and C0 controls are escaped as in RFC 8785; DEL and / are not.",
             '{"s": "q\\" b\\\\ n\\n t\\t c\\u0001 d\\u007f s\\/"}')
canonical_ok("integer-bounds", "Integers up to +/-(2^53-1) are allowed and written in plain decimal.",
             '{"max": 9007199254740991, "min": -9007199254740991, "zero": 0, "neg": -1}')
canonical_ok("arrays-and-empty", "Array order is kept; empty objects and arrays stay.",
             '{"a": [3, 1, 2], "e": {}, "l": []}')
canonical_error("float", "Floats are not allowed (use integers such as *_ppm or *_ms).", '{"score": 1.5}')
canonical_error("float-integral", "1.0 is a float in the JSON text and is refused, although its value is integral.",
                '{"score": 1.0}')
canonical_error("exponent", "Exponent notation is a float.", '{"n": 1e2}')
canonical_error("integer-too-large", "Integers beyond 2^53-1 are refused.", '{"n": 9007199254740992}')
canonical_error("non-ascii-key", "Object keys must be ASCII.", '{"\\u00e4": 1}')
canonical_error("duplicate-key", "Duplicate keys are refused (parsers disagree on them).", '{"a": 1, "a": 2}')
canonical_error("lone-surrogate", "Strings must be valid Unicode; a lone surrogate escape is refused.",
                '{"s": "\\ud800"}')
canonical_error("nan", "NaN and Infinity are not JSON.", '{"n": NaN}')

# --- valid records -------------------------------------------------------------------------------
FULL = {
    "aqt": "0.1", "id": rid(100), "type": "signoff.signature", "time": ts(10), "tz": "Europe/Vienna",
    "actor": ALICE,
    "observed": {"pid": 4242, "uid": 1000, "gid": 1000, "process_chain": ["aqt-signoff", "bash"],
                 "harness": None, "client_time": ts(9), "via": "socket"},
    "action": "sign",
    "subject": {"kind": "file", "ref": "docs/report.md", "sha256": "sha256:" + "ab" * 32},
    "before": {"sha256": "sha256:" + "01" * 32}, "after": {"sha256": "sha256:" + "02" * 32, "value": "v2"},
    "reason": "Reviewed against the change request", "meaning": "approved",
    "links": [{"rel": "evidence", "ref": rid(99)}],
    "data": {"meaning": "approved", "note": "Grüße"},
}


def record_ok(name: str, description: str, record: dict, *, pinned: list[str] | None = None,
              signatures: list | None = None) -> None:
    expect = {"valid": True, "schema_valid": True, "record_hash": record_hash(record),
              "content_hash": record_content_hash(record), "canonical": canonical_json(record).decode("utf-8")}
    if signatures is not None:
        expect["signatures"] = signatures
    add("valid", name, "record", description, expect, input=record, pinned_keys=pinned)


def record_bad(name: str, description: str, record=None, *, text: str | None = None,
               schema_valid: bool | None = False) -> None:
    expect = {"valid": False}
    if schema_valid is not None:
        expect["schema_valid"] = schema_valid
    add("invalid", name, "record", description, expect, input=record, input_text=text)


record_ok("minimal", "Only the required fields: aqt, id, type, time, actor, action.", minimal(1))
record_ok("full", "Every envelope field, including writer-owned observed and a meaning.", FULL)
record_ok("extension-type", "x-<org>. types are valid envelopes (registration is checked at conformance L1).",
          minimal(2, type="x-example.thing"))
signed_full = sign_record(FULL, SIGNER)
record_ok("signed", "A record signed by the RFC 8032 TEST 1 key; the signature covers the record without sig.",
          signed_full, pinned=["rfc8032-test1"], signatures=[[SIGNER.key_id, True]])
cosigned = sign_record(signed_full, OTHER)
record_ok("cosigned-unknown-key", "Two independent signatures; only TEST 1 is pinned, so TEST 2 reports unknown "
          "(null).", cosigned, pinned=["rfc8032-test1"], signatures=[[SIGNER.key_id, True], [OTHER.key_id, None]])
tampered_sig = {**signed_full, "reason": "changed after signing"}
record_ok("signature-tampered", "The envelope is still valid, but the signature no longer verifies (false).",
          tampered_sig, pinned=["rfc8032-test1"], signatures=[[SIGNER.key_id, False]])

record_bad("unknown-field", "Unknown top-level fields are invalid; extensions go into data.",
           minimal(3, extra="x"))
record_bad("wrong-version", "aqt must be \"0.1\".", {**minimal(4), "aqt": "0.2"})
record_bad("bad-id", "id is rec_ plus 28 lower-case hex digits.", {**minimal(5), "id": "rec_123"})
record_bad("bad-type", "type is <tool>.<kind> in lower case.", {**minimal(6), "type": "Trail.Event"})
record_bad("time-offset", "time is UTC with a Z suffix; offsets go into tz as a zone name.",
           {**minimal(7), "time": "2026-10-21T14:00:00+02:00"})
record_bad("missing-actor", "actor is required.", {k: v for k, v in minimal(8).items() if k != "actor"})
record_bad("bad-actor-kind", "actor.kind is human, agent or service.",
           {**minimal(9), "actor": {"kind": "robot", "id": "x"}})
record_bad("bad-meaning", "meaning comes from the fixed vocabulary.", minimal(10, meaning="liked"))
record_bad("blank-reason", "reason, when present, is non-blank.", minimal(11, reason="   "))
record_bad("subject-without-ref", "subject needs kind and ref.", minimal(12, subject={"kind": "file"}))
record_bad("bad-subject-hash", "sha256 values are sha256:<64 lower-case hex>.",
           minimal(13, subject={"kind": "file", "ref": "a", "sha256": "md5:abc"}))
record_bad("bad-chain", "chain.seq is an integer.", minimal(14, chain={"seq": "0", "prev": GENESIS}))
record_bad("bad-sig-alg", "sig entries use alg ed25519.",
           minimal(15, sig=[{"alg": "rsa", "key": "k", "value": "v"}]))
record_bad("link-without-ref", "links are {rel, ref}.", minimal(16, links=[{"rel": "case"}]))
record_bad("float-in-data", "No floats anywhere, also inside data; the schema alone cannot see this.",
           text=json.dumps(minimal(17)).replace('"action": "step-17"', '"action": "step-17", "data": {"x": 1.5}'),
           schema_valid=True)
record_bad("duplicate-key", "Duplicate keys make a record ambiguous and invalid.",
           text=json.dumps(minimal(18)).replace('"action": "step-18"', '"action": "step-18", "action": "other"'),
           schema_valid=None)
record_bad("lone-surrogate", "A lone surrogate in a string makes the record invalid.",
           text=json.dumps(minimal(19)).replace('"action": "step-19"', '"action": "step-19", "reason": "\\udc00"'),
           schema_valid=None)

# --- chains --------------------------------------------------------------------------------------
base = [minimal(20 + i) for i in range(4)]
unsigned = chain_of(base)
signed = chain_of(base, SIGNER)


def chain_vector(category: str, name: str, description: str, records: list[dict], ok: bool, *,
                 first_bad: int | None = None, pinned: list[str] | None = None, require: bool = False) -> None:
    expect: dict = {"ok": ok, "first_bad_seq": first_bad, "require_signature": require}
    if ok:
        expect["head_seq"] = len(records) - 1
        expect["head_hash"] = record_hash(records[-1])
    add(category, name, "chain", description, expect, input=records, pinned_keys=pinned)


chain_vector("chained", "intact", "Four records chained from GENESIS (64 zeros).", unsigned, True)
chain_vector("chained", "intact-signed", "The same chain, each record signed by TEST 1; signatures required.",
             signed, True, pinned=["rfc8032-test1"], require=True)
edited = copy.deepcopy(unsigned)
edited[1]["action"] = "rewritten"
chain_vector("tampered", "edited-unsigned", "Record 1 edited: without signatures the break shows at the next "
             "record (seq 2), whose prev no longer matches.", edited, False, first_bad=2)
edited_signed = copy.deepcopy(signed)
edited_signed[1]["action"] = "rewritten"
chain_vector("tampered", "edited-signed", "Record 1 edited in a signed chain: its own signature fails (seq 1).",
             edited_signed, False, first_bad=1, pinned=["rfc8032-test1"], require=True)
last_edited = copy.deepcopy(unsigned)
last_edited[-1]["action"] = "rewritten"
chain_vector("tampered", "edited-last-unsigned", "LIMIT: editing the last record of an unsigned chain is not "
             "detectable by the chain alone; signatures or a checkpoint are needed.", last_edited, True)
chain_vector("tampered", "deleted", "Record 1 deleted: record seq 2 appears where seq 1 is expected.",
             [unsigned[0], *unsigned[2:]], False, first_bad=1)
chain_vector("tampered", "reordered", "Records 0 and 1 swapped.", [unsigned[1], unsigned[0], *unsigned[2:]], False,
             first_bad=0)
foreign = chain_of([minimal(40)])[0]
chain_vector("tampered", "inserted", "A record from another chain inserted at position 2.",
             [*unsigned[:2], foreign, *unsigned[2:]], False, first_bad=2)
wrong_start = chain_of(base, start_prev="sha256:" + "11" * 32)
chain_vector("tampered", "wrong-genesis", "The first record's prev is not GENESIS.", wrong_start, False, first_bad=0)
chain_vector("tampered", "truncated", "LIMIT: dropping the last record leaves a valid shorter chain; only a "
             "checkpoint detects it (see checkpoint/truncated).", unsigned[:3], True)
rewritten = chain_of([{**r, "action": "forged"} for r in base], OTHER)
chain_vector("tampered", "rewritten-fresh-key", "A complete rewrite signed with another key verifies as a chain but "
             "fails against the pinned key (no valid signature from a known key at seq 0).", rewritten, False,
             first_bad=0, pinned=["rfc8032-test1"], require=True)
chain_vector("tampered", "unsigned-but-required", "Signatures required, but the records carry none.", unsigned,
             False, first_bad=0, pinned=["rfc8032-test1"], require=True)

# --- checkpoints ---------------------------------------------------------------------------------
checkpoint = make_checkpoint(log_id="example-log", seq=3, head=record_hash(signed[3]), signer=SIGNER, time=ts(30))
add("signed", "checkpoint-valid", "checkpoint", "A signed checkpoint of the head (seq 3) that matches the chain.",
    {"valid": True, "matches": True}, input={"checkpoint": checkpoint, "records": signed},
    pinned_keys=["rfc8032-test1"])
add("signed", "checkpoint-truncated", "checkpoint", "The chain was truncated after the checkpoint: no record at "
    "seq 3 any more, so the checkpoint does not match.", {"valid": True, "matches": False},
    input={"checkpoint": checkpoint, "records": signed[:3]}, pinned_keys=["rfc8032-test1"])
add("signed", "checkpoint-rewritten", "checkpoint", "A rewritten chain has another head hash at seq 3.",
    {"valid": True, "matches": False}, input={"checkpoint": checkpoint, "records": rewritten},
    pinned_keys=["rfc8032-test1"])
add("signed", "checkpoint-tampered", "checkpoint", "The checkpoint's seq was changed after signing.",
    {"valid": False}, input={"checkpoint": {**checkpoint, "seq": 2}, "records": signed},
    pinned_keys=["rfc8032-test1"])
foreign_cp = make_checkpoint(log_id="example-log", seq=3, head=record_hash(rewritten[3]), signer=OTHER, time=ts(31))
add("signed", "checkpoint-unpinned-key", "checkpoint", "A checkpoint signed by a key that is not pinned is not "
    "valid.", {"valid": False}, input={"checkpoint": foreign_cp, "records": rewritten},
    pinned_keys=["rfc8032-test1"])

# --- detached signed statements (data.signature) -------------------------------------------------
target = minimal(50, type="change.finish", actor=AGENT,
                 data={"plan_ref": "plan-1", "receipts": [rid(49)], "waivers": [], "gate": "GO"})
stored_target = sign_record(link({**target, "time": ts(51), "observed": {"pid": 7, "uid": 1000, "via": "socket"}},
                                 seq=12, prev="sha256:" + "22" * 32), SIGNER)
statement = {
    "aqt_signature": "0.1", "signer": {"id": "human:alice", "name": "Alice Example", "role": "quality-manager"},
    "key": SIGNER.key_id, "meaning": "approved", "reason": "Receipts and review checked",
    "signed_at": ts(55), "tz": "Europe/Vienna", "record_type": "change.finish",
    "subject": {"kind": "record", "ref": target["id"], "sha256": record_content_hash(target)},
    "nonce": "0123456789abcdef",
}
signed_statement = sign_statement(statement, SIGNER)
add("signed", "statement-record", "statement", "A detached signed statement over a record's content hash "
    "(record_content_hash excludes sig, chain, observed and time), so it still matches after the trail stored it.",
    {"valid": True, "target_matches": True, "stored_target_matches": True},
    input={"signature": signed_statement, "target": target, "stored_target": stored_target},
    pinned_keys=["rfc8032-test1"])
changed_target = {**target, "data": {**target["data"], "gate": "NO-GO"}}
add("signed", "statement-target-changed", "statement", "The statement still verifies, but the signed record's "
    "content changed: the signature no longer applies to it (invalidated).",
    {"valid": True, "target_matches": False}, input={"signature": signed_statement, "target": changed_target},
    pinned_keys=["rfc8032-test1"])
forged = {**signed_statement, "statement": {**statement, "meaning": "released"}}
add("signed", "statement-tampered", "statement", "The meaning inside the statement was changed after signing.",
    {"valid": False}, input={"signature": forged}, pinned_keys=["rfc8032-test1"])
add("signed", "statement-unpinned", "statement", "Signed by a key that is not pinned: unknown (null).",
    {"valid": None}, input={"signature": sign_statement({**statement, "key": OTHER.key_id}, OTHER)},
    pinned_keys=["rfc8032-test1"])


def render() -> dict[Path, str]:
    keys = {"warning": "TEST ONLY. These are the published RFC 8032 section 7.1 test keys. Never use them for "
                       "real evidence; anyone can sign with them.",
            "keys": {name: {**entry, "key_id": signer.key_id}
                     for (name, entry), signer in zip(KEYS.items(), (SIGNER, OTHER))}}
    files = {OUT / "keys.json": json.dumps(keys, indent=2) + "\n"}
    index = []
    for vector in vectors:
        path = OUT / vector["category"] / f"{vector['name']}.json"
        files[path] = json.dumps(vector, indent=2, ensure_ascii=False) + "\n"
        index.append({"file": str(path.relative_to(OUT)), "kind": vector["kind"], "description": vector["description"]})
    files[OUT / "index.json"] = json.dumps({"aqt": "0.1", "count": len(index), "vectors": index}, indent=2,
                                           ensure_ascii=False) + "\n"
    return files


def main(argv: list[str]) -> int:
    files = render()
    if "--check" in argv:
        stale = [str(p.relative_to(ROOT)) for p, text in files.items() if not p.exists() or p.read_text() != text]
        for item in stale:
            print("out of date:", item)
        return 1 if stale else 0
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    keys = load_keys(OUT)
    failures = [r for r in (run_vector({**v, "_file": v["name"]}, keys) for v in vectors) if not r.ok]
    for failure in failures:
        print("library disagrees:", failure.name, failure.mismatches)
    print(f"wrote {len(vectors)} vectors")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
