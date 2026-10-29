"""Verify a trail: chain, service signatures, checkpoints, anchors, external heads
and detached signatures in ``data.signature`` (aqt-spec spec §6.3).

What "intact" covers: every line is canonical JSON, the hash chain links and every
record is signed by a service key you gave. In user mode the service key is
readable by the same user, so a rewrite that re-chains and re-signs passes; only an
external head (``--heads``, kept out of the agent's reach) or an RFC 3161 anchor
verified to a CA you trust, made *after* the edit, detects it. ``covered_seq`` and a
warning say how far those reach.

Detached signatures are bound to the registry (``signers``): the key must belong to
the signer the statement names, be enrolled before and not revoked at ``signed_at``,
and the statement must name the record's type and meaning. A ``trail.review`` must be
signed that way by its reviewer, cover its own content, and name a scope whose head
and actors match the trail, with a reviewer who did not act in it.

Malformed payloads are reported as problems; verification never stops on them.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from aqt_evidence import CanonicalError, canonical_json, content_hash, parse_record, record_hash, verify_chain
from aqt_evidence import verify_checkpoint, verify_statement

from . import tsa
from .review import in_period, is_writer_record, scope_actors
from .signers import SignerInfo, key_owners, parse_time

STATEMENT_VERSION = "0.1"


@dataclass
class TrailReport:
    ok: bool
    count: int = 0
    head_seq: int | None = None
    head: str | None = None
    log_id: str | None = None
    first_bad_seq: int | None = None
    reason: str | None = None
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checkpoints: int = 0
    anchors: int = 0
    anchors_verified: int = 0
    heads: int = 0
    signatures: int = 0
    reviews: int = 0
    covered_seq: int | None = None          # highest seq covered by a matching external head or CA-verified anchor
    signature_problems: list[str] = field(default_factory=list)   # the part of ``problems`` about signatures

    def summary(self) -> str:
        if self.first_bad_seq is not None:
            return f"broken from seq {self.first_bad_seq}: {self.reason}"
        if not self.ok:
            return f"chain intact ({self.count} records) but: {self.problems[0]}"
        return f"intact: {self.count} records, head seq {self.head_seq} {self.head}"

    def as_dict(self) -> dict:
        return asdict(self)

    def _signature_problem(self, text: str) -> None:
        self.problems.append(text)
        self.signature_problems.append(text)


def load_lines(path: str | os.PathLike) -> tuple[list[dict], tuple[int, str] | None]:
    """Records of a trail file and, if a line is unreadable, (line number, reason).

    Strict: duplicate keys, floats and anything else that is not AQT JSON are refused, and every line must be
    exactly the canonical form of its record, so the stored bytes are the record."""
    records = []
    with open(path, "rb") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                return records, (number, "empty line")
            if not line.endswith(b"\n"):
                return records, (number, "incomplete last line")
            try:
                record = parse_record(line[:-1])
            except CanonicalError as error:
                text = str(error)
                return records, (number, "line is not valid JSON" if text.startswith("not valid JSON")
                                 else f"line is not AQT JSON ({text})")
            if canonical_json(record) != line[:-1]:
                return records, (number, "line is not in canonical form (re-serialised or edited)")
            records.append(record)
    return records, None


def _load_points(path: str | os.PathLike, label: str, report: TrailReport) -> list:
    """Checkpoints from a heads or checkpoints file (JSON lines or one JSON array); unreadable lines are problems."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        report.problems.append(f"{label} file {path} is unreadable ({error})")
        return []
    stripped = text.strip()
    if stripped.startswith("["):
        try:
            items = json.loads(stripped)
        except ValueError:
            report.problems.append(f"{label} file {path} is not valid JSON")
            return []
        if isinstance(items, list):
            return items
        report.problems.append(f"{label} file {path} is not a list of checkpoints")
        return []
    items = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            items.append(json.loads(line))
        except ValueError:
            report.problems.append(f"{label} file {path} line {number} is not valid JSON")
    return items


def _point_shape(point) -> bool:
    sig = point.get("sig") if isinstance(point, dict) else None
    return (isinstance(point, dict) and type(point.get("seq")) is int and isinstance(point.get("head"), str)
            and isinstance(point.get("log"), str) and isinstance(sig, dict) and isinstance(sig.get("key"), str)
            and isinstance(sig.get("value"), str))


def _check_point(point, records: list[dict], keys: dict, label: str, report: TrailReport) -> bool:
    """True when ``point`` is signed by a service key, names this log and matches the record at its seq."""
    if not _point_shape(point):
        report.problems.append(f"{label}: malformed checkpoint (needs log, seq, head and sig)")
        return False
    try:
        valid = verify_checkpoint(point, keys)
    except (TypeError, ValueError, AttributeError):
        valid = False
    if not valid:
        report.problems.append(f"{label} at seq {point['seq']}: signature invalid or key unknown")
        return False
    if report.log_id and point["log"] != report.log_id:
        report.problems.append(f"{label} at seq {point['seq']} belongs to another log ({point['log']})")
        return False
    if report.head_seq is None or point["seq"] > report.head_seq:
        report.problems.append(f"{label} at seq {point['seq']} is beyond the head: the trail was truncated")
        return False
    if point["seq"] < 0 or record_hash(records[point["seq"]]) != point["head"]:
        report.problems.append(f"{label} at seq {point['seq']} does not match the record: the trail was rewritten")
        return False
    return True


def _cover(report: TrailReport, seq: int) -> None:
    report.covered_seq = seq if report.covered_seq is None else max(report.covered_seq, seq)


def _check_anchor(record: dict, seq: int, data: dict, records: list[dict], keys: dict, tsa_ca,
                  report: TrailReport) -> None:
    action = record.get("action")
    if not is_writer_record(record):
        report.problems.append(f"seq {seq}: trail.anchor ({action}) was not written by the writer (a client sent "
                               "it); it does not count as an anchor")
        return
    point = data.get("checkpoint")
    if action == "external-head":   # a note that a head was exported; the copy itself is checked with --heads
        _check_point(point, records, keys, f"external-head note seq {seq}", report)
        return
    if action != "rfc3161":
        report.problems.append(f"seq {seq}: trail.anchor with unknown action {action!r}")
        return
    report.anchors += 1
    matched = _check_point(point, records, keys, "anchor checkpoint", report)
    stamp = data.get("tsa")
    try:
        token = base64.b64decode(stamp["token_b64"], validate=True)
        digest = bytes.fromhex(point["head"].split(":", 1)[1])
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        report.problems.append(f"anchor seq {seq}: token unreadable")
        return
    check = tsa.verify_token(token, digest, ca_certs=tsa_ca)
    if check.problems:
        report.problems.append(f"anchor seq {seq}: {'; '.join(check.problems)}")
    elif check.chain_checked:
        report.anchors_verified += 1
        if matched:
            _cover(report, point["seq"])
    else:
        report.warnings.append(f"anchor seq {seq}: TSA certificate chain not checked (no --tsa-ca)")


def signature_status(record: dict, *, signers: dict[str, SignerInfo] | None = None,
                     keys: dict | None = None) -> tuple[str, str]:
    """``(status, detail)`` of the detached statement in ``record['data']['signature']``.

    ``signers`` is the full registry (``load_registry()``); without one, ``keys`` (``{key_id: public key}``) can only
    show that some trusted key signed. Status: ``valid``; ``invalid`` (malformed, altered, not bound to the record's
    type or meaning, or signed with a key that belongs to someone else); ``revoked`` (signed before the key was
    enrolled or at/after its revocation); ``unknown-key`` (key not in the registry); ``unbound`` (verifies, but the
    key's owner is unknown); ``unsigned`` (no statement)."""
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    block = data.get("signature")
    if not isinstance(block, dict) or not isinstance(block.get("statement"), dict):
        return "unsigned", "no detached signature in data.signature"
    statement = block["statement"]
    signer = statement.get("signer") if isinstance(statement.get("signer"), dict) else {}
    problems = []
    if statement.get("aqt_signature") != STATEMENT_VERSION:
        problems.append("unsupported statement version")
    if block.get("alg") != "ed25519":
        problems.append("alg must be ed25519")
    if not isinstance(block.get("key"), str) or statement.get("key") != block.get("key"):
        problems.append("statement key differs from the signing key")
    if statement.get("record_type") != record.get("type"):
        problems.append(f"statement is for record type {statement.get('record_type')!r}, not {record.get('type')!r}")
    if "meaning" in record and record["meaning"] != statement.get("meaning"):
        problems.append("record meaning differs from the signed meaning")
    if not isinstance(signer.get("id"), str) or not signer["id"]:
        problems.append("statement names no signer")
    signed_at = parse_time(statement.get("signed_at"))
    if signed_at is None:
        problems.append("signed_at is not a time")
    if problems:
        return "invalid", "; ".join(problems)
    key_id = block["key"]
    if not signers:
        valid = verify_statement(block, keys or {})
        if valid is None:
            return "unknown-key", f"key {key_id} is not in the signer registry"
        if not valid:
            return "invalid", "signature does not verify (statement altered or wrong key)"
        return "unbound", "valid, but the key's owner was not checked (no signer registry)"
    owners = key_owners(signers, key_id)
    if not owners:
        return "unknown-key", f"key {key_id} is not in the signer registry"
    entry = next((key for owner, key in owners if owner.id == signer["id"]), None)
    if entry is None:
        return "invalid", f"key {key_id} belongs to {owners[0][0].id}, but the statement names {signer['id']}"
    if entry.public is None or not verify_statement(block, {key_id: entry.public}):
        return "invalid", "signature does not verify (statement altered or wrong key)"
    enrolled, revoked = parse_time(entry.enrolled_at), parse_time(entry.revoked_at)
    if enrolled is not None and signed_at < enrolled:
        return "revoked", f"signed before key {key_id} was enrolled ({entry.enrolled_at})"
    if entry.revoked_at and (revoked is None or signed_at >= revoked):
        return "revoked", f"key {key_id} was revoked at {entry.revoked_at}"
    stored = parse_time(record.get("time"))
    if revoked is not None and stored is not None and stored >= revoked:
        return "valid", f"signed before key {key_id} was revoked ({entry.revoked_at}) but stored after it"
    return "valid", ""


def _review_problems(record: dict, seq: int, data: dict, records: list[dict]) -> list[str]:
    """What is wrong with a ``trail.review`` apart from the key: binding to its content, reviewer and scope."""
    statement = data["signature"]["statement"]
    signer = statement.get("signer") if isinstance(statement.get("signer"), dict) else {}
    who = record.get("actor") if isinstance(record.get("actor"), dict) else {}
    subject = statement.get("subject") if isinstance(statement.get("subject"), dict) else {}
    problems = []
    if statement.get("meaning") != "reviewed" or record.get("meaning") != "reviewed":
        problems.append("meaning is not 'reviewed'")
    if who.get("kind") != "human" or who.get("id") != signer.get("id"):
        problems.append(f"the record's actor {who.get('id')!r} is not the signer {signer.get('id')!r}")
    body = {key: value for key, value in data.items() if key != "signature"}
    if subject.get("kind") != "trail-review" or subject.get("sha256") != content_hash(body) \
            or record.get("subject") != subject:
        problems.append("review content differs from what was signed")
    scope = data.get("scope") if isinstance(data.get("scope"), dict) else {}
    start, end = scope.get("from_seq"), scope.get("to_seq")
    if type(start) is not int or type(end) is not int or not 0 <= start <= end < seq:
        problems.append("its scope is not a seq range before the review")
        return problems
    if record_hash(records[end]) != data.get("head") or data.get("head") != scope.get("head"):
        problems.append(f"its head does not match the record at seq {end}")
    since, until = scope.get("since"), scope.get("until")
    if (since is not None and not isinstance(since, str)) or (until is not None and not isinstance(until, str)):
        problems.append("its period is malformed")
        return problems
    actors = scope_actors([r for r in records[start:end + 1] if in_period(r, since, until)])
    if data.get("actors_reviewed") != actors:
        problems.append("its actors in scope differ from the trail")
    if signer.get("id") in actors:
        problems.append(f"the reviewer {signer.get('id')} acted in the reviewed scope (not independent)")
    return problems


def verify_trail(path: str | os.PathLike, *, keys: dict, checkpoints: str | os.PathLike | None = None,
                 heads: str | os.PathLike | None = None, tsa_ca: list | None = None,
                 signer_keys: dict | None = None, log_id: str | None = None, pinned: bool = False,
                 signers: dict[str, SignerInfo] | None = None) -> TrailReport:
    """``signers`` is the signer registry to check detached signatures against; ``registry_keys(...)`` passed as
    ``signer_keys`` carries it too. A plain ``{key_id: key}`` dict only shows that a trusted key signed."""
    report = TrailReport(ok=False, log_id=log_id)
    if not keys:
        report.problems.append("no service public key to verify with")
        return report
    if signers is None:
        signers = getattr(signer_keys, "signers", None)
    records, bad_line = load_lines(path)
    for index, record in enumerate(records):   # shapes that would stop the chain check itself
        if "sig" in record and not isinstance(record["sig"], list) or \
                any(not isinstance(s, dict) for s in record.get("sig") or []):
            records, bad_line = records[:index], (index + 1, "sig is not a list of signature objects")
            break
    try:
        result = verify_chain(records, keys=keys, require_signature=True)
    except (TypeError, AttributeError, ValueError, KeyError) as error:
        report.first_bad_seq, report.reason = 0, f"a record could not be checked ({type(error).__name__}: {error})"
        return report
    report.count, report.head_seq, report.head = result.count, result.head_seq, result.head_hash
    report.warnings.extend(result.warnings)
    if not result.ok:
        report.first_bad_seq, report.reason = result.first_bad_seq, result.reason
        return report
    if bad_line:
        report.first_bad_seq, report.reason = len(records), f"line {bad_line[0]}: {bad_line[1]}"
        return report
    if not pinned:
        report.warnings.append("service key not pinned (--pin-key): a full rewrite under a new key is only "
                               "detected by external heads or anchors")
    if checkpoints and Path(checkpoints).exists():
        for point in _load_points(checkpoints, "checkpoints", report):
            report.checkpoints += 1
            _check_point(point, records, keys, "checkpoint", report)
    if heads:
        for point in _load_points(heads, "heads", report):
            report.heads += 1
            if _check_point(point, records, keys, "external head", report):
                _cover(report, point["seq"])
    unknown, unbound, unchecked_reviews = 0, 0, 0
    for record in records:
        seq = record["chain"]["seq"]
        data = record.get("data") if isinstance(record.get("data"), dict) else {}
        try:
            if record.get("type") == "trail.anchor":
                _check_anchor(record, seq, data, records, keys, tsa_ca, report)
            is_review = record.get("type") == "trail.review"
            if not is_review and not (isinstance(data.get("signature"), dict)
                                      and isinstance(data["signature"].get("statement"), dict)):
                continue
            status, detail = signature_status(record, signers=signers, keys=signer_keys)
            if status != "unsigned":
                report.signatures += 1
            if is_review:
                report.reviews += 1
                if status == "unsigned":
                    report._signature_problem(f"seq {seq}: trail.review is not signed (no data.signature)")
                    continue
                if status != "invalid":
                    for problem in _review_problems(record, seq, data, records):
                        report._signature_problem(f"seq {seq}: review signature: {problem}")
            if status in ("invalid", "revoked"):
                report._signature_problem(f"seq {seq}: detached signature in data.signature is invalid: {detail}")
            elif status == "unknown-key":
                if is_review and signers:
                    report._signature_problem(f"seq {seq}: review signature: {detail}")
                elif is_review:
                    unchecked_reviews += 1
                else:
                    unknown += 1
            elif status == "unbound":
                unbound += 1
            elif detail:
                report.warnings.append(f"seq {seq}: {detail}")
        except (TypeError, AttributeError, KeyError, ValueError, IndexError) as error:
            report._signature_problem(f"seq {seq}: malformed {record.get('type')} payload "
                                      f"({type(error).__name__})")
    if unknown:
        report.warnings.append(f"{unknown} detached signature(s) by keys not in the signer registry")
    if unchecked_reviews:
        report.warnings.append(f"{unchecked_reviews} review signature(s) not checked: no signer registry, so the "
                               "reviewer's identity is unverified")
    if unbound:
        report.warnings.append(f"{unbound} detached signature(s) verify, but key ownership was not checked "
                               "(no signer registry)")
    if report.head_seq is not None:
        if report.covered_seq is None:
            report.warnings.append("no external head (--heads) or CA-verified RFC 3161 anchor covers this trail: in "
                                   "user mode an agent that reads the service key could rewrite and re-sign it "
                                   "unnoticed")
        elif report.covered_seq < report.head_seq:
            report.warnings.append(f"records seq {report.covered_seq + 1}–{report.head_seq} are not covered by an "
                                   "external head or a CA-verified anchor (in user mode they could be rewritten "
                                   "and re-signed unnoticed)")
    report.ok = not report.problems
    return report
