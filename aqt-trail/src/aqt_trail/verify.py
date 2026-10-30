"""Verify a trail: chain, service signatures, checkpoints, anchors, external heads
and detached signatures in ``data.signature`` (aqt-spec spec §6.3).

What "intact" covers: every line is canonical JSON, the hash chain links and every
record is signed by a service key you gave. In user mode the service key is
readable by the same user, so a rewrite that re-chains and re-signs passes; only an
external head (``--heads``, kept out of the agent's reach) or an RFC 3161 anchor
verified to a CA you trust, made *after* the edit, detects it. ``covered_seq`` and a
warning say how far those reach. Truncation (records dropped from the end) is detected
only up to the newest checkpoint; ``checkpoint_seq`` and a warning give the records after it.

Detached signatures are bound to the registry (``signers``): the key must belong to
the signer the statement names, be backed by its ``signoff.key.enrolled`` record in this
trail (aqt-signoff's rules, when aqt-signoff is installed; otherwise a warning says the keys
rest on ``signers.json`` alone), be enrolled before and not revoked at ``signed_at``,
and the statement must name the record's type and meaning. A ``trail.review`` must be
signed that way by its reviewer, cover its own content, and name a scope whose head
and actors match the trail, with a reviewer who did not act in it. A review statement
counts once: a copy in a later record is a problem. TEST ONLY anchors count only when
their CA is trusted (``--test-tsa``); otherwise they are a warning, never a problem.

Malformed payloads are reported as problems; verification never stops on them.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from aqt_evidence import (CanonicalError, checkpoint_problems, content_hash, parse_canonical_line, record_hash,
                          verify_chain, verify_checkpoint, verify_statement)

from . import tsa
from .review import _profile_entry, in_period, is_test_anchor, is_writer_record, scope_actors
from .signers import SignerInfo, check_enrolment, key_owners, parse_time

STATEMENT_VERSION = "0.1"
UNCHECKED = "the key rests on signers.json alone: it was not checked against its enrolment record"


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
    checkpoint_seq: int | None = None       # newest matching checkpoint outside the file (truncation shows up to here)
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
                record = parse_canonical_line(line)
            except CanonicalError as error:
                text = str(error)
                if text.startswith("not valid JSON"):
                    return records, (number, "line is not valid JSON")
                if "canonical form" in text:
                    return records, (number, "line is not in canonical form (re-serialised or edited)")
                return records, (number, f"line is not AQT JSON ({text})")
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


def _check_point(point, records: list[dict], keys: dict, label: str, report: TrailReport) -> bool:
    """True when ``point`` is signed by a service key, names this log and matches the record at its seq."""
    shape = checkpoint_problems(point)
    if shape:
        report.problems.append(f"{label}: malformed checkpoint ({'; '.join(shape)})")
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
    if record_hash(records[point["seq"]]) != point["head"]:
        report.problems.append(f"{label} at seq {point['seq']} does not match the record: the trail was rewritten")
        return False
    return True


def _cover(report: TrailReport, seq: int) -> None:
    report.covered_seq = seq if report.covered_seq is None else max(report.covered_seq, seq)


def _outside(report: TrailReport, seq: int) -> None:
    """A checkpoint kept outside the trail file matched: dropping records up to ``seq`` would show."""
    report.checkpoint_seq = seq if report.checkpoint_seq is None else max(report.checkpoint_seq, seq)


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
    if is_test_anchor(record):     # any client may ask for one: it never breaks verify and counts only if trusted
        own = tsa.verify_token(token, digest)
        if own.problems:
            report.problems.append(f"anchor seq {seq}: {'; '.join(own.problems)}")
            return
        check = tsa.verify_token(token, digest, ca_certs=tsa_ca) if tsa_ca else None
        if check is None or check.problems or not check.chain_checked:
            report.warnings.append(f"anchor seq {seq}: from the built-in TEST ONLY authority; not counted "
                                   "(--test-tsa trusts it, for tests and demos)")
            return
    else:
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

    ``signers`` is the full registry, checked against the trail's enrolment records
    (``load_registry(records=...)`` or ``check_enrolment``); without one, ``keys`` (``{key_id: public key}``) can
    only show that some trusted key signed. Status: ``valid``; ``invalid`` (malformed, altered, not bound to the
    record's type or meaning, or signed with a key that belongs to someone else); ``revoked`` (signed before the key
    was enrolled or at/after its revocation); ``unknown-key`` (key not in the registry, or in it but not backed by
    its enrolment record); ``unbound`` (verifies, but the key's owner is unknown); ``unsigned`` (no statement).
    ``valid`` from a registry whose keys were not checked says so in ``detail`` (``UNCHECKED``)."""
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
    if own_key_statement(record):
        # A key's own enrolment request or revocation proves possession of the key; it is signed just
        # before the writer stores it (and a revocation at its revocation time), so the key's validity
        # period does not apply. Whether the key counts is the enrolment check's business.
        return "valid", ("" if entry.backed is not False else f"key {key_id} does not count: {entry.evidence}")
    if entry.backed is False:
        return "unknown-key", (f"key {key_id} of {signer['id']} is in signers.json but not backed by its enrolment "
                               f"record ({entry.evidence}); see 'aqt-signoff signers check'")
    enrolled, revoked = parse_time(entry.enrolled_at), parse_time(entry.revoked_at)
    if enrolled is not None and signed_at < enrolled:
        return "revoked", f"signed before key {key_id} was enrolled ({entry.enrolled_at})"
    if entry.revoked_at and (revoked is None or signed_at >= revoked):
        return "revoked", f"key {key_id} was revoked at {entry.revoked_at}"
    notes = []
    stored = parse_time(record.get("time"))
    if revoked is not None and stored is not None and stored >= revoked:
        notes.append(f"signed before key {key_id} was revoked ({entry.revoked_at}) but stored after it")
    if entry.backed is None:
        notes.append(f"{UNCHECKED} ({entry.evidence or 'the registry was not checked against the trail'})")
    elif entry.evidence:
        notes.append(f"key {key_id}: {entry.evidence}")
    return "valid", "; ".join(notes)


def own_key_statement(record: dict) -> bool:
    """A ``signoff.key.enrolled`` request or a ``signoff.key.revoked`` record signed by the key it is about."""
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    block = data.get("signature") if isinstance(data.get("signature"), dict) else {}
    return (record.get("type") in ("signoff.key.enrolled", "signoff.key.revoked") and "imported" not in data
            and isinstance(block.get("key"), str) and data.get("key_id") == block["key"])


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
    if "profile_params" in data:     # reviews since the parameters are signed: they must be the profile's
        params, queries = data.get("profile_params"), data.get("profile_queries")
        if not isinstance(params, dict) or not isinstance(queries, list) or \
                _profile_entry(str(data.get("profile")), queries, params)["sha256"] != data.get("profile_sha256"):
            problems.append("its profile parameters do not match its profile hash")
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
    selected = [r for r in records[start:end + 1] if in_period(r, since, until)]
    actors = scope_actors(selected)
    # reviews signed before a signer's own enrolment stopped counting as activity list those signers too
    if data.get("actors_reviewed") not in (actors, scope_actors(selected, legacy=True)):
        problems.append("its actors in scope differ from the trail")
    if signer.get("id") in actors:
        problems.append(f"the reviewer {signer.get('id')} acted in the reviewed scope (not independent)")
    return problems


def _statement_digest(data: dict) -> str | None:
    try:
        return content_hash(data["signature"]["statement"])
    except (KeyError, TypeError, ValueError):
        return None


def review_statuses(records: list[dict], *, signers: dict[str, SignerInfo] | None = None,
                    keys: dict | None = None) -> list[tuple[dict, str, str]]:
    """``(record, status, detail)`` for every ``trail.review`` in ``records``, which must be the whole trail (its
    enrolment records and the reviewed scopes are read from it). ``valid`` only when the signature is valid against
    ``signers`` (checked here against the trail's enrolment records), the review is bound to its content, its scope
    and an independent reviewer as ``verify`` checks, and its signed statement did not appear in an earlier
    record: a copy counts once and is ``invalid``. Only a ``valid`` review shows that a review was done."""
    if signers:
        signers = check_enrolment(signers, records)
    results, first = [], {}
    for record in records:
        if not isinstance(record, dict) or record.get("type") != "trail.review":
            continue
        try:
            data = record.get("data") if isinstance(record.get("data"), dict) else {}
            status, detail = signature_status(record, signers=signers, keys=keys)
            if status == "valid":
                problems = _review_problems(record, record["chain"]["seq"], data, records)
                if problems:
                    status, detail = "invalid", "; ".join(problems)
            digest = _statement_digest(data) if status != "unsigned" else None
            if digest in first:
                status, detail = "invalid", f"replayed copy of the review signed in record {first[digest]}; it counts once"
            elif digest:
                first[digest] = record.get("id")
        except (TypeError, AttributeError, KeyError, ValueError, IndexError) as error:
            status, detail = "invalid", f"malformed trail.review ({type(error).__name__})"
        results.append((record, status, detail))
    return results


def verify_trail(path: str | os.PathLike, *, keys: dict, checkpoints: str | os.PathLike | None = None,
                 heads: str | os.PathLike | None = None, tsa_ca: list | None = None,
                 signer_keys: dict | None = None, log_id: str | None = None, pinned: bool = False,
                 signers: dict[str, SignerInfo] | None = None) -> TrailReport:
    """``signers`` is the signer registry to check detached signatures against; ``registry_keys(...)`` passed as
    ``signer_keys`` carries it too. Its keys are checked against the enrolment records in this trail
    (``check_enrolment``). A plain ``{key_id: key}`` dict only shows that a trusted key signed."""
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
    if signers:
        signers = check_enrolment(signers, records)
    if checkpoints and Path(checkpoints).exists():
        for point in _load_points(checkpoints, "checkpoints", report):
            report.checkpoints += 1
            if _check_point(point, records, keys, "checkpoint", report):
                _outside(report, point["seq"])
    elif checkpoints and report.head_seq is not None:
        report.warnings.append(f"no checkpoints file ({checkpoints}): only external heads and anchors can show "
                               "that records were dropped from the end")
    if heads:
        for point in _load_points(heads, "heads", report):
            report.heads += 1
            if _check_point(point, records, keys, "external head", report):
                _cover(report, point["seq"])
                _outside(report, point["seq"])
    unknown, unbound, unchecked_reviews, unenrolled, unchecked_keys = 0, 0, 0, 0, 0
    reviewed: dict[str, int] = {}      # signed review statement -> seq of its first record
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
            if is_review and status != "unsigned":
                digest = _statement_digest(data)
                if digest in reviewed:
                    report._signature_problem(f"seq {seq}: trail.review repeats the review signed at seq "
                                              f"{reviewed[digest]} (same signed statement); it counts once")
                    continue
                if digest:
                    reviewed[digest] = seq
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
            in_registry = bool(signers) and bool(key_owners(signers, str(data["signature"].get("key"))))
            if status in ("invalid", "revoked"):
                report._signature_problem(f"seq {seq}: detached signature in data.signature is invalid: {detail}")
            elif status == "unknown-key":
                if is_review and signers:
                    report._signature_problem(f"seq {seq}: review signature: {detail}")
                elif is_review:
                    unchecked_reviews += 1
                elif in_registry:
                    unenrolled += 1
                else:
                    unknown += 1
            elif status == "unbound":
                unbound += 1
            elif detail:
                if UNCHECKED in detail:
                    unchecked_keys += 1
                    detail = detail.split(UNCHECKED)[0].rstrip("; ")
                if detail:
                    report.warnings.append(f"seq {seq}: {detail}")
        except (TypeError, AttributeError, KeyError, ValueError, IndexError) as error:
            text = f"seq {seq}: malformed {record.get('type')} payload ({type(error).__name__})"
            if record.get("type") == "trail.anchor":
                report.problems.append(text)
            else:
                report._signature_problem(text)
    if unknown:
        report.warnings.append(f"{unknown} detached signature(s) by keys not in the signer registry")
    if unenrolled:
        report.warnings.append(f"{unenrolled} detached signature(s) by registry keys not backed by their enrolment "
                               "records; they do not count (aqt-signoff signers check)")
    if unchecked_keys:
        report.warnings.append(f"{unchecked_keys} detached signature(s) rest on signers.json alone: "
                               f"{getattr(signers, 'enrolment', None) or 'registry keys were not checked'}")
    if unchecked_reviews:
        report.warnings.append(f"{unchecked_reviews} review signature(s) not checked: no signer registry, so the "
                               "reviewer's identity is unverified")
    if unbound:
        report.warnings.append(f"{unbound} detached signature(s) verify, but key ownership was not checked "
                               "(no signer registry)")
    if report.head_seq is not None:
        if report.checkpoint_seq is None:
            report.warnings.append("no checkpoint matches the trail: records dropped from the end would go unnoticed")
        elif report.checkpoint_seq < report.head_seq:
            report.warnings.append(f"{report.head_seq - report.checkpoint_seq} record(s) after the newest checkpoint "
                                   f"(seq {report.checkpoint_seq}): dropping them would go unnoticed")
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
