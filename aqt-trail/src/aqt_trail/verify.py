"""Verify a trail: chain, service signatures, checkpoints, anchors, external heads
and detached signatures in ``data.signature`` (INTERFACES I1)."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from aqt_evidence import checkpoint_matches, content_hash, verify_chain, verify_checkpoint
from aqt_evidence import verify_statement

from . import tsa
from .anchors import load_heads


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

    def summary(self) -> str:
        if self.first_bad_seq is not None:
            return f"broken from seq {self.first_bad_seq}: {self.reason}"
        if not self.ok:
            return f"chain intact ({self.count} records) but: {self.problems[0]}"
        return f"intact: {self.count} records, head seq {self.head_seq} {self.head}"

    def as_dict(self) -> dict:
        return asdict(self)


def load_lines(path: str | os.PathLike) -> tuple[list[dict], tuple[int, str] | None]:
    """Records of a trail file and, if a line is unreadable, (line number, reason)."""
    records = []
    with open(path, "rb") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                return records, (number, "empty line")
            if not line.endswith(b"\n"):
                return records, (number, "incomplete last line")
            try:
                record = json.loads(line)
            except ValueError:
                return records, (number, "line is not valid JSON")
            records.append(record)
    return records, None


def _check_point(point: dict, records: list[dict], keys: dict, label: str, report: TrailReport) -> None:
    if not verify_checkpoint(point, keys):
        report.problems.append(f"{label} at seq {point.get('seq')}: signature invalid or key unknown")
        return
    if report.log_id and point.get("log") != report.log_id:
        report.problems.append(f"{label} at seq {point.get('seq')} belongs to another log ({point.get('log')})")
        return
    if report.head_seq is None or point.get("seq", -1) > report.head_seq:
        report.problems.append(f"{label} at seq {point.get('seq')} is beyond the head: the trail was truncated")
    elif not checkpoint_matches(point, records):
        report.problems.append(f"{label} at seq {point.get('seq')} does not match the record: the trail was rewritten")


def verify_trail(path: str | os.PathLike, *, keys: dict, checkpoints: str | os.PathLike | None = None,
                 heads: str | os.PathLike | None = None, tsa_ca: list | None = None,
                 signer_keys: dict | None = None, log_id: str | None = None, pinned: bool = False) -> TrailReport:
    report = TrailReport(ok=False, log_id=log_id)
    if not keys:
        report.problems.append("no service public key to verify with")
        return report
    records, bad_line = load_lines(path)
    result = verify_chain(records, keys=keys, require_signature=True)
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
        for point in load_heads(checkpoints):
            report.checkpoints += 1
            _check_point(point, records, keys, "checkpoint", report)
    if heads:
        for point in load_heads(heads):
            report.heads += 1
            _check_point(point, records, keys, "external head", report)
    unknown_signers = 0
    for record in records:
        data = record.get("data") if isinstance(record.get("data"), dict) else {}
        if record.get("type") == "trail.anchor" and record.get("action") == "rfc3161":
            report.anchors += 1
            point = data.get("checkpoint", {})
            _check_point(point, records, keys, "anchor checkpoint", report)
            try:
                token = base64.b64decode(data["tsa"]["token_b64"])
                digest = bytes.fromhex(point["head"].split(":", 1)[1])
            except (KeyError, ValueError, TypeError):
                report.problems.append(f"anchor seq {record['chain']['seq']}: token unreadable")
                continue
            check = tsa.verify_token(token, digest, ca_certs=tsa_ca)
            if check.problems:
                report.problems.append(f"anchor seq {record['chain']['seq']}: {'; '.join(check.problems)}")
            elif check.chain_checked:
                report.anchors_verified += 1
            else:
                report.warnings.append(f"anchor seq {record['chain']['seq']}: TSA certificate chain not checked "
                                       "(no --tsa-ca)")
        signature = data.get("signature")
        if isinstance(signature, dict) and isinstance(signature.get("statement"), dict):
            report.signatures += 1
            if record.get("type") == "trail.review":
                body = {key: value for key, value in data.items() if key != "signature"}
                if signature["statement"].get("subject", {}).get("sha256") != content_hash(body):
                    report.problems.append(f"seq {record['chain']['seq']}: review content differs from what was signed")
            statement_key = signature["statement"].get("key")
            valid = verify_statement(signature, signer_keys or {})
            if valid is None:
                unknown_signers += 1
            elif not valid or statement_key not in (None, signature.get("key")):
                report.problems.append(f"seq {record['chain']['seq']}: detached signature in data.signature is invalid")
    if unknown_signers:
        report.warnings.append(f"{unknown_signers} detached signature(s) by keys not in the signer registry")
    report.ok = not report.problems
    return report
