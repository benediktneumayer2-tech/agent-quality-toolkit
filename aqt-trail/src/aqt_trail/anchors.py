"""Checkpoints and anchors: evidence of the chain head outside the writer's reach."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from aqt_evidence import canonical_json, make_checkpoint, subject

from . import tsa
from .writer import TrailWriter


def current_checkpoint(writer: TrailWriter) -> dict:
    with writer.lock:
        if writer.seq < 0:
            raise ValueError("the trail is empty; nothing to checkpoint")
        return make_checkpoint(log_id=writer.log_id, seq=writer.seq, head=writer.head, signer=writer.signer)


def save_checkpoint(writer: TrailWriter, checkpoint: dict) -> None:
    path = writer.state / "checkpoints.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, writer.file_mode)
    try:
        os.write(fd, canonical_json(checkpoint) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)


def _head_subject(checkpoint: dict) -> dict:
    return subject("trail-head", f"{checkpoint['log']}:{checkpoint['seq']}", sha256=checkpoint["head"])


def checkpoint(writer: TrailWriter, *, tsa_url: str = "", timeout: float = 10, transport=None,
               test_dir: str | os.PathLike | None = None) -> tuple[dict, dict | None]:
    """Sign the head, store the checkpoint and, with a TSA URL, append an RFC 3161 ``trail.anchor``.

    The TSA is asked outside the writer lock, so appends continue meanwhile.
    """
    point = current_checkpoint(writer)
    save_checkpoint(writer, point)
    if not tsa_url:
        return point, None
    digest = bytes.fromhex(point["head"].split(":", 1)[1])
    token = tsa.request_timestamp(tsa_url, digest, timeout=timeout, transport=transport, test_dir=test_dir)
    check = tsa.verify_token(token, digest)
    data = {"checkpoint": point, "imprint": point["head"],
            "tsa": {"url": "test:" if tsa_url.startswith("test:") else tsa_url, "token_b64": tsa.b64(token),
                    "gen_time": check.gen_time, "serial": str(check.serial), "policy": check.policy,
                    "cert_sha256": check.cert_sha256}}
    anchor = writer.write_internal("trail.anchor", "rfc3161", data=data, subject=_head_subject(point),
                                   reason="RFC 3161 time stamp of the chain head")
    return point, anchor


def record_external_head(writer: TrailWriter, point: dict) -> dict:
    """Note in the trail that a head copy was exported (for the unanchored-head query)."""
    return writer.write_internal("trail.anchor", "external-head", data={"checkpoint": point, "imprint": point["head"]},
                                 subject=_head_subject(point), reason="signed head exported for storage elsewhere")


def token_bytes(anchor: dict) -> bytes:
    return base64.b64decode(anchor["data"]["tsa"]["token_b64"])


def load_heads(path: str | os.PathLike) -> list[dict]:
    """Checkpoints from a heads file: JSON lines or one JSON array."""
    import json

    text = Path(path).read_text()
    stripped = text.strip()
    if stripped.startswith("["):
        return json.loads(stripped)
    return [json.loads(line) for line in text.splitlines() if line.strip()]
