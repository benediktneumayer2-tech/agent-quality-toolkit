"""The body store for ``store = full``: content-addressed, compressed, masked, pruned by age.

Objects are ``bodies/<2 hex>/<64 hex>.gz`` (gzip of the stored bytes; the name is the SHA-256 of
the uncompressed stored bytes). A record references an object by that hash, so a changed or
deleted object is detected (``read`` checks the hash). Text bodies are decoded (Content-Encoding)
and masked before they are stored; binary bodies are stored as they passed. Storing an object
that exists already renews its time, so retention counts from the last use.

Bodies are written to a temporary file while they stream through the proxy and moved into the
store when the exchange is complete: nothing is held back from the agent.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from .mask import mask_text, masked_headers
from .settings import private_dir


class StoreError(RuntimeError):
    pass


def _text_like(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    sample = text[:4096]
    odd = sum(1 for ch in sample if ord(ch) < 32 and ch not in "\t\r\n")
    return None if sample and odd * 20 > len(sample) else text


def decode_body(data: bytes, encoding: str | None) -> tuple[bytes, bool]:
    """(decoded bytes, whether a Content-Encoding was removed)."""
    if not encoding or encoding.lower() in ("identity", ""):
        return data, False
    try:
        from mitmproxy.net.encoding import decode
        return decode(data, encoding.lower()), True
    except Exception:  # noqa: BLE001 - unknown or broken encoding: keep the bytes as they passed
        return data, False


class BodyStore:
    def __init__(self, root: Path):
        self.root = root

    def ensure(self) -> "BodyStore":
        private_dir(self.root)
        private_dir(self.root / "tmp")
        return self

    def spool(self):
        """A temporary 0600 file for a body in flight (caller closes and removes it)."""
        fd, name = tempfile.mkstemp(dir=self.root / "tmp", prefix="body-")
        return os.fdopen(fd, "w+b"), Path(name)

    def path(self, digest: str) -> Path:
        hexdigest = digest.removeprefix("sha256:")
        return self.root / hexdigest[:2] / f"{hexdigest}.gz"

    def put(self, data: bytes) -> dict:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        target = self.path(digest)
        if target.exists():
            os.utime(target)
        else:
            private_dir(target.parent)
            fd, name = tempfile.mkstemp(dir=target.parent, prefix=".new-")
            with os.fdopen(fd, "wb") as handle:
                handle.write(gzip.compress(data, compresslevel=6, mtime=0))
            os.replace(name, target)
        return {"sha256": digest, "bytes": len(data)}

    def read(self, digest: str) -> bytes:
        try:
            data = gzip.decompress(self.path(digest).read_bytes())
        except FileNotFoundError:
            raise StoreError(f"{digest} is not in the body store (pruned or deleted)") from None
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            raise StoreError(f"{digest}: the stored object was changed")
        return data

    def put_body(self, raw: bytes, encoding: str | None) -> dict:
        data, decoded = decode_body(raw, encoding)
        text = _text_like(data)
        if text is not None:
            data = mask_text(text).encode("utf-8")
        ref = self.put(data)
        ref.update(decoded=decoded, masked=text is not None)
        if encoding:
            ref["encoding"] = encoding
        return ref

    def put_headers(self, request_fields, response_fields) -> dict:
        document = {"request": masked_headers(request_fields), "response": masked_headers(response_fields or [])}
        return self.put(json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def objects(self):
        for folder in self.root.iterdir() if self.root.exists() else ():
            if folder.is_dir() and len(folder.name) == 2:
                yield from folder.glob("*.gz")

    def prune(self, retention_days: int | None, *, now: float | None = None, dry_run: bool = False) -> dict:
        """Delete objects not used for ``retention_days`` (None: keep forever) and stale temporary files."""
        now = time.time() if now is None else now
        removed = size = kept = 0
        cutoff = None if retention_days is None else now - retention_days * 86400
        for path in list(self.objects()):
            info = path.stat()
            if cutoff is not None and info.st_mtime < cutoff:
                removed += 1
                size += info.st_size
                if not dry_run:
                    path.unlink()
            else:
                kept += 1
        for path in (self.root / "tmp").glob("body-*") if (self.root / "tmp").exists() else ():
            if path.stat().st_mtime < now - 86400 and not dry_run:   # left behind by a crash
                path.unlink()
        return {"removed": removed, "bytes": size, "kept": kept, "cutoff": cutoff}
