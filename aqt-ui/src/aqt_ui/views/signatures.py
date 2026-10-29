"""Signatures view (aqt-signoff): verify a file, record or hash without recording anything,
and show the signer registry. Also opens a ``Signoff`` whose human check is the UI guard.

File verification reads only regular files, at most ``MAX_FILE_BYTES``, and hashes them in
pieces; larger files are verified with ``aqt-signoff verify`` in a terminal."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Callable

from aqt_evidence import HumanCheckError

from . import NotFound, UsageProblem, require

MAX_FILE_BYTES = 64 * 1024 * 1024


def bounded_file_hash(path: Path) -> str:
    """``sha256:<hex>`` of a regular file of at most ``MAX_FILE_BYTES`` (refused otherwise)."""
    limit = MAX_FILE_BYTES
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except FileNotFoundError:
        raise NotFound(f"{path} does not exist") from None
    except OSError as error:
        raise UsageProblem(f"{path} cannot be read: {error.strerror}") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise UsageProblem(f"{path} is not a regular file")
        if info.st_size > limit:
            raise UsageProblem(f"{path} is larger than {limit // (1024 * 1024)} MiB; verify it with aqt-signoff "
                               "verify in a terminal")
        digest, total = hashlib.sha256(), 0
        while chunk := handle.read(1 << 20):
            total += len(chunk)
            if total > limit:          # grew while being read, or a file that reports no size
                raise UsageProblem(f"{path} is larger than {limit // (1024 * 1024)} MiB; verify it with "
                                   "aqt-signoff verify in a terminal")
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def open_signoff(*, passphrase: str | None = None, human_check: Callable | None = None):
    """A ``Signoff`` for the UI: the passphrase (if any) as a one-shot ``StaticPassphrase``, the
    terminal check replaced by the per-request guard. Refusals are recorded by aqt-signoff itself."""
    require("aqt_signoff", "aqt-signoff")
    from aqt_signoff import Signoff, StaticPassphrase

    class GuardedSignoff(Signoff):
        def file_subject(self, path) -> dict:
            from aqt_evidence import subject as make_subject
            from aqt_signoff.core import file_ref
            return make_subject("file", file_ref(Path(path)), sha256=bounded_file_hash(Path(path)))

        def require_human(self, attempted: str, who: dict) -> None:
            if human_check is None:
                raise RuntimeError("a decision through a read-only Signoff")
            try:
                human_check()
            except HumanCheckError as error:
                code = "agent_context" if error.context.is_agent else "no_tty"
                raise self.refuse(attempted, who, code, str(error), error.context.markers) from None

    return GuardedSignoff.open(authenticator=StaticPassphrase(passphrase or ""), require_tty=False)


def signer_rows(so) -> list[dict]:
    rows = []
    for signer in so.registry.signers:
        active = signer.active_key()
        rows.append({"id": signer.id, "name": signer.name, "role": signer.role,
                     "active_key": active.key_id if active else None,
                     "keys": [{"key_id": k.key_id, "enrolled_at": k.enrolled_at, "revoked_at": k.revoked_at}
                              for k in signer.keys]})
    return rows


class SignaturesView:
    def __init__(self):
        require("aqt_signoff", "aqt-signoff")

    def registry(self) -> dict:
        so = open_signoff()
        return {"signers": signer_rows(so), "path": str(so.settings.registry_path), "tz": so.settings.tz}

    def verify(self, *, file: str | None = None, record: str | None = None, sha256: str | None = None) -> dict:
        """Passive verification: never writes ``signoff.invalidation`` records."""
        from aqt_signoff import SignoffError
        from aqt_signoff.manifest import render, rows
        so = open_signoff()
        try:
            if file:
                path = Path(file).expanduser()
                if not path.is_absolute():
                    raise UsageProblem("give an absolute file path")
                report = so.verify_file(path, record_invalidations=False)
            elif record:
                report = so.verify_record(record.strip(), record_invalidations=False)
            elif sha256:
                value = sha256.strip()
                if not value.startswith("sha256:"):
                    value = "sha256:" + value
                report = so.verify_hash(value)
            else:
                raise UsageProblem("give a file path, a record ID or a sha256 hash")
        except SignoffError as error:
            raise (NotFound if type(error).__name__ == "NotFound" else UsageProblem)(str(error)) from error
        return {"ok": report.ok, "summary": report.summary(), "subject": report.subject,
                "rows": rows(report), "policies": {m: p.as_dict() for m, p in report.policies.items()},
                "manifest_md": render(report, "md"), "manifest_html": render(report, "html")}
