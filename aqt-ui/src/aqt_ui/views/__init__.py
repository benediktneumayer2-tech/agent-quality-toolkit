"""View adapters: thin wrappers around the package APIs, one module per view.

Each adapter imports its package lazily, so a missing package only disables its view.
"""

from __future__ import annotations

import importlib.util


class ViewProblem(Exception):
    status = 400


class UsageProblem(ViewProblem):
    status = 400


class NotFound(ViewProblem):
    status = 404


class Stale(ViewProblem):
    """The decision does not match the current state shown to the person (nothing was signed)."""
    status = 409


class NotInstalled(ViewProblem):
    status = 501

    def __init__(self, package: str):
        super().__init__(f"{package} is not installed: uv pip install -e {package}  (or pip install {package})")
        self.package = package


# Refusal codes of aqt-signoff and of the aqt-trail review in words; the code stays visible next to them.
REFUSALS = {
    "agent_context": "The request came from an agent session; only a person may decide",
    "no_tty": "No person at a terminal confirmed the decision",
    "auth_failed": "The passphrase did not unlock the key",
    "self_approval": "Whoever prepared or wrote this may not decide on it",
    "role_not_allowed": "The signer's role may not make this decision",
    "registry_mismatch": "The signer's registry entry does not match its enrolment record, so the key does not "
                         "count; check it with aqt-signoff signers check",
    "payload_required": "The action binds a payload; it runs only when that exact payload is presented",
    "payload_mismatch": "The payload presented differs from the approved payload",
    "not_approved": "The action has no valid approval for this exact version",
    "action_altered": "The stored action no longer matches its approved hash",
    "claim_in_progress": "The action is still running or within its grace period",
    "not_human": "Only a human identity can sign this",
    "not_independent": "The reviewer acted in the reviewed period and may not review it",
    "worksheet_changed": "The worksheet differs from the one shown",
    "worksheet_mismatch": "The worksheet differs from what the trail gives",
    "stale_worksheet": "The trail at the end of the worksheet's scope changed",
    "trail_broken": "The trail does not verify up to the reviewed records",
    "unknown_signer": "The reviewer is not in the signer registry",
    "key_mismatch": "The key is registered to someone else",
    "revoked_key": "The key is revoked",
    "unknown_key": "The key is not registered for this signer",
}


def refusal_text(code) -> str | None:
    """The words for a refusal code, or None for a code without words."""
    return REFUSALS.get(code) if isinstance(code, str) else None


def installed(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def require(module: str, package: str) -> None:
    if not installed(module):
        raise NotInstalled(package)


def fingerprint(*paths) -> tuple:
    """Size and modification time of each path (missing ones count as absent). Cached derived
    values are kept while this stays equal and rebuilt when a file grows or is replaced."""
    import os
    out = []
    for path in paths:
        try:
            info = os.stat(path)
            out.append((str(path), info.st_ino, info.st_size, info.st_mtime_ns))
        except OSError:
            out.append((str(path), None))
    return tuple(out)


def evidence_fingerprint() -> tuple:
    from aqt_evidence import evidence_sources
    return fingerprint(*evidence_sources())
