"""View adapters: thin wrappers around the package APIs, one module per view.

Each adapter imports its package lazily, so a missing package only disables its view.
"""

from __future__ import annotations

import importlib.util
import json
import shlex
import sys
from importlib import metadata
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname


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
        self.package = package
        self.install = install_command(package)
        super().__init__(f"{package} is not installed: {self.install}")


TOOLKIT = "agent-quality-toolkit"
VIEW_PACKAGES = ("aqt-quarantine", "aqt-signoff", "aqt-change", "aqt-capa", "aqt-validate")   # aqt-ui[all]


def _has(dist: str) -> bool:
    try:
        metadata.version(dist)
    except metadata.PackageNotFoundError:
        return False
    return True


def _clone() -> Path | None:
    """The repository clone aqt-ui is installed from (editable install), or None."""
    try:
        origin = json.loads(metadata.distribution("aqt-ui").read_text("direct_url.json") or "{}")
    except (metadata.PackageNotFoundError, ValueError):
        return None
    url = urlsplit(origin.get("url", ""))
    if not origin.get("dir_info", {}).get("editable") or url.scheme != "file":
        return None
    return Path(url2pathname(unquote(url.path))).parent      # Windows: /D:/a/b is D:\\a\\b


def install_command(package: str) -> str:
    """The command that adds ``package`` to the installation aqt-ui runs in, as aqt's own hints: the toolkit (or
    aqt-ui[all]) again for a uv tool or pipx, ``pip install`` elsewhere, the editable install in a clone."""
    prefix = Path(sys.prefix)
    toolkit = _has(TOOLKIT)
    spec = (f'"{TOOLKIT}[egress]"' if _has("aqt-egress") else TOOLKIT) if toolkit else '"aqt-ui[all]"'
    if (prefix / "uv-receipt.toml").is_file():
        return f"uv tool install {spec}" + ("" if toolkit or package in VIEW_PACKAGES else f" --with {package}")
    if (prefix / "pipx_metadata.json").is_file():
        return f"pipx install --force {spec}" if toolkit else f"pipx inject aqt-ui {package}"
    clone = _clone()
    if clone is not None:
        return f"uv pip install --python {shlex.quote(sys.executable)} -e {shlex.quote(str(clone / package))}"
    return f"pip install {package}"


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
    "unenrolled_key": "The key is in the signer registry but has no matching enrolment record in the trail, so it "
                      "does not count; check it with aqt-signoff signers check",
    "enrolment_pending": "The key waits for approval by an enrolled signer and does not count yet; that signer "
                         "approves it with aqt-signoff signers approve",
    "import_needed": "Enrolment records from before the trail must be imported into the trail once "
                     "(aqt-signoff signers import) before keys count",
    "no_enrolment": "The key has no enrolment record, so it does not count; check it with aqt-signoff signers check",
    "sink_not_trail": "The record would not reach the audit trail (the writer is not the sink), so nothing was done",
}


def refusal_text(code) -> str | None:
    """The words for a refusal code, or None for a code without words."""
    return REFUSALS.get(code) if isinstance(code, str) else None


def coded_fields(name: str, value) -> dict:
    """``{name}_code`` and ``{name}_args`` for a sentence that carries a message code (``aqt_evidence.Text``,
    or an exception whose message is one), else nothing: the page shows it in the chosen language from its
    catalogue (static/messages.js) and falls back to the English ``name`` field."""
    from aqt_evidence import coded
    found = coded(value)
    return {f"{name}_code": found["code"], f"{name}_args": found["args"]} if found else {}


def coded_list(values) -> list:
    """``{code, args}`` (or None) per sentence of a list, for a ``{name}_codes`` field beside it."""
    from aqt_evidence import coded
    return [coded(value) for value in values or []]


def message(error) -> str:
    """The message of ``error`` as it was raised: an ``aqt_evidence.Text`` keeps its code (``str()`` drops it)."""
    first = error.args[0] if error.args else None
    return first if isinstance(first, str) else str(error)


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
