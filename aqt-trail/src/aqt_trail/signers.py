"""Reviewer identities: the shared signer registry and detached statements.

Reads ``$XDG_CONFIG_HOME/aqt/signers.json`` (aqt-spec spec §12.2, owned by
aqt-signoff) without importing aqt-signoff. ``AQT_SIGNERS`` and ``AQT_KEYS_DIR``
override the registry and the key directory, as in aqt-signoff and
aqt-quarantine. Statements follow the shape of
aqt-spec ``schemas/signature.schema.json`` (spec §6.3): ``{"aqt_signature": "0.1",
"signer", "key", "meaning", "reason", "signed_at", "tz", "record_type", "nonce",
"subject"}``, signed over ``canonical_json(statement)``.

``signers.json`` is plain configuration any process of the user can edit. A key therefore
counts only when its ``signoff.key.enrolled`` record in the trail backs it, judged by
aqt-signoff's own rules (``check_enrolment``; aqt-trail does not depend on aqt-signoff and
uses them when it is installed). Without aqt-signoff the keys are marked unchecked and
``verify`` warns that they rest on the file alone.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aqt_evidence import key_id as key_id_of
from aqt_evidence import sign_statement

__all__ = ["KeyInfo", "RegistryKeys", "SignerInfo", "SignerRegistry", "build_statement", "check_enrolment",
           "key_owners", "load_registry", "parse_time", "registry_keys", "sign_statement"]

from .config import config_dir

STATEMENT_VERSION = "0.1"


def registry_path() -> Path:
    override = os.environ.get("AQT_SIGNERS")
    return Path(override).expanduser() if override else config_dir() / "signers.json"


def keys_dir() -> Path:
    override = os.environ.get("AQT_KEYS_DIR")
    return Path(override).expanduser() if override else config_dir() / "keys"


def key_file(signer_id: str) -> Path:
    slug = re.sub(r"[^a-z0-9._-]", "_", signer_id.replace(":", "-"))
    return keys_dir() / f"{slug}.key"


def parse_time(value) -> datetime | None:
    """An RFC 3339 time (``Z`` or offset) as an aware datetime, or None."""
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else None


@dataclass
class KeyInfo:
    """One registered key with its enrolment and (optional) revocation time.

    ``backed``: None while the key was not checked against enrolment records, else whether its
    ``signoff.key.enrolled`` record backs it (``check_enrolment``; then the times come from the
    evidence). ``evidence``: why it does not count, notes on its enrolment, or why it was not checked."""
    key_id: str
    public: Ed25519PublicKey | None
    enrolled_at: str | None = None
    revoked_at: str | None = None
    backed: bool | None = None
    evidence: str = ""


@dataclass
class SignerInfo:
    id: str
    name: str
    role: str
    active_keys: dict[str, Ed25519PublicKey]
    revoked_keys: set[str]
    keys: dict[str, KeyInfo] = field(default_factory=dict)   # every key, revoked ones included


class RegistryKeys(dict):
    """``{key_id: public key}`` of the active keys (as before), plus ``signers``: the full registry, so a
    verifier can check that a key belongs to the signer a statement names and was valid when it signed."""

    def __init__(self, keys=(), signers: dict[str, SignerInfo] | None = None):
        super().__init__(keys)
        self.signers = signers or {}


class SignerRegistry(dict):
    """``{signer id: SignerInfo}`` read from ``path``. ``enrolment`` is None until ``check_enrolment`` ran,
    then ``"checked"`` or why the keys could not be checked (they are left unchecked: ``backed`` None)."""

    def __init__(self, signers=(), *, path: Path | None = None, enrolment: str | None = None):
        super().__init__(signers)
        self.path, self.enrolment = path, enrolment


def load_registry(path: str | os.PathLike | None = None, *, records: list[dict] | None = None) -> SignerRegistry:
    """The registry file; with ``records`` (the trail) its keys are checked against their enrolment records."""
    path = Path(path) if path else registry_path()
    if not path.exists():
        return SignerRegistry(path=path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError(f"{path}: unsupported registry version {data.get('version') if isinstance(data, dict) else None!r}")
    signers = {}
    for item in data.get("signers", []):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError(f"{path}: a signer entry needs an id")
        active, revoked, every = {}, set(), {}
        for key in item.get("keys", []):
            if not isinstance(key, dict) or not isinstance(key.get("key_id"), str):
                continue
            try:
                public = serialization.load_pem_public_key(str(key.get("public_pem", "")).encode("ascii"))
            except (ValueError, TypeError, UnicodeEncodeError):
                public = None
            if not isinstance(public, Ed25519PublicKey) or key_id_of(public) != key["key_id"]:
                public = None             # not an Ed25519 key, or the key id belongs to another key
            every[key["key_id"]] = KeyInfo(key["key_id"], public, key.get("enrolled_at"), key.get("revoked_at"))
            if key.get("revoked_at"):
                revoked.add(key["key_id"])
            elif public is not None:
                active[key["key_id"]] = public
        signers[item["id"]] = SignerInfo(item["id"], item.get("name", ""), item.get("role", ""), active, revoked,
                                         every)
    loaded = SignerRegistry(signers, path=path)
    return check_enrolment(loaded, records) if records is not None else loaded


def _signoff_registry():
    """aqt-signoff's ``Registry`` (its enrolment rules), or None when aqt-signoff is not installed. The one
    place that names aqt-signoff: when the reconciliation moves to aqt-spec, only this import changes."""
    try:
        from aqt_signoff.registry import Registry
    except ImportError:
        return None
    return Registry


def check_enrolment(signers: dict[str, SignerInfo], records: list[dict]) -> SignerRegistry:
    """A copy of ``signers`` whose keys are checked against the ``signoff.key.enrolled`` and
    ``signoff.key.revoked`` records in ``records`` (the trail), with aqt-signoff's rules
    (``Registry.reconcile``): a key counts (``backed``) only as aqt-signoff would count it, and its
    enrolment and revocation times are the evidence's. If the check cannot be made, no key counts; without
    aqt-signoff every key is left unchecked and ``enrolment`` says so."""
    path = getattr(signers, "path", None) or registry_path()
    result = SignerRegistry(path=path, enrolment="checked")
    reconciled, failure = None, ""
    registry_class = _signoff_registry()
    if registry_class is None:
        result.enrolment = failure = ("aqt-signoff is not installed, so registry keys were not checked against "
                                      "their enrolment records")
    elif signers:
        try:
            reconciled = registry_class(path, keys_dir())
            reconciled.reconcile(records, records, source="trail")
        except Exception as error:  # noqa: BLE001 - fail closed: no key counts
            reconciled, failure = None, f"the enrolment check failed ({type(error).__name__}: {error})"
    for signer in signers.values():
        every, active, revoked = {}, {}, set()
        for key in signer.keys.values():
            info = KeyInfo(key.key_id, key.public, key.enrolled_at, key.revoked_at)
            if registry_class is None:
                info.evidence = failure
            elif reconciled is None:
                info.backed, info.evidence = False, failure
            else:
                found = reconciled.key_evidence(key.key_id, signer.id)
                if found is None:
                    info.backed, info.evidence = False, "aqt-signoff does not see this key in the registry"
                else:
                    info.backed = bool(found.counts)
                    info.evidence = "; ".join(str(x) for x in (found.notes if found.counts else found.problems))
                    if found.counts:
                        info.enrolled_at, info.revoked_at = found.enrolled_at, found.revoked_at
            every[key.key_id] = info
            if info.revoked_at:
                revoked.add(key.key_id)
            elif info.public is not None and info.backed is not False:
                active[key.key_id] = info.public
        result[signer.id] = SignerInfo(signer.id, signer.name, signer.role, active, revoked, every)
    return result


def registry_keys(signers: dict[str, SignerInfo]) -> RegistryKeys:
    keys = {}
    for signer in signers.values():
        keys.update(signer.active_keys)
    return RegistryKeys(keys, signers)


def key_owners(signers: dict[str, SignerInfo], key_id: str) -> list[tuple[SignerInfo, KeyInfo]]:
    """Every registry entry that lists ``key_id`` (normally zero or one)."""
    return [(signer, signer.keys[key_id]) for signer in signers.values() if key_id in signer.keys]


def build_statement(*, record_type: str, signer: dict, key: str, meaning: str, reason: str, subject: dict,
                    signed_at: str, tz: str) -> dict:
    """A statement as in aqt-spec ``schemas/signature.schema.json``."""
    return {"aqt_signature": STATEMENT_VERSION, "signer": signer, "key": key, "meaning": meaning,
            "reason": reason, "signed_at": signed_at, "tz": tz, "record_type": record_type,
            "nonce": os.urandom(8).hex(), "subject": {k: subject[k] for k in ("kind", "ref", "sha256")}}
