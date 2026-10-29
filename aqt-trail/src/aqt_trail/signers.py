"""Reviewer identities: the shared signer registry and detached statements.

Reads ``$XDG_CONFIG_HOME/aqt/signers.json`` (aqt-spec spec §12.2, owned by
aqt-signoff) without importing aqt-signoff. ``AQT_SIGNERS`` and ``AQT_KEYS_DIR``
override the registry and the key directory, as in aqt-signoff and
aqt-quarantine. Statements follow the shape of
aqt-spec ``schemas/signature.schema.json`` (spec §6.3): ``{"aqt_signature": "0.1",
"signer", "key", "meaning", "reason", "signed_at", "tz", "record_type", "nonce",
"subject"}``, signed over ``canonical_json(statement)``.
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

from aqt_evidence import sign_statement

__all__ = ["KeyInfo", "RegistryKeys", "SignerInfo", "build_statement", "key_owners", "load_registry", "parse_time",
           "registry_keys", "sign_statement"]

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
    """One registered key with its enrolment and (optional) revocation time."""
    key_id: str
    public: Ed25519PublicKey | None
    enrolled_at: str | None = None
    revoked_at: str | None = None


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


def load_registry(path: str | os.PathLike | None = None) -> dict[str, SignerInfo]:
    path = Path(path) if path else registry_path()
    if not path.exists():
        return {}
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
            if not isinstance(public, Ed25519PublicKey):
                public = None
            every[key["key_id"]] = KeyInfo(key["key_id"], public, key.get("enrolled_at"), key.get("revoked_at"))
            if key.get("revoked_at"):
                revoked.add(key["key_id"])
            elif public is not None:
                active[key["key_id"]] = public
        signers[item["id"]] = SignerInfo(item["id"], item.get("name", ""), item.get("role", ""), active, revoked,
                                         every)
    return signers


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
