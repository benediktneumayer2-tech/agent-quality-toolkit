"""Reviewer identities: the shared signer registry and detached statements.

Reads ``$XDG_CONFIG_HOME/aqt/signers.json`` (INTERFACES I9, owned by
aqt-signoff) without importing aqt-signoff. Statements follow the shape of
aqt-spec ``schemas/signature.schema.json`` (INTERFACES I1): ``{"aqt_signature": "0.1",
"signer", "key", "meaning", "reason", "signed_at", "tz", "record_type", "nonce",
"subject"}``, signed over ``canonical_json(statement)``.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aqt_evidence import sign_statement

__all__ = ["build_statement", "load_registry", "registry_keys", "sign_statement"]

from .config import config_dir

STATEMENT_VERSION = "0.1"


def registry_path() -> Path:
    return config_dir() / "signers.json"


def key_file(signer_id: str) -> Path:
    slug = re.sub(r"[^a-z0-9._-]", "_", signer_id.replace(":", "-"))
    return config_dir() / "keys" / f"{slug}.key"


@dataclass
class SignerInfo:
    id: str
    name: str
    role: str
    active_keys: dict[str, Ed25519PublicKey]
    revoked_keys: set[str]


def load_registry(path: str | os.PathLike | None = None) -> dict[str, SignerInfo]:
    path = Path(path) if path else registry_path()
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise ValueError(f"{path}: unsupported registry version {data.get('version')!r}")
    signers = {}
    for item in data.get("signers", []):
        active, revoked = {}, set()
        for key in item.get("keys", []):
            if key.get("revoked_at"):
                revoked.add(key["key_id"])
                continue
            public = serialization.load_pem_public_key(key["public_pem"].encode("ascii"))
            if isinstance(public, Ed25519PublicKey):
                active[key["key_id"]] = public
        signers[item["id"]] = SignerInfo(item["id"], item.get("name", ""), item.get("role", ""), active, revoked)
    return signers


def registry_keys(signers: dict[str, SignerInfo]) -> dict[str, Ed25519PublicKey]:
    keys = {}
    for signer in signers.values():
        keys.update(signer.active_keys)
    return keys


def build_statement(*, record_type: str, signer: dict, key: str, meaning: str, reason: str, subject: dict,
                    signed_at: str, tz: str) -> dict:
    """A statement as in aqt-spec ``schemas/signature.schema.json``."""
    return {"aqt_signature": STATEMENT_VERSION, "signer": signer, "key": key, "meaning": meaning,
            "reason": reason, "signed_at": signed_at, "tz": tz, "record_type": record_type,
            "nonce": os.urandom(8).hex(), "subject": {k: subject[k] for k in ("kind", "ref", "sha256")}}
