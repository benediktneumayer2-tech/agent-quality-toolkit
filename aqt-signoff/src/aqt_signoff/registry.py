"""The signer registry (``signers.json``), key files and authenticators.

Registry format (version 1, shared with aqt-trail, aqt-quarantine and aqt-capa)::

    {"version": 1, "signers": [{"id": "human:alice", "name": "Alice Example", "role": "quality-manager",
      "keys": [{"key_id": "ed25519:…", "public_pem": "…", "enrolled_at": "…Z", "revoked_at": null}]}]}

Key files: ``<keys_dir>/<slug>.key`` (passphrase-encrypted PKCS#8 PEM, 0600) and
``<slug>.key.pub``. The slug is the signer id with ``:`` replaced by ``-``.
"""

from __future__ import annotations

import getpass
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aqt_evidence import Signer, key_id as key_id_of, load_signer

from .errors import AuthFailed, NotFound, UsageError

_ID = re.compile(r"^human:[a-z0-9][a-z0-9._-]{0,63}$")


def slug(signer_id: str) -> str:
    return re.sub(r"[^a-z0-9._-]", "_", signer_id.replace(":", "-"))


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class KeyEntry:
    key_id: str
    public_pem: str
    enrolled_at: str
    revoked_at: str | None = None

    def public_key(self) -> Ed25519PublicKey:
        key = serialization.load_pem_public_key(self.public_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise UsageError(f"{self.key_id}: not an Ed25519 public key")
        return key


@dataclass
class SignerEntry:
    id: str
    name: str
    role: str
    keys: list[KeyEntry]

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "role": self.role,
                "keys": [vars(key).copy() for key in self.keys]}

    def active_key(self) -> KeyEntry | None:
        return next((key for key in reversed(self.keys) if not key.revoked_at), None)


class Registry:
    def __init__(self, path: Path, keys_dir: Path):
        self.path, self.keys_dir = Path(path), Path(keys_dir)
        self.signers: list[SignerEntry] = []
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except ValueError as error:
                raise UsageError(f"{self.path}: not valid JSON") from error
            if data.get("version") != 1:
                raise UsageError(f"{self.path}: unsupported registry version {data.get('version')!r}")
            for item in data.get("signers", []):
                self.signers.append(SignerEntry(item["id"], item.get("name", ""), item.get("role", ""),
                                                [KeyEntry(k["key_id"], k["public_pem"], k["enrolled_at"],
                                                          k.get("revoked_at")) for k in item.get("keys", [])]))

    def as_dict(self) -> dict:
        return {"version": 1, "signers": [signer.as_dict() for signer in self.signers]}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(self.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)

    def get(self, signer_id: str) -> SignerEntry:
        for signer in self.signers:
            if signer.id == signer_id:
                return signer
        raise NotFound(f"unknown signer {signer_id!r}; run 'aqt-signoff init' first", code="unknown_signer")

    def find_key(self, key_id: str) -> tuple[SignerEntry, KeyEntry] | None:
        for signer in self.signers:
            for key in signer.keys:
                if key.key_id == key_id:
                    return signer, key
        return None

    def key_path(self, signer_id: str) -> Path:
        return self.keys_dir / f"{slug(signer_id)}.key"

    def add_signer(self, signer_id: str, name: str, role: str) -> SignerEntry:
        if not _ID.match(signer_id):
            raise UsageError("signer id must look like human:<name> (lower case letters, digits, . _ -)")
        if any(s.id == signer_id for s in self.signers):
            raise UsageError(f"signer {signer_id} already exists; ids are never reused", code="signer_exists")
        if not name.strip() or not role.strip():
            raise UsageError("a signer needs a printed name and a role")
        entry = SignerEntry(signer_id, name.strip(), role.strip(), [])
        self.signers.append(entry)
        return entry

    def add_key(self, signer: SignerEntry, public_key: Ed25519PublicKey, enrolled_at: str) -> KeyEntry:
        pem = public_key.public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        entry = KeyEntry(key_id_of(public_key), pem, enrolled_at)
        signer.keys.append(entry)
        return entry

    def retire_key_file(self, signer_id: str, key_id: str) -> None:
        """Move a revoked key's files aside so a new key can take the standard name."""
        path = self.key_path(signer_id)
        if not path.exists():
            return
        try:
            if load_public_key_id(Path(f"{path}.pub")) != key_id:
                return
        except (OSError, ValueError):
            return
        suffix = key_id.split(":", 1)[1]
        os.replace(path, path.with_name(f"{path.stem}.{suffix}.revoked.key"))
        pub = Path(f"{path}.pub")
        if pub.exists():
            os.replace(pub, path.with_name(f"{path.stem}.{suffix}.revoked.key.pub"))


def load_public_key_id(path: Path) -> str:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not Ed25519")
    return key_id_of(key)


class Authenticator(Protocol):
    """Unlocks a signer's private key for one signing operation (re-authentication)."""

    def passphrase(self, signer: SignerEntry, purpose: str) -> bytes: ...

    def new_passphrase(self, signer_id: str, min_length: int) -> bytes: ...


class TtyAuthenticator:
    """Reads the passphrase interactively (``getpass`` uses the controlling terminal)."""

    def passphrase(self, signer: SignerEntry, purpose: str) -> bytes:
        return getpass.getpass(f"Passphrase for {signer.name} ({signer.id}) to {purpose}: ").encode("utf-8")

    def new_passphrase(self, signer_id: str, min_length: int) -> bytes:
        first = getpass.getpass(f"New passphrase for {signer_id} (at least {min_length} characters): ")
        if len(first) < min_length:
            raise UsageError(f"the passphrase must have at least {min_length} characters", code="weak_passphrase")
        if getpass.getpass("Repeat the passphrase: ") != first:
            raise UsageError("the passphrases differ", code="passphrase_mismatch")
        return first.encode("utf-8")


class StaticPassphrase:
    """Fixed passphrase for tests and for embedding code that runs its own prompt. Never read from env."""

    def __init__(self, passphrase: str | bytes):
        self.value = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase

    def passphrase(self, signer: SignerEntry, purpose: str) -> bytes:
        return self.value

    def new_passphrase(self, signer_id: str, min_length: int) -> bytes:
        if len(self.value) < min_length:
            raise UsageError(f"the passphrase must have at least {min_length} characters", code="weak_passphrase")
        return self.value


def unlock(registry: Registry, signer: SignerEntry, authenticator: Authenticator, purpose: str) -> Signer:
    """Load the signer's active key with a freshly entered passphrase. Raises ``AuthFailed``."""
    active = signer.active_key()
    if active is None:
        raise AuthFailed(f"{signer.id} has no active key; enrol a new one with 'aqt-signoff init --add-key'",
                         code="no_active_key")
    path = registry.key_path(signer.id)
    if not path.exists():
        raise NotFound(f"key file for {signer.id} not found in {registry.keys_dir}", code="key_missing")
    try:
        key = load_signer(path, passphrase=authenticator.passphrase(signer, purpose))
    except (ValueError, TypeError) as error:
        raise AuthFailed("re-authentication failed: wrong passphrase or unreadable key") from error
    if key.key_id != active.key_id:
        raise AuthFailed(f"key file holds {key.key_id}, but the active registry key is {active.key_id}",
                         code="key_mismatch")
    return key
