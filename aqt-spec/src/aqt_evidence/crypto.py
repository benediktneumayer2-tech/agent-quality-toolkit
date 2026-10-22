"""Ed25519 keys and record signatures.

Private keys are PKCS#8 PEM files (optionally passphrase-encrypted), written
with mode 0600. Public keys are SubjectPublicKeyInfo PEM files. A key ID is
``ed25519:`` plus the first 16 hex digits of the SHA-256 of the raw public key.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json
from .record import unsigned


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


@dataclass(frozen=True)
class Signer:
    key_id: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self.private_key.sign(data)).decode("ascii")


def generate_key(path: str | os.PathLike, *, passphrase: bytes | None = None) -> str:
    """Write a new private key to ``path`` and its public key to ``path.pub``. Returns the key ID."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"{path} already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    encryption = (serialization.BestAvailableEncryption(passphrase) if passphrase
                  else serialization.NoEncryption())
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    Path(f"{path}.pub").write_bytes(public_pem(private.public_key()))
    return key_id(private.public_key())


def public_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_signer(path: str | os.PathLike, *, passphrase: bytes | None = None) -> Signer:
    private = serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return Signer(key_id(private.public_key()), private)


def load_public_key(path: str | os.PathLike) -> tuple[str, Ed25519PublicKey]:
    public = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key_id(public), public


def signing_bytes(record: dict) -> bytes:
    """The bytes a signature covers: the canonical record without ``sig``."""
    return canonical_json(unsigned(record))


def sign_record(record: dict, signer: Signer) -> dict:
    """Return a copy of ``record`` with one more signature appended to ``sig``."""
    signed = dict(record)
    signed["sig"] = [*record.get("sig", []),
                     {"alg": "ed25519", "key": signer.key_id, "value": signer.sign(signing_bytes(record))}]
    return signed


def verify_signature(public_key: Ed25519PublicKey, data: bytes, value: str) -> bool:
    try:
        public_key.verify(base64.b64decode(value, validate=True), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_record_signatures(record: dict, keys: dict[str, Ed25519PublicKey]) -> list[tuple[str, bool | None]]:
    """Check every signature. ``None`` means the key is unknown, ``False`` means invalid."""
    data = signing_bytes(record)
    results = []
    for sig in record.get("sig", []):
        public = keys.get(sig.get("key"))
        results.append((sig.get("key"), None if public is None else verify_signature(public, data, sig.get("value", ""))))
    return results


def signer_from_seed(seed: bytes) -> Signer:
    """A signer from a raw 32-byte Ed25519 seed (test vectors, deterministic fixtures)."""
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return Signer(key_id(private.public_key()), private)


def public_key_from_raw(raw: bytes) -> tuple[str, Ed25519PublicKey]:
    """``(key_id, public_key)`` from a raw 32-byte Ed25519 public key."""
    public = Ed25519PublicKey.from_public_bytes(raw)
    return key_id(public), public


def sign_statement(statement: dict, signer: Signer) -> dict:
    """Detached signed statement ``{statement, alg, key, value}`` (spec §6.3), as stored in
    ``data.signature``. The value covers ``canonical_json(statement)``."""
    return {"statement": statement, "alg": "ed25519", "key": signer.key_id,
            "value": signer.sign(canonical_json(statement))}


def verify_statement(signed: dict, keys: dict[str, Ed25519PublicKey]) -> bool | None:
    """``True`` valid, ``False`` invalid, ``None`` key not pinned."""
    if not isinstance(signed, dict) or signed.get("alg") != "ed25519" or not isinstance(signed.get("statement"), dict):
        return False
    public = keys.get(signed.get("key"))
    if public is None:
        return None
    try:
        data = canonical_json(signed["statement"])
    except ValueError:
        return False
    return verify_signature(public, data, str(signed.get("value", "")))
