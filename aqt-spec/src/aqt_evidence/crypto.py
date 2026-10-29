"""Ed25519 keys and record signatures.

Private keys are written with mode 0600; a key directory created here gets 0700.
A passphrase-protected key uses the AQT key format, version 1::

    -----BEGIN AQT ENCRYPTED PRIVATE KEY-----
    base64(canonical_json({"format": "aqt-key", "version": 1, "key_id": "ed25519:...",
        "kdf": {"name": "scrypt", "n": 131072, "r": 8, "p": 1, "salt": "<base64, 16 bytes>"},
        "cipher": {"name": "aes-256-gcm", "nonce": "<base64, 12 bytes>"},
        "ciphertext": "<base64>"}))
    -----END AQT ENCRYPTED PRIVATE KEY-----

The 32-byte Ed25519 seed is encrypted with AES-256-GCM under a key that scrypt derives
from the passphrase (memory-hard: 128 MiB per guess at the default cost). Every field
except ``ciphertext`` is authenticated as associated data. Keys written by earlier
versions (passphrase-encrypted PKCS#8 PEM, PBKDF2 with 2048 iterations) still load;
``upgrade_key`` re-encrypts such a key in the current format. A key without a passphrase
(unattended service keys) stays unencrypted PKCS#8 PEM. Public keys are
SubjectPublicKeyInfo PEM files. A key ID is ``ed25519:`` plus the first 16 hex digits of
the SHA-256 of the raw public key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .canonical import canonical_json
from .record import unsigned

STATEMENT_VERSION = "0.1"          # detached signed statements (spec section 6.3)
KEY_LABEL = "AQT ENCRYPTED PRIVATE KEY"
KEY_FORMAT, KEY_FORMAT_VERSION = "aqt-key", 1
# scrypt cost for new keys (OWASP's first recommended setting). Loading accepts the cost a
# file records, within the bounds below, so tests may lower SCRYPT_N to run faster.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1
_MAX_SCRYPT_MEMORY = 1 << 30   # refuse files that would make loading allocate more than 1 GiB


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
    """Write a new private key to ``path`` and its public key to ``path.pub``. Returns the key ID.

    With a passphrase the key uses the AQT key format (scrypt + AES-256-GCM)."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"{path} already exists")
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
    private = Ed25519PrivateKey.generate()
    _write_secret(path, private_key_bytes(private, passphrase), replace=False)
    Path(f"{path}.pub").write_bytes(public_pem(private.public_key()))
    return key_id(private.public_key())


def private_key_bytes(private: Ed25519PrivateKey, passphrase: bytes | None = None) -> bytes:
    """The key file content: the AQT key format with a passphrase, else unencrypted PKCS#8 PEM."""
    if not passphrase:
        return private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())
    seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    salt, nonce = os.urandom(16), os.urandom(12)
    header = {"format": KEY_FORMAT, "version": KEY_FORMAT_VERSION, "key_id": key_id(private.public_key()),
              "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt)},
              "cipher": {"name": "aes-256-gcm", "nonce": _b64(nonce)}}
    secret = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(passphrase)
    sealed = AESGCM(secret).encrypt(nonce, seed, canonical_json(header))
    body = base64.encodebytes(canonical_json({**header, "ciphertext": _b64(sealed)})).decode("ascii")
    return f"-----BEGIN {KEY_LABEL}-----\n{body}-----END {KEY_LABEL}-----\n".encode("ascii")


def key_file_format(path: str | os.PathLike) -> str:
    """``aqt-key`` (current), ``pkcs8-encrypted`` (earlier versions) or ``pkcs8`` (no passphrase)."""
    data = Path(path).read_bytes()
    if data.lstrip().startswith(f"-----BEGIN {KEY_LABEL}-----".encode()):
        return KEY_FORMAT
    return "pkcs8-encrypted" if b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in data else "pkcs8"


def upgrade_key(path: str | os.PathLike, passphrase: bytes) -> bool:
    """Re-encrypt an earlier-version (PKCS#8, PBKDF2) key file in the AQT key format, in place
    (atomic, mode 0600). Returns False when the file needs no upgrade. Raises like ``load_signer``."""
    if key_file_format(path) != "pkcs8-encrypted":
        return False
    signer = load_signer(path, passphrase=passphrase)
    _write_secret(Path(path), private_key_bytes(signer.private_key, passphrase), replace=True)
    return True


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _write_secret(path: Path, data: bytes, *, replace: bool) -> None:
    target = path.with_name(f".{path.name}.{os.getpid()}.tmp") if replace else path
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(target, path)
    except BaseException:
        if replace:
            target.unlink(missing_ok=True)
        raise


def _open_aqt_key(data: bytes, passphrase: bytes | None) -> Ed25519PrivateKey:
    if not passphrase:
        raise TypeError("the key is passphrase-protected; a passphrase is needed")
    text = data.decode("ascii", errors="replace").strip()
    begin, end = f"-----BEGIN {KEY_LABEL}-----", f"-----END {KEY_LABEL}-----"
    if not (text.startswith(begin) and text.endswith(end)):
        raise ValueError("damaged AQT key file (armour)")
    try:
        body = json.loads(base64.b64decode("".join(text[len(begin):-len(end)].split()), validate=True))
        kdf, cipher = body["kdf"], body["cipher"]
        n, r, p = (kdf[name] for name in ("n", "r", "p"))
        salt, nonce = base64.b64decode(kdf["salt"]), base64.b64decode(cipher["nonce"])
        sealed = base64.b64decode(body["ciphertext"])
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError(f"damaged AQT key file: {error}") from None
    if (body.get("format"), body.get("version"), kdf.get("name"), cipher.get("name")) != (
            KEY_FORMAT, KEY_FORMAT_VERSION, "scrypt", "aes-256-gcm"):
        raise ValueError("unsupported AQT key file format, version, KDF or cipher")
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (n, r, p)) or n < 2 or n & (n - 1) \
            or not 1 <= r <= 32 or not 1 <= p <= 16 or 128 * n * r > _MAX_SCRYPT_MEMORY or len(salt) < 16 \
            or len(nonce) != 12:
        raise ValueError("AQT key file with unsupported scrypt or cipher parameters")
    header = {key: value for key, value in body.items() if key != "ciphertext"}
    secret = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase)
    try:
        seed = AESGCM(secret).decrypt(nonce, sealed, canonical_json(header))
    except InvalidTag:
        raise ValueError("wrong passphrase or damaged key file") from None
    private = Ed25519PrivateKey.from_private_bytes(seed)
    if body.get("key_id") != key_id(private.public_key()):
        raise ValueError("the key file's key_id does not match its key")
    return private


def public_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_signer(path: str | os.PathLike, *, passphrase: bytes | None = None) -> Signer:
    """Load a private key in any supported format. A wrong passphrase raises ``ValueError``,
    a missing one ``TypeError``."""
    data = Path(path).read_bytes()
    if data.lstrip().startswith(f"-----BEGIN {KEY_LABEL}-----".encode()):
        private = _open_aqt_key(data, passphrase)
    else:
        private = serialization.load_pem_private_key(data, password=passphrase)
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
    """Check every signature. ``None`` means the key is unknown, ``False`` means invalid.
    A malformed ``sig`` (not a list of ``{key, value}`` objects, e.g. ``null``) counts as one
    invalid signature instead of raising."""
    sigs = record.get("sig", []) if isinstance(record, dict) else None
    if not isinstance(sigs, list):
        return [(None, False)]
    try:
        data = signing_bytes(record)
    except ValueError:      # not representable in canonical JSON: nothing can verify
        return [(sig.get("key") if isinstance(sig, dict) else None, False) for sig in sigs] or [(None, False)]
    results = []
    for sig in sigs:
        if not isinstance(sig, dict) or not isinstance(sig.get("key"), str) or not isinstance(sig.get("value"), str):
            results.append((sig.get("key") if isinstance(sig, dict) and isinstance(sig.get("key"), str) else None,
                            False))
            continue
        public = keys.get(sig["key"])
        results.append((sig["key"], None if public is None else verify_signature(public, data, sig["value"])))
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
    """``True`` valid, ``False`` invalid, ``None`` key not pinned.

    Only a detached statement counts (``aqt_signature`` ``"0.1"``, ``signer`` and ``subject``
    objects, ``statement.key`` equal to the block's ``key``): a record signature presented as
    a statement (same key, same signed bytes) is invalid."""
    if not isinstance(signed, dict) or signed.get("alg") != "ed25519" or not isinstance(signed.get("statement"), dict):
        return False
    statement = signed["statement"]
    if (statement.get("aqt_signature") != STATEMENT_VERSION or not isinstance(statement.get("signer"), dict)
            or not isinstance(statement.get("subject"), dict) or not isinstance(signed.get("key"), str)
            or statement.get("key") != signed["key"] or not isinstance(signed.get("value"), str)):
        return False
    public = keys.get(signed.get("key"))
    if public is None:
        return None
    try:
        data = canonical_json(signed["statement"])
    except ValueError:
        return False
    return verify_signature(public, data, str(signed.get("value", "")))
