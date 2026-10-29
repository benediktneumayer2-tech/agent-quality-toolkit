"""The signer registry (``signers.json``), key files and authenticators.

Registry format (version 1, shared with aqt-trail, aqt-quarantine and aqt-capa)::

    {"version": 1, "signers": [{"id": "human:alice", "name": "Alice Example", "role": "quality-manager",
      "keys": [{"key_id": "ed25519:…", "public_pem": "…", "enrolled_at": "…Z", "revoked_at": null}]}]}

Key files: ``<keys_dir>/<slug>.key`` (passphrase-protected, AQT key format with scrypt;
earlier PKCS#8 keys still load and are re-encrypted at the next unlock; 0600) and
``<slug>.key.pub``. The slug is the signer id with ``:`` replaced by ``-``.

The file is plain configuration that any process of the user can edit. A key therefore
counts only when ``reconcile`` finds its ``signoff.key.enrolled`` record in the evidence (the
chained trail when there is one): same signer, key, public key and role, with a statement
that the key itself signed. Enrolment and revocation times are taken from that evidence;
a revocation record always applies, even when the file says the key is active.
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

from aqt_evidence import Signer, bytes_hash, key_id as key_id_of, load_signer, verify_statement
from aqt_evidence.crypto import upgrade_key

from .errors import AuthFailed, NotFound, UsageError

_ID = re.compile(r"^human:[a-z0-9][a-z0-9._-]{0,63}$")
SLACK_S = 300   # registry, statement and trail times of one enrolment may differ by this much without a note


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


@dataclass
class KeyEvidence:
    """A registry key reconciled with its enrolment and revocation records."""
    signer_id: str
    key_id: str
    counts: bool
    problems: list
    notes: list
    enrolled_at: str | None = None
    revoked_at: str | None = None
    enrolled_role: str | None = None
    record: dict | None = None        # id, time, source, adopted and observed of the enrolment record
    missing: bool = False             # no enrolment record at all (aqt-signoff records one at the next unlock)

    def as_dict(self) -> dict:
        return {"signer": self.signer_id, "key_id": self.key_id, "counts": self.counts, "problems": self.problems,
                "notes": self.notes, "enrolled_at": self.enrolled_at, "revoked_at": self.revoked_at,
                "enrolled_role": self.enrolled_role, "enrolment": self.record}


def _data(record: dict) -> dict:
    return record.get("data") if isinstance(record.get("data"), dict) else {}


def _time(value) -> datetime | None:
    try:
        moment = parse_time(value)
    except (TypeError, ValueError, AttributeError):
        return None
    return moment if moment.tzinfo else None


class Registry:
    def __init__(self, path: Path, keys_dir: Path):
        self.path, self.keys_dir = Path(path), Path(keys_dir)
        self.signers: list[SignerEntry] = []
        self.reconciled = False
        self.evidence: dict[tuple[str, str], KeyEvidence] = {}   # (signer id, key id) -> evidence
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

    def key_evidence(self, key_id: str, signer_id: str | None = None) -> KeyEvidence | None:
        """The reconciled evidence of a key (of ``signer_id``, else of the signer ``find_key`` returns)."""
        if signer_id is None:
            found = self.find_key(key_id)
            signer_id = found[0].id if found else None
        return self.evidence.get((signer_id, key_id))

    def reconcile(self, enrolments: list[dict], revocations: list[dict], *, source: str = "evidence") -> None:
        """Check every key against ``signoff.key.enrolled`` records in ``enrolments`` and apply
        every ``signoff.key.revoked`` record in ``revocations``. Sets ``evidence`` and ``reconciled``."""
        enrolled: dict[str, list[dict]] = {}
        for record in enrolments:
            if isinstance(record, dict) and record.get("type") == "signoff.key.enrolled":
                enrolled.setdefault(str(_data(record).get("key_id")), []).append(record)
        revoked: dict[str, list[str]] = {}
        for record in revocations:
            if not isinstance(record, dict):
                continue
            data = _data(record)
            if record.get("type") == "signoff.key.revoked" and _time(data.get("revoked_at")):
                revoked.setdefault(str(data.get("key_id")), []).append(data["revoked_at"])
        self.evidence = {}
        owners: dict[str, set[str]] = {}
        for signer in self.signers:
            for key in signer.keys:
                owners.setdefault(key.key_id, set()).add(signer.id)
        for signer in self.signers:
            for key in signer.keys:
                ev = self._reconcile_key(signer, key, enrolled.get(key.key_id, []), revoked.get(key.key_id, []),
                                         source)
                if len(owners[key.key_id]) > 1 or sum(k.key_id == key.key_id for k in signer.keys) > 1:
                    ev.problems.append("the key id is registered more than once")
                    ev.counts = ev.missing = False
                self.evidence[(signer.id, key.key_id)] = ev
        self.reconciled = True

    def _reconcile_key(self, signer: SignerEntry, key: KeyEntry, candidates: list[dict], revocations: list[str],
                       source: str) -> KeyEvidence:
        ev = KeyEvidence(signer.id, key.key_id, False, [], [])
        try:
            public = key.public_key()
        except (ValueError, UsageError):
            ev.problems.append("the registry public key is not an Ed25519 key")
            return ev
        if key_id_of(public) != key.key_id:
            ev.problems.append("the registry key_id does not belong to its public key")
            return ev
        best, best_time, rejected = None, None, []
        for record in candidates:
            why = self._enrolment_problem(record, signer, key, public)
            if why:
                rejected.append(why)
                continue
            st = _data(record)["signature"]["statement"]
            moment = _time(st.get("signed_at"))
            if best is None or moment < best_time:
                best, best_time = record, moment
        if best is None:
            ev.missing = not candidates
            ev.problems.append(f"no signoff.key.enrolled record for this key in the {source}" if not candidates
                               else "its enrolment record does not match: " + "; ".join(rejected))
            return ev
        st = _data(best)["signature"]["statement"]
        ev.enrolled_role = st["signer"].get("role")
        ev.enrolled_at = st.get("enrolled_at") if _time(st.get("enrolled_at")) else st["signed_at"]
        ev.record = {"id": best.get("id"), "time": best.get("time"), "source": source,
                     "adopted": bool(_data(best).get("adopted")), "observed": best.get("observed")}
        if signer.role != ev.enrolled_role:
            ev.problems.append(f"registry role {signer.role!r} differs from the enrolled role {ev.enrolled_role!r}")
        if signer.name != st["signer"].get("name"):
            ev.notes.append(f"registry name {signer.name!r} differs from the enrolled name "
                            f"{st['signer'].get('name')!r}")
        registered = _time(key.enrolled_at)
        if registered is None or (_time(ev.enrolled_at) - registered).total_seconds() > SLACK_S:
            ev.notes.append(f"registry enrolled_at {key.enrolled_at} is earlier than the enrolment record "
                            f"({ev.enrolled_at}); the record's time applies")
        recorded = _time(best.get("time"))
        if ev.record["adopted"]:
            ev.notes.append(f"enrolled outside 'aqt-signoff init'; the enrolment was recorded at its first use "
                            f"({best.get('time')}, record {best.get('id')}); check that this person and key are known")
        elif recorded and (recorded - _time(ev.enrolled_at)).total_seconds() > SLACK_S:
            ev.notes.append(f"enrolment recorded at {best.get('time')}, later than the enrolment time it states "
                            f"({ev.enrolled_at})")
        times = [t for t in (key.revoked_at, *revocations) if _time(t)]
        if key.revoked_at and not _time(key.revoked_at):
            ev.problems.append(f"registry revoked_at {key.revoked_at!r} is not a time")
        ev.revoked_at = min(times, key=_time) if times else None
        if revocations and not key.revoked_at:
            ev.notes.append(f"registry shows the key active, but a signoff.key.revoked record revokes it at "
                            f"{ev.revoked_at}; the revocation applies")
        ev.counts = not ev.problems
        return ev

    @staticmethod
    def _enrolment_problem(record: dict, signer: SignerEntry, key: KeyEntry, public) -> str | None:
        data = _data(record)
        block = data.get("signature")
        st = block.get("statement") if isinstance(block, dict) else None
        if not isinstance(st, dict):
            return f"{record.get('id')}: no signed statement"
        subject = st.get("subject") if isinstance(st.get("subject"), dict) else {}
        signer_part = st.get("signer") if isinstance(st.get("signer"), dict) else {}
        checks = [
            (st.get("record_type") == "signoff.key.enrolled", "statement is not an enrolment"),
            (signer_part.get("id") == signer.id and data.get("signer") in (None, signer.id), "other signer"),
            (block.get("key") == st.get("key") == key.key_id, "other key"),
            (subject.get("kind") == "key" and subject.get("ref") == key.key_id
             and subject.get("sha256") == bytes_hash(key.public_pem.encode("ascii")), "other public key"),
            (data.get("public_pem") in (None, key.public_pem), "other public key"),
            (_time(st.get("signed_at")) is not None, "no signing time"),
        ]
        for ok, why in checks:
            if not ok:
                return f"{record.get('id')}: {why}"
        if not verify_statement(block, {key.key_id: public}):
            return f"{record.get('id')}: not signed by this key"
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
    passphrase = authenticator.passphrase(signer, purpose)
    try:
        key = load_signer(path, passphrase=passphrase)
    except (ValueError, TypeError) as error:
        raise AuthFailed("re-authentication failed: wrong passphrase or unreadable key") from error
    if key.key_id != active.key_id:
        raise AuthFailed(f"key file holds {key.key_id}, but the active registry key is {active.key_id}",
                         code="key_mismatch")
    try:   # a key from an earlier version (PKCS#8, PBKDF2) is re-encrypted with scrypt now
        upgrade_key(path, passphrase)
    except (OSError, ValueError, TypeError):
        pass   # read-only key directory or a concurrent rewrite: keep the old file, it still works
    return key
