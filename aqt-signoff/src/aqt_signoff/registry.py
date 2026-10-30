"""The signer registry (``signers.json``), key files and authenticators.

Registry format (version 1, shared with aqt-trail, aqt-quarantine and aqt-capa)::

    {"version": 1, "signers": [{"id": "human:alice", "name": "Alice Example", "role": "quality-manager",
      "keys": [{"key_id": "ed25519:…", "public_pem": "…", "enrolled_at": "…Z", "revoked_at": null}]}]}

Key files: ``<keys_dir>/<slug>.key`` (passphrase-protected, AQT key format with scrypt;
earlier PKCS#8 keys still load and are re-encrypted at the next unlock; 0600) and
``<slug>.key.pub``. The slug is the signer id with ``:`` replaced by ``-``.

The file is plain configuration that any process of the user can edit. A key therefore
counts only as ``reconcile`` finds it in the enrolment evidence (the chained trail when there
is one; rules in ``enrolment``): its own signed enrolment request, and either the first
enrolment of all (bootstrap) or an approval by another enrolled signer. Enrolment times, roles
and revocations are taken from that evidence; a revocation record always applies, even when
the file says the key is active, and a registry role that differs from the enrolled role
stops the key.
"""

from __future__ import annotations

import getpass
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aqt_evidence import Signer, key_id as key_id_of, load_signer
from aqt_evidence.crypto import upgrade_key

from .enrolment import EnrolmentHistory, parse_time, revocations as revocations_of
from .errors import AuthFailed, NotFound, UsageError

_ID = re.compile(r"^human:[a-z0-9][a-z0-9._-]{0,63}$")
SLACK_S = 300   # registry, statement and trail times of one enrolment may differ by this much without a note


def slug(signer_id: str) -> str:
    return re.sub(r"[^a-z0-9._-]", "_", signer_id.replace(":", "-"))


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
    """A registry key reconciled with the enrolment evidence (``enrolment.EnrolmentHistory``)."""
    signer_id: str
    key_id: str
    counts: bool
    problems: list
    notes: list
    enrolled_at: str | None = None    # from when the key counts: its enrolment request's record time
    revoked_at: str | None = None
    enrolled_role: str | None = None  # the signer's role now, from the evidence
    record: dict | None = None        # id, time, source, adopted and observed of the enrolment request
    missing: bool = False             # no enrolment record at all (aqt-signoff records one at the next unlock)
    pending: bool = False             # enrolment recorded, waiting for an approval
    basis: str | None = None          # bootstrap | rebootstrap | approved
    approvals: list = field(default_factory=list)
    roles: list = field(default_factory=list)   # [{"from", "role", "record"}] of the signer

    def as_dict(self) -> dict:
        return {"signer": self.signer_id, "key_id": self.key_id, "counts": self.counts, "problems": self.problems,
                "notes": self.notes, "enrolled_at": self.enrolled_at, "revoked_at": self.revoked_at,
                "enrolled_role": self.enrolled_role, "enrolment": self.record, "pending": self.pending,
                "basis": self.basis, "approvals": self.approvals, "roles": self.roles}


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
        self.history: EnrolmentHistory | None = None
        self.pre_trail: list[dict] = []     # set by Signoff.trust: enrolment requests only outside the trail
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
        """Build the enrolment history from ``enrolments`` (in order; see ``enrolment``) and check every
        registry key against it; every ``signoff.key.revoked`` record in ``revocations`` (or carried by an
        import) applies. Sets ``history``, ``evidence`` and ``reconciled``."""
        revoked = revocations_of([*revocations, *enrolments])
        pems = {key.key_id: key.public_pem for signer in self.signers for key in signer.keys}
        self.history = EnrolmentHistory(revoked, source, pems).run(enrolments)
        self.evidence = {}
        owners: dict[str, set[str]] = {}
        for signer in self.signers:
            for key in signer.keys:
                owners.setdefault(key.key_id, set()).add(signer.id)
        for signer in self.signers:
            for key in signer.keys:
                ev = self._reconcile_key(signer, key, revoked.get(key.key_id, []), source)
                if len(owners[key.key_id]) > 1 or sum(k.key_id == key.key_id for k in signer.keys) > 1:
                    ev.problems.append("the key id is registered more than once")
                    ev.counts = ev.missing = False
                self.evidence[(signer.id, key.key_id)] = ev
            active = [k.key_id for k in signer.keys if self.evidence[(signer.id, k.key_id)].counts
                      and not self.evidence[(signer.id, k.key_id)].revoked_at]
            if len(active) > 1:
                for key_id in active:
                    self.evidence[(signer.id, key_id)].notes.append(
                        f"{signer.id} has {len(active)} active keys that count ({', '.join(active)})")
        self.reconciled = True

    def role_at(self, signer_id: str, moment: datetime) -> str | None:
        """The signer's role in effect at ``moment`` (reconciled registries only)."""
        return self.history.role_at(signer_id, moment) if self.history else None

    def _reconcile_key(self, signer: SignerEntry, key: KeyEntry, revocations: list[str], source: str) -> KeyEvidence:
        ev = KeyEvidence(signer.id, key.key_id, False, [], [])
        try:
            public = key.public_key()
        except (ValueError, UsageError):
            ev.problems.append("the registry public key is not an Ed25519 key")
            return ev
        if key_id_of(public) != key.key_id:
            ev.problems.append("the registry key_id does not belong to its public key")
            return ev
        history = self.history
        state = history.keys.get(key.key_id)
        if state is None:
            rejected = history.rejected.get(key.key_id, [])
            ev.missing = not rejected
            ev.problems.append(f"no signoff.key.enrolled record for this key in the {source}" if not rejected
                               else "its enrolment record does not match: " + "; ".join(rejected))
            return ev
        request = state.request
        ev.record = {"id": request.get("id"), "time": state.time, "source": state.source,
                     "adopted": bool(_data(request).get("adopted")), "observed": request.get("observed")}
        if state.imported:
            ev.record["imported"] = state.imported
        ev.basis, ev.approvals = state.basis, list(state.approvals)
        ev.roles = [{"from": when, "role": role, "record": rid} for when, role, rid in history.roles.get(signer.id, [])]
        if state.signer != signer.id:
            ev.problems.append(f"its enrolment record names {state.signer}, the registry {signer.id}")
        if state.public_pem.strip() != key.public_pem.strip():
            ev.problems.append("its enrolment record holds another public key")
        ev.problems.extend(state.problems)
        if state.conflict:
            pass
        elif state.start is None:
            ev.pending = True
            ev.problems.append(f"enrolment {request.get('id')} ({state.time}) waits for approval: another enrolled "
                               f"signer runs 'aqt-signoff signers approve {signer.id} --key {key.key_id}'")
        else:
            ev.enrolled_at = state.start
            ev.enrolled_role = history.current_role(signer.id)
            if signer.role != ev.enrolled_role:
                ev.problems.append(f"registry role {signer.role!r} differs from the enrolled role {ev.enrolled_role!r} "
                                   f"(a role changes with 'aqt-signoff signers approve {signer.id} --key KEY --role "
                                   "ROLE' by another signer)")
        if signer.name != state.name:
            ev.notes.append(f"registry name {signer.name!r} differs from the enrolled name {state.name!r}")
        st = _data(request).get("signature", {}).get("statement", {})
        registered, stated = _time(key.enrolled_at), _time(st.get("enrolled_at")) or _time(st.get("signed_at"))
        if registered is None or (_time(state.time) - registered).total_seconds() > SLACK_S:
            ev.notes.append(f"registry enrolled_at {key.enrolled_at} is earlier than the enrolment record "
                            f"({state.time}); the record's time applies")
        if ev.record["adopted"]:
            ev.notes.append(f"enrolled outside 'aqt-signoff init'; the enrolment was recorded at its first use "
                            f"({state.time}, record {request.get('id')}); check that this person and key are known")
        elif stated and (_time(state.time) - stated).total_seconds() > SLACK_S:
            ev.notes.append(f"enrolment recorded at {state.time}, later than the enrolment time it states "
                            f"({st.get('enrolled_at') or st.get('signed_at')}); the recorded time applies")
        if state.imported:
            ev.notes.append(f"enrolment from before the trail, imported by {state.imported['by']} "
                            f"(record {state.imported['record']})")
        for entry in history.rebootstraps:
            if entry["key_id"] == key.key_id:
                confirmed = ", ".join(c["by"] for c in entry["confirmed_by"])
                ev.notes.append(f"RE-BOOTSTRAP: enrolled at {entry['time']} when no other key counted any more "
                                f"(all revoked); it counts without an approval"
                                + (f"; confirmed by {confirmed}" if confirmed else
                                   "; check that this was you, and let another signer confirm it with "
                                   f"'aqt-signoff signers approve {signer.id} --key {key.key_id}'"))
        times = [t for t in (key.revoked_at, *revocations) if _time(t)]
        if key.revoked_at and not _time(key.revoked_at):
            ev.problems.append(f"registry revoked_at {key.revoked_at!r} is not a time")
        ev.revoked_at = min(times, key=_time) if times else None
        if revocations and not key.revoked_at:
            ev.notes.append(f"registry shows the key active, but a signoff.key.revoked record revokes it at "
                            f"{ev.revoked_at}; the revocation applies")
        ev.counts = not ev.problems
        return ev

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
