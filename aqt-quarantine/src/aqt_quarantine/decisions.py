"""Human decisions: release, trust source, declare threat. Guarded and signed.

Layer 1 (``aqt_evidence.require_human``): refuse when the caller looks like an
agent (environment markers, agent process in the parent chain) or has no
terminal. Layer 2 (the real control): the decision is signed with the
responsible person's passphrase-protected Ed25519 key, as a detached statement
in ``data.signature`` (INTERFACES.md I1). The hooks honour only decisions whose
statement verifies against the signer registry (I9), so a record an agent
appends to the journal, or a command it types into the owner's terminal
without the passphrase, has no effect. Every refusal is recorded as
``quarantine.refused``.
"""

from __future__ import annotations

import base64
import fcntl
import getpass
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aqt_evidence import (HumanCheckError, actor, canonical_json, content_hash, generate_key, load_public_key,
                          load_signer, require_human, subject, utc_now)

from . import records
from .config import Config
from .store import Case, Store, StoreError, normalise_case_id

STATEMENT_VERSION = "0.1"
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class DecisionError(RuntimeError):
    """Usage or state problem (exit 2 for usage, 1 for a failed check)."""

    def __init__(self, message: str, exit_code: int = 1):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class Outcome:
    ok: bool
    record: dict
    message: str


SIGNER_ID = re.compile(r"^human:[a-z0-9][a-z0-9._-]{0,63}$")  # same rule as aqt-signoff


def slug(signer_id: str) -> str:
    """Key file name stem, identical to aqt-signoff's: ``human:alex`` -> ``human-alex``."""
    return re.sub(r"[^a-z0-9._-]", "_", signer_id.replace(":", "-"))


# -- signer registry (owned by aqt-signoff; read directly, I9) ----------------------------------------------
def load_registry(path: Path) -> dict[str, dict]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}
    signers = doc.get("signers") if isinstance(doc, dict) else None
    return {item["id"]: item for item in signers or [] if isinstance(item, dict) and item.get("id")}


def enrol(path: Path, *, signer_id: str, name: str, role: str, key_id: str, public_pem: str) -> None:
    """Add a signer key to the registry (same format as aqt-signoff; used when aqt-signoff is not installed)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    with open(lock, "a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            doc = {"version": 1, "signers": []}
        entry = next((item for item in doc["signers"] if item.get("id") == signer_id), None)
        if entry is None:
            entry = {"id": signer_id, "name": name, "role": role, "keys": []}
            doc["signers"].append(entry)
        entry.setdefault("keys", []).append({"key_id": key_id, "public_pem": public_pem, "enrolled_at": utc_now(),
                                              "revoked_at": None})
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)


def _registered_key(registry: dict[str, dict], signer_id: str, key_id: str) -> dict | None:
    for key in (registry.get(signer_id) or {}).get("keys", []):
        if key.get("key_id") == key_id:
            return key
    return None


# -- statements --------------------------------------------------------------------------------------
def sign_statement(signer, *, person: dict, meaning: str, reason: str, decision: dict, record_type: str,
                   ref: str, tz: str | None) -> dict:
    statement = {
        "aqt_signature": STATEMENT_VERSION,
        "signer": {"id": person["id"], "name": person.get("name", ""), "role": person.get("role", "")},
        "key": signer.key_id, "meaning": meaning, "reason": reason, "signed_at": utc_now(),
        "subject": {"kind": "quarantine-decision", "ref": ref, "sha256": content_hash(decision)},
        "record_type": record_type, "nonce": secrets.token_hex(8),
    }
    if tz:
        statement["tz"] = tz
    return {"statement": statement, "alg": "ed25519", "key": signer.key_id,
            "value": signer.sign(canonical_json(statement))}


def verify_decision(record: dict, registry: dict[str, dict], responsible: list[str] | None = None) -> str:
    """valid | unsigned | mismatch | unknown-signer | revoked | not-responsible | invalid."""
    data = record.get("data") or {}
    signature = data.get("signature")
    if not signature:
        return "unsigned"
    statement = signature.get("statement") or {}
    who = (record.get("actor") or {}).get("id")
    if (statement.get("record_type") != record.get("type") or statement.get("meaning") != record.get("meaning")
            or statement.get("reason") != record.get("reason") or (statement.get("signer") or {}).get("id") != who
            or statement.get("key") != signature.get("key") or "decision" not in data
            or (statement.get("subject") or {}).get("sha256") != content_hash(data["decision"])):
        return "mismatch"
    if responsible and who not in responsible:
        return "not-responsible"
    key = _registered_key(registry, who, signature.get("key"))
    if key is None:
        return "unknown-signer"
    if key.get("revoked_at") and str(key["revoked_at"]) <= str(statement.get("signed_at")):
        return "revoked"
    try:
        public = serialization.load_pem_public_key(key["public_pem"].encode("ascii"))
        if not isinstance(public, Ed25519PublicKey):
            return "invalid"
        public.verify(base64.b64decode(signature.get("value", ""), validate=True), canonical_json(statement))
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return "invalid"
    return "valid"


# -- the decision flow -----------------------------------------------------------------------------------
class Decider:
    def __init__(self, config: Config, store: Store, *, passphrase: Callable[[str], str] | None = None,
                 human_check: Callable[[], object] | None = None):
        self.config, self.store = config, store
        self.passphrase = passphrase or (lambda prompt: getpass.getpass(prompt))
        self.human_check = human_check or require_human
        self.registry = load_registry(config.registry)

    def verifier(self):
        return lambda record: verify_decision(record, self.registry, self.config.responsible or None)

    def fold(self):
        return self.store.fold(self.verifier(), require_signed=self.config.require_signed_decisions)

    def person(self, signer_id: str | None) -> dict:
        candidates = self.config.responsible or list(self.registry)
        if signer_id is None:
            if len(candidates) != 1:
                raise DecisionError("say who decides with --as SIGNER_ID "
                                    f"(registered: {', '.join(candidates) or 'none; run aqt-quarantine init'})", 2)
            signer_id = candidates[0]
        entry = self.registry.get(signer_id, {})
        return {"id": signer_id, "name": entry.get("name", ""), "role": entry.get("role", "")}

    def _refuse(self, who: dict, attempted: str, reason_code: str, markers: list[str], detail: str,
                extra: dict) -> Outcome:
        record = records.refused(actor("human", who["id"], role=who.get("role") or None), attempted_action=attempted,
                                 reason_code=reason_code, agent_markers=markers, detail=detail, extra=extra,
                                 tz=self.config.tz)
        self.store.write(record)
        return Outcome(False, record, detail)

    def _guard(self, who: dict, attempted: str, extra: dict) -> Outcome | None:
        try:
            self.human_check()
        except HumanCheckError as error:
            context = error.context
            return self._refuse(who, attempted, "agent_context" if context.is_agent else "no_tty",
                                list(context.markers), str(error), {**extra, "process_chain": context.process_chain[:12]})
        if self.config.responsible and who["id"] not in self.config.responsible:
            return self._refuse(who, attempted, "not_responsible", [], f"{who['id']} is not a responsible person",
                                extra)
        return None

    def _sign(self, who: dict, attempted: str, extra: dict, **statement) -> tuple[dict | None, Outcome | None]:
        key_path = self.config.keys_dir / f"{slug(who['id'])}.key"
        if not key_path.exists():
            if self.config.require_signed_decisions:
                return None, self._refuse(who, attempted, "no_key", [], f"no signing key at {key_path}; "
                                          "run aqt-quarantine init (or aqt-signoff init)", extra)
            return None, None
        try:
            signer = load_signer(key_path, passphrase=self.passphrase(f"Passphrase for {who['id']}: ").encode())
        except (ValueError, TypeError) as error:
            return None, self._refuse(who, attempted, "auth_failed", [], f"key could not be unlocked: {error}", extra)
        key = _registered_key(self.registry, who["id"], signer.key_id)
        if key is None or key.get("revoked_at"):
            return None, self._refuse(who, attempted, "unknown_key", [],
                                      f"key {signer.key_id} is not an active key of {who['id']} in {self.config.registry}",
                                      extra)
        return sign_statement(signer, person=who, tz=self.config.tz, **statement), None

    def _case(self, case_id: str) -> Case:
        cases, _ = self.fold()
        case = cases.get(normalise_case_id(case_id))
        if case is None:
            raise DecisionError(f"no case {case_id}")
        return case

    def _decide_case(self, kind: str, action: str, meaning: str, case_id: str, reason: str, signer_id: str | None,
                     extra_data: dict) -> Outcome:
        reason = _reason(reason)
        who = self.person(signer_id)
        try:
            case_id = normalise_case_id(case_id)
        except StoreError as error:
            raise DecisionError(str(error), 2) from error
        attempted = {"quarantine.released": "release", "quarantine.threat.declared": "declare-threat"}[kind]
        blocked = self._guard(who, attempted, {"case_id": case_id})
        if blocked:
            return blocked
        case = self._case(case_id)
        if kind == "quarantine.released":
            if case.state == "released":
                raise DecisionError(f"case {case_id} is already released")
            if case.state == "threat" and not extra_data.get("overrule_threat"):
                raise DecisionError(f"case {case_id} was declared a threat; add --overrule-threat to release it anyway")
            extra_data = {"kind": "deliver" if case.band == "hold" else "confirm_harmless", **extra_data}
        elif case.state == "threat":
            raise DecisionError(f"case {case_id} is already declared a threat")
        else:
            extra_data = {"reached_model": case.reached_model, **extra_data}
        base = {key: case.data[key] for key in ("band", "score_ppm", "source", "content_sha256") if key in case.data}
        decision = {"action": action, "case_id": case_id, "content_sha256": case.data.get("content_sha256"),
                    **{k: v for k, v in extra_data.items() if k != "reached_model"}}
        signature, refused = self._sign(who, attempted, {"case_id": case_id}, meaning=meaning, reason=reason,
                                        decision=decision, record_type=kind, ref=f"case:{case_id}")
        if refused:
            return refused
        data = {"case_id": case_id, **base, **extra_data, "decision": decision}
        if signature:
            data["signature"] = signature
        record = records.decision(kind, actor("human", who["id"], role=who.get("role") or None,
                                              display=who.get("name") or None),
                                  action=action, meaning=meaning, reason=reason,
                                  subject_=records.case_subject(case_id, case.data["content_sha256"]), data=data,
                                  links=[{"rel": "case", "ref": case.opened["id"]}], tz=self.config.tz)
        self.store.write(record)
        return Outcome(True, record, f"{attempted}: case {case_id} recorded as {record['id']}")

    def release(self, case_id: str, reason: str, *, signer_id: str | None = None,
                overrule_threat: bool = False) -> Outcome:
        extra = {"overrule_threat": True} if overrule_threat else {}
        return self._decide_case("quarantine.released", "release", "released", case_id, reason, signer_id, extra)

    def declare_threat(self, case_id: str, reason: str, *, signer_id: str | None = None) -> Outcome:
        return self._decide_case("quarantine.threat.declared", "declare", "rejected", case_id, reason, signer_id, {})

    def trust_source(self, domain: str, reason: str, *, expires: str | None, signer_id: str | None = None,
                     subdomains: bool = False, revoke: bool = False, today: date | None = None) -> Outcome:
        reason = _reason(reason)
        domain = domain.strip().lower().rstrip(".")
        if not _DOMAIN.match(domain):
            raise DecisionError(f"not a domain name: {domain!r}", 2)
        if not revoke:
            try:
                until = date.fromisoformat(expires or "")
            except ValueError as error:
                raise DecisionError("--expires YYYY-MM-DD is required", 2) from error
            if until < (today or date.today()):
                raise DecisionError("--expires must not be in the past", 2)
        who = self.person(signer_id)
        attempted = "trust-source"
        blocked = self._guard(who, attempted, {"domain": domain})
        if blocked:
            return blocked
        action, meaning = ("revoke", "rejected") if revoke else ("trust", "approved")
        decision = {"action": action, "domain": domain, "subdomains": subdomains}
        if not revoke:
            decision["expires"] = expires
        signature, refused = self._sign(who, attempted, {"domain": domain}, meaning=meaning, reason=reason,
                                        decision=decision, record_type="quarantine.source.trusted",
                                        ref=f"domain:{domain}")
        if refused:
            return refused
        data = {**{k: v for k, v in decision.items() if k != "action"}, "policy": self.config.trusted_source_policy,
                "decision": decision}
        if signature:
            data["signature"] = signature
        record = records.decision("quarantine.source.trusted", actor("human", who["id"], role=who.get("role") or None,
                                                                     display=who.get("name") or None),
                                  action=action, meaning=meaning, reason=reason,
                                  subject_=subject("source", f"domain:{domain}", sha256=content_hash(decision)),
                                  data=data, links=None, tz=self.config.tz)
        self.store.write(record)
        return Outcome(True, record, f"{action} source {domain} recorded as {record['id']}")


def _reason(reason: str | None) -> str:
    reason = (reason or "").strip()
    if not reason:
        raise DecisionError("--reason is required and must not be empty", 2)
    return reason


def create_identity(config: Config, *, signer_id: str, name: str, role: str,
                    passphrase: Callable[[str], str] | None = None) -> tuple[str, Path]:
    """Create the responsible person's key (I9 paths) and enrol it in the registry."""
    if not SIGNER_ID.match(signer_id):
        raise DecisionError("signer ids look like human:<id> (lower case letters, digits, . _ -)", 2)
    ask = passphrase or (lambda prompt: getpass.getpass(prompt))
    first = ask(f"New passphrase for {signer_id}: ")
    if len(first) < 8:
        raise DecisionError("use a passphrase of at least 8 characters", 2)
    if ask("Repeat the passphrase: ") != first:
        raise DecisionError("passphrases differ", 2)
    config.keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(config.keys_dir, 0o700)
    key_path = config.keys_dir / f"{slug(signer_id)}.key"
    key_id = generate_key(key_path, passphrase=first.encode())
    # aqt_evidence writes <slug>.key.pub; aqt-signoff uses the same name, so it is kept as is.
    enrol(config.registry, signer_id=signer_id, name=name, role=role, key_id=key_id,
          public_pem=Path(f"{key_path}.pub").read_text(encoding="ascii"))
    return key_id, key_path


def adopt_identity(config: Config, *, signer_id: str, name: str | None, role: str,
                   passphrase: Callable[[str], str] | None = None) -> tuple[str, Path, bool]:
    """Reuse the existing key of ``signer_id`` (for example from ``aqt-signoff init``).

    Returns the key id, its path and whether it was enrolled now. A key already enrolled for this
    signer is only reported; otherwise the passphrase must unlock it before it is enrolled."""
    key_path = config.keys_dir / f"{slug(signer_id)}.key"
    registry = load_registry(config.registry)
    try:
        key_id, _ = load_public_key(f"{key_path}.pub")
    except (OSError, ValueError):
        key_id = None
    known = _registered_key(registry, signer_id, key_id) if key_id else None
    if known is not None:
        if known.get("revoked_at"):
            raise DecisionError(f"the key {key_id} at {key_path} is revoked; create a new key with "
                                f"aqt-signoff init --id {signer_id} --add-key")
        return key_id, key_path, False
    ask = passphrase or (lambda prompt: getpass.getpass(prompt))
    try:
        signer = load_signer(key_path, passphrase=ask(f"Passphrase of the existing key {key_path}: ").encode())
    except (ValueError, TypeError) as error:
        raise DecisionError(f"{key_path} exists but could not be unlocked ({error}); enter its passphrase, "
                            "or move the file away if it is not yours") from error
    if signer_id not in registry and not name:
        raise DecisionError("--name is required to enrol a new signer", 2)
    enrol(config.registry, signer_id=signer_id, name=name or "", role=role, key_id=signer.key_id,
          public_pem=signer.public_key.public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"))
    return signer.key_id, key_path, True
