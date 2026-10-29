"""Signers, signatures with meaning, verification and policy."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from aqt_evidence import (MEANINGS, HumanCheckError, JsonlSink, SinkError, actor, bytes_hash, evidence_sources,
                          iter_evidence, new_record, open_sink, record_content_hash, require_human, sign_record,
                          subject as make_subject)
from aqt_evidence import detect_agent_context, generate_key, load_public_key
from aqt_evidence.crypto import key_file_format

from .errors import AuthFailed, NotFound, Refused, SignoffError, UsageError
from .registry import Authenticator, Registry, SignerEntry, TtyAuthenticator, parse_time, unlock
from .settings import Policy, Settings, load_settings
from .statements import SignatureStatus, build_statement, check_block, sign, statement_digest, statement_of
from .store import Store

SERVICE = actor("service", "service:aqt-signoff")


def format_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def file_ref(path: Path) -> str:
    """Path relative to the working directory (the project) when inside it, else absolute."""
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


@dataclass
class PolicyResult:
    meaning: str
    met: bool
    count: int
    policy: Policy
    authors: list[str]
    signers: list[str]
    note: str = ""

    def as_dict(self) -> dict:
        return {"meaning": self.meaning, "met": self.met, "count": self.count, "needed": self.policy.min_signatures,
                "policy": self.policy.as_dict(), "authors": self.authors, "signers": self.signers, "note": self.note}


@dataclass
class VerifyReport:
    subject: dict
    signatures: list[SignatureStatus]
    policies: dict[str, PolicyResult] = field(default_factory=dict)
    required: list[str] = field(default_factory=list)
    recorded: list[str] = field(default_factory=list)
    registry_problems: list[dict] = field(default_factory=list)   # registry keys that do not count

    @property
    def current(self) -> list[SignatureStatus]:
        return [s for s in self.signatures if s.subject.get("sha256") == self.subject.get("sha256")]

    @property
    def ok(self) -> bool:
        if any(s.status == "invalid" for s in self.signatures):
            return False
        if not any(s.valid for s in self.current):
            return False
        return all(self.policies[m].met for m in self.required)

    def summary(self) -> str:
        if any(s.status == "invalid" for s in self.signatures):
            return "INVALID: at least one signature does not verify or is a replayed copy"
        if not any(s.valid for s in self.current):
            return "UNSIGNED: no valid signature on the current content"
        unmet = [m for m in self.required if not self.policies[m].met]
        return f"POLICY NOT MET: {', '.join(unmet)}" if unmet else "SIGNED: valid signature(s) on the current content"

    def as_dict(self) -> dict:
        return {"ok": self.ok, "summary": self.summary(), "subject": self.subject,
                "signatures": [s.as_dict() for s in self.signatures],
                "policies": {m: p.as_dict() for m, p in self.policies.items()}, "required": self.required,
                "recorded": self.recorded, "registry_problems": self.registry_problems}


class Signoff:
    """Entry point. ``environ``/``chain``/``require_tty``/``clock`` exist so tests can be deterministic."""

    def __init__(self, settings: Settings | None = None, *, authenticator: Authenticator | None = None,
                 environ: dict | None = None, chain: list[str] | None = None, require_tty: bool = True,
                 stdin=None, clock: Callable[[], datetime] | None = None):
        self.settings = settings or load_settings()
        self.authenticator = authenticator or TtyAuthenticator()
        self.environ = os.environ if environ is None else environ
        self.chain, self.require_tty, self.stdin = chain, require_tty, stdin
        self.clock = clock or (lambda: datetime.now(UTC))
        self._registry: Registry | None = None
        self._store: Store | None = None
        self._sink = None
        self._records: tuple | None = None    # (stamp of the sources, records)
        from .actions import Actions
        self.actions = Actions(self)

    @classmethod
    def open(cls, **kwargs) -> "Signoff":
        settings_keys = {"config", "registry", "keys_dir", "state_dir", "sink", "evidence"}
        settings = load_settings(**{k: kwargs.pop(k) for k in list(kwargs) if k in settings_keys})
        return cls(settings, **kwargs)

    # ---- plumbing -------------------------------------------------------------------------------
    @property
    def registry(self) -> Registry:
        if self._registry is None:
            self._registry = Registry(self.settings.registry_path, self.settings.keys_dir)
        return self._registry

    def reload_registry(self) -> Registry:
        self._registry = None
        return self.registry

    @property
    def store(self) -> Store:
        if self._store is None:
            self._store = Store(self.settings.db_path)
        return self._store

    @property
    def sink(self):
        if self._sink is None:
            self._sink = open_sink(self.settings.sink)
        return self._sink

    def now(self) -> str:
        return format_time(self.clock())

    def sources(self) -> list[Path]:
        if self.settings.evidence is not None:
            return list(self.settings.evidence)
        paths = evidence_sources(self.environ)
        spec = self.settings.sink or ""
        sink_file = Path(spec[5:]) if spec.startswith("file:") else (
            self.sink.path if isinstance(self.sink, JsonlSink) else None)
        if sink_file is not None and sink_file.exists() and sink_file not in paths:
            paths.insert(0, sink_file)
        return paths

    def _stamp(self, paths: list[Path]) -> tuple:
        out = []
        for path in paths:
            try:
                info = os.stat(path)
                out.append((str(path), info.st_mtime_ns, info.st_size))
            except OSError:
                out.append((str(path), None, None))
        return tuple(out)

    def records(self) -> list[dict]:
        """All evidence records (``iter_evidence``), re-read whenever a source file changed."""
        sources = self.sources()
        stamp = self._stamp(sources)
        if self._records is None or self._records[0] != stamp:
            self._records = (stamp, [r for r in iter_evidence(sources) if isinstance(r, dict)])
        return list(self._records[1])

    def trail_sources(self) -> list[Path]:
        """The evidence sources that are aqt-trail logs (``trail.jsonl`` next to its ``trail.json``)."""
        return [p for p in self.sources() if p.name == "trail.jsonl" and (p.parent / "trail.json").exists()]

    def trust(self, records: list[dict] | None = None) -> Registry:
        """The registry, reconciled with the enrolment and revocation records (see ``Registry.reconcile``).
        Enrolments count from the chained trail when there is one, else from every evidence source."""
        registry = self.registry
        trail = self.trail_sources()
        stamp = (self._stamp([self.settings.registry_path]), self._stamp(self.sources()))
        if registry.reconciled and getattr(registry, "_stamp", None) == stamp:
            return registry
        records = self.records() if records is None else records
        enrolments = list(iter_evidence(trail)) if trail else records
        registry.reconcile(enrolments, records, source="trail" if trail else "evidence")
        registry._stamp = stamp
        return registry

    def check_signers(self) -> dict:
        """Every registry key and whether its enrolment evidence backs it (``aqt-signoff signers check``).
        ``ok`` is False when a key does not count; ``notes`` are discrepancies that do not stop it."""
        registry = self.trust()
        keys = []
        for signer in registry.signers:
            for key in signer.keys:
                ev = registry.key_evidence(key.key_id, signer.id)
                keys.append({"name": signer.name, "role": signer.role,
                             "state": "revoked" if key.revoked_at else "active", **ev.as_dict()})
        return {"ok": all(k["counts"] for k in keys), "registry": str(self.settings.registry_path),
                "evidence": "trail" if self.trail_sources() else "evidence", "keys": keys}

    def emit(self, record: dict, key=None) -> dict:
        """Append to the sink. The envelope is signed only for a JSONL sink (aqt-trail signs its own)."""
        if key is not None and isinstance(self.sink, JsonlSink):
            record = sign_record(record, key)
        return self.sink.append(record)

    def record(self, type: str, who: dict, action: str, **kwargs) -> dict:
        kwargs.setdefault("tz", self.settings.tz)
        return new_record(type, who, action, time=self.now(), **kwargs)

    def caller(self) -> dict:
        """Actor for non-human steps (prepare, claim, outcome): AQT_ACTOR, a detected agent, or a service."""
        claimed = self.environ.get("AQT_ACTOR")
        if claimed and ":" in claimed and claimed.split(":", 1)[0] in {"human", "agent", "service"}:
            return actor(claimed.split(":", 1)[0], claimed)
        context = detect_agent_context(self.environ, chain=self.chain)
        if context.is_agent:
            return actor("agent", f"agent:{context.harness}:pid{os.getppid()}", harness=context.harness)
        if self.settings.signer:
            return actor("human", self.settings.signer)
        return actor("service", "service:aqt-signoff")

    def signer_actor(self, signer: SignerEntry) -> dict:
        return actor("human", signer.id, role=signer.role, display=signer.name)

    def signer_entry(self, signer_id: str | None) -> SignerEntry:
        signer_id = signer_id or self.settings.signer
        if not signer_id:
            raise UsageError("no signer given; pass --signer or set [signoff] signer in the config")
        return self.registry.get(signer_id)

    def refuse(self, attempted: str, who: dict, reason_code: str, message: str, markers=None,
               subject: dict | None = None) -> Refused:
        """Record a refusal (best effort) and return the exception to raise."""
        try:
            self.emit(self.record("signoff.refused", who, "refused", subject=subject,
                                  data={"attempted_action": attempted, "reason_code": reason_code,
                                        "agent_markers": list(markers or [])}))
        except (SinkError, ValueError):
            pass
        return Refused(message, code=reason_code)

    def require_human(self, attempted: str, who: dict) -> None:
        try:
            require_human(environ=self.environ, chain=self.chain, require_tty=self.require_tty, stdin=self.stdin)
        except HumanCheckError as error:
            code = "agent_context" if error.context.is_agent else "no_tty"
            raise self.refuse(attempted, who, code, str(error), error.context.markers) from None

    def unlock(self, signer: SignerEntry, purpose: str, *, adopt: bool = True):
        """The signer's key, unlocked with a freshly entered passphrase. A key that is in the registry
        but has no enrolment record yet (made by another tool) gets one now (``adopt``); a key whose
        registry entry contradicts its enrolment record is refused."""
        try:
            key = unlock(self.registry, signer, self.authenticator, purpose)
        except AuthFailed as error:
            try:
                self.emit(self.record("signoff.auth.failed", self.signer_actor(signer), "auth.failed",
                                      subject=make_subject("signer", signer.id),
                                      data={"signer": signer.id, "operation": purpose, "code": error.code}))
            except (SinkError, ValueError):
                pass
            raise
        if adopt:
            self._ensure_enrolled(signer, key)
        return key

    def _ensure_enrolled(self, signer: SignerEntry, key) -> None:
        evidence = self.trust().key_evidence(key.key_id, signer.id)
        if evidence is not None and evidence.counts:
            return
        if evidence is None or not evidence.missing:
            why = "; ".join(evidence.problems) if evidence else "the key is not in the registry"
            raise self.refuse("sign", self.signer_actor(signer), "registry_mismatch",
                              f"the registry entry of {signer.id} does not match its enrolment record ({why}); "
                              "run 'aqt-signoff signers check'")
        entry = signer.active_key()
        self.emit(self.signed_record(
            "signoff.key.enrolled", "enroll", signer=signer, key=key, meaning="acknowledged",
            reason="Enrolment recorded at first use of a key enrolled outside aqt-signoff init",
            envelope_meaning=False, enrolled_at=entry.enrolled_at,
            subject=make_subject("key", entry.key_id, sha256=bytes_hash(entry.public_pem.encode("ascii"))),
            data={"signer": signer.id, "name": signer.name, "role": signer.role, "key_id": entry.key_id,
                  "public_pem": entry.public_pem, "adopted": True}), key)

    def signed_record(self, type: str, action: str, *, signer: SignerEntry, key, meaning: str, reason: str,
                      subject: dict, data: dict | None = None, links=None, envelope_meaning: bool = True,
                      **statement_extra) -> dict:
        statement = build_statement(record_type=type, signer=signer, key=key.key_id, meaning=meaning,
                                    reason=reason, subject=subject, signed_at=self.now(), tz=self.settings.tz,
                                    **statement_extra)
        payload = {**(data or {}), "signature": sign(statement, key)}
        return self.record(type, self.signer_actor(signer), action, subject=subject, reason=reason,
                           meaning=meaning if envelope_meaning else None, links=links, data=payload)

    # ---- identities ---------------------------------------------------------------------------
    def init_signer(self, signer_id: str, name: str, role: str, *, add_key: bool = False) -> dict:
        """Create a signer (or a new key for a signer whose keys are all revoked) and record the enrolment."""
        who = actor("human", signer_id, role=role or None, display=name or None)
        self.require_human("init", who)
        registry = self.reload_registry()
        if add_key:
            signer = registry.get(signer_id)
            if signer.active_key():
                raise UsageError(f"{signer_id} still has an active key; revoke it first", code="active_key")
        else:
            signer = registry.add_signer(signer_id, name, role)
        passphrase = self.authenticator.new_passphrase(signer_id, self.settings.passphrase_min_length)
        path = registry.key_path(signer_id)
        if path.exists():
            raise UsageError(f"{path} already exists; move it away or revoke the old key", code="key_exists")
        registry.keys_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(registry.keys_dir, 0o700)
        generate_key(path, passphrase=passphrase)
        try:
            _, public = load_public_key(f"{path}.pub")
            entry = registry.add_key(signer, public, self.now())
            from aqt_evidence import load_signer
            key = load_signer(path, passphrase=passphrase)
            record = self.signed_record(
                "signoff.key.enrolled", "enroll", signer=signer, key=key, meaning="acknowledged",
                reason="Key enrolled for electronic signatures", envelope_meaning=False, enrolled_at=entry.enrolled_at,
                subject=make_subject("key", entry.key_id, sha256=bytes_hash(entry.public_pem.encode("ascii"))),
                data={"signer": signer.id, "name": signer.name, "role": signer.role,
                      "key_id": entry.key_id, "public_pem": entry.public_pem})
            stored = self.emit(record, key)
            registry.save()
        except BaseException:
            for leftover in (path, Path(f"{path}.pub")):
                leftover.unlink(missing_ok=True)
            self.reload_registry()
            raise
        return stored

    def rekey(self, signer_id: str | None = None) -> dict:
        """Unlock the signer's key once: a key file from an earlier version (PKCS#8, PBKDF2) is
        re-encrypted with scrypt, and a key without an enrolment record gets one."""
        signer = self.signer_entry(signer_id)
        self.require_human("rekey", self.signer_actor(signer))
        path = self.registry.key_path(signer.id)
        before = key_file_format(path) if path.exists() else None
        active = signer.active_key()
        evidence = self.trust().key_evidence(active.key_id, signer.id) if active else None
        self.unlock(signer, "re-encrypt your key file")
        after = key_file_format(path)
        return {"signer": signer.id, "path": str(path), "format": after,
                "upgraded": before != after and after == "aqt-key",
                "enrolled": not (evidence and evidence.counts)}

    def revoke(self, signer_id: str, reason: str, *, compromised_since: str | None = None,
               lost: bool = False) -> dict:
        registry = self.reload_registry()
        signer = registry.get(signer_id)
        who = self.signer_actor(signer)
        self.require_human("revoke", who)
        if not reason or not reason.strip():
            raise UsageError("a revocation needs a reason")
        active = signer.active_key()
        if active is None:
            raise NotFound(f"{signer_id} has no active key", code="no_active_key")
        revoked_at = self.now()
        if compromised_since:
            try:
                since = parse_time(compromised_since)
            except ValueError as error:
                raise UsageError("--compromised-since must be an RFC 3339 time") from error
            if since.tzinfo is None:
                raise UsageError("--compromised-since needs a zone (e.g. Z)")
            revoked_at = min(revoked_at, format_time(since), key=parse_time)
        subject = make_subject("key", active.key_id, sha256=bytes_hash(active.public_pem.encode("ascii")))
        data = {"signer": signer.id, "key_id": active.key_id, "revoked_at": revoked_at,
                "compromised_since": compromised_since and format_time(parse_time(compromised_since)),
                "signed": not lost}
        data = {k: v for k, v in data.items() if v is not None}
        if lost:
            record, key = self.record("signoff.key.revoked", who, "revoke", subject=subject, reason=reason,
                                      data=data), None
        else:
            key = self.unlock(signer, "revoke this key", adopt=False)
            record = self.signed_record("signoff.key.revoked", "revoke", signer=signer, key=key,
                                        meaning="acknowledged", reason=reason, subject=subject, data=data,
                                        envelope_meaning=False)
        active.revoked_at = revoked_at
        stored = self.emit(record, key)
        registry.save()
        registry.retire_key_file(signer.id, active.key_id)
        return stored

    # ---- signing -------------------------------------------------------------------------------
    def file_subject(self, path: str | os.PathLike) -> dict:
        path = Path(path)
        if not path.is_file():
            raise NotFound(f"{path} is not a file")
        return make_subject("file", file_ref(path), sha256=bytes_hash(path.read_bytes()))

    def find_record(self, record_id: str) -> dict:
        for record in self.records():
            if record.get("id") == record_id:
                return record
        raise NotFound(f"record {record_id} not found in {', '.join(map(str, self.sources())) or 'any source'}")

    def record_subject(self, record_id: str) -> tuple[dict, dict]:
        record = self.find_record(record_id)
        return make_subject("record", record_id, sha256=record_content_hash(record)), record

    def sign(self, subject: dict, meaning: str, reason: str, *, signer_id: str | None = None,
             authors: list[str] | tuple = (), links: list[dict] | None = None) -> dict:
        """Sign ``subject`` (``{kind, ref, sha256}``) with a meaning. Returns the stored record."""
        if meaning not in MEANINGS:
            raise UsageError(f"meaning must be one of {', '.join(sorted(MEANINGS))}")
        if not reason or not reason.strip():
            raise UsageError("a signature needs a reason")
        if not subject.get("sha256"):
            raise UsageError("the subject needs a sha256")
        signer = self.signer_entry(signer_id)
        who = self.signer_actor(signer)
        self.require_human("sign", who)
        policy = self.settings.policy(meaning)
        if policy.roles and signer.role not in policy.roles:
            raise self.refuse("sign", who, "role_not_allowed",
                              f"role {signer.role!r} may not sign with meaning {meaning!r} "
                              f"(allowed: {', '.join(policy.roles)})", subject=subject)
        records = self.records()
        statuses = self.signatures_for(subject["sha256"], records=records)
        all_authors = (set(authors) | {s.signer_id for s in statuses if s.valid and s.meaning == "authored"}
                       | self.record_authors(subject["sha256"], records))
        if policy.distinct_from_author and signer.id in all_authors:
            raise self.refuse("sign", who, "self_approval",
                              f"{signer.id} is an author of this content and may not sign it as {meaning!r}",
                              subject=subject)
        key = self.unlock(signer, f"sign as {meaning!r}")
        if subject.get("kind") == "record":
            links = [*(links or []), {"rel": "signs", "ref": subject["ref"]}]
        record = self.signed_record("signoff.signature", "sign", signer=signer, key=key, meaning=meaning,
                                    reason=reason, subject=subject, links=links, data={"meaning": meaning})
        return self.emit(record, key)

    def withdraw(self, signature_id: str, reason: str) -> dict:
        """The signer withdraws one of their signatures; it then shows as invalidated."""
        original = self.find_record(signature_id)
        st = statement_of(original)
        if st is None:
            raise UsageError(f"{signature_id} carries no signed statement")
        signer = self.registry.get(st["signer"]["id"])
        who = self.signer_actor(signer)
        self.require_human("withdraw", who)
        if not reason or not reason.strip():
            raise UsageError("a withdrawal needs a reason")
        key = self.unlock(signer, "withdraw a signature")
        subject = make_subject("record", signature_id, sha256=record_content_hash(original))
        record = self.signed_record(
            "signoff.invalidation", "withdraw", signer=signer, key=key, meaning="rejected", reason=reason,
            subject=subject, envelope_meaning=False, links=[{"rel": "invalidates", "ref": signature_id}],
            data={"signature_record": signature_id, "cause": "withdrawn",
                  "signed_sha256": st["subject"]["sha256"]},
            withdraws=statement_digest(st))
        return self.emit(record, key)

    # ---- verification --------------------------------------------------------------------------
    def record_authors(self, sha256: str, records: list[dict]) -> set[str]:
        """Actor ids of the evidence records whose ``record_content_hash`` is ``sha256``: the authors of
        a signed record, whichever check (file, record, hash) asks."""
        authors = set()
        for record in records:
            who = record.get("actor") if isinstance(record, dict) else None
            if not isinstance(who, dict) or not isinstance(who.get("id"), str):
                continue
            try:
                if record_content_hash(record) == sha256:
                    authors.add(who["id"])
            except ValueError:
                continue
        return authors

    def _withdrawals(self, records: list[dict], registry: Registry) -> dict[str, list[SignatureStatus]]:
        """Valid signed withdrawals, keyed by the digest of the statement they withdraw. A withdrawal
        names it in its signed ``withdraws``; earlier withdrawals name the carrying record by id and
        content hash (their signed subject), which must match exactly. The unsigned
        ``data.signature_record`` is never used."""
        by_id = {r["id"]: r for r in records if isinstance(r, dict) and isinstance(r.get("id"), str)}
        found: dict[str, list[SignatureStatus]] = {}
        for record in records:
            if record.get("type") != "signoff.invalidation" or record.get("action") != "withdraw":
                continue
            status = check_block((record.get("data") or {}).get("signature"), registry, record=record)
            if not status.valid:
                continue
            digest = statement_of(record).get("withdraws")
            if not isinstance(digest, str):
                target = by_id.get(status.subject.get("ref"))
                try:
                    exact = target is not None and record_content_hash(target) == status.subject.get("sha256")
                except ValueError:
                    exact = False
                digest = statement_digest(statement_of(target)) if exact else None
            if digest:
                found.setdefault(digest, []).append(status)
        return found

    def _evaluate(self, records: list[dict], match: Callable[[dict], bool]) -> list[SignatureStatus]:
        """One status per carrying record. A statement counts once: a copy of the same signed statement
        in another record is reported ``invalid`` (replay), and a withdrawal applies to every copy."""
        registry = self.trust(records)
        withdrawals = self._withdrawals(records, registry)
        results, first = [], {}
        for record in records:
            st = statement_of(record)
            if st is None or record.get("type") == "signoff.invalidation" or not match(st):
                continue
            status = check_block(record["data"]["signature"], registry, record=record)
            digest = status.statement_sha256
            if digest and status.status != "invalid":
                if digest in first:
                    status.worsen("invalid", f"replayed copy of the statement signed in record "
                                             f"{first[digest].record_id}; it counts once")
                else:
                    first[digest] = status
            withdrawal = next((w for w in withdrawals.get(digest, []) if w.signer_id == status.signer_id), None)
            if withdrawal:
                status.worsen("invalidated", f"withdrawn by the signer: {withdrawal.reason}")
            results.append(status)
        return results

    def signatures_for(self, sha256: str, *, meaning: str | None = None,
                       records: list[dict] | None = None) -> list[SignatureStatus]:
        records = self.records() if records is None else records
        statuses = self._evaluate(records, lambda st: st.get("subject", {}).get("sha256") == sha256)
        return [s for s in statuses if meaning is None or s.meaning == meaning]

    def evaluate_policies(self, statuses: list[SignatureStatus], sha256: str, *, authors=(), required=(),
                          policies: dict[str, Policy] | None = None) -> dict[str, PolicyResult]:
        current = [s for s in statuses if s.subject.get("sha256") == sha256 and s.valid]
        all_authors = sorted(set(authors) | {s.signer_id for s in current if s.meaning == "authored"})
        results = {}
        for meaning in sorted({s.meaning for s in current} | set(required)):
            policy = (policies or {}).get(meaning) or self.settings.policy(meaning)
            signers = sorted({s.signer_id for s in current if s.meaning == meaning
                              and (not policy.roles or s.authorized_role in policy.roles)
                              and not (policy.distinct_from_author and s.signer_id in all_authors)})
            note = ""
            if len(signers) < policy.min_signatures:
                note = f"needs {policy.min_signatures - len(signers)} more valid signature(s)"
                if policy.distinct_from_author and all_authors:
                    note += f" from someone other than {', '.join(all_authors)}"
                if policy.roles:
                    note += f" with role {' or '.join(policy.roles)}"
            results[meaning] = PolicyResult(meaning, len(signers) >= policy.min_signatures, len(signers), policy,
                                            all_authors, signers, note)
        return results

    def verify_file(self, path, *, required=(), record_invalidations: bool = True) -> VerifyReport:
        current = self.file_subject(path)
        records = self.records()
        statuses = self._evaluate(records, lambda st: st.get("subject", {}).get("kind") == "file" and (
            st["subject"].get("ref") == current["ref"] or st["subject"].get("sha256") == current["sha256"]))
        return self._finish(current, statuses, records, required=required, record=record_invalidations)

    def verify_record(self, record_id: str, *, required=(), record_invalidations: bool = True) -> VerifyReport:
        current, target = self.record_subject(record_id)
        records = self.records()
        statuses = self._evaluate(records, lambda st: st.get("subject", {}).get("kind") == "record"
                                  and st["subject"].get("ref") == record_id)
        authors = [target["actor"]["id"]] if isinstance(target.get("actor"), dict) else []
        return self._finish(current, statuses, records, required=required, authors=authors,
                            record=record_invalidations)

    def verify_hash(self, sha256: str, *, required=(), authors=()) -> VerifyReport:
        """Signatures over ``sha256``. The actors of records with that content hash count as authors."""
        records = self.records()
        statuses = self.signatures_for(sha256, records=records)
        return self._finish({"kind": "hash", "ref": sha256, "sha256": sha256}, statuses, records,
                            required=required, authors=authors, record=False)

    def _finish(self, current: dict, statuses: list[SignatureStatus], records: list[dict], *, required=(),
                authors=(), record: bool) -> VerifyReport:
        report = VerifyReport(current, statuses, required=list(required))
        authors = set(authors) | self.record_authors(current["sha256"], records)
        report.registry_problems = [k for k in self.check_signers()["keys"] if not k["counts"]]
        for status in statuses:
            if status.subject.get("sha256") != current["sha256"] and status.status != "invalid":
                status.worsen("invalidated", f"content changed since signing (signed {status.subject.get('sha256')})")
                if record and status.record_id:
                    stored = self._record_invalidation(status, current, records)
                    if stored:
                        report.recorded.append(stored["id"])
        report.policies = self.evaluate_policies(statuses, current["sha256"], authors=authors, required=required)
        return report

    def _record_invalidation(self, status: SignatureStatus, current: dict, records: list[dict]) -> dict | None:
        for existing in records:
            data = existing.get("data", {}) if isinstance(existing.get("data"), dict) else {}
            if (existing.get("type") == "signoff.invalidation" and data.get("signature_record") == status.record_id
                    and data.get("observed_sha256") == current["sha256"]):
                return None
        record = self.record("signoff.invalidation", SERVICE, "content-changed", subject=current,
                             links=[{"rel": "invalidates", "ref": status.record_id}],
                             data={"signature_record": status.record_id, "cause": "content-changed",
                                   "signed_sha256": status.subject.get("sha256"),
                                   "observed_sha256": current["sha256"]})
        try:
            return self.emit(record)
        except SinkError:
            return None

    # ---- delivery ------------------------------------------------------------------------------
    def sync(self) -> dict:
        delivered, failed = [], []
        for record in self.store.pending():
            try:
                self.sink.append(record)
            except SinkError as error:
                failed.append({"id": record["id"], "error": str(error)})
                continue
            self.store.drop_pending(record["id"])
            delivered.append(record["id"])
        return {"delivered": delivered, "failed": failed}


__all__ = ["PolicyResult", "Signoff", "SignoffError", "VerifyReport", "file_ref", "format_time"]
