"""Signers, signatures with meaning, verification and policy."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable

from aqt_evidence import (MEANINGS, HumanCheckError, JsonlSink, SinkError, Text, actor, bytes_hash, content_hash,
                          evidence_sources, iter_evidence, new_record, open_sink, read_jsonl, record_content_hash,
                          require_human, sign_record, subject as make_subject)
from aqt_evidence import detect_agent_context, generate_key, load_public_key
from aqt_evidence.crypto import key_file_format

from .errors import AuthFailed, NotFound, Refused, SignoffError, UsageError
from .enrolment import ENROLLED, REVOKED, EnrolmentHistory, kind_of, revocations as revocations_of
from .registry import (Authenticator, KeyEntry, Registry, SignerEntry, TtyAuthenticator, parse_time, rebootstrap_text,
                       unlock)
from .settings import Policy, Settings, load_settings
from .statements import SignatureStatus, build_statement, check_block, sign, statement_digest, statement_of
from .store import Store

SERVICE = actor("service", "service:aqt-signoff")


def format_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _data_of(record: dict) -> dict:
    return record.get("data") if isinstance(record.get("data"), dict) else {}


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
    registry_warnings: list[str] = field(default_factory=list)    # e.g. an unconfirmed re-bootstrap

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
            return Text("signoff.verify.invalid",
                        "INVALID: at least one signature does not verify or is a replayed copy")
        if not any(s.valid for s in self.current):
            return Text("signoff.verify.unsigned", "UNSIGNED: no valid signature on the current content")
        unmet = [m for m in self.required if not self.policies[m].met]
        return Text("signoff.verify.policy_not_met", "POLICY NOT MET: {meanings}", meanings=", ".join(unmet)) \
            if unmet else Text("signoff.verify.signed", "SIGNED: valid signature(s) on the current content")

    def as_dict(self) -> dict:
        return {"ok": self.ok, "summary": self.summary(), "subject": self.subject,
                "signatures": [s.as_dict() for s in self.signatures],
                "policies": {m: p.as_dict() for m, p in self.policies.items()}, "required": self.required,
                "recorded": self.recorded, "registry_problems": self.registry_problems,
                "registry_warnings": self.registry_warnings}


def policy_note(missing: int, others_than: list[str], roles) -> Text:
    """Why a policy is not met: ``missing`` more valid signatures, from someone other than ``others_than`` (the
    authors, when the policy wants a signer distinct from them), with one of ``roles``."""
    authors, roles = ", ".join(others_than), " or ".join(roles or ())
    if others_than and roles:
        return Text("signoff.policy.needs_more_other_role", "needs {n} more valid signature(s) from someone other "
                    "than {authors} with role {roles}", n=missing, authors=authors, roles=roles)
    if others_than:
        return Text("signoff.policy.needs_more_other", "needs {n} more valid signature(s) from someone other than "
                    "{authors}", n=missing, authors=authors)
    if roles:
        return Text("signoff.policy.needs_more_role", "needs {n} more valid signature(s) with role {roles}",
                    n=missing, roles=roles)
    return Text("signoff.policy.needs_more", "needs {n} more valid signature(s)", n=missing)


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
        """The registry, reconciled with the enrolment and revocation records (see ``Registry.reconcile``
        and ``enrolment``). Enrolments count from the chained trail when there is one; else from the
        enrolment records of an export (``signers export``) that the registry file carries, followed by
        every evidence source; else from every evidence source. Revocations count from every source.
        With a trail, ``registry.pre_trail`` lists the enrolment requests that exist only in other sources,
        were written before the trail and are not imported yet; ``registry.ignored`` the records outside the
        trail that never count (written after the trail started, or after the one import)."""
        registry = self.registry
        trail = self.trail_sources()
        stamp = (self._stamp([self.settings.registry_path]), self._stamp(self.sources()))
        if registry.reconciled and getattr(registry, "_stamp", None) == stamp:
            return registry
        records = self.records() if records is None else records
        enrolments, revocations, source = self._enrolment_inputs(trail, records)
        registry.reconcile(enrolments, revocations, source=source)
        importable, registry.ignored = self._side_enrolments(trail, enrolments, registry) if trail else ([], [])
        registered = {(s.id, k.key_id) for s in registry.signers for k in s.keys}
        registry.pre_trail = [r for r in importable if kind_of(r) == "request"
                              and (_data_of(r).get("signer"), _data_of(r).get("key_id")) in registered]
        registry._stamp = stamp
        return registry

    def _enrolment_inputs(self, trail: list[Path], records: list[dict]) -> tuple[list[dict], list[dict], str]:
        """(enrolment records in order, revocation sources, source name) for ``Registry.reconcile``."""
        if trail:
            return list(iter_evidence(trail)), records, "trail"
        embedded = self.registry.embedded
        if embedded:
            own = list(embedded.get("records") or [])
            ids = {r.get("id") for r in own}
            return ([*own, *(r for r in records if r.get("id") not in ids)],
                    [*records, *(embedded.get("revocations") or [])], "registry export")
        return records, records, "evidence"

    def _trail_genesis(self, trail: list[Path]) -> datetime | None:
        """When the trail started: the earliest of its first record's time and ``trail.json`` ``created``."""
        times = []
        for path in trail:
            try:
                times.append(json.loads((path.parent / "trail.json").read_text(encoding="utf-8")).get("created"))
            except (OSError, ValueError, AttributeError):
                pass
            try:
                first = next(iter(read_jsonl(path)), None)
            except (OSError, SinkError, ValueError):
                first = None
            times.append(first.get("time") if isinstance(first, dict) else None)
        moments = []
        for value in times:
            try:
                moment = parse_time(value)
            except (TypeError, ValueError, AttributeError):
                continue
            if moment.tzinfo:
                moments.append(moment)
        return min(moments) if moments else None

    def _side_enrolments(self, trail: list[Path], enrolments: list[dict],
                         registry: Registry) -> tuple[list[dict], list[dict]]:
        """(importable, ignored): the enrolment and revocation records in the non-trail sources that the
        trail does not hold, neither directly nor through the import that counts (``registry`` is reconciled
        with ``enrolments``). Importable are those written before the trail started, as long as nothing was
        imported yet; ``ignored`` are the other enrolment records, which never count (revocations apply from
        every source anyway)."""
        known = {r.get("id") for r in enrolments if isinstance(r, dict)}
        counted = {entry["record"] for entry in registry.history.imports} if registry.history else set()
        for record in enrolments:
            if kind_of(record) == "import" and record.get("id") in counted:
                known.update(item.get("id") for item in record["data"]["imported"] if isinstance(item, dict))
        side = [p for p in self.sources() if p not in trail]
        found = [r for r in iter_evidence(side) if isinstance(r, dict) and r.get("type") in (ENROLLED, REVOKED)
                 and r.get("id") not in known]
        if counted:
            return [], [r for r in found if r.get("type") == ENROLLED]
        genesis = self._trail_genesis(trail)

        def before(record) -> bool:
            try:
                moment = parse_time(record.get("time"))
            except (TypeError, ValueError, AttributeError):
                return False
            return genesis is None or (moment.tzinfo is not None and moment < genesis)

        return [r for r in found if before(r)], [r for r in found if r.get("type") == ENROLLED and not before(r)]

    def check_signers(self) -> dict:
        """Every registry key and whether the enrolment evidence backs it (``aqt-signoff signers check``).

        ``ok`` is False when a key does not count (pending approval, conflicting records, a registry entry
        that contradicts its enrolment), when a record signed by an enrolled key does not count, when
        enrolment records from before the trail were not imported, or when a re-bootstrap is not confirmed.
        ``notes`` are discrepancies that do not stop a key. ``bootstrap`` is the first signer (counted
        without approval), ``rebootstrap`` every later one, ``pending`` every enrolment waiting for an
        approval (also those not in the registry), ``problems``/``ignored`` registry-wide findings."""
        registry = self.trust()
        history = registry.history
        keys = []
        pre_trail = {(_data_of(r).get("signer"), _data_of(r).get("key_id")): r for r in registry.pre_trail}
        ignored = {(_data_of(r).get("signer"), _data_of(r).get("key_id")): r for r in registry.ignored
                   if kind_of(r) == "request"}
        for signer in registry.signers:
            for key in signer.keys:
                ev = registry.key_evidence(key.key_id, signer.id)
                row = {"name": signer.name, "role": signer.role,
                       "state": "revoked" if key.revoked_at else "active", **ev.as_dict()}
                if (signer.id, key.key_id) in pre_trail and ev.missing:
                    row["problems"] = [*row["problems"], "its enrolment record is in a file written before the trail "
                                       "(" + ", ".join(str(p) for p in self._pre_trail_files()) + "): a signer imports "
                                       "it once with 'aqt-signoff signers import'"]
                elif (signer.id, key.key_id) in ignored and ev.missing:
                    late = ignored[(signer.id, key.key_id)]
                    row["problems"] = [f"its only enrolment record {late.get('id')} ({late.get('time')}) is outside the "
                                       "trail and was added after the trail started or after the import: it never "
                                       "counts and cannot be imported. Remove this key from the registry unless you "
                                       "know it (a key of yours is enrolled again and approved)"]
                keys.append(row)
        in_registry = {(k["signer"], k["key_id"]) for k in keys}
        pending = [{"signer": s.signer, "key_id": s.key_id, "name": s.name, "role": s.role, "record": s.request.get("id"),
                    "time": s.time, "in_registry": (s.signer, s.key_id) in in_registry,
                    "observed": s.request.get("observed"),
                    "approve": f"aqt-signoff signers approve {s.signer} --key {s.key_id}"} for s in history.pending()]
        problems = list(history.problems)
        if registry.pre_trail:
            problems.append(f"{len(registry.pre_trail)} enrolment record(s) from before the trail are only in "
                            + ", ".join(str(p) for p in self._pre_trail_files())
                            + ": their keys do not count until a signer imports them once with "
                              "'aqt-signoff signers import'")
        rebootstrap = [dict(entry) for entry in history.rebootstraps]
        ok = (all(k["counts"] for k in keys) and not problems
              and all(entry["confirmed_by"] for entry in rebootstrap))
        notes = list(history.notes)
        if registry.ignored:
            notes.append(f"{len(registry.ignored)} enrolment record(s) in "
                         + ", ".join(str(p) for p in self._pre_trail_files())
                         + " are not in the trail and were added after the trail started or after the import ("
                         + ", ".join(str(r.get("id")) for r in registry.ignored[:5])
                         + (", ..." if len(registry.ignored) > 5 else "") + "): they never count")
        if registry.embedded and history.source != "registry export":
            notes.append(f"{self.settings.registry_path} carries the enrolment records of an export; with a trail "
                         "they are not used")
        return {"ok": ok, "registry": str(self.settings.registry_path), "evidence": history.source, "keys": keys,
                "bootstrap": history.bootstrap, "rebootstrap": rebootstrap, "pending": pending,
                "imports": list(history.imports), "problems": problems, "ignored": notes,
                "unsigned_revocations": list(registry.unsigned_revocations)}

    def export_registry(self) -> dict:
        """The registry with the enrolment evidence that backs it (``enrolment_evidence``: the enrolment and
        revocation records in evidence order, and revocations from other sources), for verification on
        another machine (``--registry FILE``; see ``trust``)."""
        registry = self.trust()
        records = self.records()
        enrolments, revocations, source = self._enrolment_inputs(self.trail_sources(), records)
        own = [r for r in enrolments if isinstance(r, dict) and r.get("type") in (ENROLLED, REVOKED)]
        ids = {r.get("id") for r in own}
        extra = []
        for record in revocations:
            if isinstance(record, dict) and record.get("type") == REVOKED and record.get("id") not in ids:
                ids.add(record.get("id"))
                extra.append(record)
        return {**registry.as_dict(), "enrolment_evidence": {"source": source, "exported_at": self.now(),
                                                             "records": own, "revocations": extra}}

    def _pre_trail_files(self) -> list[Path]:
        trail = self.trail_sources()
        return [p for p in self.sources() if p not in trail and p.exists()]

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
            raise UsageError(Text("signoff.error.no_signer",
                                  "no signer given; pass --signer or set [signoff] signer in the config"))
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
            message = error.args[0] if error.args and isinstance(error.args[0], str) else str(error)
            raise self.refuse(attempted, who, code, message, error.context.markers) from None

    def unlock(self, signer: SignerEntry, purpose: str, *, adopt: bool = True, require_counting: bool = True):
        """The signer's key, unlocked with a freshly entered passphrase. A key that is in the registry
        but has no enrolment record yet (made by another tool) gets one now (``adopt``); a key whose
        registry entry contradicts its enrolment record, or (``require_counting``) whose enrolment
        waits for an approval, is refused."""
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
            self._ensure_enrolled(signer, key, require_counting=require_counting)
        return key

    def _enrolment_record(self, signer: SignerEntry, key, entry: KeyEntry, *, role: str | None = None,
                          reason: str = "Key enrolled for electronic signatures", **extra) -> dict:
        """A self-signed enrolment request for ``entry`` (the key proves that its holder has it)."""
        role = role or signer.role
        as_enrolled = SignerEntry(signer.id, signer.name, role, signer.keys)
        return self.signed_record(
            ENROLLED, "enroll", signer=as_enrolled, key=key, meaning="acknowledged", reason=reason,
            envelope_meaning=False, enrolled_at=entry.enrolled_at,
            subject=make_subject("key", entry.key_id, sha256=bytes_hash(entry.public_pem.encode("ascii"))),
            data={"signer": signer.id, "name": signer.name, "role": role, "key_id": entry.key_id,
                  "public_pem": entry.public_pem, **extra})

    def _ensure_enrolled(self, signer: SignerEntry, key, *, require_counting: bool = True,
                         reason: str = "Enrolment recorded at first use of a key enrolled outside aqt-signoff init",
                         adopted: bool = True) -> dict | None:
        """Record the enrolment of a registry key that has none (returns the record), refuse a key whose
        registry entry contradicts its enrolment, and with ``require_counting`` one that does not count."""
        registry = self.trust()
        evidence = registry.key_evidence(key.key_id, signer.id)
        if evidence is not None and evidence.counts:
            if require_counting and evidence.revoked_at and parse_time(evidence.revoked_at) <= self.clock():
                why = (Text("signoff.refused.why_conflicting", "conflicting enrolment records (see 'aqt-signoff "
                            "signers check')") if evidence.stopped_at == evidence.revoked_at else
                       Text("signoff.refused.why_revoked", "a signoff.key.revoked record revokes it"))
                raise self.refuse("sign", self.signer_actor(signer), "registry_mismatch", Text(
                    "signoff.refused.key_stopped", "the key {key} of {signer} does not count from {time}: {why}; "
                    "revoke it and enrol a new key ('aqt-signoff init --add-key')", key=key.key_id, signer=signer.id,
                    time=evidence.revoked_at, why=why))
            return None
        stored = None
        if evidence is not None and evidence.missing:
            if any(_data_of(r).get("key_id") == key.key_id for r in registry.pre_trail):
                raise self.refuse("sign", self.signer_actor(signer), "import_needed", Text(
                    "signoff.refused.import_needed", "the enrolment of {signer} is in a file written before the "
                    "trail; a signer imports those records once with 'aqt-signoff signers import'", signer=signer.id))
            entry = next(k for k in signer.keys if k.key_id == key.key_id)
            stored = self.emit(self._enrolment_record(signer, key, entry, reason=reason,
                                                      **({"adopted": True} if adopted else {})), key)
            evidence = self.trust().key_evidence(key.key_id, signer.id)
            if evidence is not None and (evidence.counts or not require_counting):
                return stored
        if evidence is not None and evidence.pending:
            if not require_counting:
                return stored
            raise self.refuse("sign", self.signer_actor(signer), "enrolment_pending", Text(
                "signoff.refused.enrolment_pending", "the key {key} of {signer} does not count yet: its enrolment "
                "waits for an approval by another enrolled signer ('aqt-signoff signers approve {signer} --key "
                "{key}')", key=key.key_id, signer=signer.id))
        why = "; ".join(evidence.problems) if evidence else Text("signoff.refused.why_not_in_registry",
                                                                 "the key is not in the registry")
        raise self.refuse("sign", self.signer_actor(signer), "registry_mismatch", Text(
            "signoff.refused.registry_mismatch", "the registry entry of {signer} does not match its enrolment record "
            "({why}); run 'aqt-signoff signers check'", signer=signer.id, why=why))

    def record_enrolment(self, signer_id: str, key, *, tool: str = "another tool") -> dict | None:
        """Record the self-signed enrolment of a registry key that ``tool`` just created with its holder's
        passphrase (aqt-quarantine init). None when the key already has one. The enrolment counts at once
        only for the first signer; otherwise it waits for an approval (``approve_enrolment``)."""
        signer = self.reload_registry().get(signer_id)
        return self._ensure_enrolled(signer, key, require_counting=False, adopted=False,
                                     reason=f"Key enrolled for electronic signatures ({tool})")

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
    def _require_imported(self) -> None:
        if self.trust().pre_trail:
            raise UsageError(f"enrolment records from before the trail are only in "
                             f"{', '.join(map(str, self._pre_trail_files()))}; import them once first with "
                             "'aqt-signoff signers import' (run by a signer listed there)", code="import_needed")

    def init_signer(self, signer_id: str, name: str, role: str, *, add_key: bool = False) -> dict:
        """Create a signer (or a new key for an existing signer) and record the enrolment request.

        The first signer counts at once (bootstrap). Every later enrolment counts after another enrolled
        signer approves it (``approve_enrolment``). ``add_key`` for a signer whose active key counts is a
        rotation: the old key approves the new one and is revoked (same role; a role change is approved
        by another signer). ``add_key`` for a signer without an active key records a new request with
        ``role`` (default: the signer's role)."""
        who = actor("human", signer_id, role=role or None, display=name or None)
        self.require_human("init", who)
        registry = self.reload_registry()
        self._require_imported()
        requested = None
        if add_key:
            signer = registry.get(signer_id)
            active = signer.active_key()
            if active:
                evidence = self.trust().key_evidence(active.key_id, signer.id)
                if evidence is not None and evidence.counts and not evidence.revoked_at:
                    return self._rotate(signer, role)
                raise UsageError(f"{signer_id} still has an active key {active.key_id} that does not count; revoke "
                                 "it first", code="active_key")
            requested = (role or "").strip() or signer.role
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
            stored = self.emit(self._enrolment_record(signer, key, entry, role=requested), key)
            registry.save()
        except BaseException:
            for leftover in (path, Path(f"{path}.pub")):
                leftover.unlink(missing_ok=True)
            self.reload_registry()
            raise
        if requested and requested != signer.role:      # a re-bootstrap counts at once: the file follows it
            evidence = self.trust().key_evidence(entry.key_id, signer.id)
            if evidence is not None and evidence.basis == "rebootstrap":
                signer.role = requested
                registry.save()
        return stored

    def _rotate(self, signer: SignerEntry, role: str | None) -> dict:
        """Replace the signer's counting key: the new key's request, approved by the old key, then the
        old key's revocation, both signed by it. Returns the request record."""
        if role and role.strip() and role.strip() != signer.role:
            raise UsageError(f"a role change is approved by another enrolled signer: "
                             f"'aqt-signoff signers approve {signer.id} --key KEY --role {role.strip()}'",
                             code="role_change")
        registry = self.registry
        old = signer.active_key()
        old_key = self.unlock(signer, "rotate your key (current passphrase)")
        passphrase = self.authenticator.new_passphrase(signer.id, self.settings.passphrase_min_length)
        path = registry.key_path(signer.id)
        fresh = path.with_name(f"{path.stem}.new.key")
        for leftover in (fresh, Path(f"{fresh}.pub")):
            leftover.unlink(missing_ok=True)
        generate_key(fresh, passphrase=passphrase)
        try:
            from aqt_evidence import load_signer
            _, public = load_public_key(f"{fresh}.pub")
            new_key = load_signer(fresh, passphrase=passphrase)
            entry = registry.add_key(signer, public, self.now())
            request = self._enrolment_record(signer, new_key, entry, reason="Key rotated: new key")
            stored = self.emit(request, new_key)
            approval = self.emit(self._approval_record(signer, old_key, request, signer.id, entry, signer.role,
                                                       f"Key rotation from {old.key_id}"), old_key)
            approved_at = parse_time(approval.get("time") or self.now())     # the trail writer's time
            revoked_at = format_time(max(self.clock(), approved_at + timedelta(microseconds=1)))
            self.emit(self.signed_record(
                REVOKED, "revoke", signer=signer, key=old_key, meaning="acknowledged",
                reason=f"Key rotated to {entry.key_id}", envelope_meaning=False,
                subject=make_subject("key", old.key_id, sha256=bytes_hash(old.public_pem.encode("ascii"))),
                data={"signer": signer.id, "key_id": old.key_id, "revoked_at": revoked_at, "signed": True,
                      "rotated_to": entry.key_id}), old_key)
            old.revoked_at = revoked_at
            registry.retire_key_file(signer.id, old.key_id)
            os.replace(fresh, path)
            os.replace(f"{fresh}.pub", f"{path}.pub")
            registry.save()
        except BaseException:
            for leftover in (fresh, Path(f"{fresh}.pub")):
                leftover.unlink(missing_ok=True)
            self.reload_registry()
            raise
        return stored

    def _approval_record(self, approver: SignerEntry, key, request: dict, signer_id: str, entry, role: str,
                         reason: str) -> dict:
        data = request.get("data") or {}
        enrolment = {"signer": signer_id, "name": data.get("name"), "role": role, "request": request["id"],
                     "request_sha256": record_content_hash(request)}
        return self.signed_record(
            ENROLLED, "enroll", signer=approver, key=key, meaning="approved", reason=reason, envelope_meaning=False,
            subject=make_subject("key", entry.key_id, sha256=bytes_hash(entry.public_pem.encode("ascii"))),
            data={"signer": signer_id, "name": data.get("name"), "role": role, "key_id": entry.key_id,
                  "public_pem": entry.public_pem, "approves": request["id"], "approved_by": approver.id},
            enrolment=enrolment)

    def approve_enrolment(self, signer_id: str, key_id: str, *, role: str | None = None,
                          approver_id: str | None = None, reason: str | None = None) -> dict:
        """Approve the enrolment of ``key_id`` for ``signer_id`` (or change the signer's role to ``role``),
        signed with the approver's passphrase. The approver's key must count; nobody approves their own
        enrolment or role. Returns the approval record; the registry follows it (key and role)."""
        registry = self.reload_registry()
        approver = self.signer_entry(approver_id)
        if approver.id == signer_id:
            raise UsageError("nobody approves their own enrolment or role; another enrolled signer does (a key "
                             f"rotation is 'aqt-signoff init --id {signer_id} --add-key')", code="self_approval")
        who = self.signer_actor(approver)
        self.require_human("approve-enrolment", who)
        history = self.trust().history
        state = history.keys.get(key_id)
        if state is None or state.signer != signer_id:
            raise NotFound(f"no enrolment record for key {key_id} of {signer_id} in the {history.source}; the key "
                           "holder records it with 'aqt-signoff init' (or 'aqt-signoff rekey')", code="no_enrolment")
        if state.conflict:
            raise UsageError(f"key {key_id} has conflicting enrolment records; it cannot be approved "
                             "(see 'aqt-signoff signers check')", code="enrolment_conflict")
        role = (role or "").strip() or (history.current_role(signer_id) if state.start else state.role)
        key = self.unlock(approver, f"approve the enrolment of {signer_id} ({role})")
        mine = self.trust().key_evidence(key.key_id, approver.id)
        if mine is None or mine.revoked_at:
            raise self.refuse("approve-enrolment", who, "no_active_key", Text(
                "signoff.refused.no_active_key", "the key of {signer} is revoked", signer=approver.id))
        entry = KeyEntry(key_id, state.public_pem, state.time)
        record = self._approval_record(approver, key, state.request, signer_id, entry, role,
                                       reason or (f"Enrolment of {signer_id} as {role} approved"))
        stored = self.emit(record, key)
        try:
            target = registry.get(signer_id)
        except NotFound:
            target = registry.add_signer(signer_id, state.name or signer_id, role)
        if not any(k.key_id == key_id for k in target.keys):
            target.keys.append(entry)
        target.role = role
        registry.save()
        return stored

    def import_preview(self) -> dict:
        """What ``import_enrolments`` would carry into the trail: ``records`` (enrolment and revocation records
        only in non-trail sources, written before the trail started), ``sources``, ``view`` (a registry
        reconciled with them alone), ``outcome`` (per enrolled key in them: what it is after the import) and
        ``ignored`` (records there that are never imported). Refused after the one import (``already_imported``)."""
        trail = self.trail_sources()
        if not trail:
            raise UsageError("there is no trail: enrolments already count from the evidence files", code="no_trail")
        registry = self.trust()
        history = registry.history
        if history.imports:
            first = history.imports[0]
            raise UsageError(f"the enrolment records from before the trail were imported once (record "
                             f"{first['record']} by {first['by']} at {first['time']}), and only that import counts. "
                             "Records added to the old file later never count and are not imported; a key that does "
                             "not count is enrolled again ('aqt-signoff init', 'init --add-key' or 'rekey') and "
                             "approved by another signer", code="already_imported")
        records, ignored = self._side_enrolments(trail, list(iter_evidence(trail)), registry)
        view = Registry(self.settings.registry_path, self.settings.keys_dir)
        view.reconcile(records, records, source="evidence")
        return {"records": records, "sources": [str(p) for p in self._pre_trail_files()], "view": view,
                "outcome": self._import_outcome(records, registry), "ignored": ignored}

    def _import_outcome(self, records: list[dict], registry: Registry) -> list[dict]:
        """Per key enrolled in ``records``: what it is in the trail after importing them (as
        ``EnrolmentHistory._import`` merges them). Every record claims its signer; nothing here proves it."""
        history = registry.history
        revoked = {k: list(v) for k, v in history.revoked.items()}
        for key_id, times in revocations_of(records).items():
            revoked.setdefault(key_id, []).extend(times)
        pems = {key.key_id: key.public_pem for signer in registry.signers for key in signer.keys}
        nested = EnrolmentHistory(revoked, "import", pems).run(records, nested=True)
        registered = {key.key_id for signer in registry.signers for key in signer.keys}
        out = []
        for key_id, state in nested.keys.items():
            here = history.keys.get(key_id)
            if here is not None:
                result = "in-trail"
            elif state.conflict:
                result = "conflict"
            else:
                result = "counts" if state.start else "pending"
            others = sorted({k for k, s in [*history.keys.items(), *nested.keys.items()]
                             if s.signer == state.signer and k != key_id})
            out.append({"signer": state.signer, "key_id": key_id, "name": state.name, "role": state.role,
                        "record": state.request.get("id"), "time": state.time, "result": result,
                        "from": state.start, "basis": state.basis,
                        "approved_by": sorted({a["by"] for a in state.approvals}),
                        "in_registry": key_id in registered, "other_keys": others})
        return out

    def import_enrolments(self, *, signer_id: str | None = None, reason: str | None = None) -> dict:
        """Carry the enrolment records written before the trail existed into the trail, once, signed by a
        signer whose key counts there (or in the trail). Records added to those files after the trail started
        or after the import never count, and a second import is refused (``already_imported``)."""
        preview = self.import_preview()
        records = preview["records"]
        if not records:
            raise UsageError("no enrolment records from before the trail to import", code="nothing_to_import")
        if isinstance(self.sink, JsonlSink) and self.sink.path not in self.trail_sources():
            raise UsageError(f"records go to {self.sink.path}, not to the trail; start 'aqt-trail serve' (or point "
                             "AQT_SINK at the trail writer) and import again", code="sink_not_trail")
        importer = self.signer_entry(signer_id)
        who = self.signer_actor(importer)
        self.require_human("import-enrolments", who)
        key = self.unlock(importer, "import the enrolment records from before the trail", adopt=False)
        before = preview["view"].key_evidence(key.key_id, importer.id)
        now = self.trust().key_evidence(key.key_id, importer.id)
        counted = self.trust().history.counted
        if counted and not (now and now.counts and not now.revoked_at):
            raise self.refuse("import-enrolments", who, "importer_not_enrolled", Text(
                "signoff.refused.importer_not_holder", "keys already count in the trail; the import is made by one "
                "of their holders, not by {signer}", signer=importer.id))
        if not counted and not (before and before.counts and not before.revoked_at):
            raise self.refuse("import-enrolments", who, "importer_not_enrolled", Text(
                "signoff.refused.importer_not_enrolled", "the key of {signer} does not count in the records to import",
                signer=importer.id))
        record = self.signed_record(
            ENROLLED, "enroll", signer=importer, key=key, meaning="approved", envelope_meaning=False,
            reason=reason or f"{len(records)} enrolment record(s) from before the trail imported",
            subject=make_subject("enrolment-import", "pre-trail", sha256=content_hash(records)),
            data={"signer": importer.id, "key_id": key.key_id, "imported": records,
                  "imported_from": preview["sources"]})
        return self.emit(record, key)

    def rekey(self, signer_id: str | None = None) -> dict:
        """Unlock the signer's key once: a key file from an earlier version (PKCS#8, PBKDF2) is
        re-encrypted with scrypt, and a key without an enrolment record gets one (which waits for an
        approval unless it is the first signer's)."""
        signer = self.signer_entry(signer_id)
        self.require_human("rekey", self.signer_actor(signer))
        path = self.registry.key_path(signer.id)
        before = key_file_format(path) if path.exists() else None
        active = signer.active_key()
        evidence = self.trust().key_evidence(active.key_id, signer.id) if active else None
        self.unlock(signer, "re-encrypt your key file", require_counting=False)
        after = key_file_format(path)
        now = self.trust().key_evidence(active.key_id, signer.id) if active else None
        return {"signer": signer.id, "path": str(path), "format": after,
                "upgraded": before != after and after == "aqt-key",
                "enrolled": bool(evidence and evidence.missing and now and not now.missing),
                "pending": bool(now and now.pending)}

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
            raise UsageError(Text("signoff.error.meaning", "meaning must be one of {meanings}",
                                  meanings=", ".join(sorted(MEANINGS))))
        if not reason or not reason.strip():
            raise UsageError(Text("signoff.error.signature_reason", "a signature needs a reason"))
        if not subject.get("sha256"):
            raise UsageError(Text("signoff.error.subject_hash", "the subject needs a sha256"))
        signer = self.signer_entry(signer_id)
        who = self.signer_actor(signer)
        self.require_human("sign", who)
        policy = self.settings.policy(meaning)
        if policy.roles and signer.role not in policy.roles:
            raise self.refuse("sign", who, "role_not_allowed", Text(
                "signoff.refused.role_meaning", "role {role} may not sign with meaning {meaning} (allowed: {allowed})",
                role=repr(signer.role), meaning=repr(meaning), allowed=", ".join(policy.roles)), subject=subject)
        records = self.records()
        statuses = self.signatures_for(subject["sha256"], records=records)
        all_authors = (set(authors) | {s.signer_id for s in statuses if s.valid and s.meaning == "authored"}
                       | self.record_authors(subject["sha256"], records))
        if policy.distinct_from_author and signer.id in all_authors:
            raise self.refuse("sign", who, "self_approval", Text(
                "signoff.refused.author", "{signer} is an author of this content and may not sign it as {meaning}",
                signer=signer.id, meaning=repr(meaning)), subject=subject)
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
                    status.worsen("invalid", Text("signoff.signature.replayed", "replayed copy of the statement "
                                                  "signed in record {record}; it counts once",
                                                  record=first[digest].record_id))
                else:
                    first[digest] = status
            withdrawal = next((w for w in withdrawals.get(digest, []) if w.signer_id == status.signer_id), None)
            if withdrawal:
                status.worsen("invalidated", Text("signoff.signature.withdrawn", "withdrawn by the signer: {reason}",
                                                  reason=withdrawal.reason))
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
                note = policy_note(policy.min_signatures - len(signers),
                                   all_authors if policy.distinct_from_author else [], policy.roles)
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
        check = self.check_signers()
        report.registry_problems = [k for k in check["keys"] if not k["counts"]]
        report.registry_warnings = [rebootstrap_text(entry, who=True) for entry in check["rebootstrap"]
                                    if not entry["confirmed_by"]]
        for status in statuses:
            if status.subject.get("sha256") != current["sha256"] and status.status != "invalid":
                status.worsen("invalidated", Text("signoff.signature.content_changed", "content changed since "
                                                  "signing (signed {sha256})", sha256=status.subject.get("sha256")))
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
