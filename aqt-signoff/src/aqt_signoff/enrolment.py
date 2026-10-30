"""Enrolment history: which keys count, from when, and with which role, read from the evidence.

Three kinds of ``signoff.key.enrolled`` record (all ``action: enroll``):

* **request**: the new key signs its own enrolment (proof of possession). Written by
  ``aqt-signoff init`` (and at the first use of a key another tool made). The statement's
  ``key`` is the enrolled key.
* **approval**: an enrolled signer counter-signs a request with their own key
  (``aqt-signoff signers approve``). The statement's ``key`` is the approver's key; its
  ``enrolment`` field names the signer, the role and the request (id and
  ``record_content_hash``); its subject is the approved key.
* **import**: a signer carries the enrolment records written before the trail existed into the
  trail (``aqt-signoff signers import``); the records are in ``data.imported`` and the signed
  subject is their ``content_hash``.

Rules, applied in evidence order (the trail's order when there is a trail):

* The first request counts at once (the **bootstrap**). Every later request counts only after an
  approval by another signer whose key counts and is active at the approval's record time; the
  key then counts from its request's record time (the trail writer's time). A signer's own other
  key may approve only a rotation: same role, and the approving key is revoked.
* A request made when no earlier key counts and is active any more (all revoked) is a
  **re-bootstrap**: it counts, and stays flagged until a signer whose key counted *before* it
  approves it. A key that counts through the re-bootstrapped key (approved by it, directly or
  through further approvals) never confirms it. In practice every key that counted before is
  revoked by then, so a re-bootstrap stays flagged.
* A revocation is *signed* when the revoked key or another key that counts at the revocation's
  record time signed it; every revocation applies, signed or not, and the unsigned ones are
  reported (``unsigned_revocations``, and on each re-bootstrap they made possible).
* The role of a signer changes only through an approval (by another signer); signatures are
  judged by the role in effect at their ``signed_at``.
* A copy of a request (same signed statement, another record) counts once. A different signed
  request for a key that already has one is a conflict: from the conflicting record's time the
  key stops counting (signatures made before it keep counting), and it is reported.
* Only the first import that counts counts. It counts when it is the first enrolment evidence of
  the trail (its own bootstrap applies, and the importer's key must count in it) or when the
  importer's key counts and is active in the trail at the import; the imported records keep their
  own order and times.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aqt_evidence import bytes_hash, content_hash, key_id as key_id_of, record_content_hash, verify_statement


def _digest(statement) -> str | None:
    try:
        return content_hash(statement) if isinstance(statement, dict) and statement else None
    except ValueError:
        return None

ENROLLED, REVOKED = "signoff.key.enrolled", "signoff.key.revoked"
IMPORT_KIND = "enrolment-import"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _time(value) -> datetime | None:
    try:
        moment = parse_time(value)
    except (TypeError, ValueError, AttributeError):
        return None
    return moment if moment.tzinfo else None


def _data(record: dict) -> dict:
    return record.get("data") if isinstance(record.get("data"), dict) else {}


def _statement(record: dict) -> tuple[dict, dict]:
    block = _data(record).get("signature")
    st = block.get("statement") if isinstance(block, dict) else None
    return (block, st) if isinstance(st, dict) else ({}, {})


def kind_of(record: dict) -> str | None:
    """``request``, ``approval`` or ``import`` for a ``signoff.key.enrolled`` record, else None."""
    if not isinstance(record, dict) or record.get("type") != ENROLLED:
        return None
    block, st = _statement(record)
    subject = st.get("subject") if isinstance(st.get("subject"), dict) else {}
    if subject.get("kind") == IMPORT_KIND or "imported" in _data(record):
        return "import"
    if isinstance(st.get("enrolment"), dict) and block.get("key") != _data(record).get("key_id"):
        return "approval"
    return "request"


def _public(pem) -> Ed25519PublicKey | None:
    try:
        key = serialization.load_pem_public_key(str(pem).encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError):
        return None
    return key if isinstance(key, Ed25519PublicKey) else None


@dataclass
class KeyState:
    """One enrolled key as the evidence shows it."""
    key_id: str
    signer: str
    name: str
    role: str                  # the role the request asked for
    public_pem: str
    request: dict              # the self-signed request record
    time: str                  # the request's record time
    source: str
    start: str | None = None   # from when the key counts (None: pending)
    basis: str | None = None   # bootstrap | rebootstrap | approved
    approvals: list = field(default_factory=list)
    problems: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    conflict: bool = False
    conflict_at: str | None = None   # record time of the first conflicting record: the key stops counting then
    conflicts: list = field(default_factory=list)
    imported: dict | None = None


class EnrolmentHistory:
    """Run ``records`` (the enrolment evidence, in order) through the rules in the module docstring.

    ``revoked``: every known revocation ``{key_id: [revoked_at, ...]}`` (they always apply);
    ``pems``: registry public keys, used for requests that carry no ``public_pem``."""

    def __init__(self, revoked: dict[str, list[str]], source: str, pems: dict[str, str] | None = None):
        self.revoked, self.source, self.pems = revoked, source, pems or {}
        self.keys: dict[str, KeyState] = {}
        self.roles: dict[str, list[tuple[str, str, str]]] = {}   # signer -> [(effective time, role, record id)]
        self.bootstrap: dict | None = None
        self.rebootstraps: list[dict] = []
        self.problems: list[str] = []     # signed by an enrolled key, so its holder made it
        self.notes: list[str] = []        # records that do not count (anyone could have written them)
        self.rejected: dict[str, list[str]] = {}
        self.imports: list[dict] = []
        self.stream_revoked: dict[str, list[str]] = {}
        self.revocations: list[dict] = []   # every revocation record of the stream, with ``signed``
        self.counted = False

    # -- queries ---------------------------------------------------------------------------------
    def _revoked_by(self, key_id: str, moment: datetime, *, stream: bool = False) -> bool:
        times = (self.stream_revoked if stream else self.revoked).get(key_id, [])
        return any(_time(t) is not None and _time(t) <= moment for t in times)

    def active_at(self, key_id: str, moment: datetime | None, *, stream: bool = False) -> bool:
        """The key counts and is not revoked (or stopped by a conflict) at ``moment``."""
        state = self.keys.get(key_id)
        if moment is None or state is None or state.start is None:
            return False
        if state.conflict and (state.conflict_at is None or moment >= _time(state.conflict_at)):
            return False
        return _time(state.start) <= moment and not self._revoked_by(key_id, moment, stream=stream)

    def revocation_problem(self, record: dict) -> str | None:
        """Why a ``signoff.key.revoked`` record is not signed by the revoked key or by another key that
        counts at its record time (None: it is). Such a revocation still applies."""
        data = _data(record)
        block, st = _statement(record)
        key_id = str(data.get("key_id"))
        if not st:
            return "not signed"
        subject = st.get("subject") if isinstance(st.get("subject"), dict) else {}
        if st.get("record_type") != REVOKED or subject.get("kind") != "key" or subject.get("ref") != key_id:
            return "its signed statement is not this revocation"
        signing = str(block.get("key"))
        if signing == key_id:
            state = self.keys.get(key_id)
            public = _public(state.public_pem if state else self.pems.get(key_id))
            return None if verify_statement(block, {key_id: public}) else "its signature does not verify"
        other = self.keys.get(signing)
        if other is None or not self.active_at(signing, _time(record.get("time"))):
            return f"signed by {signing}, which does not count at {record.get('time')}"
        return None if verify_statement(block, {signing: _public(other.public_pem)}) else \
            "its signature does not verify"

    def role_at(self, signer_id: str, moment: datetime | None) -> str | None:
        role = None
        for when, value, _ in self.roles.get(signer_id, []):
            if moment is not None and _time(when) <= moment:
                role = value
        return role

    def current_role(self, signer_id: str) -> str | None:
        entries = self.roles.get(signer_id, [])
        return entries[-1][1] if entries else None

    def pending(self) -> list[KeyState]:
        return [s for s in self.keys.values() if s.start is None and not s.conflict]

    # -- processing ------------------------------------------------------------------------------
    def run(self, records, *, nested: bool = False) -> "EnrolmentHistory":
        for record in records:
            if not isinstance(record, dict):
                continue
            if record.get("type") == REVOKED:
                data = _data(record)
                if _time(data.get("revoked_at")):
                    key_id = str(data.get("key_id"))
                    self.stream_revoked.setdefault(key_id, []).append(data["revoked_at"])
                    why = self.revocation_problem(record)
                    self.revocations.append({"key_id": key_id, "signer": data.get("signer"), "record": record.get("id"),
                                             "time": record.get("time"), "revoked_at": data["revoked_at"],
                                             "signed": why is None, "why": why})
                continue
            kind = kind_of(record)
            try:
                if kind == "request":
                    self._request(record)
                elif kind == "approval":
                    self._approval(record)
                elif kind == "import" and not nested:
                    self._import(record)
            except (TypeError, ValueError, KeyError, AttributeError) as error:
                self.notes.append(f"record {record.get('id')}: malformed enrolment record ({type(error).__name__})")
        return self

    def _role(self, signer_id: str, when: str, role: str, record_id) -> None:
        entries = self.roles.setdefault(signer_id, [])
        entries.append((when, role, record_id))
        entries.sort(key=lambda entry: _time(entry[0]))

    def _request_problem(self, record: dict) -> str | None:
        data = _data(record)
        block, st = _statement(record)
        if not st:
            return "no signed statement"
        subject = st.get("subject") if isinstance(st.get("subject"), dict) else {}
        signer = st.get("signer") if isinstance(st.get("signer"), dict) else {}
        key_id = data.get("key_id")
        pem = data.get("public_pem") or self.pems.get(str(key_id))
        public = _public(pem)
        checks = [
            (st.get("record_type") == ENROLLED, "statement is not an enrolment"),
            (isinstance(signer.get("id"), str) and data.get("signer") in (None, signer.get("id")), "other signer"),
            (isinstance(signer.get("role"), str) and signer["role"].strip() != "", "no role"),
            (block.get("key") == st.get("key") == key_id, "other key"),
            (public is not None and key_id_of(public) == key_id, "other public key"),
            (subject.get("kind") == "key" and subject.get("ref") == key_id
             and subject.get("sha256") == bytes_hash(str(pem).encode("ascii")), "other public key"),
            (_time(st.get("signed_at")) is not None, "no signing time"),
            (_time(record.get("time")) is not None, "no record time"),
        ]
        for ok, why in checks:
            if not ok:
                return f"{record.get('id')}: {why}"
        if not verify_statement(block, {key_id: public}):
            return f"{record.get('id')}: not signed by this key"
        return None

    def _request(self, record: dict) -> None:
        data = _data(record)
        key_id = str(data.get("key_id"))
        why = self._request_problem(record)
        if why:
            self.rejected.setdefault(key_id, []).append(why)
            return
        _, st = _statement(record)
        existing = self.keys.get(key_id)
        if existing is not None:
            if existing.request.get("id") == record.get("id"):
                return                     # the same record read twice
            digest = _digest(st)
            if digest is not None and digest == _digest(_statement(existing.request)[1]):
                self.notes.append(f"record {record.get('id')}: a copy of the enrolment request "
                                  f"{existing.request.get('id')} for key {key_id}; it counts once")
                return
            self._conflict(existing, record.get("id"), record.get("time"))
            return
        signer = st["signer"]
        state = KeyState(key_id, signer["id"], signer.get("name") or "", signer["role"],
                         data.get("public_pem") or self.pems[key_id], record, record["time"], self.source)
        self.keys[key_id] = state
        moment = _time(state.time)
        if not self.counted:
            state.start, state.basis, self.counted = state.time, "bootstrap", True
            self._role(state.signer, state.time, state.role, record.get("id"))
            self.bootstrap = {"signer": state.signer, "key_id": key_id, "record": record.get("id"),
                              "time": state.time, "via": "enrolment"}
        elif self._all_gone(key_id, moment):
            state.start, state.basis = state.time, "rebootstrap"
            if self.role_at(state.signer, moment) != state.role:
                self._role(state.signer, state.time, state.role, record.get("id"))
            before = sorted(k for k, s in self.keys.items() if k != key_id and s.start is not None)
            unsigned = []
            for other in before:           # the revocations in force: did any key holder sign one?
                in_force = [r for r in self.revocations if r["key_id"] == other and _time(r["revoked_at"]) <= moment]
                if in_force and not any(r["signed"] for r in in_force):
                    unsigned.append({"key_id": other, "signer": self.keys[other].signer,
                                     "records": [r["record"] for r in in_force]})
            self.rebootstraps.append({"signer": state.signer, "key_id": key_id, "record": record.get("id"),
                                      "time": state.time, "confirmed_by": [], "counted_before": before,
                                      "unsigned_revocations": unsigned, "not_confirming": []})

    def _all_gone(self, key_id: str, moment: datetime | None) -> bool:
        """Every other key that counted is revoked (or stopped by a conflict) at ``moment``, by the revocations
        read so far. A key that starts only after ``moment`` (a backdated request) is not gone."""
        others = [(k, s) for k, s in self.keys.items() if k != key_id and s.start is not None]

        def gone(other: str, state: KeyState) -> bool:
            if state.conflict and (state.conflict_at is None or moment >= _time(state.conflict_at)):
                return True
            return self._revoked_by(other, moment, stream=True)

        return moment is not None and bool(others) and all(gone(k, s) for k, s in others)

    def _conflict(self, existing: KeyState, record_id, when) -> None:
        """A different signed request for a key that has one: the key stops counting from ``when``."""
        if not existing.conflict:
            existing.conflict, existing.conflict_at = True, when if _time(when) else None
        self.problems.append(f"key {existing.key_id} of {existing.signer}: a second, different enrolment record "
                             f"{record_id} (signed by that key; the first is {existing.request.get('id')}): the key "
                             f"does not count from {existing.conflict_at or when}")
        existing.conflicts.append(
            f"a second, different enrolment record {record_id} for this key (the first is "
            f"{existing.request.get('id')}): conflicting enrolment records; the key does not count from {when} "
            "(signatures made before that keep counting)")

    def _approval(self, record: dict) -> None:
        data = _data(record)
        block, st = _statement(record)
        wanted = st["enrolment"]
        key_id, approver_key = data.get("key_id"), block.get("key")
        approver_id = (st.get("signer") or {}).get("id")
        target, approver = self.keys.get(str(key_id)), self.keys.get(str(approver_key))
        moment = _time(record.get("time"))

        def ignore(why: str, *, problem: bool = False) -> None:
            text = (f"approval {record.get('id')} by {approver_id} of {wanted.get('signer')} key {key_id} "
                    f"does not count: {why}")
            (self.problems if problem else self.notes).append(text)

        if approver is None or approver.signer != approver_id:
            return ignore(f"the approving key {approver_key} has no enrolment record for {approver_id}")
        subject = st.get("subject") if isinstance(st.get("subject"), dict) else {}
        if not (st.get("record_type") == ENROLLED and st.get("meaning") == "approved"
                and st.get("key") == approver_key and verify_statement(block, {approver_key: _public(approver.public_pem)})):
            return ignore("its signature does not verify")
        if moment is None:
            return ignore("no record time")
        if target is None:
            return ignore("no enrolment request for that key comes before it", problem=True)
        try:
            request_hash = record_content_hash(target.request)
        except ValueError:
            request_hash = None
        if not (wanted.get("signer") == target.signer and data.get("signer") in (None, target.signer)
                and wanted.get("request") == target.request.get("id") and wanted.get("request_sha256") == request_hash
                and subject.get("kind") == "key" and subject.get("ref") == key_id
                and subject.get("sha256") == bytes_hash(target.public_pem.encode("ascii"))
                and isinstance(wanted.get("role"), str) and wanted["role"].strip()):
            return ignore("it does not match the enrolment request it names", problem=True)
        if not self.active_at(approver_key, moment):
            return ignore(f"the approving key {approver_key} does not count or is revoked at {record.get('time')}",
                          problem=True)
        if target.conflict:
            return
        role = wanted["role"]
        if approver_id == target.signer:
            if self.role_at(target.signer, moment) != role:
                target.problems.append(f"approval {record.get('id')}: a signer cannot approve a role for themselves; "
                                       "another enrolled signer approves it")
                return
            if not self.revoked.get(str(approver_key)):
                target.problems.append(f"approved by the signer's own key {approver_key} (record {record.get('id')}): "
                                       f"that is a rotation, and it counts once {approver_key} is revoked")
                return
        target.approvals.append({"by": approver_id, "key": approver_key, "record": record.get("id"),
                                 "time": record.get("time"), "role": role})
        if target.start is None:
            target.start, target.basis, self.counted = target.time, "approved", True
            if not self.roles.get(target.signer) and role == target.role:
                self._role(target.signer, target.time, role, record.get("id"))
            elif self.role_at(target.signer, moment) != role:
                self._role(target.signer, record["time"], role, record.get("id"))
            return
        if self.role_at(target.signer, moment) != role:
            self._role(target.signer, record["time"], role, record.get("id"))
        if target.basis == "rebootstrap" and approver_id != target.signer:
            for entry in self.rebootstraps:
                if entry["key_id"] != target.key_id:
                    continue
                if approver_key in entry.get("counted_before", ()):
                    entry["confirmed_by"].append({"by": approver_id, "record": record.get("id")})
                else:
                    entry.setdefault("not_confirming", []).append(
                        {"by": approver_id, "record": record.get("id"),
                         "why": f"the key {approver_key} did not count before the re-bootstrap; it counts through keys "
                                "enrolled after it, so it cannot vouch for it"})

    def _import(self, record: dict) -> None:
        data = _data(record)
        block, st = _statement(record)
        imported = data.get("imported")
        importer, importer_key = (st.get("signer") or {}).get("id"), block.get("key")
        moment = _time(record.get("time"))

        def ignore(why: str) -> None:
            text = f"import {record.get('id')} by {importer} does not count: {why}"
            (self.problems if str(importer_key) in self.pems else self.notes).append(text)   # a registered key made it

        subject = st.get("subject") if isinstance(st.get("subject"), dict) else {}
        if not isinstance(imported, list) or not all(isinstance(item, dict) for item in imported):
            return ignore("data.imported is not a list of records")
        try:
            digest = content_hash(imported)
        except ValueError:
            return ignore("the imported records are not canonical JSON")
        if subject.get("kind") != IMPORT_KIND or subject.get("sha256") != digest or moment is None \
                or data.get("signer") not in (None, importer) or st.get("key") != importer_key:
            return ignore("its statement does not cover the imported records")
        nested = EnrolmentHistory(self.revoked, "import", self.pems).run(imported, nested=True)
        here = self.keys.get(str(importer_key))
        known = here if here is not None else nested.keys.get(str(importer_key))
        if known is None or known.signer != importer or \
                not verify_statement(block, {importer_key: _public(known.public_pem)}):
            return ignore("its signature does not verify with an enrolled key of the importer")
        if not self.counted:
            if not nested.active_at(importer_key, moment):
                return ignore("the importer's key does not count in the imported records")
            via = "import"
        elif here is not None and self.active_at(importer_key, moment):
            via = "vouched"
        else:
            return ignore("the importer's key does not count in the trail at the import")
        if self.imports:
            first = self.imports[0]
            return ignore(f"only the first import counts (record {first['record']} by {first['by']} at "
                          f"{first['time']}); records added to the old file later are never imported")
        self.imports.append({"record": record.get("id"), "by": importer, "time": record.get("time"),
                             "count": len(imported), "via": via})
        for key_id, state in nested.keys.items():
            existing = self.keys.get(key_id)
            if existing is not None:
                same = _digest(_statement(state.request)[1])
                if existing.request.get("id") != state.request.get("id") and \
                        (same is None or same != _digest(_statement(existing.request)[1])):
                    self._conflict(existing, f"{state.request.get('id')} (in import {record.get('id')})",
                                   record.get("time"))
                continue
            state.imported = {"by": importer, "record": record.get("id"), "time": record.get("time")}
            self.keys[key_id] = state
        for signer_id, entries in nested.roles.items():
            if signer_id not in self.roles:
                self.roles[signer_id] = list(entries)
        for key_id, times in nested.stream_revoked.items():
            self.stream_revoked.setdefault(key_id, []).extend(times)
        self.revocations.extend(nested.revocations)
        for key_id, reasons in nested.rejected.items():
            self.rejected.setdefault(key_id, []).extend(reasons)
        if not self.counted and nested.bootstrap:
            self.bootstrap = {**nested.bootstrap, "via": "import", "import": record.get("id")}
        self.counted = self.counted or nested.counted
        self.rebootstraps.extend(nested.rebootstraps)
        self.problems.extend(f"imported: {text}" for text in nested.problems)
        self.notes.extend(f"imported: {text}" for text in nested.notes)


def revocations(records) -> dict[str, list[str]]:
    """``{key_id: [revoked_at, ...]}`` from ``signoff.key.revoked`` records, including those carried by an import."""
    found: dict[str, list[str]] = {}

    def add(record) -> None:
        data = _data(record)
        if record.get("type") == REVOKED and _time(data.get("revoked_at")):
            found.setdefault(str(data.get("key_id")), []).append(data["revoked_at"])

    for record in records:
        if not isinstance(record, dict):
            continue
        add(record)
        if kind_of(record) == "import" and isinstance(_data(record).get("imported"), list):
            for item in _data(record)["imported"]:
                if isinstance(item, dict):
                    add(item)
    return found
