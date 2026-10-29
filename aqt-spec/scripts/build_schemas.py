#!/usr/bin/env python3
"""Generate ``schemas/`` (JSON Schema 2020-12) and ``schemas/registry.json``.

This file is the source of truth for the record-type registry and the payload
schemas; the JSON files are committed so that implementers in other languages
never need Python. ``tests/test_schemas.py`` fails when they are out of date.

Usage: ``python scripts/build_schemas.py [--check]``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "schemas"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
BASE = "urn:aqt:schema:0.1:"


def ref(name: str, pointer: str = "") -> dict:
    return {"$ref": f"{BASE}{name}{'#' + pointer if pointer else ''}"}


SHA = ref("common", "/$defs/sha256")
TIME = ref("common", "/$defs/time")
DATE = ref("common", "/$defs/date")
RECID = ref("common", "/$defs/record_id")
PPM = ref("common", "/$defs/ppm")
MS = {"type": "integer", "minimum": 0}
STR = {"type": "string"}
NESTR = {"type": "string", "minLength": 1}
INT = {"type": "integer"}
BOOL = {"type": "boolean"}
OBJ = {"type": "object"}
ARR = {"type": "array"}
STRS = {"type": "array", "items": {"type": "string"}}
SIGNATURE = ref("signature")
MEANINGS = ["authored", "reviewed", "approved", "released", "rejected", "verified", "waived", "acknowledged"]


def enum(*values):
    return {"enum": list(values)}


def obj(required=(), **props):
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = list(required)
    return schema


COMMON = {
    "$schema": DIALECT, "$id": BASE + "common", "title": "AQT common definitions",
    "$defs": {
        "sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
        "time": {"type": "string", "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$"},
        "date": {"type": "string", "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
        "record_id": {"type": "string", "pattern": "^rec_[0-9a-f]{28}$"},
        "key_id": {"type": "string", "pattern": "^ed25519:[0-9a-f]{16}$"},
        "ppm": {"type": "integer", "minimum": 0, "maximum": 1000000},
        "safe_integer": {"type": "integer", "minimum": -9007199254740991, "maximum": 9007199254740991},
        "meaning": {"enum": MEANINGS},
        "ed25519_sig": obj(["alg", "key", "value"], alg={"const": "ed25519"},
                           key={"$ref": "#/$defs/key_id"}, value=NESTR),
    },
}

OBSERVED = {
    "$schema": DIALECT, "$id": BASE + "observed", "title": "observed (writer-owned process attribution)",
    "description": "Set only by the aqt-trail writer (or, inside data.peer, by a tool that observes a peer itself).",
    **obj(pid=INT, uid=INT, gid=INT,
          process_chain={**STRS, "description": "command names, nearest first"},
          processes={"type": "array", "items": obj(["pid"], pid=INT, comm=STR, start_time=INT)},
          harness={"type": ["string", "null"]}, client_time=TIME, via=enum("socket", "spool")),
}

ENVELOPE = {
    "$schema": DIALECT, "$id": BASE + "envelope", "title": "AQT evidence record envelope 0.1",
    "description": "Structural rules only. Canonical-JSON rules (no floats, ASCII keys, integers within "
                   "+/-2^53, no duplicate keys, valid Unicode) are checked by the canonicaliser, not by this schema.",
    "type": "object", "additionalProperties": False,
    "required": ["aqt", "id", "type", "time", "actor", "action"],
    "properties": {
        "aqt": {"const": "0.1"},
        "id": RECID,
        "type": {"type": "string", "pattern": r"^[a-z0-9-]+\.[a-z0-9_.-]+$"},
        "time": TIME,
        "tz": NESTR,
        "actor": {
            "type": "object", "required": ["kind", "id"],
            "properties": {
                "kind": enum("human", "agent", "service"), "id": NESTR, "role": STR, "display": STR,
                "agent": obj(harness=STR, model=STR, version=STR, session=STR),
            },
        },
        "observed": ref("observed"),
        "action": NESTR,
        "subject": obj(["kind", "ref"], kind=NESTR, ref=NESTR, sha256=SHA),
        "before": obj(sha256=SHA),
        "after": obj(sha256=SHA),
        "reason": {"type": "string", "pattern": r"\S"},
        "meaning": ref("common", "/$defs/meaning"),
        "links": {"type": "array", "items": obj(["rel", "ref"], rel=NESTR, ref=NESTR)},
        "data": OBJ,
        "chain": obj(["seq", "prev"], seq={"type": "integer", "minimum": 0}, prev=SHA),
        "sig": {"type": "array", "items": ref("common", "/$defs/ed25519_sig")},
    },
}

SIGNATURE_SCHEMA = {
    "$schema": DIALECT, "$id": BASE + "signature", "title": "Detached signed statement (data.signature)",
    "description": "Ed25519 over canonical_json(statement). Used by aqt-signoff and by every tool that signs a "
                   "human decision.",
    **obj(["statement", "alg", "key", "value"],
          statement={
              **obj(["aqt_signature", "signer", "key", "meaning", "signed_at", "subject"],
                    aqt_signature={"const": "0.1"},
                    signer=obj(["id", "name"], id=NESTR, name=NESTR, role=STR),
                    key=ref("common", "/$defs/key_id"),
                    meaning=ref("common", "/$defs/meaning"),
                    reason={"type": "string", "pattern": r"\S"},
                    signed_at=TIME, tz=NESTR,
                    subject=obj(["kind", "ref", "sha256"], kind=NESTR, ref=NESTR, sha256=SHA),
                    record_type=STR, nonce=STR, expires_at=TIME),
          },
          alg={"const": "ed25519"}, key=ref("common", "/$defs/key_id"), value=NESTR),
}

CHECKPOINT = {
    "$schema": DIALECT, "$id": BASE + "checkpoint", "title": "Signed checkpoint (chain head statement)",
    "type": "object", "additionalProperties": False,
    "required": ["aqt_checkpoint", "log", "seq", "head", "time", "sig"],
    "properties": {"aqt_checkpoint": {"const": "0.1"}, "log": NESTR, "seq": {"type": "integer", "minimum": 0},
                   "head": SHA, "time": TIME, "sig": ref("common", "/$defs/ed25519_sig")},
}

THRESHOLDS = {
    "$schema": DIALECT, "$id": BASE + "thresholds", "title": "Detector thresholds file (aqt-validate -> aqt-quarantine)",
    "description": "Scores and thresholds in parts per million (score_ppm of the detector).",
    **obj(["aqt_thresholds", "detectors", "bands"],
          aqt_thresholds={"const": "0.1"},
          protocol=obj(["id", "sha256"], id=NESTR, sha256=SHA),
          run=RECID,
          detectors={"type": "array", "minItems": 1,
                     "items": obj(["id", "version"], id=NESTR, version=STR, sha256=SHA)},
          bands={"type": "array", "minItems": 1, "items": obj(
              ["name", "rule", "thresholds"], name=enum("warn", "hold"), fpr_target_ppm=PPM,
              rule={"oneOf": [{"const": "any"},
                              obj(["at_least"], at_least={"type": "integer", "minimum": 1})]},
              thresholds={"type": "object", "minProperties": 1, "additionalProperties": PPM})},
          calibration=obj(n={"type": "integer", "minimum": 0},
                          realised_fpr_ppm={"type": "object", "additionalProperties": PPM})),
}

SIGNERS = {
    "$schema": DIALECT, "$id": BASE + "signers", "title": "Signer registry ($XDG_CONFIG_HOME/aqt/signers.json)",
    **obj(["version", "signers"], version={"const": 1},
          signers={"type": "array", "items": obj(
              ["id", "name", "keys"], id=NESTR, name=NESTR, role=STR,
              keys={"type": "array", "items": obj(
                  ["key_id", "public_pem"], key_id=ref("common", "/$defs/key_id"), public_pem=NESTR,
                  enrolled_at=TIME, revoked_at={"anyOf": [TIME, {"type": "null"}]})})}),
}

REFUSED = obj(["attempted_action", "reason_code", "agent_markers"], attempted_action=NESTR, reason_code=NESTR,
              agent_markers=STRS)
NULLSTR = {"type": ["string", "null"]}
SOURCE = obj(tool=STR, ref=NULLSTR, domain=NULLSTR)
FINDINGS = {"type": "array", "items": OBJ}

# type -> (summary, actions, meanings, human_reason, data schema)
TYPES: dict[str, tuple] = {
    # aqt-trail
    "trail.event": ("Generic event (service start/stop, clock jump, user events)", [], [], False, OBJ),
    "trail.gap": ("Spooled records follow; marks the time the writer was unavailable", ["spool.drained"], [], False,
                  obj(reason=STR, first_time=TIME, last_time=TIME, count=INT, spool_ids=STRS)),
    "trail.import": ("Event imported from an agent harness (hook, session JSONL)", [], [], False,
                     obj(["source", "source_hash"], source=OBJ, source_hash=SHA, source_time=STR, tool=OBJ,
                         model=STR, harness_version=STR)),
    "trail.anchor": ("External anchor of a checkpoint (RFC 3161 token or exported head)", ["rfc3161", "external-head"],
                     [], False, obj(["checkpoint"], checkpoint=ref("checkpoint"), imprint=STR, tsa=OBJ)),
    "trail.review": ("Signed audit-trail review", ["review.signed"], ["reviewed"], True,
                     obj(["findings", "head"], head=SHA, scope=OBJ, profile=STR, profile_sha256=SHA,
                         worksheet_sha256=SHA, actors_reviewed=STRS, conclusion=STR, signature=SIGNATURE,
                         findings={"type": "array", "items": obj(
                             ["query", "severity", "record_ids", "disposition"], query=NESTR, severity=NESTR,
                             record_ids=STRS, disposition=enum("ok", "explained", "deviation"))})),
    # aqt-signoff
    "signoff.signature": ("Signature with meaning bound to a subject hash", ["sign"], MEANINGS, True,
                          obj(["signature", "meaning"], signature=SIGNATURE, meaning=ref("common", "/$defs/meaning"),
                              policy_check=OBJ)),
    "signoff.invalidation": ("A signature stopped applying (content changed or withdrawn)",
                             ["content-changed", "withdraw"], [], True,
                             obj(["cause"], cause=enum("content-changed", "withdrawn", "key-revoked"),
                                 signed_sha256=SHA, observed_sha256=SHA)),
    "signoff.action.prepared": ("An action proposed for approval", ["prepare", "revise"], [], False,
                                obj(["action_sha256"], action=OBJ, action_sha256=SHA, request_key_sha256=SHA,
                                    supersedes=STR, expires_at=TIME)),
    "signoff.action.approved": ("Approval of the exact action hash", ["approve"], ["approved"], True,
                                obj(["action_id", "action_sha256", "signature"], action_id=NESTR, version=INT,
                                    action_sha256=SHA, signature=SIGNATURE, expires_at=TIME)),
    "signoff.action.rejected": ("Rejection of the exact action hash", ["reject"], ["rejected"], True,
                                obj(["action_id", "action_sha256", "signature"], action_id=NESTR, version=INT,
                                    action_sha256=SHA, signature=SIGNATURE)),
    "signoff.action.claimed": ("Executor claimed an approved action (at most once)", ["claim"], [], False,
                               obj(["action_id", "claim_id"], action_id=NESTR, action_sha256=SHA, claim_id=NESTR,
                                   approvals=STRS, payload_checked=BOOL)),
    "signoff.action.outcome": ("Outcome of a claimed action; unknown is never retried", ["outcome", "resolve"],
                               ["verified"], False,
                               obj(["outcome", "action_id"], action_id=NESTR, claim_id=STR,
                                   outcome=enum("succeeded", "failed", "unknown", "not-applied"),
                                   basis=STR, exit_code={"type": ["integer", "null"]}, stdout_sha256=SHA,
                                   stderr_sha256=SHA, excerpt=STR, signature=SIGNATURE)),
    "signoff.key.enrolled": ("Signer key enrolled", ["enroll"], [], False,
                             obj(["key_id"], signer=STR, role=STR, key_id=ref("common", "/$defs/key_id"),
                                 public_pem=STR)),
    "signoff.key.revoked": ("Signer key revoked", ["revoke"], [], True,
                            obj(["key_id"], key_id=ref("common", "/$defs/key_id"), compromised_since=TIME)),
    "signoff.auth.failed": ("Failed re-authentication", ["auth.failed"], [], False,
                            obj(signer=STR, operation=STR, count=INT)),
    # aqt-change
    "change.plan.reconciled": ("Plan baseline or reconciled plan edit", ["baseline", "begin", "reconcile"], [], False,
                               obj(["plan_id", "kind"], plan_id=NESTR, path=STR,
                                   kind=enum("baseline", "editorial", "semantic"), status=STR, basis_before=STR,
                                   basis_after=STR, items=obj(added=STRS, removed=STRS, changed=STRS))),
    "change.receipt": ("Runner-captured verification receipt", ["run", "attest"], ["verified"], False,
                       obj(["argv", "exit_code", "passed", "plan_basis_hash", "tree_fingerprint", "counts"],
                           argv=STRS, exit_code={"type": ["integer", "null"]}, passed=BOOL, plan_basis_hash=STR,
                           tree_fingerprint=STR, counts=OBJ, plan_id=STR, item=STR, outcome=STR, duration_ms=MS,
                           stdout=OBJ, stderr=OBJ, git=OBJ, env=OBJ, warnings=ARR)),
    "change.review": ("Review record with reviewer independence class", ["review"], ["reviewed"], False,
                      obj(["verdict", "independence", "diff_sha256", "findings"],
                          verdict=enum("PASS", "CONCERNS", "FAIL", "WAIVED"),
                          independence=enum("same-session", "fresh-context", "different-model", "human"),
                          diff_sha256=SHA, findings=FINDINGS, plan_id=STR, reviewer=OBJ)),
    "change.reconciliation": ("Approved-versus-actual diff reconciliation", ["reconcile-diff"], [], False,
                              obj(plan_id=STR, base_commit=STR, declared_paths=STRS, changed=ARR, unapproved=STRS,
                                  missing_evidence=ARR, result=enum("clean", "findings"))),
    "change.finish": ("Evidenced finish of a plan", ["finish"], [], False,
                      obj(["plan_ref", "receipts", "waivers", "gate"], plan_ref=NESTR, receipts=STRS, waivers=ARR,
                          gate=enum("GO", "NO-GO", "MANUAL_VERIFY_REQUIRED"), commit=STR, paths=STRS)),
    # aqt-sensei
    "sensei.pair": ("Advisor pairing lifecycle", ["attached", "updated", "paused", "resumed", "ended", "doctor"], [],
                    False, obj(pair=STR, backend=STR, worker=OBJ, advisor=OBJ, mode=STR, budget=OBJ,
                               independence=STR)),
    "sensei.message": ("Message between worker and advisor (hash + excerpt)",
                       ["enqueued", "delivered", "failed", "no-reply"], [], False,
                       obj(pair=STR, message=STR, excerpt=STR, digest_sha256=SHA, rendered_sha256=SHA,
                           peer=ref("observed"))),
    "sensei.decision": ("Owner decision on a message", ["approved", "edited", "discarded", "forwarded"],
                        ["approved", "rejected", "released"], True,
                        obj(["decision", "message_id", "pair_id"],
                            decision=enum("approve", "edit", "discard", "forward"), message_id=NESTR,
                            pair_id=NESTR)),
    "sensei.budget": ("Budget consumption and limits", ["consumed", "reached", "set", "cost-added"], [], False,
                      obj(pair=STR, messages_used=INT, exchanges_used=INT, fallback_mode=STR)),
    # aqt-quarantine
    "quarantine.passed": ("Untrusted input passed (pass or warn band)", ["pass"], [], False,
                          obj(band=enum("pass", "warn"), case_id=STR, source=SOURCE, scores=OBJ, detectors=ARR,
                              thresholds=OBJ)),
    "quarantine.held": ("Untrusted input held in quarantine", ["hold"], [], False,
                        obj(["case_id", "band", "score_ppm", "source"], case_id=NESTR, band=NESTR, score_ppm=PPM,
                            source=SOURCE, reason_code=STR, evidence=ARR, original=OBJ)),
    "quarantine.released": ("Held input released by a responsible person", ["release"], ["released"], True,
                            obj(case_id=STR, content_sha256=SHA, kind=STR, signature=SIGNATURE)),
    "quarantine.source.trusted": ("Source trusted (or trust revoked) with expiry", ["trust", "revoke"],
                                  ["approved", "rejected"], True,
                                  obj(domain=STR, subdomains=BOOL, expires=DATE, policy=STR, signature=SIGNATURE)),
    "quarantine.threat.declared": ("Held input declared a threat", ["declare"], ["rejected"], True,
                                   obj(["case_id", "band", "score_ppm", "source"], case_id=NESTR, band=NESTR,
                                       score_ppm=PPM, source=SOURCE, reached_model=BOOL, signature=SIGNATURE)),
    "quarantine.delivered": ("Released content delivered to the agent", ["deliver"], [], False,
                             obj(case_id=STR, kind=enum("content", "threat-note"), decision=STR, harness=STR,
                                 session=NULLSTR, mode=enum("inline", "pointer", "command", "failed"),
                                 content_sha256=SHA)),
    # aqt-validate
    "validate.run": ("Validation run lifecycle", ["protocol-locked", "completed", "failed"], [], False,
                     obj(["protocol"], kind=enum("detector", "reviewer"), protocol=obj(["sha256"], id=STR, sha256=SHA),
                         datasets=ARR, results_sha256=SHA, headline=OBJ)),
    "validate.report": ("Validation report", ["issued"], [], False,
                        obj(run=STR, conclusion=enum("meets", "does-not-meet", "inconclusive"), criteria=ARR,
                            deviations=ARR, thresholds_sha256=SHA)),
    "validate.qualification": ("Human qualification decision with validity period", ["approve", "reject"],
                               ["approved", "rejected"], True,
                               obj(["configuration_hash", "valid_until"], configuration_hash=NESTR, valid_until=TIME,
                                   valid_from=TIME, report=STR, triggers=ARR, thresholds_sha256=SHA,
                                   expected_fpr_upper_ppm=PPM)),
    "validate.requalification": ("Requalification trigger fired", ["triggered"], [], False,
                                 obj(["configuration_hash", "valid_until", "trigger"], configuration_hash=NESTR,
                                     valid_until=TIME, trigger=NESTR, qualification=STR)),
    # aqt-capa
    "capa.deviation": ("Deviation lifecycle", ["opened", "accepted", "dismissed", "classified", "closed"], [], False,
                       obj(dev_id=STR, title=STR, severity=enum("minor", "major", "critical"), category=STR,
                           source=OBJ, similar=ARR)),
    "capa.investigation": ("Root-cause investigation", ["drafted", "recorded", "revised"], [], False,
                           obj(whys=STRS, factors=ARR, root_cause=STR, root_category=STR, impact=STR)),
    "capa.action": ("Corrective or preventive change to an agent control",
                    ["planned", "implemented", "approved", "cancelled"], ["authored", "approved"], False,
                    obj(["target", "effectiveness_criterion"],
                        target=obj(["path", "before_sha256", "after_sha256"], path=NESTR,
                                   before_sha256={"anyOf": [SHA, {"type": "null"}]},
                                   after_sha256={"anyOf": [SHA, {"type": "null"}]}),
                        effectiveness_criterion={"type": ["object", "string"]}, action_id=STR, kind=STR)),
    "capa.effectiveness": ("Effectiveness check result", ["evaluated", "extended"], [], False,
                           obj(action_id=STR, result=enum("effective", "not-effective", "pending"), counts=OBJ)),
    "capa.closure": ("CAPA closure", ["closed"], ["approved"], True,
                     obj(dev_id=STR, basis=STR, actions=ARR)),
}
for tool in ("trail", "signoff", "change", "sensei", "quarantine", "validate", "capa"):
    TYPES[f"{tool}.refused"] = ("Refused attempt (typically by an agent)", ["refused"], [], False, REFUSED)

TOOLS = {"trail": "aqt-trail", "signoff": "aqt-signoff", "change": "aqt-change", "sensei": "aqt-sensei",
         "quarantine": "aqt-quarantine", "validate": "aqt-validate", "capa": "aqt-capa"}


def payload_schema(name: str, summary: str, data: dict) -> dict:
    return {"$schema": DIALECT, "$id": f"{BASE}data:{name}", "title": f"{name} data", "description": summary, **data}


def build() -> dict[Path, str]:
    files: dict[Path, dict] = {
        OUT / "common.schema.json": COMMON, OUT / "envelope.schema.json": ENVELOPE,
        OUT / "observed.schema.json": OBSERVED, OUT / "signature.schema.json": SIGNATURE_SCHEMA,
        OUT / "checkpoint.schema.json": CHECKPOINT, OUT / "thresholds.schema.json": THRESHOLDS,
        OUT / "signers.schema.json": SIGNERS,
    }
    registry = {"aqt": "0.1", "extension_prefix": "x-", "types": {}}
    for name in sorted(TYPES):
        summary, actions, meanings, human_reason, data = TYPES[name]
        files[OUT / "data" / f"{name}.schema.json"] = payload_schema(name, summary, data)
        registry["types"][name] = {
            "tool": TOOLS[name.split(".")[0]], "summary": summary, "schema": f"data/{name}.schema.json",
            "actions": actions, "meanings": meanings, "human_reason": human_reason,
        }
    files[OUT / "registry.json"] = registry
    return {path: json.dumps(content, indent=2, ensure_ascii=False) + "\n" for path, content in files.items()}


def main(argv: list[str]) -> int:
    outputs = build()
    if "--check" in argv:
        stale = [str(p.relative_to(ROOT)) for p, text in outputs.items()
                 if not p.exists() or p.read_text() != text]
        extra = sorted(str(p.relative_to(ROOT)) for p in (OUT / "data").glob("*.json") if p not in outputs)
        for item in stale + extra:
            print("out of date:", item)
        return 1 if stale or extra else 0
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print(f"wrote {len(outputs)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
