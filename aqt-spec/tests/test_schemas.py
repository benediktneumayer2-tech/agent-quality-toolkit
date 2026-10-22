"""Schemas are valid JSON Schema 2020-12, cover the registry and accept example payloads."""

import json

import pytest
from jsonschema import Draft202012Validator

from aqt_evidence import schemas

REGISTRY = schemas.registry()


def test_every_schema_is_valid_draft_2020_12():
    for path in schemas.schema_dir().rglob("*.schema.json"):
        Draft202012Validator.check_schema(json.loads(path.read_text()))


def test_registry_covers_suite_types_and_refused():
    types = set(REGISTRY["types"])
    for name in ("trail.gap", "trail.review", "signoff.signature", "signoff.key.revoked", "signoff.auth.failed",
                 "change.receipt", "change.finish", "sensei.decision", "quarantine.delivered", "validate.qualification",
                 "capa.closure"):
        assert name in types
    for tool in ("trail", "signoff", "change", "sensei", "quarantine", "validate", "capa"):
        assert f"{tool}.refused" in types
    assert all(schemas.schema_for(t) is not None for t in types)
    assert schemas.is_registered("x-acme.thing") and not schemas.is_registered("acme.thing")


EXAMPLES = {
    "change.receipt": {"argv": ["pytest", "-q"], "exit_code": 0, "passed": True, "plan_basis_hash": "sha256:" + "a" * 64,
                       "tree_fingerprint": "sha256:" + "b" * 64, "counts": {"passed": 3}},
    "change.finish": {"plan_ref": "plan-1", "receipts": ["rec_" + "0" * 28], "waivers": [], "gate": "GO"},
    "change.review": {"verdict": "PASS", "independence": "fresh-context", "diff_sha256": "sha256:" + "c" * 64,
                      "findings": []},
    "trail.review": {"head": "sha256:" + "d" * 64, "findings": [
        {"query": "self-approval", "severity": "major", "record_ids": [], "disposition": "explained"}]},
    "signoff.action.outcome": {"outcome": "unknown", "action_id": "act_1"},
    "quarantine.held": {"case_id": "q-1", "band": "hold", "score_ppm": 812000,
                        "source": {"tool": "WebFetch", "ref": "https://example.org/", "domain": "example.org"}},
    "sensei.decision": {"decision": "approve", "message_id": "m-1", "pair_id": "p-1"},
    "validate.qualification": {"configuration_hash": "sha256:" + "e" * 64, "valid_until": "2027-04-21T00:00:00Z"},
    "capa.action": {"target": {"path": "AGENTS.md", "before_sha256": "sha256:" + "1" * 64,
                               "after_sha256": "sha256:" + "2" * 64}, "effectiveness_criterion": "no recurrence"},
    "quarantine.refused": {"attempted_action": "release", "reason_code": "agent-context", "agent_markers": ["env:CLAUDECODE"]},
}


@pytest.mark.parametrize("type_", sorted(EXAMPLES))
def test_examples_match_and_required_fields_are_enforced(type_):
    assert schemas.validate_payload({"type": type_, "data": EXAMPLES[type_]}) == []
    required = schemas.schema_for(type_).get("required", [])
    assert required, f"{type_} should fix its minimal fields (spec §11)"
    broken = {k: v for k, v in EXAMPLES[type_].items() if k != required[0]}
    assert schemas.validate_payload({"type": type_, "data": broken})


def test_payloads_are_loose_and_units_are_ppm():
    data = {**EXAMPLES["quarantine.held"], "extra_field": {"anything": 1}}
    assert schemas.validate_payload({"type": "quarantine.held", "data": data}) == []
    assert schemas.validate_payload({"type": "quarantine.held", "data": {**data, "score_ppm": 1000001}})


def test_signature_thresholds_signers_schemas():
    signature = {"statement": {"aqt_signature": "0.1", "signer": {"id": "human:alice", "name": "Alice Example"},
                               "key": "ed25519:0123456789abcdef", "meaning": "approved",
                               "signed_at": "2026-10-21T12:00:00Z",
                               "subject": {"kind": "file", "ref": "a.md", "sha256": "sha256:" + "f" * 64}},
                 "alg": "ed25519", "key": "ed25519:0123456789abcdef", "value": "c2ln"}
    assert schemas.validate_schema(signature, "signature") == []
    assert schemas.validate_payload({"type": "signoff.signature", "data": {"signature": signature, "meaning": "liked"}})
    thresholds = {"aqt_thresholds": "0.1", "detectors": [{"id": "heuristics", "version": "1"}],
                  "bands": [{"name": "hold", "fpr_target_ppm": 10000, "rule": "any", "thresholds": {"heuristics": 655000}}]}
    assert schemas.validate_schema(thresholds, "thresholds") == []
    assert schemas.validate_schema({**thresholds, "bands": [{**thresholds["bands"][0], "thresholds": {"h": "0.6"}}]},
                                   "thresholds")
    signers = {"version": 1, "signers": [{"id": "human:alice", "name": "Alice Example", "role": "qa", "keys": [
        {"key_id": "ed25519:0123456789abcdef", "public_pem": "-----BEGIN PUBLIC KEY-----", "revoked_at": None}]}]}
    assert schemas.validate_schema(signers, "signers") == []
    assert schemas.validate_schema({"pid": 1, "via": "socket", "client_time": "2026-10-21T12:00:00Z"}, "observed") == []
    assert schemas.validate_schema({"via": "carrier-pigeon"}, "observed")
