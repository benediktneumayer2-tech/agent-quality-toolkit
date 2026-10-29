"""Property tests (Hypothesis): canonical JSON, record hashing, chain and signature verification.

Deterministic (derandomized, no example database), so CI runs are reproducible."""

import copy
import json

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from aqt_evidence import (GENESIS, CanonicalError, canonical_json, content_hash, link,  # noqa: E402
                          parse_canonical_line, parse_json, record_content_hash, record_hash, sign_record,
                          signer_from_seed, validate_record, verify_chain, verify_record_signatures)

settings.register_profile("aqt", derandomize=True, database=None, deadline=None, max_examples=150)
settings.load_profile("aqt")

SIGNER = signer_from_seed(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
OTHER = signer_from_seed(bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
KEYS = {SIGNER.key_id: SIGNER.public_key}
LIMIT = 2**53 - 1

keys = st.text(st.characters(min_codepoint=0, max_codepoint=127), max_size=6)
texts = st.text(st.characters(exclude_categories=("Cs",)), max_size=12)
scalars = st.none() | st.booleans() | st.integers(-LIMIT, LIMIT) | texts
values = st.recursive(scalars, lambda inner: st.lists(inner, max_size=4) | st.dictionaries(keys, inner, max_size=4),
                      max_leaves=16)
objects = st.dictionaries(keys, values, max_size=5)


def records(draw_index: int, action: str, data: dict) -> dict:
    return {"aqt": "0.1", "id": f"rec_019a0f3c2b00{draw_index:016x}", "type": "trail.event",
            "time": "2026-10-21T12:00:00.000000Z", "actor": {"kind": "agent", "id": "agent:x:s1"},
            "action": action, "data": data}


actions = st.text(st.characters(exclude_categories=("Cs",)), min_size=1, max_size=10)
chains = st.lists(st.tuples(actions, objects), min_size=1, max_size=6)


def build_chain(items, signer=SIGNER):
    out, prev = [], GENESIS
    for seq, (action, data) in enumerate(items):
        record = sign_record(link(records(seq, action, data), seq=seq, prev=prev), signer)
        out.append(record)
        prev = record_hash(record)
    return out


# --- canonical JSON ------------------------------------------------------------------------------------
@given(values)
def test_canonical_round_trip_and_idempotence(value):
    text = canonical_json(value)
    assert parse_json(text) == value
    assert canonical_json(parse_json(text)) == text


@given(objects, st.randoms(use_true_random=False), st.sampled_from([None, 0, 2]))
def test_canonical_form_ignores_key_order_and_whitespace(value, rng, indent):
    def shuffled(v):
        if isinstance(v, dict):
            items = list(v.items())
            rng.shuffle(items)
            return {k: shuffled(x) for k, x in items}
        return [shuffled(x) for x in v] if isinstance(v, list) else v
    text = json.dumps(shuffled(value), indent=indent, ensure_ascii=rng.random() < 0.5)
    assert canonical_json(parse_json(text)) == canonical_json(value)
    assert content_hash(parse_json(text)) == content_hash(value)


@given(objects, st.floats(allow_nan=False, allow_infinity=False))
def test_floats_are_always_refused(value, number):
    with pytest.raises(CanonicalError):
        canonical_json({**value, "x": number})
    with pytest.raises(CanonicalError):
        parse_json(f'{{"x":{number!r}}}')  # repr always has a fraction or an exponent, as 1.0 does


@given(objects.filter(bool), values)
def test_duplicate_keys_are_always_refused(value, extra):
    key = sorted(value)[0]
    text = canonical_json(value).decode()
    forged = "{" + json.dumps(key) + ":" + canonical_json(extra).decode() + "," + text[1:]
    with pytest.raises(CanonicalError):
        parse_json(forged)


@given(st.integers().filter(lambda n: abs(n) > LIMIT))
def test_integers_beyond_the_safe_range_are_refused(number):
    with pytest.raises(CanonicalError):
        parse_json(f'{{"n":{number}}}')


@given(values, values)
def test_different_values_have_different_hashes(first, second):
    assert (canonical_json(first) == canonical_json(second)) == (content_hash(first) == content_hash(second))


# --- record hashing ------------------------------------------------------------------------------------
@given(actions, objects)
def test_record_hash_ignores_sig_and_content_hash_ignores_writer_fields(action, data):
    record = records(1, action, data)
    assert validate_record(record) == []
    signed = sign_record(record, SIGNER)
    assert record_hash(signed) == record_hash(record)
    stored = sign_record(link({**record, "time": "2030-01-01T00:00:00Z", "observed": {"pid": 1, "via": "socket"}},
                              seq=7, prev=GENESIS), SIGNER)
    assert record_content_hash(stored) == record_content_hash(record)
    assert record_hash(stored) != record_hash(record)
    assert record_content_hash({**record, "action": action + "!"}) != record_content_hash(record)


# --- chains and signatures -----------------------------------------------------------------------------
@given(chains)
def test_signed_chains_verify_and_survive_storage_as_lines(items):
    chain = build_chain(items)
    result = verify_chain(chain, keys=KEYS, require_signature=True)
    assert result.ok and result.count == len(chain) and result.head_hash == record_hash(chain[-1])
    assert [parse_canonical_line(canonical_json(record) + b"\n") for record in chain] == chain


MUTATIONS = ("edit", "drop", "swap", "duplicate", "strip-sig", "flip-sig", "other-key", "reseq")


@given(chains, st.integers(min_value=0), st.sampled_from(MUTATIONS))
def test_any_single_tampering_of_a_signed_chain_is_detected(items, where, mutation):
    chain = build_chain(items)
    i = where % len(chain)
    tampered = copy.deepcopy(chain)
    if mutation == "edit":
        tampered[i]["action"] += "!"
    elif mutation == "drop":
        if len(chain) == 1 or i == len(chain) - 1:
            return  # dropping the last record is truncation: only a checkpoint reveals it (spec section 7)
        del tampered[i]
    elif mutation == "swap":
        if len(chain) == 1:
            return
        j = (i + 1) % len(chain)
        tampered[i], tampered[j] = tampered[j], tampered[i]
        i = min(i, j)
    elif mutation == "duplicate":
        tampered.insert(i, copy.deepcopy(tampered[i]))
        i += 1
    elif mutation == "strip-sig":
        del tampered[i]["sig"]
    elif mutation == "flip-sig":
        value = bytearray(tampered[i]["sig"][0]["value"].encode())
        value[3] = ord("A") if value[3] != ord("A") else ord("B")
        tampered[i]["sig"][0]["value"] = value.decode()
    elif mutation == "other-key":
        tampered[i] = sign_record({k: v for k, v in tampered[i].items() if k != "sig"}, OTHER)
    elif mutation == "reseq":
        tampered[i]["chain"]["seq"] += len(chain)
    result = verify_chain(tampered, keys=KEYS, require_signature=True)
    assert not result.ok
    assert result.first_bad_seq is not None and result.first_bad_seq <= i + 1


@given(chains, st.integers(min_value=0))
def test_a_duplicate_key_on_any_stored_line_is_refused(items, where):
    lines = [canonical_json(record) for record in build_chain(items)]
    i = where % len(lines)
    lines[i] = lines[i].replace(b'"action":', b'"action":"forged","action":', 1)
    with pytest.raises(CanonicalError):
        parse_canonical_line(lines[i])


@given(actions, objects, st.sampled_from(("action", "data", "actor", "chain")))
def test_a_signature_does_not_survive_a_change_of_the_record(action, data, member):
    record = sign_record(link(records(1, action, data), seq=0, prev=GENESIS), SIGNER)
    assert verify_record_signatures(record, KEYS) == [(SIGNER.key_id, True)]
    changed = copy.deepcopy(record)
    if member == "action":
        changed["action"] = action + "!"
    elif member == "data":
        changed["data"]["~"] = None if changed["data"].get("~", 0) is not None else 0
    elif member == "actor":
        changed["actor"]["id"] = "agent:x:s2"
    else:
        changed["chain"]["seq"] = 1
    assert verify_record_signatures(changed, KEYS) == [(SIGNER.key_id, False)]
