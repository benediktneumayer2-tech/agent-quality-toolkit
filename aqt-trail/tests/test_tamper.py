"""Editing, inserting, deleting, reordering, truncating or rewriting the trail is detected."""

import json

import pytest

from aqt_evidence import GENESIS, canonical_json, generate_key, link, load_public_key, load_signer, record_hash, sign_record

from aqt_trail import anchors
from aqt_trail.state import open_writer, service_keys
from aqt_trail.verify import verify_trail

from conftest import event, observed_stub


@pytest.fixture
def trail(config):
    w = open_writer(config)
    for i in range(5):
        w.append(event(f"step-{i}"), observed_stub())
    point = anchors.current_checkpoint(w)
    anchors.save_checkpoint(w, point)
    w.close()
    heads = config.state.parent / "heads.jsonl"
    heads.write_text(json.dumps(point) + "\n")
    return config, heads


def lines(config):
    return config.trail_path.read_bytes().splitlines(keepends=True)


def check(config, **kw):
    return verify_trail(config.trail_path, keys=service_keys(config), checkpoints=config.checkpoints_path, **kw)


def test_intact(trail):
    config, heads = trail
    report = check(config, heads=heads)
    assert report.ok and report.count == 5 and report.checkpoints == 1 and report.heads == 1


def test_edit_is_detected(trail):
    config, _ = trail
    data = lines(config)
    record = json.loads(data[2])
    record["reason"] = "changed afterwards"
    data[2] = canonical_json(record) + b"\n"
    config.trail_path.write_bytes(b"".join(data))
    report = check(config)
    assert not report.ok and report.first_bad_seq == 2 and "signature" in report.reason


def test_insert_is_detected(trail):
    config, _ = trail
    data = lines(config)
    config.trail_path.write_bytes(b"".join(data[:2] + [data[1]] + data[2:]))
    assert check(config).first_bad_seq == 2


def test_delete_is_detected(trail):
    config, _ = trail
    data = lines(config)
    config.trail_path.write_bytes(b"".join(data[:1] + data[2:]))
    report = check(config)
    assert report.first_bad_seq == 1 and "expected seq 1" in report.reason


def test_reorder_is_detected(trail):
    config, _ = trail
    data = lines(config)
    config.trail_path.write_bytes(b"".join([data[0], data[2], data[1], *data[3:]]))
    assert check(config).first_bad_seq == 1


def test_truncation_is_detected_by_checkpoint_and_heads(trail):
    config, heads = trail
    config.trail_path.write_bytes(b"".join(lines(config)[:3]))
    report = check(config, heads=heads)
    assert not report.ok and report.first_bad_seq is None
    assert any("truncated" in p for p in report.problems)


def test_forged_signature_is_detected(trail):
    config, _ = trail
    data = lines(config)
    record = json.loads(data[4])
    record["sig"][0]["value"] = record["sig"][0]["value"][::-1]
    data[4] = canonical_json(record) + b"\n"
    config.trail_path.write_bytes(b"".join(data))
    assert check(config).first_bad_seq == 4


def test_wrong_key_is_detected(trail, tmp_path):
    config, _ = trail
    generate_key(tmp_path / "other.key")
    keys = dict([load_public_key(tmp_path / "other.key.pub")])
    report = verify_trail(config.trail_path, keys=keys)
    assert report.first_bad_seq == 0 and "known key" in report.reason


def _rewrite_under_new_key(config, tmp_path):
    """The attack Sasana warns about: rebuild the whole chain with a fresh key."""
    generate_key(tmp_path / "evil.key")
    evil = load_signer(tmp_path / "evil.key")
    out, prev = [], GENESIS
    for seq, line in enumerate(lines(config)[:3]):
        record = json.loads(line)
        record["reason"] = "history rewritten"
        record = sign_record(link(record, seq=seq, prev=prev), evil)
        prev = record_hash(record)
        out.append(canonical_json(record) + b"\n")
    config.trail_path.write_bytes(b"".join(out))
    for pub in (config.state / "keys").glob("*.pub"):
        pub.unlink()
    (config.state / "keys" / "service.key.pub").write_bytes((tmp_path / "evil.key.pub").read_bytes())
    config.checkpoints_path.unlink()


def test_full_rewrite_is_detected_by_pinned_key_and_external_heads(trail, tmp_path):
    config, heads = trail
    original_pub = tmp_path / "pinned.pub"
    original_pub.write_bytes((config.state / "keys" / "service.key.pub").read_bytes())
    _rewrite_under_new_key(config, tmp_path)
    naive = check(config)
    assert naive.ok and any("not pinned" in w for w in naive.warnings)  # why pinning and anchors matter
    pinned = verify_trail(config.trail_path, keys=dict([load_public_key(original_pub)]), pinned=True)
    assert pinned.first_bad_seq == 0
    with_heads = check(config, heads=heads)
    assert not with_heads.ok and any("external head" in p for p in with_heads.problems)


def test_garbage_line_is_reported_with_position(trail):
    config, _ = trail
    with open(config.trail_path, "ab") as handle:
        handle.write(b"not json\n")
    report = check(config)
    assert report.first_bad_seq == 5 and "not valid JSON" in report.reason
