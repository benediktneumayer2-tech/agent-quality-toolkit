import json

import pytest

from aqt_evidence import canonical_json, record_content_hash, sign_record, verify_chain

from aqt_trail.state import open_writer, read_records, service_keys
from aqt_trail.writer import LogBroken, Refused, WriterBusy

from conftest import agent, event, observed_stub


def test_append_sets_writer_fields(writer, config):
    record = event("demo.start", time="2020-01-01T00:00:00.000000Z")
    stored, created = writer.append(record, observed_stub())
    assert created
    assert stored["observed"]["client_time"] == "2020-01-01T00:00:00.000000Z"
    assert stored["time"] > "2026"
    assert stored["chain"] == {"seq": 0, "prev": "sha256:" + "0" * 64}
    assert record_content_hash(stored) == record_content_hash(record)
    assert verify_chain(read_records(config.trail_path), keys=service_keys(config), require_signature=True).ok


@pytest.mark.parametrize("field,value", [("chain", {"seq": 0, "prev": "sha256:" + "0" * 64}),
                                         ("observed", {"pid": 1})])
def test_writer_fields_are_refused_and_logged(writer, config, field, value):
    record = event()
    record[field] = value
    with pytest.raises(Refused) as caught:
        writer.append(record, observed_stub())
    assert caught.value.code == "invalid_record"
    refusal = read_records(config.trail_path)[-1]
    assert refusal["type"] == "trail.refused" and refusal["action"] == "refused"
    assert refusal["actor"]["id"] == "human:alice"
    assert refusal["data"]["reason_code"] == "invalid_record"
    assert refusal["data"]["attempted_id"] == record["id"]


def test_client_signature_is_refused(writer, signer_key):
    with pytest.raises(Refused):
        writer.append(sign_record(event(), signer_key), observed_stub())


@pytest.fixture
def signer_key(tmp_path):
    from aqt_evidence import generate_key, load_signer
    generate_key(tmp_path / "client.key")
    return load_signer(tmp_path / "client.key")


def test_human_decision_needs_reason(writer):
    record = event("approve", meaning="approved")
    del record["reason"]
    with pytest.raises(Refused, match="needs a reason"):
        writer.append(record, observed_stub())


def test_idempotent_by_id_and_duplicate_id(writer, config):
    record = event()
    first, created = writer.append(record, observed_stub())
    again, created_again = writer.append(dict(record), observed_stub())
    assert created and not created_again and again == first
    changed = dict(record, action="something-else")
    with pytest.raises(Refused) as caught:
        writer.append(changed, observed_stub())
    assert caught.value.code == "duplicate_id"
    assert len([r for r in read_records(config.trail_path) if r["type"] == "trail.event"]) == 1


def test_single_writer_lock(writer, config):
    with pytest.raises(WriterBusy):
        open_writer(config)


def test_torn_last_line_is_repaired_and_recorded(config):
    w = open_writer(config)
    w.append(event(), observed_stub())
    w.close()
    with open(config.trail_path, "ab") as handle:
        handle.write(b'{"partial": ')
    w = open_writer(config)
    w.close()
    records = read_records(config.trail_path)
    assert records[-1]["action"] == "log.repaired"
    assert records[-1]["data"]["removed_bytes"] == len(b'{"partial": ')
    assert verify_chain(records, keys=service_keys(config), require_signature=True).ok


def test_writer_refuses_to_continue_a_broken_log(config):
    w = open_writer(config)
    for i in range(3):
        w.append(event(f"a{i}"), observed_stub())
    w.close()
    lines = config.trail_path.read_bytes().splitlines(keepends=True)
    config.trail_path.write_bytes(lines[0] + lines[2])
    with pytest.raises(LogBroken):
        open_writer(config)


def test_clock_jump_backwards_is_recorded(config):
    times = iter(["2026-10-21T10:00:00.000000Z", "2026-10-21T09:00:00.000000Z", "2026-10-21T09:00:00.000000Z"])
    w = open_writer(config)
    w.clock = lambda: next(times)
    w.append(event("one"), observed_stub())
    w.append(event("two"), observed_stub())
    w.close()
    records = read_records(config.trail_path)
    assert [r["action"] for r in records] == ["one", "clock.jump", "two"]
    assert records[1]["data"]["direction"] == "backward"


def test_drain_writes_gap_then_spooled_records(writer, config):
    spooled = [event("a", who=agent()), event("b")]
    bad = event("c")
    bad["sig"] = [{"alg": "ed25519", "key": "k", "value": "v"}]
    result = writer.drain([*spooled, bad, "not json {"], source="spool.jsonl")
    records = read_records(config.trail_path)
    assert records[0]["type"] == "trail.gap"
    assert records[0]["data"]["count"] == 2 and records[0]["data"]["spool_ids"] == [r["id"] for r in spooled]
    assert [r["observed"]["via"] for r in records[1:3]] == ["spool", "spool"]
    assert "pid" not in records[1]["observed"]
    assert len(result.refused) == 2 and all(r["type"] == "trail.refused" for r in records[3:])
    again = writer.drain(spooled, source="spool.jsonl")
    assert again.gap is None and len(again.already_stored) == 2


def test_stored_records_are_canonical_lines(writer, config):
    writer.append(event(data={"n": 1}), observed_stub())
    line = config.trail_path.read_bytes().splitlines()[0]
    assert json.loads(line)["data"] == {"n": 1}
    assert line == canonical_json(json.loads(line))
