"""Additive library features: strict parsing, spooling, conformance, CLI."""

import json
import os
import socket
import threading

import pytest

from aqt_evidence import (GENESIS, CanonicalError, SinkError, SocketSink, actor, canonical_json, conformance,
                          generate_key, link, load_public_key, load_signer, make_checkpoint, new_record, open_sink,
                          parse_record, read_jsonl, record_hash, sign_record, spool_file, validate_record)
from aqt_evidence.cli import main


def record(type_="trail.event", **extra):
    return new_record(type_, actor("agent", "agent:claude-code:s1"), "step", **extra)


def test_lone_surrogate_is_a_validation_problem_not_a_crash():
    bad = {**record(), "reason": json.loads('"\\ud800"')}
    assert any("surrogate" in problem for problem in validate_record(bad))
    with pytest.raises(CanonicalError):
        canonical_json({"s": "\udc00"})


def test_parse_record_is_strict():
    good = canonical_json(record())
    assert parse_record(good)["action"] == "step"
    for text in ('{"a":1,"a":2}', '{"a":1.0}', '{"a":NaN}', '[1]', '{"a":"\\ud800"}', b'\xff'):
        with pytest.raises(CanonicalError):
            parse_record(text)


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    return tmp_path


def test_socket_sink_spools_when_unavailable(state):
    sink = open_sink(f"unix:{state / 'missing.sock'}")
    first = record()
    assert sink.append(first) == first and sink.last_spooled
    assert spool_file() == state / "state" / "aqt" / "spool" / "spool.jsonl"
    assert [r["id"] for r in read_jsonl(spool_file())] == [first["id"]]
    assert oct(os.stat(spool_file()).st_mode & 0o777) == "0o600"
    with pytest.raises(SinkError):
        sink.append({"not": "a record"})  # invalid records are never spooled
    with pytest.raises(SinkError):
        SocketSink(state / "missing.sock", spool=False).append(record())


def test_socket_sink_does_not_spool_refusals(state):
    path = str(state / "t.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)

    def serve():
        connection, _ = server.accept()
        with connection:
            while connection.recv(65536):
                pass
            connection.sendall(b'{"ok": false, "code": "duplicate_id", "message": "id exists"}\n')

    thread = threading.Thread(target=serve)
    thread.start()
    sink = SocketSink(path)
    with pytest.raises(SinkError, match="duplicate_id"):
        sink.append(record())
    thread.join()
    server.close()
    assert not sink.last_spooled and not spool_file().exists()


@pytest.fixture
def keyed(tmp_path):
    generate_key(tmp_path / "k")
    return load_signer(tmp_path / "k"), tmp_path / "k.pub"


def chain(records, signer=None):
    out, prev = [], GENESIS
    for seq, item in enumerate(records):
        item = link(item, seq=seq, prev=prev)
        out.append(sign_record(item, signer) if signer else item)
        prev = record_hash(out[-1])
    return out


def test_conformance_levels(keyed):
    signer, pub = keyed
    keys = dict([load_public_key(pub)])
    records = chain([record() for _ in range(3)], signer)
    checkpoint = make_checkpoint(log_id="t", seq=2, head=record_hash(records[2]), signer=signer)
    assert conformance(records, 3, keys=keys, checkpoints=[checkpoint]).level == 3
    no_anchor = conformance(records, 3, keys=keys)
    assert no_anchor.level == 2 and "checkpoint" in no_anchor.problems[0]
    assert conformance(records[:2], 3, keys=keys, checkpoints=[checkpoint]).level == 2
    unchained = [record(), record()]
    assert conformance(unchained, 1).ok and conformance(unchained, 2).level == 1
    assert conformance([record("acme.thing")], 1).level == 0
    assert conformance([record("x-acme.thing")], 1).ok
    duplicate = record()
    assert "duplicate id" in conformance([duplicate, duplicate]).problems[0]
    human = new_record("quarantine.released", actor("human", "human:alice"), "release", data={"case_id": "q1"})
    assert "needs a reason" in conformance([human]).problems[0]
    bad_payload = record("change.finish", data={"plan_ref": "p"})
    assert any("receipts" in p for p in conformance([bad_payload]).problems)
    assert conformance([bad_payload], check_payloads=False).ok


def test_cli_conform_and_vectors(tmp_path, keyed, capsys):
    signer, pub = keyed
    records = chain([record() for _ in range(2)], signer)
    path = tmp_path / "trail.jsonl"
    path.write_bytes(b"".join(canonical_json(r) + b"\n" for r in records))
    cp = tmp_path / "cp.json"
    cp.write_text(json.dumps(make_checkpoint(log_id="t", seq=1, head=record_hash(records[1]), signer=signer)))
    assert main(["conform", str(path), "--level", "3", "--key", str(pub), "--checkpoint", str(cp)]) == 0
    assert "L3 reached" in capsys.readouterr().out
    path.write_text(path.read_text().replace('"action":"step"', '"action":"step","action":"x"', 1))
    assert main(["conform", str(path), "--json"]) == 1
    assert "duplicate object key" in json.loads(capsys.readouterr().out)["problems"][0]
    assert main(["vectors"]) == 0
    assert "vectors agree" in capsys.readouterr().out
