import json
import os
import socket
import threading

import pytest

from aqt_evidence import (GENESIS, CanonicalError, JsonlSink, SinkError, SocketSink, actor, canonical_json,
                          checkpoint_matches, generate_key, link, load_public_key, load_signer,
                          make_checkpoint, new_record, read_jsonl, record_hash, sign_record, subject,
                          validate_record, verify_chain, verify_checkpoint, verify_record_signatures)
from aqt_evidence.cli import main


def owner():
    return actor("human", "owner", role="quality-manager")


def records(n):
    return [new_record("trail.event", owner(), f"act-{i}", subject=subject("file", f"f{i}"), reason="test")
            for i in range(n)]


def chained(rs, signer=None):
    out, prev = [], GENESIS
    for seq, record in enumerate(rs):
        record = link(record, seq=seq, prev=prev)
        if signer:
            record = sign_record(record, signer)
        out.append(record)
        prev = record_hash(record)
    return out


@pytest.fixture
def signer(tmp_path):
    generate_key(tmp_path / "k")
    return load_signer(tmp_path / "k")


def test_canonical_json_is_sorted_compact_and_rejects_floats():
    assert canonical_json({"b": 1, "a": "ä"}) == '{"a":"ä","b":1}'.encode()
    with pytest.raises(CanonicalError):
        canonical_json({"x": 1.5})
    with pytest.raises(CanonicalError):
        canonical_json({"x": 2**60})


def test_new_record_is_valid_and_rejects_bad_meaning():
    record = new_record("signoff.signature", owner(), "sign", meaning="approved",
                        subject=subject("plan", "p1", sha256="sha256:" + "a" * 64))
    assert validate_record(record) == []
    with pytest.raises(ValueError):
        new_record("signoff.signature", owner(), "sign", meaning="liked")
    assert "type must be" in " ".join(validate_record({**record, "type": "Bad"}))


def test_signature_round_trip_and_tamper(signer, tmp_path):
    record = sign_record(records(1)[0], signer)
    keys = dict([load_public_key(tmp_path / "k.pub")])
    assert verify_record_signatures(record, keys) == [(signer.key_id, True)]
    tampered = {**record, "action": "other"}
    assert verify_record_signatures(tampered, keys) == [(signer.key_id, False)]
    assert record_hash(record) == record_hash({k: v for k, v in record.items() if k != "sig"})


def test_chain_detects_edit_insert_delete_reorder(signer, tmp_path):
    keys = dict([load_public_key(tmp_path / "k.pub")])
    chain = chained(records(5), signer)
    assert verify_chain(chain, keys=keys, require_signature=True).ok
    edited = [*chain[:2], {**chain[2], "reason": "changed"}, *chain[3:]]
    assert verify_chain(edited, keys=keys).first_bad_seq == 2
    assert not verify_chain([*chain[:2], *chain[3:]]).ok
    assert not verify_chain([chain[1], chain[0], *chain[2:]]).ok
    inserted = [*chain[:2], chained(records(1))[0], *chain[2:]]
    assert not verify_chain(inserted).ok
    unsigned_chain = chained(records(2))
    assert not verify_chain(unsigned_chain, keys=keys, require_signature=True).ok


def test_checkpoint_detects_truncation_and_rewrite(signer, tmp_path):
    keys = dict([load_public_key(tmp_path / "k.pub")])
    chain = chained(records(4), signer)
    checkpoint = make_checkpoint(log_id="demo", seq=3, head=record_hash(chain[3]), signer=signer)
    assert verify_checkpoint(checkpoint, keys)
    assert checkpoint_matches(checkpoint, chain)
    assert not checkpoint_matches(checkpoint, chain[:3])
    rewritten = chained(records(4), signer)
    assert verify_chain(rewritten, keys=keys).ok and not checkpoint_matches(checkpoint, rewritten)
    assert not verify_checkpoint({**checkpoint, "seq": 2}, keys)


def test_jsonl_sink_and_cli(tmp_path, signer, capsys):
    path = tmp_path / "e.jsonl"
    sink = JsonlSink(path)
    for record in chained(records(3), signer):
        sink.append(record)
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert len(list(read_jsonl(path))) == 3
    assert main(["verify", str(path), "--key", str(tmp_path / "k.pub"), "--require-signature"]) == 0
    assert "intact: 3 records" in capsys.readouterr().out
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert main(["verify", str(path)]) == 1
    with pytest.raises(SinkError):
        sink.append({"not": "a record"})


def test_socket_sink_protocol(tmp_path):
    path = str(tmp_path / "t.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)

    def serve():
        connection, _ = server.accept()
        with connection:
            data = b""
            while chunk := connection.recv(65536):
                data += chunk
            request = json.loads(data)
            stored = {**request["record"], "chain": {"seq": 0, "prev": GENESIS}}
            connection.sendall(json.dumps({"ok": True, "record": stored}).encode() + b"\n")

    thread = threading.Thread(target=serve)
    thread.start()
    stored = SocketSink(path).append(records(1)[0])
    thread.join()
    server.close()
    assert stored["chain"]["seq"] == 0
    with pytest.raises(SinkError):
        SocketSink(str(tmp_path / "missing.sock"), timeout=0.5, spool=False).append(records(1)[0])


def test_agent_context_detection():
    from aqt_evidence.session import HumanCheckError, detect_agent_context, require_human

    class Tty:
        def isatty(self):
            return True

    assert not detect_agent_context({}, chain=["python3", "bash", "login"]).is_agent
    context = detect_agent_context({"CLAUDECODE": "1"}, chain=["python3"])
    assert context.is_agent and context.harness == "claude-code"
    assert detect_agent_context({}, chain=["python3", "bash", "codex"]).harness == "codex"
    with pytest.raises(HumanCheckError):
        require_human(environ={}, chain=["python3", "claude"], stdin=Tty())
    with pytest.raises(HumanCheckError):
        require_human(environ={}, chain=["python3", "bash"], stdin=open(os.devnull))
    assert not require_human(environ={}, chain=["python3", "bash"], stdin=Tty()).is_agent


def test_record_content_hash_ignores_writer_fields(tmp_path, signer):
    from aqt_evidence import iter_evidence, record_content_hash
    record = records(1)[0]
    stored = sign_record(link({**record, "time": "2030-01-01T00:00:00Z", "observed": {"pid": 1}},
                              seq=0, prev=GENESIS), signer)
    assert record_content_hash(stored) == record_content_hash(record)
    assert record_content_hash({**record, "action": "x"}) != record_content_hash(record)
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    JsonlSink(a).append(record)
    JsonlSink(b).append(record)
    JsonlSink(b).append(records(1)[0])
    assert len(list(iter_evidence([a, b]))) == 2
