"""Regressions from the 2026-10 security review: shadowing by side files, lenient parsing in
verifiers, signatures required without keys, envelope types, checkpoint shape, deep nesting."""

import json
from pathlib import Path

import pytest

from aqt_evidence import (GENESIS, CanonicalError, JsonlSink, RecordLineError, actor, canonical_json, conformance,
                          evidence_sources, iter_evidence, link, make_checkpoint, new_record, parse_canonical_line,
                          parse_record, read_jsonl, record_hash, sign_record, signer_from_seed, spool_file,
                          state_dir, validate_record, verify_chain, verify_checkpoint)
from aqt_evidence import sink as sink_module
from aqt_evidence.cli import main
from aqt_evidence.crypto import public_pem

SIGNER = signer_from_seed(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
KEYS = {SIGNER.key_id: SIGNER.public_key}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    for name in ("AQT_SINK", "AQT_EVIDENCE", "AQT_TRAIL_STATE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sink_module, "_warned", set())
    return tmp_path


def signed_chain(actions):
    out, prev = [], GENESIS
    for seq, action in enumerate(actions):
        record = sign_record(link(new_record("trail.event", actor("human", "human:alice"), action,
                                             reason="r"), seq=seq, prev=prev), SIGNER)
        out.append(record)
        prev = record_hash(record)
    return out


def write_lines(path: Path, lines) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join((line if isinstance(line, bytes) else canonical_json(line)) + b"\n" for line in lines))
    return path


def pub_key(tmp_path) -> Path:
    path = tmp_path / "writer.pub"
    path.write_bytes(public_pem(SIGNER.public_key))
    return path


# --- A-1, C-17: a side file must not shadow a trail record -------------------------------------------
def test_side_file_cannot_hide_or_replace_a_trail_record(env, capsys):
    approve, withdraw = signed_chain(["approve", "withdraw"])
    trail = write_lines(state_dir() / "trail" / "trail.jsonl", [approve, withdraw])
    decoy = {**new_record("trail.event", actor("agent", "agent:x:s1"), "noop"), "id": withdraw["id"]}
    side = write_lines(state_dir() / "evidence.jsonl", [decoy])
    assert evidence_sources() == [trail, side]  # the trail is read first

    conflicts = []
    for paths in (None, [side, trail]):  # also when a caller lists the side file first
        seen = list(iter_evidence(paths, conflicts=conflicts))
        assert [r["action"] for r in seen] == ["approve", "withdraw"]
    assert conflicts == [{"id": withdraw["id"], "kept": str(trail), "dropped": str(side)}] * 2

    list(iter_evidence())  # without a list the conflict is reported on stderr
    assert f"record {withdraw['id']} in {side} differs" in capsys.readouterr().err


def test_side_file_records_without_conflict_are_still_read(env, capsys):
    (stored,) = signed_chain(["stored"])
    write_lines(state_dir() / "trail" / "trail.jsonl", [stored])
    spooled = {key: value for key, value in stored.items() if key not in ("sig", "chain")}
    spooled["time"] = "2026-01-01T00:00:00Z"  # the producer's time; the trail restamped it
    own = new_record("trail.event", actor("agent", "agent:x:s1"), "own")
    write_lines(spool_file(), [spooled, own])
    conflicts = []
    seen = list(iter_evidence(conflicts=conflicts))
    assert [r["action"] for r in seen] == ["stored", "own"] and "chain" in seen[0]
    assert conflicts == [] and capsys.readouterr().err == ""


# --- A-5, C-19, AQT-EI-001: verifiers parse strictly ----------------------------------------------
def test_strict_reader_rejects_duplicate_keys_and_non_canonical_lines(tmp_path):
    first, second = signed_chain(["one", "two"])
    line = canonical_json(second)
    duplicate = line.replace(b'"action":"two"', b'"action":"forged","action":"two"', 1)
    spaced = json.dumps(second).encode()
    for bad, reason in ((duplicate, "duplicate object key"), (spaced, "not in canonical form"),
                        (line + b"\r", "not in canonical form"), (b'{"aqt":1.5}', "floats")):
        path = write_lines(tmp_path / "log.jsonl", [first, bad])
        assert len(list(read_jsonl(path))) == 2  # the lenient reader (consumers) still reads it
        with pytest.raises(RecordLineError) as caught:
            list(read_jsonl(path, strict=True))
        assert caught.value.line == 2 and reason in caught.value.reason
    assert parse_canonical_line(line + b"\n") == second == parse_canonical_line(line.decode())


def test_verify_cli_breaks_at_a_duplicate_key_line(tmp_path, capsys):
    records = signed_chain(["start", "review", "stop"])
    lines = [canonical_json(r) for r in records]
    lines[1] = lines[1].replace(b'"action":"review"', b'"action":"approve-all","action":"review"', 1)
    path = write_lines(tmp_path / "dup.jsonl", lines)
    code = main(["verify", str(path), "--key", str(pub_key(tmp_path)), "--require-signature"])
    out = capsys.readouterr().out
    assert code == 1 and "broken from seq 1: line 2: duplicate object key 'action'" in out
    assert main(["validate", str(path)]) == 1 and "record 2: duplicate object key" in capsys.readouterr().out
    assert main(["verify", str(write_lines(tmp_path / "ok.jsonl", records)), "--key", str(pub_key(tmp_path)),
                 "--require-signature"]) == 0


# --- A-6, AQT-EI-013: signatures required without a key ---------------------------------------------
def test_require_signature_without_key_fails(tmp_path, capsys):
    unsigned, prev = [], GENESIS
    for seq in range(2):
        record = link(new_record("trail.event", actor("agent", "agent:x:s1"), f"s{seq}"), seq=seq, prev=prev)
        unsigned.append(record)
        prev = record_hash(record)
    for keys in (None, {}):
        result = verify_chain(unsigned, keys=keys, require_signature=True)
        assert not result.ok and result.first_bad_seq == 0 and "no pinned public key" in result.reason
    path = write_lines(tmp_path / "unsigned.jsonl", unsigned)
    with pytest.raises(SystemExit) as caught:
        main(["verify", str(path), "--require-signature"])
    assert caught.value.code == 2 and "--require-signature needs the pinned public key" in capsys.readouterr().err


# --- A-7, AQT-EI-014: envelope types; no crash on sig null -----------------------------------------
BASE = {"aqt": "0.1", "id": "rec_019a0f3c2b000000000000000001", "type": "trail.event",
        "time": "2026-10-21T12:00:01.000000Z", "actor": {"kind": "agent", "id": "agent:x:s1"}, "action": "step-1"}


@pytest.mark.parametrize("change", [
    {"actor": {"kind": "human", "id": ["human:alice"]}}, {"actor": {"kind": ["human"], "id": "a"}},
    {"actor": {"kind": "human", "id": "a", "role": 5}}, {"actor": {"kind": "agent", "id": "a", "agent": "x"}},
    {"tz": 5}, {"tz": None}, {"before": "x"}, {"after": None}, {"subject": None},
    {"subject": {"kind": "file", "ref": {"a": 1}}}, {"links": [{"rel": "case", "ref": 5}]}, {"links": None},
    {"data": [1]}, {"data": None}, {"meaning": ["approved"]}, {"sig": None}, {"chain": None},
    {"chain": {"seq": -1, "prev": GENESIS}}, {"chain": {"seq": True, "prev": GENESIS}},
    {"sig": [{"alg": "ed25519", "key": "alice", "value": "AAAA"}]}, {"observed": {"pid": "1"}},
    {"observed": {"via": "pigeon"}}, {"observed": None},
])
def test_validate_record_applies_the_envelope_types(change):
    assert validate_record({**BASE, **change})


def test_level1_needs_a_valid_envelope_and_sig_null_does_not_crash():
    result = conformance([{**BASE, "actor": {"kind": "human", "id": ["human:alice"]}, "tz": 5, "before": "x"}], 1)
    assert result.level == 0 and len(result.problems) >= 3
    record = {**link(BASE, seq=0, prev=GENESIS), "sig": None}
    assert not verify_chain([record], keys=KEYS, require_signature=True).ok


# --- A-8: full matches and ASCII digits ---------------------------------------------------------------
@pytest.mark.parametrize("change", [
    {"id": BASE["id"] + "\n"}, {"type": "trail.event\n"}, {"time": BASE["time"] + "\n"},
    {"time": "٢٠٢٦-١٠-٢١T١٢:٠٠:٠١Z"}, {"time": "9999-99-99T99:99:99Z"}, {"time": "2026-02-29T00:00:00Z"},
    {"subject": {"kind": "file", "ref": "a", "sha256": "sha256:" + "0" * 64 + "\n"}},
    {"chain": {"seq": 0, "prev": GENESIS + "\n"}},
])
def test_patterns_match_the_whole_value(change):
    assert validate_record({**BASE, **change})


def test_real_times_stay_valid():
    for time in ("2024-02-29T23:59:60Z", "2026-10-21T12:00:01Z", "2026-10-21T12:00:01.123456Z"):
        assert validate_record({**BASE, "time": time}) == [], time


# --- A-10: checkpoints are checked for shape and domain -----------------------------------------------
def test_verify_checkpoint_rejects_other_shapes_without_raising():
    (record,) = signed_chain(["one"])
    checkpoint = make_checkpoint(log_id="log", seq=0, head=record_hash(record), signer=SIGNER)
    assert verify_checkpoint(checkpoint, KEYS)
    as_checkpoint = {**{k: v for k, v in record.items() if k != "sig"}, "sig": record["sig"][0]}
    assert verify_checkpoint(as_checkpoint, KEYS) is False  # a valid Ed25519 signature, but a record
    for bad in ({**checkpoint, "sig": [checkpoint["sig"]]}, {**checkpoint, "extra": 1}, {**checkpoint, "seq": True},
                {**checkpoint, "head": "x"}, {**checkpoint, "sig": None}, [], None, "x"):
        assert verify_checkpoint(bad, KEYS) is False
    true_seq = make_checkpoint(log_id="log", seq=True, head=record_hash(record), signer=SIGNER)
    assert verify_checkpoint(true_seq, KEYS) is False


# --- A-11: deep nesting is a parse problem, not a crash -----------------------------------------------
def test_deep_nesting_is_reported_not_raised(tmp_path, capsys):
    text = '{"a":' + "[" * 100_000 + "]" * 100_000 + "}"
    with pytest.raises(CanonicalError):
        parse_record(text)
    path = tmp_path / "deep.jsonl"
    path.write_text(text + "\n")
    with pytest.raises(RecordLineError):
        list(read_jsonl(path))
    assert main(["conform", str(path)]) == 1
    assert main(["verify", str(path)]) == 1 and "broken from seq 0: line 1" in capsys.readouterr().out
    nested: list = []
    for _ in range(100_000):
        nested = [nested]
    with pytest.raises(CanonicalError):
        canonical_json({"a": nested})
    assert validate_record({**BASE, "data": {"a": nested}})


# --- A-12: L3 says how far the newest checkpoint reaches -----------------------------------------------
def test_level3_reports_records_after_the_newest_checkpoint():
    records = signed_chain(["a", "b", "c"])
    early = make_checkpoint(log_id="log", seq=0, head=record_hash(records[0]), signer=SIGNER)
    result = conformance(records, 3, keys=KEYS, checkpoints=[early], check_payloads=False)
    assert result.level == 3 and result.anchored_seq == 0 and result.unanchored == 2
    assert "anchored up to seq 0, 2 later record(s) not covered by a checkpoint" in result.summary()
    head = make_checkpoint(log_id="log", seq=2, head=record_hash(records[2]), signer=SIGNER)
    assert conformance(records, 3, keys=KEYS, checkpoints=[early, head], check_payloads=False).unanchored == 0


def test_conform_reads_checkpoints_strictly(tmp_path, capsys):
    records = signed_chain(["a"])
    log = write_lines(tmp_path / "log.jsonl", records)
    checkpoint = make_checkpoint(log_id="log", seq=0, head=record_hash(records[0]), signer=SIGNER)
    text = canonical_json(checkpoint).replace(b'"seq":0', b'"seq":5,"seq":0', 1)
    (tmp_path / "cp.json").write_bytes(text)
    code = main(["conform", str(log), "--level", "3", "--key", str(pub_key(tmp_path)), "--checkpoint",
                 str(tmp_path / "cp.json"), "--no-payloads"])
    assert code == 2 and "duplicate object key 'seq'" in capsys.readouterr().err


def test_jsonl_sink_output_passes_the_strict_reader(tmp_path):
    path = tmp_path / "sink.jsonl"
    for record in signed_chain(["a", "b"]):
        JsonlSink(path).append(record)
    assert len(list(read_jsonl(path, strict=True))) == 2
