"""Message codes: a Text is its English sentence byte for byte, and carries code and parameters along."""

import copy
import dataclasses
import io
import json
import pickle

import pytest

from aqt_evidence import (GENESIS, HumanCheckError, Text, actor, canonical_json, coded, link, new_record, require_human,
                          text_join, verify_chain)


def test_a_text_is_the_english_sentence():
    text = Text("demo.count", "{n} record(s) in {path}", n=3, path="a b")
    assert text == "3 record(s) in a b" and isinstance(text, str)
    assert (text.code, text.args) == ("demo.count", {"n": 3, "path": "a b"})
    assert json.dumps({"t": text}) == json.dumps({"t": "3 record(s) in a b"})
    assert json.dumps([text], indent=2) == json.dumps(["3 record(s) in a b"], indent=2)
    assert canonical_json({"t": text}) == canonical_json({"t": "3 record(s) in a b"})
    out = io.StringIO()
    print(text, file=out)
    assert out.getvalue() == "3 record(s) in a b\n"
    assert type(str(text)) is str and type(text + "") is str and type(f"{text}") is str


def test_copies_keep_code_and_args():
    @dataclasses.dataclass
    class Report:
        detail: str

    text = Text("demo.nested", "{inner}; {n}", inner=Text("demo.inner", "inner"), n=1)
    for copied in (copy.copy(text), copy.deepcopy(text), pickle.loads(pickle.dumps(text)),
                   dataclasses.asdict(Report(text))["detail"]):
        assert copied == text and copied.code == "demo.nested" and copied.args["inner"].code == "demo.inner"


def test_coded_gives_plain_json_for_texts_and_exceptions():
    text = Text("demo.outer", "{what} at {path}", what=Text("demo.what", "a thing"), path=__import__("pathlib").Path("/x"))
    assert coded(text) == {"code": "demo.outer", "args": {"what": {"code": "demo.what", "args": {}}, "path": "/x"}}
    assert coded(ValueError(text)) == coded(text)
    assert coded("plain") is None and coded(ValueError("plain")) is None and coded(None) is None
    joined = text_join("; ", [Text("demo.a", "a"), "b"])
    assert joined == "a; b" and coded(joined) == {"code": "aqt.join", "args": {
        "sep": "; ", "items": [{"code": "demo.a", "args": {}}, "b"]}}
    assert text_join(", ", []) == "" and not text_join(", ", [])


def test_chain_break_reasons_and_summary_carry_codes():
    first = link(new_record("trail.event", actor("human", "human:a"), "x", reason="r"), seq=0, prev=GENESIS)
    result = verify_chain([first, first])
    assert not result.ok and result.reason.code == "evidence.chain.seq_mismatch"
    assert result.reason == "expected seq 1, found 0" and result.reason.args == {"expected": 1, "found": 0}
    assert result.summary() == "broken from seq 1: expected seq 1, found 0"
    assert result.summary().code == "evidence.chain.broken"
    assert verify_chain([first]).summary().code == "evidence.chain.intact"


def test_human_check_refusals_carry_codes():
    with pytest.raises(HumanCheckError) as raised:
        require_human(environ={"CLAUDECODE": "1"}, chain=[])
    assert coded(raised.value)["code"] == "evidence.human.agent_context"
    assert str(raised.value).startswith("refused: this command looks like it runs inside an agent session (env:")
    with pytest.raises(HumanCheckError) as raised:
        require_human(environ={}, chain=[], stdin=io.StringIO())
    assert coded(raised.value) == {"code": "evidence.human.no_tty", "args": {}}
