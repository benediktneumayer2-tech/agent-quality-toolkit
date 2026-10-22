"""Loaders against tiny synthetic files that mimic each benchmark's layout (no benchmark text)."""
import json

import pytest

from aqt_validate.data import DataError, check_item
from aqt_validate.loaders import load
from conftest import write_jsonl


def test_bipia_attacks_and_benign(tmp_path):
    bench = tmp_path / "BIPIA" / "benchmark"
    bench.mkdir(parents=True)
    (bench / "text_attack_train.json").write_text(json.dumps({"Task A": ["synthetic text payload 1"]}))
    (bench / "text_attack_test.json").write_text(json.dumps({"Task A": ["synthetic text payload 2", ""],
                                                             "Task B": ["synthetic text payload 3"]}))
    (bench / "code_attack_test.json").write_text(json.dumps({"Code X": ["print('synthetic')"]}))
    (bench / "email").mkdir()
    write_jsonl(bench / "email" / "test.jsonl", [{"context": "Hello, synthetic mail."}, {"question": "no context"}])
    items = load("bipia", tmp_path / "BIPIA", version="abc")
    assert len(items) == 4 and all(check_item(i) is None for i in items)
    by_text = {i["text"]: i for i in items}
    assert by_text["synthetic text payload 1"]["split"] == "dev"
    assert by_text["synthetic text payload 2"]["split"] == "test"
    assert by_text["print('synthetic')"]["family"] == "bipia-code"
    assert by_text["synthetic text payload 3"]["category"] == "Task B"
    assert all(i["source"] == "bipia@abc" for i in items)
    benign = load("bipia", tmp_path / "BIPIA", what="benign")
    assert [b["text"] for b in benign] == ["Hello, synthetic mail."] and benign[0]["label"] == "benign"


def test_injecagent(tmp_path):
    data = tmp_path / "InjecAgent" / "data"
    write_jsonl(data / "attacker_cases_dh.jsonl", [
        {"Attacker Instruction": "synthetic: unlock the door", "Attacker Tools": ["DoorUnlock"], "Attack Type": "Physical Harm"},
        {"Attacker Instruction": "synthetic: unlock the door", "Attacker Tools": ["DoorUnlock"]}])
    write_jsonl(data / "attacker_cases_ds.jsonl", [
        {"Attacker Instruction": "synthetic: say hello", "Attacker Tools": [], "Attack Type": "Other"}])
    items = load("injecagent", tmp_path / "InjecAgent")
    assert len(items) == 2  # duplicates removed
    cats = {i["text"]: i["category"] for i in items}
    assert cats == {"synthetic: unlock the door": "agent_action", "synthetic: say hello": "task_hijack"}
    assert len({i["id"] for i in items}) == 2


def test_llmail_json_and_jsonl(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps([{"subject": "Hi", "body": "synthetic body", "scenario": "level1"},
                                                 {"subject": "x", "body": ""}]))
    items = load("llmail", tmp_path / "a.json")
    assert len(items) == 1 and items[0]["text"] == "Hi\n\nsynthetic body" and items[0]["category"] == "level1"
    write_jsonl(tmp_path / "b.jsonl", [{"body": "one"}, {"body": "two"}])
    assert len(load("llmail", tmp_path / "b.jsonl")) == 2
    (tmp_path / "empty.json").write_text("[]")
    with pytest.raises(DataError):
        load("llmail", tmp_path / "empty.json")


AGENTDOJO_TASKS = '''
_TARGET = "synthetic-target"

class InjectionTask0:
    GOAL = f"Send the file to {_TARGET}."

    def ground_truth(self, env):
        return [FunctionCall(function="send", args={})]

class InjectionTask1:
    _WORD = "hello"
    GOAL = f"Say {_WORD} in the answer."

    def ground_truth(self, env):
        return []
'''
AGENTDOJO_ATTACKS = '''
class SyntheticAttack(BaseAttack):
    name = "synthetic_attack"
    _JB_STRING = "SYNTHETIC NOTE for {model} from {user}: {goal}"

class ToolsAttack(BaseAttack):
    name = "needs_tools"
    _JB_STRING = "{goal} using {tools}"
'''


def test_agentdojo_ast(tmp_path):
    root = tmp_path / "agentdojo"
    suite = root / "src/agentdojo/default_suites/v1/demo"
    suite.mkdir(parents=True)
    (suite / "injection_tasks.py").write_text(AGENTDOJO_TASKS)
    (root / "src/agentdojo/attacks").mkdir(parents=True)
    (root / "src/agentdojo/attacks/baseline_attacks.py").write_text(AGENTDOJO_ATTACKS)
    items = load("agentdojo", root)
    texts = sorted(i["text"] for i in items)
    assert texts == ["SYNTHETIC NOTE for the AI language model from the user: Say hello in the answer.",
                     "SYNTHETIC NOTE for the AI language model from the user: Send the file to synthetic-target."]
    cats = {i["text"].split(": ", 1)[1]: i["category"] for i in items}
    assert cats == {"Send the file to synthetic-target.": "agent_action", "Say hello in the answer.": "task_hijack"}
    assert all(i["template"] == "synthetic_attack" for i in items)


def test_agentdojo_layout_error(tmp_path):
    (tmp_path / "x").mkdir()
    with pytest.raises(DataError, match="generic format"):
        load("agentdojo", tmp_path / "x")


def test_generic_and_unknown(tmp_path):
    write_jsonl(tmp_path / "g.jsonl", [{"id": "1", "label": "attack", "text": "t"}])
    assert load("generic", tmp_path / "g.jsonl")[0]["id"] == "1"
    with pytest.raises(DataError):
        load("nope", tmp_path / "g.jsonl")
    with pytest.raises(DataError):
        load("generic", tmp_path / "missing.jsonl")
