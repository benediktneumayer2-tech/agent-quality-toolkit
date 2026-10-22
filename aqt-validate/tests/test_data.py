import json

import pytest

from aqt_validate.data import (DataError, assign_splits, compose, disjointness, embed, read_items, sha256_text, stats,
                               unit_interval)
from conftest import attack_items, benign_items, write_jsonl


def test_unit_interval_is_deterministic():
    assert unit_interval("s", "k") == unit_interval("s", "k")
    assert unit_interval("s", "k") != unit_interval("t", "k")
    assert 0 <= unit_interval("s", "k") < 1


def test_benign_groups_stay_together_and_attacks_are_goal_disjoint():
    items = benign_items() + attack_items()
    splits = assign_splits(items, salt="x")
    by_group = {}
    for item in items:
        if item["label"] == "benign":
            by_group.setdefault(item["group"], set()).add(splits[item["id"]])
    assert all(len(s) == 1 for s in by_group.values())
    assert {"calib", "heldout"} == {next(iter(s)) for s in by_group.values()}
    overlaps = disjointness(items, splits)
    assert overlaps["goal_overlap"] == 0 and overlaps["payload_overlap"] == 0
    assert assign_splits(items, salt="x") == splits


def test_explicit_split_overrides_and_overlap_is_reported():
    items = [{"id": "a1", "label": "attack", "text": "p", "goal": "g", "split": "dev"},
             {"id": "a2", "label": "attack", "text": "q", "goal": "g", "split": "test"}]
    splits = assign_splits(items, salt="x")
    assert splits == {"a1": "dev", "a2": "test"}
    assert disjointness(items, splits)["goal_overlap"] == 1


def test_read_items_validates(tmp_path):
    write_jsonl(tmp_path / "ok.jsonl", [{"id": "1", "label": "benign", "text": "x"}])
    assert len(read_items(tmp_path / "ok.jsonl")) == 1
    write_jsonl(tmp_path / "dup.jsonl", [{"id": "1", "label": "benign", "text": "x"}] * 2)
    with pytest.raises(DataError, match="duplicate"):
        read_items(tmp_path / "dup.jsonl")
    write_jsonl(tmp_path / "bad.jsonl", [{"id": "1", "label": "maybe", "text": "x"}])
    with pytest.raises(DataError, match="label"):
        read_items(tmp_path / "bad.jsonl")
    write_jsonl(tmp_path / "split.jsonl", [{"id": "1", "label": "benign", "text": "x", "split": "test"}])
    with pytest.raises(DataError, match="split"):
        read_items(tmp_path / "split.jsonl")


def test_compose_embeds_with_span_and_provenance():
    hosts = benign_items(10)
    attacks = attack_items(3, 1)
    out = compose(hosts, attacks, seed=1)
    assert len(out) == 3
    for item, attack in zip(out, sorted(attacks, key=lambda a: a["id"])):
        start, end = item["span"]
        assert item["text"][start:end] == attack["text"]
        assert item["host"].startswith("b") and item["payload"] == sha256_text(attack["text"])
        assert item["goal"] == attack["goal"] and item["label"] == "attack"
    assert compose(hosts, attacks, seed=1) == out


def test_embed_into_search_results_json():
    import random
    host = json.dumps({"results": [{"title": "t", "snippet": "first. second part. third"}]})
    text, position = embed(host, "PAYLOAD", random.Random(3))
    assert "PAYLOAD" in json.loads(text)["results"][0][position.split(":")[0]]


def test_compose_needs_hosts():
    with pytest.raises(DataError):
        compose([], attack_items(1, 1))


def test_stats_counts():
    summary = stats(benign_items(20, groups=4, hard=2) + attack_items(2, 1))
    assert summary["items"] == 22 and summary["groups"] == 4 and summary["hard_benign"] == 2
