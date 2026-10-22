"""Generic dataset items, deterministic splits and composition of attack items.

A dataset is JSON lines; each item needs ``id``, ``label`` (``benign`` | ``attack``) and
``text``. Optional fields: ``group`` (session or source: benign items of one group land in
one split), ``family``, ``category``, ``goal``, ``payload`` (sha256 of the payload),
``template``, ``hard`` (hard-benign), ``host``, ``span``, ``source``, ``license``,
``context`` (passed to detectors unchanged) and ``split`` (an explicit split overrides the
hash rule).
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from typing import Iterable

from aqt_evidence import bytes_hash

LABELS = ("benign", "attack")
BENIGN_SPLITS = ("calib", "heldout")
ATTACK_SPLITS = ("dev", "test")


class DataError(ValueError):
    pass


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_hash(path: str | Path) -> str:
    return bytes_hash(Path(path).read_bytes())


def read_items(path: str | Path) -> list[dict]:
    items = []
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as error:
                raise DataError(f"{path}:{number}: not JSON ({error.msg})") from None
            problem = check_item(item)
            if problem:
                raise DataError(f"{path}:{number}: {problem}")
            items.append(item)
    ids = Counter(item["id"] for item in items)
    duplicates = [key for key, count in ids.items() if count > 1]
    if duplicates:
        raise DataError(f"{path}: duplicate ids: {', '.join(map(str, duplicates[:5]))}")
    return items


def write_items(path: str | Path, items: Iterable[dict]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    path.chmod(0o600)
    return count


def check_item(item) -> str | None:
    if not isinstance(item, dict):
        return "item must be a JSON object"
    if not isinstance(item.get("id"), str) or not item["id"]:
        return "item needs a string id"
    if item.get("label") not in LABELS:
        return f"item {item['id']}: label must be benign or attack"
    if not isinstance(item.get("text"), str):
        return f"item {item['id']}: text must be a string"
    if "split" in item and item["split"] not in (BENIGN_SPLITS if item["label"] == "benign" else ATTACK_SPLITS):
        return f"item {item['id']}: split {item['split']!r} does not fit label {item['label']}"
    return None


# --------------------------------------------------------------------------- splits

def unit_interval(salt: str, key: str) -> float:
    """Deterministic number in [0, 1) from sha256(salt:key)."""
    digest = hashlib.sha256(f"{salt}:{key}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2 ** 64


def split_key(item: dict, keys: Iterable[str]) -> str:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return f"{key}={value}"
    if item["label"] == "attack":
        return "payload=" + sha256_text(item["text"])
    return "id=" + item["id"]


def assign_splits(items: list[dict], *, salt: str, benign_calib_share: float = 0.5,
                  attack_dev_share: float = 0.35, benign_keys: Iterable[str] = ("group",),
                  attack_keys: Iterable[str] = ("goal", "payload")) -> dict[str, str]:
    """``{id: split}``. Benign: calib/heldout by group; attack: dev/test by goal (then payload)."""
    benign_keys, attack_keys = tuple(benign_keys), tuple(attack_keys)
    splits = {}
    for item in items:
        if "split" in item:
            splits[item["id"]] = item["split"]
        elif item["label"] == "benign":
            u = unit_interval(salt, "benign:" + split_key(item, benign_keys))
            splits[item["id"]] = "calib" if u < benign_calib_share else "heldout"
        else:
            u = unit_interval(salt, "attack:" + split_key(item, attack_keys))
            splits[item["id"]] = "dev" if u < attack_dev_share else "test"
    return splits


def disjointness(items: list[dict], splits: dict[str, str]) -> dict[str, int]:
    """Overlaps that would leak between dev and test, or from calibration into attacks."""
    by_split: dict[str, dict[str, set]] = {s: {"goal": set(), "payload": set()} for s in ATTACK_SPLITS}
    calib_ids = {i["id"] for i in items if splits.get(i["id"]) == "calib"}
    host_in_calib = 0
    for item in items:
        if item["label"] != "attack":
            continue
        split = splits[item["id"]]
        if item.get("goal"):
            by_split[split]["goal"].add(item["goal"])
        by_split[split]["payload"].add(item.get("payload") or sha256_text(item["text"]))
        if item.get("host") in calib_ids:
            host_in_calib += 1
    return {
        "goal_overlap": len(by_split["dev"]["goal"] & by_split["test"]["goal"]),
        "payload_overlap": len(by_split["dev"]["payload"] & by_split["test"]["payload"]),
        "attack_host_in_calib": host_in_calib,
    }


def stats(items: list[dict], splits: dict[str, str] | None = None) -> dict:
    counter = Counter()
    for item in items:
        split = (splits or {}).get(item["id"], item.get("split", "-"))
        counter[(item["label"], item.get("family") or "-", item.get("category") or "-", split)] += 1
    return {
        "items": len(items),
        "by_label": dict(Counter(item["label"] for item in items)),
        "rows": [{"label": k[0], "family": k[1], "category": k[2], "split": k[3], "count": v}
                 for k, v in sorted(counter.items())],
        "groups": len({item.get("group") for item in items if item["label"] == "benign" and item.get("group")}),
        "hard_benign": sum(1 for item in items if item["label"] == "benign" and item.get("hard")),
    }


# --------------------------------------------------------------------------- composition

def _locate(text: str, payload: str) -> list[int] | None:
    start = text.find(payload)
    if start >= 0:
        return [start, start + len(payload)]
    escaped = json.dumps(payload, ensure_ascii=False)[1:-1]
    start = text.find(escaped)
    return [start, start + len(escaped)] if start >= 0 else None


def embed(host_text: str, payload: str, rng: random.Random) -> tuple[str, str]:
    """Insert ``payload`` into a copy of ``host_text``; returns (text, position)."""
    try:
        doc = json.loads(host_text)
    except ValueError:
        doc = None
    if isinstance(doc, dict) and isinstance(doc.get("results"), list) and doc["results"] \
            and all(isinstance(r, dict) for r in doc["results"]):
        result = rng.choice(doc["results"])
        field = rng.choices(["snippet", "title"], [0.8, 0.2])[0]
        old = str(result.get(field, ""))
        where = rng.choice(["start", "middle", "end", "replace"] if field == "snippet" else ["start", "end"])
        if where == "replace":
            new = payload
        elif where == "start":
            new = payload + " " + old
        elif where == "end":
            new = old + " " + payload
        else:
            cut = old.find(". ", len(old) // 3)
            cut = len(old) // 2 if cut < 0 else cut + 2
            new = old[:cut] + payload + " " + old[cut:]
        result[field] = new
        return json.dumps(doc, indent=2, ensure_ascii=False), f"{field}:{where}"
    lines = host_text.split("\n")
    k = rng.choice([0, len(lines) // 2, len(lines), rng.randrange(len(lines) + 1)])
    return "\n".join(lines[:k] + [payload] + lines[k:]), f"line:{k}/{len(lines)}"


ATTACK_FIELDS = ("family", "category", "goal", "template", "source", "license")


def compose(hosts: list[dict], attacks: list[dict], *, seed: int = 36, per_payload: int = 1) -> list[dict]:
    """Attack items whose text is a benign host with the attack payload embedded."""
    if not hosts:
        raise DataError("composition needs at least one benign host item")
    rng = random.Random(seed)
    ordered_hosts = sorted(hosts, key=lambda h: h["id"])
    out = []
    for attack in sorted(attacks, key=lambda a: a["id"]):
        payload = attack["text"]
        for n in range(per_payload):
            host = rng.choice(ordered_hosts)
            text, position = embed(host["text"], payload, rng)
            item = {key: attack[key] for key in ATTACK_FIELDS if key in attack}
            item.update({
                "id": f"{attack['id']}@{host['id']}" + (f"#{n}" if per_payload > 1 else ""),
                "label": "attack", "text": text, "host": host["id"], "position": position,
                "payload": attack.get("payload") or sha256_text(payload),
                "span": _locate(text, payload),
            })
            if "split" in attack:
                item["split"] = attack["split"]
            if "context" in host:
                item["context"] = host["context"]
            out.append(item)
    return out
