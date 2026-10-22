"""Recurrence: explainable lexical similarity between deviations, in ppm (INTERFACES I7)."""

from __future__ import annotations

import re

STOP = frozenset("""a an and are as at be by for from has have in is it its of on or that the this to was were
with not no der die das und ist ein eine nicht mit von zu""".split())
BONUS_PPM = 100_000
_WORD = re.compile(r"[a-z0-9][a-z0-9_.-]*")


def tokens(text: str | None) -> set[str]:
    return {w for w in _WORD.findall((text or "").lower()) if w not in STOP and len(w) > 1}


def score_ppm(a: dict, b: dict) -> int:
    """Token Jaccard of title+description, plus a bonus for the same category, source type and subject."""
    ta = tokens(f"{a.get('title', '')} {a.get('description') or ''}")
    tb = tokens(f"{b.get('title', '')} {b.get('description') or ''}")
    score = (len(ta & tb) * 1_000_000) // len(ta | tb) if ta and tb else 0
    for field in ("category", "source_type", "subject_ref"):
        if a.get(field) and a.get(field) == b.get(field) and a.get(field) != "unclassified":
            score += BONUS_PPM
    return min(score, 1_000_000)


def similar(new: dict, past: list[dict], threshold_ppm: int, limit: int = 3) -> list[dict]:
    scored = [(score_ppm(new, p), p["dev_id"]) for p in past if p["dev_id"] != new.get("dev_id")]
    scored = sorted((s for s in scored if s[0] >= threshold_ppm), key=lambda s: (-s[0], s[1]))
    return [{"dev_id": dev, "score_ppm": score} for score, dev in scored[:limit]]
