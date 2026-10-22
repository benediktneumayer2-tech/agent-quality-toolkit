"""Callable adapters for tests: text -> score."""
import hashlib


def length_score(text: str) -> float:
    """A weak second detector: hash noise plus a bump for imperative words (float in [0, 1])."""
    noise = int(hashlib.sha256(("len:" + text).encode()).hexdigest()[:8], 16) % 1000 / 1000
    bump = 0.4 if "now" in text.lower() else 0.0
    return min(1.0, noise * 0.6 + bump)


class Result:
    def __init__(self, score_ppm):
        self.score_ppm = score_ppm
        self.spans = []


class PluginDetector:
    name = "fake-plugin"
    version = "9.9"

    def score(self, text):
        return Result(800_000 if "ignore previous" in text.lower() else 1_000)
