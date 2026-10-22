"""Example command-line detector (batch JSONL in, JSONL out) for aqt-validate.

Reads ``{"id", "text"}`` lines on stdin and writes ``{"id", "score_ppm", "latency_ms"}`` lines.
A toy keyword score, for trying the workflow only: replace it with your real detector
(for example an aqt-quarantine detector plugin, or your own model behind a small script).
"""
import json
import sys
import time

PHRASES = {"ignore previous instructions": 600_000, "ignore all previous": 600_000, "system note": 250_000,
           "you are now": 200_000, "do not tell the user": 300_000, "send the": 100_000}

for line in sys.stdin:
    if not line.strip():
        continue
    start = time.perf_counter()
    item = json.loads(line)
    text = item["text"].lower()
    score = min(1_000_000, sum(weight for phrase, weight in PHRASES.items() if phrase in text) + len(text) % 997)
    print(json.dumps({"id": item["id"], "score_ppm": score,
                      "latency_ms": round((time.perf_counter() - start) * 1000)}))
