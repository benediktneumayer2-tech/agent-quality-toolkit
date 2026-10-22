"""Synthetic stub detector (batch command adapter): JSONL {id, text} in, JSONL {id, score_ppm} out.

Scores 900,000 + noise when the text contains the synthetic marker phrase, else noise below
500,000 derived from a hash of the text. Deterministic; for tests and examples only.
"""
import hashlib
import json
import sys

MARKER = "ignore previous instructions"

for line in sys.stdin:
    if not line.strip():
        continue
    item = json.loads(line)
    text = item["text"]
    noise = int(hashlib.sha256(text.encode()).hexdigest()[:8], 16) % 100_000
    if "STUB-ERROR" in text:
        print(json.dumps({"id": item["id"], "error": "cannot score"}))
        continue
    score = 900_000 + noise if MARKER in text.lower() else (noise * 5)
    print(json.dumps({"id": item["id"], "score_ppm": score, "latency_ms": 3}))
