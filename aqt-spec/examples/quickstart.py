#!/usr/bin/env python3
"""Create, sign, chain and checkpoint a few evidence records, then check them.

Usage: python examples/quickstart.py OUT_DIR
Writes OUT_DIR/trail.jsonl, OUT_DIR/writer.key(.pub) and OUT_DIR/checkpoint.json,
then prints the conformance level. Synthetic data only.
"""

import json
import sys
from pathlib import Path

from aqt_evidence import (GENESIS, JsonlSink, actor, bytes_hash, conformance, generate_key, link, load_public_key,
                          load_signer, make_checkpoint, new_record, read_jsonl, record_content_hash, record_hash,
                          sign_record, sign_statement, subject)

out = Path(sys.argv[1] if len(sys.argv) > 1 else "aqt-demo")
out.mkdir(parents=True, exist_ok=True)
key = out / "writer.key"
if not key.exists():
    generate_key(key)  # a real writer key is passphrase-protected and kept away from agents
writer = load_signer(key)

agent = actor("agent", "agent:claude-code:s-0001", harness="claude-code", model="example-model", session="s-0001")
alice = actor("human", "human:alice", role="quality-manager", display="Alice Example")

# 1. An agent finishes a change; the record carries the evidence the gate needs.
report = b"# Test report\nall 12 tests passed\n"
finish = new_record("change.finish", agent, "finish", tz="Europe/Vienna",
                    subject=subject("file", "docs/report.md", sha256=bytes_hash(report)),
                    data={"plan_ref": "plan-0001", "receipts": [], "waivers": [], "gate": "GO"})

# 2. A human approves exactly that record: a detached signed statement in data.signature.
statement = {"aqt_signature": "0.1", "signer": {"id": alice["id"], "name": "Alice Example", "role": "quality-manager"},
             "key": writer.key_id, "meaning": "approved", "reason": "Receipts and report checked",
             "signed_at": finish["time"], "tz": "Europe/Vienna", "record_type": "signoff.signature",
             "subject": {"kind": "record", "ref": finish["id"], "sha256": record_content_hash(finish)}}
signature = new_record("signoff.signature", alice, "sign", meaning="approved", reason="Receipts and report checked",
                       subject=statement["subject"],
                       data={"signature": sign_statement(statement, writer), "meaning": "approved"})
# (In real use Alice signs with her own key from aqt-signoff; one key keeps this example short.)

# 3. The writer chains and signs what it stores, then publishes a checkpoint of the head.
trail = out / "trail.jsonl"
trail.unlink(missing_ok=True)
sink, prev = JsonlSink(trail), GENESIS
for seq, record in enumerate([finish, signature]):
    stored = sign_record(link(record, seq=seq, prev=prev), writer)
    sink.append(stored)
    prev = record_hash(stored)
checkpoint = make_checkpoint(log_id="example", seq=1, head=prev, signer=writer)
(out / "checkpoint.json").write_text(json.dumps(checkpoint))

# 4. Anyone with the pinned public key and the checkpoint can check the file.
keys = dict([load_public_key(f"{key}.pub")])
result = conformance(list(read_jsonl(trail)), 3, keys=keys, checkpoints=[checkpoint])
print(result.summary())
sys.exit(0 if result.ok else 1)
