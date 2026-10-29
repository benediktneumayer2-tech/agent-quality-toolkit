import json
import os

import pytest

from aqt_evidence import validate_record

from aqt_trail import importers
from aqt_trail.state import open_writer, read_records

from conftest import observed_stub


def test_claude_session(local_fixture):
    session = importers.claude_session(local_fixture("claude-session.jsonl"))
    assert session.id == "0b6f2c1e-1111-4a5b-8c9d-000000000001" and session.version == "2.1.300"
    actions = [e.action for e in session.events]
    assert actions == ["permission.mode", "prompt", "model.change", "message", "tool.call", "tool.result",
                       "compaction", "model.change", "tool.call", "tool.result", "session.continued"]
    records, skipped = importers.to_records(session)
    assert skipped == 0 and all(not validate_record(r) for r in records)
    prompt = records[1]
    assert prompt["data"]["prompt_excerpt"].endswith("token=[masked]")
    assert "abc123secret" not in json.dumps(records)
    result = records[5]["data"]["tool"]
    assert result == {"name": "Bash", "use_id": "toolu_1", "output_sha256": result["output_sha256"], "is_error": False}
    assert records[9]["data"]["tool"]["is_error"] is True
    assert records[8]["actor"]["agent"]["model"] == "example-model-2"
    assert records[0]["actor"]["id"] == "agent:claude-code:0b6f2c1e-1111-4a5b-8c9d-000000000001"


def test_claude_session_refuses_mixed_sessions(tmp_path):
    path = tmp_path / "mixed.jsonl"
    path.write_text('{"type":"user","sessionId":"a","message":{"content":"x"}}\n'
                    '{"type":"user","sessionId":"b","message":{"content":"y"}}\n')
    with pytest.raises(importers.ImportError_, match="mixes sessions"):
        importers.claude_session(path)


def test_codex_rollout(local_fixture):
    session = importers.codex_rollout(local_fixture("codex-rollout.jsonl"))
    assert session.id == "7a1d0c55-2222-4b6e-9f00-000000000001" and session.version == "0.150.0"
    actions = [e.action for e in session.events]
    assert actions == ["session.start", "model.change", "permission.mode", "turn.start", "prompt", "tool.call",
                       "tool.result", "message", "compaction", "turn.end", "rollback"]
    records, _ = importers.to_records(session)
    assert records[6]["data"]["tool"]["name"] == "shell"
    assert records[2]["data"] == {**records[2]["data"], "sandbox": "workspace-write", "approval_policy": "on-request"}
    assert records[10]["data"]["turns"] == 1


def test_pi_session(local_fixture):
    session = importers.pi_session(local_fixture("pi-session.jsonl"))
    assert session.id == "pi-session-0001"
    assert [e.action for e in session.events] == ["session.start", "model.change", "prompt", "message", "tool.call",
                                                  "tool.result", "compaction"]
    records, _ = importers.to_records(session)
    assert records[5]["data"]["tool"] == {**records[5]["data"]["tool"], "name": "read", "is_error": False}
    assert records[4]["actor"]["agent"]["model"] == "example-pi-model"


def test_pi_wrong_version(tmp_path):
    path = tmp_path / "old.jsonl"
    path.write_text('{"type":"session","version":2,"id":"x"}\n')
    with pytest.raises(importers.ImportError_, match="v3"):
        importers.pi_session(path)


def test_hook_payload(fixtures):
    raw = (fixtures / "claude-hook-posttooluse.json").read_bytes()
    session = importers.claude_hook(raw)
    records, _ = importers.to_records(session)
    record = records[0]
    assert record["action"] == "tool.result" and not validate_record(record)
    assert record["data"]["tool"]["name"] == "Bash" and "output_sha256" in record["data"]["tool"]
    assert "sk-test1234567890abcdef" not in json.dumps(record) and "[masked]" in record["data"]["tool"]["input_excerpt"]
    assert record["subject"] == {"kind": "tool-call", "ref": "toolu_9"}


def test_excerpts_can_be_disabled(local_fixture):
    records, _ = importers.to_records(importers.claude_session(local_fixture("claude-session.jsonl"), excerpt_chars=0))
    assert not any("excerpt" in json.dumps(r["data"]) for r in records)


def test_reimport_is_idempotent(config, local_fixture):
    path = local_fixture("pi-session.jsonl")
    writer = open_writer(config)
    records, _ = importers.to_records(importers.pi_session(path))
    for record in records:
        writer.append(record, observed_stub())
    known = importers.known_source_hashes(read_records(config.trail_path))
    again, skipped = importers.to_records(importers.pi_session(path), known=known)
    assert again == [] and skipped == len(records)
    # Even without the pre-filter, derived ids make a re-send idempotent at the writer.
    rebuilt, _ = importers.to_records(importers.pi_session(path))
    assert [r["id"] for r in rebuilt] == [r["id"] for r in records]
    for record in rebuilt:
        assert writer.append(record, observed_stub())[1] is False
    writer.close()


def test_partial_last_line_is_left_for_later(tmp_path):
    path = tmp_path / "pi.jsonl"
    path.write_text('{"type":"session","version":3,"id":"p"}\n{"type":"model_change","id":"e1"')
    assert [e.action for e in importers.pi_session(path).events] == ["session.start"]


def test_symlinks_are_refused(tmp_path, local_fixture):
    target = local_fixture("pi-session.jsonl")
    link = tmp_path / "link.jsonl"
    os.symlink(target, link)
    with pytest.raises(importers.ImportError_):
        importers.pi_session(link)


@pytest.mark.parametrize("payload", [
    {"hook_event_name": "SessionStart", "session_id": "s-start", "cwd": "/work/x", "source": "startup",
     "model": "example-model"},
    {"hook_event_name": "SessionEnd", "session_id": "s-end", "cwd": "/work/x", "reason": "logout"},
    {"hook_event_name": "UserPromptSubmit", "session_id": "s-p", "prompt": "hello"},
])
def test_hook_records_keep_data_source_and_conform(payload):
    """Regression: SessionStart's "source" once overwrote data.source and broke the payload schema."""
    from aqt_evidence import conformance
    records, _ = importers.to_records(importers.claude_hook(json.dumps(payload).encode()))
    data = records[0]["data"]
    assert data["source"]["format"] == "claude-code-hook" and data["source"]["session"] == payload["session_id"]
    if "source" in payload:
        assert data["session_source"] == "startup"
    if "reason" in payload:
        assert data["end_reason"] == "logout"
    result = conformance(records, 1, check_payloads=True)
    assert result.level == 1 and result.payloads_checked, result.problems


# Synthetic values only. Each pair: text, the secret that must not survive.
SECRETS = [
    ("export DB_PASSWORD=Xy7pq2Lm9", "Xy7pq2Lm9"),
    ("PGPASSWORD=s3cr3tvalue psql -h db", "s3cr3tvalue"),
    ("GITHUB_TOKEN=abcd1234efgh5678 gh pr list", "abcd1234efgh5678"),
    ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"),
    ("client_secret: s3cr3t-client-value", "s3cr3t-client-value"),
    ("PASSWORD='two words'", "two words"),
    ('{"password": "x1 y2", "user": "bob"}', "x1 y2"),
    (json.dumps({"command": 'export GH_TOKEN="abc def" && make'}), "abc def"),
    ("mysql --password hunter2pass", "hunter2pass"),
    ("tool --api-key=k3y-value-123", "k3y-value-123"),
    ("curl -H 'Authorization: Bearer abcdefghijklmnop' https://x", "abcdefghijklmnop"),
    ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
    ("x-api-key: abcdef123456", "abcdef123456"),
    ("psql postgres://bob:pa55word@db.example/app", "pa55word"),
    ("curl -u bob:pa55word https://x", "pa55word"),
    ("-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAABG5vbmU -----END OPENSSH PRIVATE KEY-----",
     "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU"),
    ("-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEAexamplecutoff", "MIIEowIBAAKCAQEAexamplecutoff"),
    ("hf_" + "a1B2c3D4e5" * 3, "a1B2c3D4e5" * 3),
    ("glpat-" + "x9" * 10, "x9" * 10),
    ("sk-ant-api03-" + "Z" * 20, "Z" * 20),
    ("xoxe-1-" + "q" * 12, "q" * 12),
    ("ghs_" + "R" * 30, "R" * 30),
]


@pytest.mark.parametrize("text,secret", SECRETS)
def test_mask_common_secret_forms(text, secret):
    masked = importers.mask(text)
    assert secret not in masked and "[masked" in masked
    assert secret not in (importers.excerpt(text, 160) or "")


@pytest.mark.parametrize("text", ["git commit -m 'fix the password check'", "max_tokens=4096 tokens_before=12",
                                  "run task-runner in the basic case", "the bearer of bad news"])
def test_mask_leaves_ordinary_text(text):
    assert importers.mask(text) == text


def test_excerpt_masks_near_its_end_and_stays_fast_on_large_inputs():
    import time
    text = "x " * 70 + "DB_PASSWORD=" + "p" * 40
    assert "ppp" not in importers.excerpt(text, 160)
    started = time.monotonic()
    importers.excerpt("a" * 3_000_000 + " password=x", 160)
    importers.excerpt({"content": "ab_" * 500_000}, 160)
    assert time.monotonic() - started < 2
