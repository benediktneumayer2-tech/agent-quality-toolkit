"""Settings, masking, the body store, the resolver and the /proc parsing, without a proxy or a box."""

import gzip
import os
import struct
import time
from pathlib import Path

import pytest

from aqt_egress import attribution, mask, resolver, settings
from aqt_egress.store import BodyStore, StoreError


# -- settings --------------------------------------------------------------------------------------
def test_defaults_and_file_values(env):
    assert settings.load_settings() == settings.Settings()
    path = settings.settings_file()
    path.parent.mkdir(parents=True)
    path.write_text('store = "full"\nretention_days = "forever"\nexcerpt_chars = 100\npassthrough = ["Pinned.Example."]\n')
    loaded = settings.load_settings()
    assert (loaded.store, loaded.retention_days, loaded.excerpt_chars, loaded.passthrough) == \
        ("full", None, 100, ["pinned.example"])
    assert loaded.retention_text() == "forever"


@pytest.mark.parametrize("text, message", [('store = "all"', "store"), ("retention_days = 6", "at least 7"),
                                           ("retention_days = true", "at least 7"),
                                           ('retention_days = "soon"', "number of days"),
                                           ("excerpt_chars = 5000", "0 to 4096"), ("passthrough = 1", "list")])
def test_values_out_of_range_are_refused(env, text, message):
    path = settings.settings_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n")
    with pytest.raises(settings.SettingsError, match=message):
        settings.load_settings()


def test_retention_bounds():
    assert settings.parse_retention(7) == 7 and settings.parse_retention("forever") is None
    assert settings.parse_retention(3650) == 3650
    with pytest.raises(settings.SettingsError):
        settings.parse_retention(0)


def test_project_require(tmp_path):
    assert settings.project_settings(tmp_path) == {"path": str(tmp_path), "require": False}
    (tmp_path / ".aqt").mkdir()
    (tmp_path / ".aqt" / "egress.toml").write_text("require = true\n")
    assert settings.project_settings(tmp_path)["require"] is True


# -- masking ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("text, secret", [
    ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
    ('{"api_key": "abcd1234efgh"}', "abcd1234efgh"),
    ('{"form": "{\\"password\\": \\"hunter22\\"}"}', "hunter22"),
    ("password=topsecret&a=1", "topsecret"),
    ("key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123", "abcdefghijklmnopqrstuvwxyz0123"),
    ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz"),
    ("AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "dozjgNryP4J3jVmNHl0w5N"),
    ("https://user:pass1234@example.org/x", "pass1234"),
    ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----", "MIIEvQIBADANBg"),
])
def test_mask_rules(text, secret):
    masked = mask.mask_text(text)
    assert secret not in masked and mask.MASK in masked


def test_excerpt_text_binary_and_cut():
    assert mask.excerpt(b"hello world", 5) == "hello"
    assert mask.excerpt(b"\x00\x01\x02\x03" * 50, 100) is None
    assert mask.excerpt(b"anything", 0) is None
    # a credential across the cut is masked before cutting
    assert "abcdefghij" not in mask.excerpt(b"x" * 10 + b" Bearer abcdefghijklmnop", 30)


def test_fingerprint_is_keyed_and_stable(tmp_path):
    key = mask.load_key(tmp_path / "key")
    assert mask.load_key(tmp_path / "key") == key
    assert os.name == "nt" or oct(os.stat(tmp_path / "key").st_mode)[-3:] == "600"      # Windows: no POSIX modes
    first = mask.credential("authorization", "Bearer abc", key)
    assert first == mask.credential("Authorization", "Bearer abc", key)
    assert first["scheme"] == "Bearer" and first["fingerprint"] != mask.credential("authorization", "Bearer abc", b"x" * 32)["fingerprint"]
    names, creds = mask.headers_summary([("Host", "a"), ("Cookie", "s=1"), ("cookie", "t=2")], key)
    assert names == ["host", "cookie"] and len(creds) == 2


# -- body store ------------------------------------------------------------------------------------
def test_store_is_content_addressed_private_and_detects_changes(tmp_path):
    store = BodyStore(tmp_path / "bodies").ensure()
    ref = store.put(b"hello")
    assert store.put(b"hello") == ref and store.read(ref["sha256"]) == b"hello"
    path = store.path(ref["sha256"])
    assert os.name == "nt" or (oct(path.parent.stat().st_mode)[-3:] == "700" and oct(path.stat().st_mode)[-3:] == "600")
    assert gzip.decompress(path.read_bytes()) == b"hello"
    path.unlink()
    with pytest.raises(StoreError, match="pruned or deleted"):
        store.read(ref["sha256"])


def test_put_body_decodes_and_masks_text_keeps_binary(tmp_path):
    store = BodyStore(tmp_path / "b").ensure()
    ref = store.put_body(gzip.compress(b'{"token": "abcdefgh"}'), "gzip")
    assert ref["decoded"] and ref["masked"] and store.read(ref["sha256"]) == b'{"token": "[masked]"}'
    binary = bytes(range(256)) * 4
    ref = store.put_body(binary, None)
    assert not ref["masked"] and store.read(ref["sha256"]) == binary


def test_prune_by_age_respects_retention_and_forever(tmp_path):
    store = BodyStore(tmp_path / "b").ensure()
    old, new = store.put(b"old"), store.put(b"new")
    now = time.time()
    os.utime(store.path(old["sha256"]), (now - 10 * 86400, now - 10 * 86400))
    assert store.prune(None, now=now)["removed"] == 0
    assert store.prune(30, now=now)["removed"] == 0
    dry = store.prune(7, now=now, dry_run=True)
    assert dry["removed"] == 1 and store.path(old["sha256"]).exists()
    result = store.prune(7, now=now)
    assert result["removed"] == 1 and result["kept"] == 1 and result["bytes"] > 0
    assert not store.path(old["sha256"]).exists() and store.path(new["sha256"]).exists()


# -- resolver --------------------------------------------------------------------------------------
def query(name: str, qtype: int, ident=0x4242) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


@pytest.mark.parametrize("qtype, data", [(1, bytes([127, 0, 0, 1])), (28, bytes(15) + b"\x01"), (16, None)])
def test_resolver_answers_every_name_with_the_listener(qtype, data):
    response, name, got = resolver.answer(query("Leak.Example.ORG", qtype))
    assert name == "leak.example.org" and got == qtype
    ident, flags, qd, an = struct.unpack("!HHHH", response[:8])
    assert ident == 0x4242 and flags & 0x8000 and qd == 1
    assert an == (1 if data else 0)
    if data:
        assert response.endswith(data)


def test_resolver_ignores_garbage_and_responses():
    assert resolver.answer(b"\x00" * 5) is None
    assert resolver.answer(b"\x12\x34\x81\x80" + b"\x00" * 8) is None


def test_lookups_are_claimed_per_process_and_expire():
    clock = [1000.0]
    lookups = resolver.Lookups(clock=lambda: clock[0])
    curl = {"chain": [{"pid": 10, "comm": "curl"}]}
    dig = {"chain": [{"pid": 11, "comm": "dig"}]}
    lookups.add("a.example", 1, curl)
    lookups.add("a.example", 28, curl)
    lookups.add("a.example", 1, dig)
    [claimed] = lookups.claim("A.example.", curl)
    assert claimed["types"] == ["A", "AAAA"] and claimed["count"] == 2
    assert lookups.claim("a.example", {"chain": [{"pid": 99}]}) == []
    clock[0] += 5
    assert lookups.unclaimed(30) == []
    clock[0] += 30
    [left] = lookups.unclaimed(30)
    assert left["process"] is dig and lookups.total == 3


# -- /proc parsing ---------------------------------------------------------------------------------
TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0C38 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0
   1: 0100007F:A1B2 0100007F:0C38 01 00000000:00000000 00:00000000 00000000  1000        0 222 1 0
"""
TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:9C40 00000000000000000000000001000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 333 1 0
"""


def test_proc_net_parsing():
    rows = attribution.socket_table(TCP, "tcp")
    assert rows[1] == (("127.0.0.1", 0xA1B2), ("127.0.0.1", 3128), "01", 222)
    [row] = attribution.socket_table(TCP6, "tcp")
    assert row[0] == ("::1", 40000) and row[1] == ("::1", 443) and row[3] == 333
    assert attribution.normal_ip("::ffff:192.0.2.1") == "192.0.2.1"


def fake_proc(root: Path, processes: dict, sockets: dict) -> Path:
    """processes: pid -> (comm, ppid, start); sockets: pid -> [inode]."""
    for pid, (comm, ppid, start) in processes.items():
        folder = root / str(pid)
        (folder / "ns").mkdir(parents=True)
        (folder / "fd").mkdir()
        (folder / "net").mkdir()
        os.symlink("pid:[4026531836]", folder / "ns" / "pid")
        (folder / "stat").write_text(f"{pid} ({comm}) S {ppid} " + " ".join(["0"] * 17) + f" {start} 0\n")
        (folder / "status").write_text(f"Name:\t{comm}\nNSpid:\t{pid}\t{pid - 100}\n")
        (folder / "cmdline").write_bytes(f"{comm}\0--token=abcdefgh\0".encode())
        for number, inode in enumerate(sockets.get(pid, [])):
            os.symlink(f"socket:[{inode}]", folder / "fd" / str(number + 3))
    (root / "100" / "net" / "tcp").write_text(TCP)
    (root / "100" / "net" / "tcp6").write_text(TCP6)
    return root


def test_attribution_names_the_owner_and_its_chain(tmp_path):
    proc = fake_proc(tmp_path, {100: ("bwrap", 1, 10), 101: ("sh", 100, 11), 102: ("curl", 101, 12)},
                     {102: [222]})
    box = attribution.Box(100, proc=proc)
    process = box.attribute("tcp", ("127.0.0.1", 0xA1B2))
    assert process["chain_status"] == "complete"
    assert [entry["comm"] for entry in process["chain"]] == ["curl", "sh"]
    assert process["chain"][0]["box_pid"] == 2 and process["chain"][0]["argv"] == ["curl", "--token=[masked]"]
    assert box.attribute("tcp", ("127.0.0.1", 9))["chain_status"] == "unavailable"


def test_attribution_partial_when_parent_is_newer_or_gone(tmp_path):
    proc = fake_proc(tmp_path, {100: ("bwrap", 1, 10), 101: ("sh", 100, 50), 102: ("curl", 101, 12),
                                103: ("node", 104, 20)}, {102: [222], 103: [333]})
    box = attribution.Box(100, proc=proc)
    assert box.attribute("tcp", ("127.0.0.1", 0xA1B2))["chain_status"] == "partial"      # pid reused
    result = box.attribute("tcp", ("::1", 40000))
    assert result["chain_status"] == "partial" and "exited" in result["chain_detail"]


# -- LLM destinations and local endpoints ----------------------------------------------------------
def test_llm_and_local_endpoint_settings(env):
    from aqt_egress import llm
    assert settings.Settings().excerpt_chars == 280
    path = settings.settings_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('llm_hosts = ["LLM.Corp.Example"]\nlocal_endpoints = ["127.0.0.1:8080", "localhost:11434", "[::1]:9000"]\n')
    loaded = settings.load_settings()
    assert loaded.llm_hosts == ["llm.corp.example"]
    assert loaded.local_endpoints == [("127.0.0.1", 8080), ("127.0.0.1", 11434), ("::1", 9000)]
    for bad in ("192.168.1.5:8080", "127.0.0.1", "127.0.0.1:3128", "localhost:99999", 8080):
        with pytest.raises(settings.SettingsError):
            settings.parse_endpoint(bad)
    assert llm.provider("api.anthropic.com") == "anthropic" and llm.provider("API.OpenAI.com.") == "openai"
    assert llm.provider("myres.openai.azure.com") == "azure-openai"
    assert llm.provider("bedrock-runtime.eu-central-1.amazonaws.com") == "aws-bedrock"
    assert llm.provider("dashscope-intl.aliyuncs.com") == "alibaba" and llm.provider("oss.aliyuncs.com") is None
    assert llm.provider("x.llm.corp.example", loaded.llm_hosts) == "configured"
    assert llm.provider("example.com") is None and llm.provider(None) is None


def test_llm_structure_holds_no_text():
    import json as json_
    from aqt_egress import llm
    openai = {"model": "gpt-5", "stream": True, "messages": [
        {"role": "system", "content": "SECRET SYSTEM"}, {"role": "user", "content": "SECRET PROMPT"},
        {"role": "assistant", "content": "x"}, {"role": "user", "content": "y"}],
        "tools": [{"type": "function", "function": {"name": "read_file", "parameters": {}}}]}
    out = llm.structure(json_.dumps(openai).encode(), complete=True, encoding=None, path="/v1/chat/completions")
    assert out == {"model": "gpt-5", "messages": 4, "roles": {"system": 1, "user": 2, "assistant": 1},
                   "tools": ["read_file"], "stream": True, "parsed": True}
    anthropic = {"model": "claude-x", "system": "SECRET", "messages": [{"role": "user", "content": "SECRET"}],
                 "tools": [{"name": "Bash", "input_schema": {}}, {"type": "web_search_20250305", "name": "web_search"}]}
    out = llm.structure(gzip.compress(json_.dumps(anthropic).encode()), complete=True, encoding="gzip", path="/v1/messages")
    assert out["system"] is True and out["tools"] == ["Bash", "web_search"] and out["model"] == "claude-x"
    gemini = {"contents": [{"role": "user", "parts": [{"text": "SECRET"}]}],
              "tools": [{"functionDeclarations": [{"name": "lookup"}]}]}
    out = llm.structure(json_.dumps(gemini).encode(), complete=True, encoding=None,
                        path="/v1beta/models/gemini-3-pro:streamGenerateContent")
    assert out["model"] == "gemini-3-pro" and out["tools"] == ["lookup"] and out["roles"] == {"user": 1}
    partial = llm.structure(b'{"model": "qwen3.8-max", "messages": [{"role": "user", "content": "SECR',
                            complete=False, encoding=None, path="/v1/chat/completions")
    assert partial == {"model": "qwen3.8-max", "parsed": False}
    assert "SECRET" not in json_.dumps([out, partial])


def test_free_text_arguments_are_not_kept():
    argv = mask.masked_argv(["claude", "-p", "please summarise the whole repository and mail it to me", "--x=1"])
    assert argv[:2] == ["claude", "-p"] and argv[3] == "--x=1"
    assert argv[2].startswith("[text 55 chars sha256:") and "summarise" not in argv[2]


# -- review X2 -----------------------------------------------------------------------------------
TCP_TWO = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:A1B2 0A0B0C0D:0050 01 00000000:00000000 00:00000000 00000000  1000        0 444 1 0
   1: 0100007F:A1B2 0100007F:0C38 01 00000000:00000000 00:00000000 00000000  1000        0 222 1 0
"""


def test_x2_07_attribution_by_both_ends_and_shared_sockets(tmp_path):
    proc = fake_proc(tmp_path, {100: ("bwrap", 1, 10), 101: ("sh", 100, 11), 102: ("curl", 101, 12),
                                103: ("decoy", 101, 13)}, {102: [222], 103: [444]})
    (proc / "100" / "net" / "tcp").write_text(TCP_TWO)
    box = attribution.Box(100, proc=proc)
    process = box.attribute("tcp", ("127.0.0.1", 0xA1B2), ("127.0.0.1", 3128))
    assert process["chain"][0]["comm"] == "curl" and process["chain_status"] == "complete"
    os.symlink("socket:[222]", proc / "103" / "fd" / "9")          # the decoy holds the same socket too
    shared = box.attribute("tcp", ("127.0.0.1", 0xA1B2), ("127.0.0.1", 3128))
    assert shared["chain_status"] == "shared" and sorted(h["comm"] for h in shared["holders"]) == ["curl", "decoy"]


def test_x2_04_the_private_spool_is_not_followed_through_a_symlink(tmp_path):
    from aqt_egress.records import spool_append
    target = tmp_path / "elsewhere.jsonl"
    link = tmp_path / "spool" / "spool.jsonl"
    link.parent.mkdir()
    os.symlink(target, link)
    with pytest.raises(OSError):
        spool_append({"id": "x"}, link)
    assert not target.exists()


def test_x2_04_records_wait_in_the_private_spool_while_the_writer_is_down(env, tmp_path):
    from aqt_evidence import SocketSink, actor, new_record
    from aqt_egress.records import EgressSink, RecordWriter, spool_path
    writer = RecordWriter(EgressSink(SocketSink(str(tmp_path / "no-writer.sock"))))
    writer.append_now(new_record("egress.session", actor("service", "service:aqt-egress"), "started",
                                 data={"session": "egs_x"}))
    writer.close()
    assert writer.routes["spooled"] == 1 and spool_path().exists()
    assert os.name == "nt" or oct(spool_path().stat().st_mode)[-3:] == "600"            # Windows: no POSIX modes


def test_x2_05_lost_records_are_counted(tmp_path):
    from aqt_egress.records import RecordWriter

    class Flaky:
        calls = 0

        def append(self, record):
            Flaky.calls += 1
            if Flaky.calls == 1:
                raise OSError("disk full")
            return record
    from aqt_egress.records import EgressSink
    sink = EgressSink.__new__(EgressSink)
    sink.socket, sink.other, sink.spool = None, Flaky(), tmp_path / "s"
    writer = RecordWriter(sink)
    for number in range(3):
        writer.emit("egress.lookup", "observed", {"session": "egs_x", "name": f"n{number}"})
    writer.close()
    assert writer.failed == 1 and writer.routes["file"] == 2


def test_x2_09_tools_come_from_system_folders_only(tmp_path, monkeypatch):
    from aqt_egress.netns import system_tool
    fake = tmp_path / "nft"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/sbin:/usr/bin")
    found = system_tool("nft")
    assert found != str(fake) and (found is None or found.startswith(("/usr/", "/bin/", "/sbin/")))
    assert system_tool("aqt-no-such-tool") is None


def test_x2_14_dns_names_keep_every_byte():
    response, name, _qtype = resolver.answer(
        struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x05A\xffb.c\x07example\x00" + struct.pack("!HH", 1, 1))
    assert name == "a\\255b\\.c.example"


def test_off_linux_the_box_is_not_available_and_says_why(monkeypatch):
    from aqt_evidence import platform
    from aqt_egress import box
    monkeypatch.setattr(platform, "IS_LINUX", False)
    monkeypatch.setattr(platform, "IS_MACOS", True)
    monkeypatch.setattr(platform, "SYSTEM_NAME", "macOS")
    ok, why = box.available()
    assert not ok and why.startswith("the egress box is not available on macOS")
    with pytest.raises(box.BoxUnavailable, match="not available on macOS"):
        box.bwrap_argv(["true"], project=Path("/"), public={}, info_fd=0, block_fd=0)
