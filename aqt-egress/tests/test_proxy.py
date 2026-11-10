"""The proxy in this process forwards to local upstream servers and writes one record per request."""

import gzip
import json
import socket
import time
import urllib.error

import pytest

from aqt_evidence import validate_record
from aqt_evidence.schemas import validate_payload

from aqt_egress.settings import Settings
from aqt_egress.store import BodyStore
from conftest import STREAM_CHUNKS, STREAM_PAUSE, requests_of

TOKEN = "sk-ant-api03-" + "x" * 40


def test_https_request_is_forwarded_and_recorded(make_proxy):
    proxy = make_proxy()
    body = proxy.opener().open("https://upstream.test/hello?id=7&key=abc").read()
    assert body == b"hello from upstream /hello?id=7&key=abc"
    [record] = requests_of(proxy.records())
    assert validate_record(record) == [] and validate_payload(record) == []
    data = record["data"]
    assert data["destination"]["host"] == "upstream.test" and data["destination"]["port"] == 443
    assert data["destination"]["ip"] == "127.0.0.1" and data["destination"]["via"] == "proxy"
    assert data["tls"] == {"mode": "intercepted"} and data["method"] == "GET" and data["path"] == "/hello"
    assert data["query_sha256"].startswith("sha256:") and "query" not in data   # the query only as a hash
    assert data["mode"] == "observe" and data["decision"] == "allowed"
    assert data["response"]["status"] == 200 and data["response"]["bytes"] == len(body)
    assert data["response"]["excerpt"] == body.decode()
    assert data["process"]["chain"][0]["comm"] == "test-client"
    assert record["actor"]["id"] == "service:aqt-egress" and data["session"] == "egs_test"


def test_plain_http_and_post_body(make_proxy):
    proxy = make_proxy()
    request = __import__("urllib.request").request.Request(
        "http://plain.test/submit", data=b'{"password": "hunter22", "text": "hello"}',
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    answer = json.loads(proxy.opener().open(request).read())
    assert answer == {"received": 41}
    [record] = requests_of(proxy.records())
    data = record["data"]
    assert data["tls"] == {"mode": "none"} and "sni" not in data["destination"]
    assert data["request"]["bytes"] == 41 and data["request"]["body_sha256"].startswith("sha256:")
    assert data["request"]["excerpt"] == '{"password": "[masked]", "text": "hello"}'
    [credential] = data["request"]["credentials"]
    assert credential["header"] == "authorization" and credential["scheme"] == "Bearer"
    assert credential["fingerprint"].startswith("hmac-sha256:")
    text = json.dumps(record)
    assert TOKEN not in text and "hunter22" not in text and "authorization" in data["request"]["headers"]


def test_same_key_same_fingerprint_other_key_other(make_proxy):
    proxy = make_proxy()
    opener = proxy.opener()
    Request = __import__("urllib.request").request.Request
    for value in (TOKEN, TOKEN, TOKEN + "y"):
        opener.open(Request("http://plain.test/x", headers={"x-api-key": value})).read()
    prints = [r["data"]["request"]["credentials"][0]["fingerprint"] for r in requests_of(proxy.records())]
    assert prints[0] == prints[1] != prints[2]


def test_streamed_response_reaches_the_client_before_it_ends(make_proxy):
    proxy = make_proxy()
    response = proxy.opener().open("https://upstream.test/stream")
    start = time.monotonic()
    first = response.readline()
    first_at = time.monotonic() - start
    rest = response.read()
    total = time.monotonic() - start
    assert first == STREAM_CHUNKS[0].splitlines(keepends=True)[0]
    assert first_at < STREAM_PAUSE and total >= 2 * STREAM_PAUSE * 0.9    # not buffered until the end
    [record] = requests_of(proxy.records())
    assert record["data"]["response"]["bytes"] == sum(map(len, STREAM_CHUNKS))
    assert record["data"]["response"]["excerpt"].startswith("data: one")
    assert first + rest == b"".join(STREAM_CHUNKS)


def test_full_mode_stores_masked_bodies_and_headers(make_proxy):
    proxy = make_proxy(settings=Settings(store="full"))
    Request = __import__("urllib.request").request.Request
    proxy.opener().open(Request("https://upstream.test/up", data=b"api_key=abcd1234efgh&x=1",
                                headers={"Authorization": f"Bearer {TOKEN}"})).read()
    proxy.opener().open("https://upstream.test/gzip").read()
    first, second = requests_of(proxy.records())
    store: BodyStore = proxy.store
    refs = first["data"]["store"]
    assert store.read(refs["request_body"]["sha256"]) == b"api_key=[masked]&x=1"
    headers = json.loads(store.read(refs["headers"]["sha256"]))
    assert ["authorization", "[masked]"] in [[name.lower(), value] for name, value in headers["request"]]
    assert TOKEN.encode() not in b"".join(path.read_bytes() for path in store.objects())
    assert json.loads(store.read(refs["response_body"]["sha256"])) == {"received": 24}
    gz = second["data"]["store"]["response_body"]
    assert gz["decoded"] is True and gz["encoding"] == "gzip"
    assert store.read(gz["sha256"]) == b"compressed hello, token=[masked]"
    assert second["data"]["response"]["excerpt"] == "compressed hello, token=[masked]"
    path = store.path(gz["sha256"])
    path.write_bytes(gzip.compress(b"changed"))
    with pytest.raises(Exception, match="changed"):
        store.read(gz["sha256"])
    assert not list((store.root / "tmp").iterdir())                  # spooled bodies were moved


def test_excerpt_mode_stores_nothing(make_proxy, env):
    proxy = make_proxy()
    proxy.opener().open("https://upstream.test/hello").read()
    [record] = requests_of(proxy.records())
    assert "store" not in record["data"] and proxy.store is None


def test_excerpt_length_is_configurable(make_proxy):
    proxy = make_proxy(settings=Settings(excerpt_chars=5))
    proxy.opener().open("https://upstream.test/hello").read()
    [record] = requests_of(proxy.records())
    assert record["data"]["response"]["excerpt"] == "hello"


def test_host_loopback_is_refused_and_recorded(make_proxy):
    proxy = make_proxy(test_hosts={})
    with pytest.raises(urllib.error.HTTPError) as caught:
        proxy.opener().open("http://localhost:9/")
    assert caught.value.code == 502
    [record] = requests_of(proxy.records())
    assert record["data"]["decision"] == "refused" and record["data"]["reason_code"] == "host-loopback"
    assert "loopback" in record["data"]["error"]


def test_lookup_is_claimed_by_the_request_that_followed(make_proxy):
    proxy = make_proxy()
    proxy.lookups.add("upstream.test", 1, {"chain": [{"pid": 1, "comm": "test-client"}]})
    proxy.lookups.add("other.test", 28, {"chain": [{"pid": 2, "comm": "dig"}]})
    proxy.opener().open("https://upstream.test/hello").read()
    [record] = requests_of(proxy.records())
    assert record["data"]["lookups"] == [{"name": "upstream.test", "types": ["A"], "count": 1}]
    proxy.addon.flush_lookups(older_than=0)
    lookups = [r for r in proxy.records() if r["type"] == "egress.lookup"]
    assert [r["data"]["name"] for r in lookups] == ["other.test"]
    assert lookups[0]["data"]["process"]["chain"][0]["comm"] == "dig"


def test_raw_tcp_through_the_redirect_listener(make_proxy, upstream):
    """A non-HTTP connection in transparent mode is recorded as one TCP record."""
    import threading
    echo = socket.socket()
    echo.bind(("127.0.0.1", 0))
    echo.listen(1)

    def serve():
        conn, _ = echo.accept()
        conn.sendall(b"220 hello\r\n")
        conn.recv(100)
        conn.close()
    threading.Thread(target=serve, daemon=True).start()
    proxy = make_proxy(test_hosts={"203.0.113.9:25": f"127.0.0.1:{echo.getsockname()[1]}"})
    client = socket.create_connection(("127.0.0.1", proxy.port))
    client.sendall(b"CONNECT 203.0.113.9:25 HTTP/1.1\r\nHost: 203.0.113.9:25\r\n\r\n")
    client.settimeout(10)
    received = b""                      # the 200 and the greeting may arrive in one read or several
    while b"220 hello\r\n" not in received:
        chunk = client.recv(100)
        assert chunk, f"connection closed after {received!r}"
        received += chunk
    head, _, rest = received.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200") and rest == b"220 hello\r\n"
    client.sendall(b"QUIT\r\n")
    time.sleep(0.3)
    client.close()
    [record] = requests_of(proxy.records(settle=0.5))
    data = record["data"]
    assert data["protocol"] == "tcp" and data["destination"]["host"] == "203.0.113.9"
    assert data["request"]["bytes"] == 6 and data["response"]["bytes"] == 11
    echo.close()


def test_a_name_that_lands_on_loopback_after_the_check_is_closed(make_proxy, upstream):
    """DNS rebinding: the name passed the check, the connection still reached the host's loopback."""
    proxy = make_proxy()
    proxy.addon.allow_loopback = False         # the test mapping stands in for the second, different answer
    with pytest.raises(urllib.error.URLError):
        proxy.opener().open("https://upstream.test/rebound", timeout=10).read()
    records = requests_of(proxy.records(settle=0.5))
    assert records and all(r["data"]["decision"] == "refused" for r in records)
    assert {r["data"]["reason_code"] for r in records} == {"host-loopback"}


PROMPT = {"model": "claude-test-1", "system": "You are SECRET-SYSTEM", "stream": False,
          "messages": [{"role": "user", "content": "SECRET-PROMPT summarise my repository"}],
          "tools": [{"name": "Read", "input_schema": {}}]}


@pytest.mark.parametrize("store", ["excerpt", "full"])
def test_llm_requests_are_recorded_by_structure_never_text(make_proxy, upstream, store):
    proxy = make_proxy(settings=Settings(store=store),
                       test_hosts={"api.anthropic.com": f"127.0.0.1:{upstream.http_port}"})
    Request = __import__("urllib.request").request.Request
    body = json.dumps(PROMPT).encode()
    proxy.opener().open(Request("http://api.anthropic.com/v1/messages", data=body,
                                headers={"Content-Type": "application/json", "x-api-key": TOKEN})).read()
    [record] = requests_of(proxy.records())
    data = record["data"]
    assert data["llm"] == {"provider": "anthropic", "model": "claude-test-1", "messages": 1, "roles": {"user": 1},
                           "system": True, "tools": ["Read"], "stream": False, "parsed": True}
    assert "excerpt" not in data["request"] and "excerpt" not in data["response"]
    assert data["request"]["bytes"] == len(body) and data["request"]["body_sha256"].startswith("sha256:")
    assert "SECRET" not in json.dumps(record) and TOKEN not in json.dumps(record)
    if store == "full":                         # the body lives in the body store only
        stored = json.loads(proxy.store.read(data["store"]["request_body"]["sha256"]))
        assert stored["messages"][0]["content"].startswith("SECRET-PROMPT")


def test_configured_llm_hosts_get_no_excerpt(make_proxy):
    proxy = make_proxy(settings=Settings(llm_hosts=["plain.test"]))
    Request = __import__("urllib.request").request.Request
    proxy.opener().open(Request("http://plain.test/v1/chat/completions", data=b'{"model": "local-7b", '
                                b'"messages": [{"role": "user", "content": "SECRET"}]}')).read()
    [record] = requests_of(proxy.records())
    assert record["data"]["llm"]["provider"] == "configured" and record["data"]["llm"]["model"] == "local-7b"
    assert "SECRET" not in json.dumps(record)


def test_other_destinations_keep_a_masked_excerpt_of_280_by_default(make_proxy):
    proxy = make_proxy()
    Request = __import__("urllib.request").request.Request
    proxy.opener().open(Request("http://plain.test/upload", data=b"z" * 1000)).read()
    [record] = requests_of(proxy.records())
    assert record["data"]["request"]["excerpt"] == "z" * 280 and "llm" not in record["data"]


# -- review X2 -----------------------------------------------------------------------------------
Request = __import__("urllib.request").request.Request


def test_x2_01_destination_is_where_the_proxy_connected_not_the_host_header(make_proxy):
    proxy = make_proxy()
    proxy.opener().open(Request("http://plain.test/claimed", headers={"Host": "other.example"})).read()
    [record] = requests_of(proxy.records())
    assert record["data"]["destination"]["host"] == "plain.test"
    assert record["data"]["destination"]["host_header"] == "other.example"
    assert record["subject"]["ref"] == "plain.test:80"


def _connect(proxy, target: str) -> socket.socket:
    client = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    client.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    assert client.recv(200).startswith(b"HTTP/1.1 200")
    return client


def test_x2_02_passthrough_only_after_an_explicit_alert_keyed_on_name_and_destination(make_proxy, upstream):
    import ssl
    proxy = make_proxy()
    # a client that just closes during the handshake teaches nothing
    client = _connect(proxy, "upstream.test:443")
    client.sendall(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")
    client.close()
    time.sleep(0.5)
    assert proxy.addon.learned == {}
    # a client that rejects the proxy's CA (alert unknown_ca) makes this name at this destination pass through
    strict = ssl.create_default_context(cafile=upstream.ca)          # trusts the upstream, not the proxy
    with pytest.raises(ssl.SSLError):
        strict.wrap_socket(_connect(proxy, "upstream.test:443"), server_hostname="upstream.test")
    time.sleep(0.5)
    assert list(proxy.addon.learned.values()) == ["client-rejected-certificate"]
    tls = strict.wrap_socket(_connect(proxy, "upstream.test:443"), server_hostname="upstream.test")
    payload = b"GET /through HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n"
    tls.sendall(payload)
    answer = tls.recv(200)
    tls.close()
    assert answer.startswith(b"HTTP/1.0 200") or answer.startswith(b"HTTP/1.1 200")
    records = requests_of(proxy.records(settle=0.8))
    learned = [r["data"] for r in records if r["data"]["tls"].get("passthrough_learned")]
    passed = [r["data"] for r in records if r["data"]["tls"]["mode"] == "passthrough"]
    assert len(learned) == 1 and len(passed) == 1
    assert passed[0]["tls"]["reason"] == "client-rejected-certificate"
    assert passed[0]["destination"]["host"] == "upstream.test" and passed[0]["destination"]["port"] == 443
    assert passed[0]["request"]["bytes"] >= len(payload) and passed[0]["response"]["bytes"] > 0


def test_x2_03_an_opened_record_exists_before_the_answer(make_proxy):
    import threading
    proxy = make_proxy()
    done = threading.Thread(target=lambda: proxy.opener().open(Request("http://plain.test/slow", data=b"x")).read())
    done.start()
    time.sleep(0.5)                                  # the upstream is still sleeping
    opened = requests_of(list(__import__("aqt_evidence").read_jsonl(proxy.records_path)), "opened")
    assert opened and opened[0]["data"]["destination"]["host"] == "plain.test"
    assert opened[0]["data"]["process"]["chain"][0]["comm"] == "test-client"
    done.join(10)
    [final] = requests_of(proxy.records())
    assert {"rel": "opened", "ref": opened[0]["id"]} in final["links"]


def test_x2_05_a_store_error_keeps_the_record(make_proxy, monkeypatch):
    proxy = make_proxy(settings=Settings(store="full"))

    def broken(*args, **kwargs):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(proxy.store, "put_body", broken)
    proxy.opener().open(Request("http://plain.test/full", data=b"body")).read()
    [record] = requests_of(proxy.records())
    assert "No space left" in record["data"]["store_error"] and proxy.addon.counts["store_errors"] == 1


def test_x2_06_the_hosts_own_addresses_are_refused(make_proxy):
    from aqt_egress.proxy import host_addresses
    own = sorted(address for address in host_addresses() if not address.startswith(("127.", "::1")))
    if not own:
        pytest.skip("this host has no address besides loopback")
    proxy = make_proxy(test_hosts={}, own_addresses=set(own))
    target = f"[{own[0]}]" if ":" in own[0] else own[0]
    with pytest.raises(urllib.error.HTTPError) as caught:
        proxy.opener().open(f"http://{target}:9/", timeout=10)
    assert caught.value.code == 502
    [record] = requests_of(proxy.records())
    assert record["data"]["decision"] == "refused" and record["data"]["reason_code"] == "host-local"
    assert not requests_of(proxy.records(settle=0), "opened")      # no connection was made


def test_x2_08_a_non_websocket_upgrade_records_its_request(make_proxy):
    proxy = make_proxy()
    client = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    client.sendall(b"POST http://plain.test/upgrade HTTP/1.1\r\nHost: plain.test\r\nUpgrade: x-test\r\n"
                   b"Connection: Upgrade\r\nContent-Length: 5\r\n\r\nhello")
    assert client.recv(200).startswith(b"HTTP/1.1 101")
    client.sendall(b"ping")
    assert client.recv(100) == b"echo:ping"
    client.close()
    records = requests_of(proxy.records(settle=0.8))
    [upgrade] = [r["data"] for r in records if r["data"].get("protocol") == "http-upgrade"]
    assert upgrade["path"] == "/upgrade" and upgrade["request"]["bytes"] == 5 and upgrade["upgrade"] == "x-test"
    assert [r["data"] for r in records if r["data"]["protocol"] == "tcp"]


def test_x2_12_a_failing_hook_still_leaves_a_record(make_proxy, monkeypatch):
    from aqt_egress import llm as llm_module
    proxy = make_proxy()
    real, calls = llm_module.provider, []

    def flaky(*args):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return real(*args)
    monkeypatch.setattr(llm_module, "provider", flaky)
    proxy.opener().open("http://plain.test/flaky").read()
    assert len(requests_of(proxy.records())) == 1          # its record is written before the next step
    monkeypatch.setattr(proxy.addon, "_emit_http", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("emit")))
    proxy.opener().open("http://plain.test/minimal").read()
    records = requests_of(proxy.records())
    assert len(records) == 2 and proxy.addon.counts["hook_errors"] == 2
    assert records[0]["data"]["path"] == "/flaky"
    assert records[1]["data"]["error"].startswith("aqt-egress could not record this exchange fully")
    assert records[1]["data"]["destination"]["host"] == "plain.test"


# -- review recheck (N) --------------------------------------------------------------------------
def test_n1_a_claimed_provider_host_does_not_hide_the_excerpt(make_proxy):
    proxy = make_proxy()
    proxy.opener().open(Request("http://plain.test/v1/messages", data=b"MARKER-OUTBOUND-DATA",
                                headers={"Host": "api.anthropic.com"})).read()
    [record] = requests_of(proxy.records())
    data = record["data"]
    assert "llm" not in data and data["request"]["excerpt"] == "MARKER-OUTBOUND-DATA"
    assert data["destination"]["host"] == "plain.test" and data["destination"]["host_header"] == "api.anthropic.com"


def test_n2_no_opened_record_no_traffic(make_proxy, monkeypatch):
    from conftest import Handler
    proxy = make_proxy()
    real = proxy.writer.append_now
    monkeypatch.setattr(proxy.writer, "append_now",
                        lambda record: False if record["action"] == "opened" else real(record))
    Handler.seen.clear()
    with pytest.raises((urllib.error.URLError, ConnectionError, OSError)):
        proxy.opener().open(Request("http://plain.test/never", data=b"x"), timeout=10).read()
    time.sleep(0.5)
    assert "/never" not in Handler.seen and proxy.addon.counts["unrecorded_closed"] == 1
    [record] = requests_of(proxy.records())
    assert record["data"]["decision"] == "refused" and record["data"]["reason_code"] == "record-unavailable"


def test_n4_a_local_endpoint_through_the_proxy_is_structure_only(make_proxy, upstream):
    settings = Settings(local_endpoints=[("127.0.0.1", upstream.http_port)])
    proxy = make_proxy(settings=settings, test_hosts={})
    proxy.opener().open(Request(f"http://127.0.0.1:{upstream.http_port}/v1/chat/completions",
                                data=b'{"model": "local-7b", "messages": [{"role": "user", "content": "SECRET"}]}')).read()
    [record] = requests_of(proxy.records())
    assert record["data"]["llm"]["provider"] == "local" and record["data"]["llm"]["model"] == "local-7b"
    assert "excerpt" not in record["data"]["request"] and record["data"]["decision"] == "allowed"


def test_x2_06_residual_an_empty_refresh_keeps_the_known_addresses(make_proxy):
    proxy = make_proxy(test_hosts={}, own_addresses={"192.0.2.77"})
    proxy.addon.refresh_addresses(set())
    proxy.addon.refresh_addresses({"198.51.100.9"})
    assert proxy.addon.own_addresses == {"192.0.2.77", "198.51.100.9"}
    assert proxy.addon._outside("192.0.2.77", 80) == "host-local"


def test_configured_passthrough_only_where_the_proxy_really_connects(make_proxy, upstream):
    import ssl
    proxy = make_proxy(settings=Settings(passthrough=["upstream.test"]),
                       test_hosts={"upstream.test": f"127.0.0.1:{upstream.https_port}",
                                   "other.test": f"127.0.0.1:{upstream.https_port}"})
    for target, context in (("upstream.test:443", ssl.create_default_context(cafile=upstream.ca)),
                            ("other.test:443", ssl.create_default_context(cafile=proxy.ca_file))):
        tls = context.wrap_socket(_connect(proxy, target), server_hostname="upstream.test")
        tls.sendall(b"GET /pt HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n")
        answer = tls.recv(100)          # passed through: the upstream answers; intercepted: the proxy checks
        assert b"200" in answer or target.startswith("other")   # other.test's certificate (502 here)
        tls.close()
    records = requests_of(proxy.records(settle=0.8))
    modes = {r["data"]["destination"]["host"]: r["data"]["tls"]["mode"] for r in records}
    assert modes == {"upstream.test": "passthrough", "other.test": "intercepted"}
