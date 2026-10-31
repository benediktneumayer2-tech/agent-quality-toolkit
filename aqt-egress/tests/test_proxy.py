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
    assert client.recv(100).startswith(b"HTTP/1.1 200")
    assert client.recv(100) == b"220 hello\r\n"
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
