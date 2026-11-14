"""The real box on Linux: bubblewrap, the listeners in its network namespace, attribution, escapes.

These tests run ``aqt-egress run`` as a subprocess against the local upstream servers (no internet):
``AQT_EGRESS_TEST`` maps the test names and IP literals to them. Records go through a real aqt-trail
writer and the trail must verify. They skip themselves where bubblewrap or user namespaces are
missing (the reason is in the skip message).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from aqt_evidence import platform, read_jsonl

from aqt_egress.box import available

OK, WHY = available()
pytestmark = pytest.mark.skipif(not OK or not platform.IS_LINUX,
                                reason=f"box tests need bubblewrap with user namespaces (macOS: test_box_macos.py): {WHY}")
NEEDS = [tool for tool in ("curl", "python3") if not shutil.which(tool)]

SCRIPT = r"""
set -u
say() { echo "$1=$2"; }
curl -sS -o /dev/null -w '%{http_code}' https://upstream.test/from-curl > /tmp/aqt-egress-test-curl.$$ 2>&1; say curl "$(cat /tmp/aqt-egress-test-curl.$$)"; rm -f /tmp/aqt-egress-test-curl.$$
python3 -c "import urllib.request; print('python=' + str(urllib.request.urlopen('https://upstream.test/from-python').status))"
python3 - <<'EOF'
import os, socket, ssl, struct
def tcp(host, port, payload, tls=False):
    try:
        s = socket.create_connection((host, port), timeout=5)
        if tls:
            s = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"]).wrap_socket(s, server_hostname=host)
        s.sendall(payload)
        return s.recv(64).split(b"\r\n")[0].decode()
    except OSError as error:
        return f"failed:{error.strerror or error}"
print("ip443=" + tcp("203.0.113.10", 443, b"GET /ip443 HTTP/1.1\r\nHost: 203.0.113.10\r\nConnection: close\r\n\r\n", True))
print("ip8080=" + tcp("203.0.113.10", 8080, b"GET /ip8080 HTTP/1.1\r\nHost: spoofed.example\r\nConnection: close\r\n\r\n"))
q = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + b"\x0bsecret-data\x07example\x03com\x00" + struct.pack("!HH", 16, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.connect(("8.8.8.8", 53)); s.send(q); answer = s.recv(512)
    print("udpdns=answered-by-" + ("box" if answer[:2] == q[:2] else "?"))
except OSError as error:
    print(f"udpdns=failed:{error}")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"x", ("198.51.100.7", 443)); print("udp443=sent")
except OSError as error:
    print(f"udp443=failed:{error.strerror}")
EOF
unshare -n true 2>/dev/null && say unshare_n allowed || say unshare_n refused
unshare -rn true 2>/dev/null && say unshare_rn allowed || say unshare_rn refused
cat "$XDG_STATE_HOME/aqt/egress/ca/mitmproxy-ca.pem" >/dev/null 2>&1 && say ca_key readable || say ca_key hidden
ls "$XDG_STATE_HOME/aqt/egress/bodies" >/dev/null 2>&1 && say bodies visible || say bodies hidden
kill -0 "$AQT_TEST_RUNNER_PID" 2>/dev/null && say runner_visible yes || say runner_visible no
python3 -c "
import glob
name = 'aqt_egress' + '.cli'
found = [p for p in glob.glob('/proc/[0-9]*/cmdline') if name.encode() in open(p, 'rb').read()]
print('proxy_visible=' + ('yes' if found else 'no'))"
nft flush ruleset 2>/dev/null && say nft_flush allowed || say nft_flush refused
touch "$XDG_STATE_HOME/aqt/trail/x" 2>/dev/null && say trail_state writable || say trail_state read-only
test -n "${HTTPS_PROXY:-}" && say env_proxy "$HTTPS_PROXY"
found=""
for sock in /run/docker.sock /var/run/docker.sock /run/dbus/system_bus_socket /run/user/$(id -u)/bus \
            /run/user/$(id -u)/systemd/private /run/systemd/resolve/io.systemd.Resolve; do
    test -S "$sock" && found="$found $sock"
done
say host_sockets "${found:-none}"
cg=$(cut -d: -f3 /proc/self/cgroup | head -1)
{ test -w "/sys/fs/cgroup$cg/cgroup.kill" || test -w "/sys/fs/cgroup$cg/cgroup.freeze" \
  || test -w "/sys/fs/cgroup$(dirname "$cg")/cgroup.procs"; } && say cgroup writable || say cgroup read-only
writable=""
for dir in $AQT_TEST_INSTALL; do test -w "$dir" && writable="$writable $dir"; done
say install_writable "${writable:-none}"
pipes=""
for fd in /proc/self/fd/*; do n=${fd##*/}; [ "$n" -gt 2 ] && case "$(readlink "$fd")" in pipe:*) pipes="$pipes $n";; esac; done
say extra_pipes "${pipes:-none}"
"""


def run_box(env_dir: Path, upstream, *args, script: str = SCRIPT, project: Path | None = None,
            mapped: bool = True, extra_env: dict | None = None) -> tuple:
    environ = {**os.environ, **(extra_env or {})}
    if mapped:
        environ["AQT_EGRESS_TEST"] = json.dumps({
            "hosts": {"upstream.test": f"127.0.0.1:{upstream.https_port}",
                      "203.0.113.10:443": f"127.0.0.1:{upstream.https_port}",
                      "203.0.113.10:8080": f"127.0.0.1:{upstream.http_port}"},
            "upstream_ca": upstream.ca})
    environ["AQT_TEST_RUNNER_PID"] = str(os.getpid())
    from aqt_egress.box import installation
    environ["AQT_TEST_INSTALL"] = " ".join(installation())
    project = project or env_dir
    done = subprocess.run([sys.executable, "-m", "aqt_egress.cli", "run", "--project", str(project), *args, "--",
                           "sh", "-c", script], env=environ, capture_output=True, text=True, timeout=180)
    results = dict(line.split("=", 1) for line in done.stdout.splitlines() if "=" in line)
    return done, results


@pytest.fixture
def trail(env):
    """A real aqt-trail writer for the test's folders."""
    subprocess.run([sys.executable, "-m", "aqt_trail.cli", "init"], check=True, capture_output=True, timeout=60)
    writer = subprocess.Popen([sys.executable, "-m", "aqt_trail.cli", "serve"], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    socket_path = Path(os.environ["XDG_RUNTIME_DIR"]) / "aqt" / "trail.sock"
    deadline = time.monotonic() + 20
    while not socket_path.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert socket_path.exists(), "the trail writer did not start"
    log = Path(os.environ["XDG_STATE_HOME"]) / "aqt" / "trail" / "trail.jsonl"
    yield log
    writer.terminate()
    writer.wait(10)


@pytest.mark.skipif(bool(NEEDS), reason=f"needs {', '.join(NEEDS)} in the box")
def test_box_records_attribute_verify_and_hold_against_escapes(env, upstream, trail):
    (env / ".aqt").mkdir()
    (env / ".aqt" / "egress.toml").write_text("require = true\n")
    done, results = run_box(env, upstream, "--store", "full")
    assert done.returncode == 0, done.stdout + done.stderr
    records = list(read_jsonl(trail))
    [started] = [r for r in records if r["type"] == "egress.session" and r["action"] == "started"]
    [ended] = [r for r in records if r["type"] == "egress.session" and r["action"] == "ended"]
    session = started["data"]["session"]
    redirect = started["data"]["box"]["network"]["redirect"]
    from aqt_egress.netns import system_tool
    if system_tool("nft") and system_tool("ip"):       # where the tools exist, the redirect must be on
        assert redirect, started["data"]["box"]["network"]
    requests = [r for r in records if r["type"] == "egress.request" and r["action"] == "observed"]
    by_path = {r["data"].get("path"): r for r in requests}

    # what was meant to work works, and each record names the program that sent it
    assert results["curl"] == "200" and results["python"] == "200", done.stdout + done.stderr
    curl, python = by_path["/from-curl"]["data"], by_path["/from-python"]["data"]
    assert curl["process"]["chain"][0]["comm"] == "curl" and curl["process"]["chain_status"] == "complete"
    assert python["process"]["chain"][0]["comm"].startswith("python")
    assert curl["process"]["chain"][-1]["box_pid"] == 2 and curl["process"]["chain"][-1]["comm"] == "sh"
    assert curl["destination"]["via"] == "proxy" and curl["tls"]["mode"] == "intercepted"
    assert curl["store"]["response_body"]["sha256"].startswith("sha256:")
    assert started["data"]["project"]["require"] is True and started["data"]["store"] == "full"
    assert started["data"]["ca_fingerprint"].startswith("sha256:")
    assert ended["data"]["exit_code"] == 0 and ended["data"]["counts"]["requests"] == len(requests)

    # escapes: nothing reaches the outside unseen
    if redirect:
        ip443 = by_path["/ip443"]["data"]
        assert ip443["destination"] == {**ip443["destination"], "host": "203.0.113.10", "port": 443, "via": "redirect"}
        assert ip443["tls"]["mode"] == "intercepted" and results["ip443"].startswith("HTTP/1."), results
        assert ip443["process"]["chain"][0]["comm"].startswith("python")
        ip8080 = by_path["/ip8080"]["data"]
        assert ip8080["destination"] == {**ip8080["destination"], "host": "203.0.113.10", "port": 8080,
                                         "via": "redirect", "host_header": "spoofed.example"}   # X2-01
        assert results["ip8080"].startswith("HTTP/1."), results
        assert results["udpdns"] == "answered-by-box"
        [lookup] = [r["data"] for r in records if r["type"] == "egress.lookup"
                    and r["data"]["name"] == "secret-data.example.com"]
        assert lookup["types"] == ["TXT"] and lookup["session"] == session
        assert lookup["process"]["chain"][0]["comm"].startswith("python")
    else:   # without nftables such connections cannot leave at all
        assert results["ip443"].startswith("failed") and results["ip8080"].startswith("failed")
    assert results["udp443"].startswith("failed"), results
    assert results["unshare_n"] == "refused" and results["unshare_rn"] == "refused"
    assert results["ca_key"] == "hidden" and results["bodies"] == "hidden"
    assert results["runner_visible"] == "no" and results["proxy_visible"] == "no"
    assert results["nft_flush"] == "refused" and results["trail_state"] == "read-only"
    assert results["env_proxy"] == "http://127.0.0.1:3128"
    assert results["host_sockets"] == "none"         # docker, D-Bus, systemd, resolved: /run is empty
    assert results["cgroup"] == "read-only"            # X2-03: the box cannot freeze or kill the proxy
    assert results["install_writable"] == "none"       # X2-09: the recorder's own code is read-only
    assert results["extra_pipes"] == "none"            # G2: the start gate's pipe is not left to the command
    tools = started["data"]["box"]["tools"]
    assert tools["bwrap"]["path"].startswith(("/usr/", "/bin/")) and tools["bwrap"]["sha256"].startswith("sha256:")
    assert started["data"]["test_options"] == ["hosts", "upstream_ca"]          # X2-10
    assert "test options in effect" in done.stderr
    if redirect:
        assert "aqt_egress" in started["data"]["box"]["network"]["nft_table"]
    opened = [r for r in records if r["type"] == "egress.request" and r["action"] == "opened"]
    assert opened and all(r["data"]["destination"]["host"] for r in opened)   # X2-03

    # the trail with the egress records verifies
    verify = subprocess.run([sys.executable, "-m", "aqt_trail.cli", "verify"], capture_output=True, text=True,
                            timeout=60)
    assert verify.returncode == 0 and verify.stdout.startswith("intact"), verify.stdout + verify.stderr


@pytest.mark.skipif(bool(NEEDS), reason=f"needs {', '.join(NEEDS)} in the box")
def test_box_exit_code_and_report(env, upstream, capsys):
    done, _ = run_box(env, upstream, script="curl -sS -o /dev/null https://upstream.test/report; exit 3")
    assert done.returncode == 3, done.stderr
    from aqt_egress import cli
    assert cli.main(["report", "--json"]) == 0
    [session] = json.loads(capsys.readouterr().out)["sessions"]
    [destination] = session["destinations"]
    assert session["exit_code"] == 3 and destination["host"] == "upstream.test" and destination["new"] is True
    assert list(destination["processes"]) == ["curl < sh"]
    status = cli.status()
    assert status["ca"] is True and status["last_session"]["exit_code"] == 3


LOCAL = r"""
curl -sS -o /dev/null -w 'local=%{http_code}\n' -H 'Content-Type: application/json' \
    -d '{"model": "local-gguf", "messages": [{"role": "user", "content": "SECRET-LOCAL"}]}' \
    "http://127.0.0.1:$LOCAL_PORT/v1/chat/completions"
curl -sS -o /dev/null -w 'other_loopback=%{http_code}\n' --noproxy '' -x http://127.0.0.1:3128 "http://127.0.0.1:$OTHER_PORT/" 2>/dev/null
curl -sS -o /dev/null -w 'other_direct=%{http_code}\n' "http://127.0.0.1:$OTHER_PORT/" 2>/dev/null
echo "agent_session=$AQT_AGENT_SESSION"
test -e "$MARKER" && echo marker=visible || echo marker=hidden
test -w /tmp && echo tmp=writable
"""


@pytest.mark.skipif(bool(NEEDS), reason=f"needs {', '.join(NEEDS)} in the box")
def test_box_local_endpoint_loopback_boundary_private_tmp_and_session(env, upstream):
    marker = Path(tempfile.mkstemp(prefix="aqt-egress-marker-", dir="/tmp")[1])
    try:
        done, results = run_box(env, upstream, "--local-endpoint", f"127.0.0.1:{upstream.http_port}",
                                "--private-tmp", script=LOCAL, mapped=False,
                                extra_env={"LOCAL_PORT": str(upstream.http_port), "OTHER_PORT": str(upstream.https_port),
                                           "MARKER": str(marker)})
    finally:
        marker.unlink()
    assert done.returncode == 0, done.stdout + done.stderr
    records = list(read_jsonl(Path(os.environ["XDG_STATE_HOME"]) / "aqt" / "evidence.jsonl"))
    [started] = [r["data"] for r in records if r["type"] == "egress.session" and r["action"] == "started"]
    requests = {r["data"]["destination"]["port"]: r["data"] for r in records if r["type"] == "egress.request"
                and r["action"] == "observed"}
    # the configured local inference server: reached, recorded like any request, structure only
    assert results["local"] == "200"
    local = requests[upstream.http_port]
    assert local["destination"]["via"] == "local" and local["tls"] == {"mode": "none"}
    assert local["llm"]["provider"] == "local" and local["llm"]["model"] == "local-gguf"
    assert "excerpt" not in local["request"] and "SECRET" not in json.dumps(local)
    assert local["process"]["chain"][0]["comm"] == "curl"
    assert started["local_endpoints"] == [f"127.0.0.1:{upstream.http_port}"]
    # any other service on the host's loopback stays outside the box
    assert results["other_loopback"] == "502" and results["other_direct"] == "000"   # refused / nothing there
    assert requests[upstream.https_port]["decision"] == "refused"
    # a fresh /tmp, and the agent session names the egress session
    assert results["marker"] == "hidden" and results["tmp"] == "writable" and started["box"]["tmp"] == "private"
    assert results["agent_session"] == started["session"]


@pytest.mark.skipif(bool(NEEDS), reason=f"needs {', '.join(NEEDS)} in the box")
def test_x2_04_records_wait_in_a_private_spool_and_are_drained(env, upstream):
    subprocess.run([sys.executable, "-m", "aqt_trail.cli", "init"], check=True, capture_output=True, timeout=60)
    done, results = run_box(env, upstream, script="curl -sS -o /dev/null https://upstream.test/spooled; "
                            "test -e \"$XDG_STATE_HOME/aqt/egress/spool.jsonl\" && echo spool=visible || echo spool=hidden")
    assert done.returncode == 0, done.stderr
    assert results["spool"] == "hidden"
    state = Path(os.environ["XDG_STATE_HOME"]) / "aqt"
    private = list(read_jsonl(state / "egress" / "spool.jsonl"))
    assert {r["type"] for r in private} >= {"egress.session", "egress.request"}
    shared = state / "spool" / "spool.jsonl"
    assert not shared.exists() or not any(r["type"].startswith("egress.") for r in read_jsonl(shared))
    writer = subprocess.Popen([sys.executable, "-m", "aqt_trail.cli", "serve"], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    try:
        socket_path = Path(os.environ["XDG_RUNTIME_DIR"]) / "aqt" / "trail.sock"
        deadline = time.monotonic() + 20
        while not socket_path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        drained = subprocess.run([sys.executable, "-m", "aqt_egress.cli", "drain"], capture_output=True, text=True,
                                 timeout=60)
        assert drained.returncode == 0 and f"drained {len(private)}" in drained.stdout, drained.stdout + drained.stderr
        trail = [r for r in read_jsonl(state / "trail" / "trail.jsonl") if r["type"].startswith("egress.")]
        assert {r["id"] for r in trail} == {r["id"] for r in private}
        verify = subprocess.run([sys.executable, "-m", "aqt_trail.cli", "verify"], capture_output=True, text=True,
                                timeout=60)
        assert verify.returncode == 0, verify.stdout + verify.stderr
    finally:
        writer.terminate()
        writer.wait(10)


@pytest.mark.skipif(bool(NEEDS), reason=f"needs {', '.join(NEEDS)} in the box")
def test_x2_13_a_failure_before_release_ends_the_box(env, monkeypatch):
    from aqt_egress import run as run_module
    from aqt_egress.settings import Settings
    marker = env / "started.marker"

    def broken(*args, **kwargs):
        raise RuntimeError("records unavailable")
    monkeypatch.setattr(run_module, "RecordWriter", broken)
    with pytest.raises(RuntimeError, match="records unavailable"):
        run_module.run(["sh", "-c", f"touch {marker}"], project=env, settings=Settings())
    time.sleep(0.5)
    assert not marker.exists()
    left = subprocess.run(["pgrep", "-f", str(marker)], capture_output=True, text=True)
    assert left.stdout.strip() == ""


@pytest.mark.skipif(bool(NEEDS), reason=f"needs {', '.join(NEEDS)} in the box")
def test_launcher_killed_before_release_never_starts_the_command(env):
    marker = env / "gate.marker"
    script = (
        "import time, aqt_egress.run as r\n"
        "from pathlib import Path\n"
        "from aqt_egress.settings import Settings\n"
        "real = r.open_listeners\n"
        "def slow(*a, **k):\n"
        "    Path(%r).write_text('waiting')\n"
        "    time.sleep(60)\n"
        "    return real(*a, **k)\n"
        "r.open_listeners = slow\n"
        "r.run(['sh', '-c', 'touch %s'], project=Path(%r), settings=Settings())\n"
    ) % (str(env / "waiting"), marker, str(env))
    launcher = subprocess.Popen([sys.executable, "-c", script])
    deadline = time.monotonic() + 30
    while not (env / "waiting").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert (env / "waiting").exists(), "the launcher did not reach the box setup"
    launcher.kill()                                   # SIGKILL: no cleanup runs in the launcher
    launcher.wait(10)
    time.sleep(1.0)
    assert not marker.exists()
    left = subprocess.run(["pgrep", "-f", str(marker)], capture_output=True, text=True)
    assert left.stdout.strip() == ""
