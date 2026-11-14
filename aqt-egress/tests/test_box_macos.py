"""The box on macOS: the generated Seatbelt profile (on every system) and real ``sandbox-exec`` runs (macOS).

The real runs start ``aqt-egress run`` as a subprocess against the local upstream servers, as
``test_box.py`` does on Linux; records go through a real aqt-trail writer and the trail must verify.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from aqt_evidence import platform, read_jsonl

from aqt_egress import box

MACOS = pytest.mark.skipif(not platform.IS_MACOS, reason="Seatbelt (sandbox-exec) exists only on macOS")


# -- the profile, on every POSIX system -------------------------------------------------------------------------
@pytest.mark.skipif(platform.IS_WINDOWS, reason="Seatbelt profiles name POSIX paths; on Windows os.path.realpath "
                                                "makes /s/aqt into D:\\s\\aqt")
def test_profile_reaches_only_the_proxy_port_and_protects_the_aqt_folders():
    text = box.seatbelt_profile(port=40123, hidden=["/s/aqt/egress"], read_only=["/c/aqt", "/s/aqt"],
                                writable=["/s/aqt/spool"], readable=["/s/aqt/egress/sessions/x/public"],
                                closed=(["/private/var/run", "/r"], [r"^/private/tmp/com\.apple\.launchd\."]),
                                opened=["/r/aqt"])
    lines = text.splitlines()
    assert lines[:2] == ["(version 1)", "(deny default)"]
    assert [line for line in lines if "remote ip" in line] == ['(allow network-outbound (remote ip "localhost:40123"))']
    assert not any("network-bind (local ip" in line or "network*" in line for line in lines)

    def block(head):        # the paths of the rule that starts with ``head``, in order
        start = lines.index(head)
        return [line.strip()[len("(subpath "):-1].strip('"') for line in lines[start + 1:lines.index(")", start)]]
    assert block("(deny file-write*") == ["/c/aqt", "/s/aqt"]
    assert block("(deny file-read* file-write*") == ["/s/aqt/egress"]
    order = [lines.index(head) for head in ("(deny file-write*", "(deny file-read* file-write*",
                                            "(allow file-read* file-write*", "(allow file-read*")]
    assert order == sorted(order)                         # the last matching rule wins: the exceptions come last
    assert '  (literal "/s")' in lines and '  (literal "/s/aqt/egress")' in lines   # no renaming them away
    closed = lines.index('(deny network-outbound (remote unix-socket (subpath "/r")))')
    assert lines.index('(allow network-outbound (remote unix-socket (subpath "/r/aqt")))') > closed
    assert "com.apple.SecurityServer" in text and "com.apple.trustd.agent" not in text   # trustd fetches URLs


def test_environment_names_the_proxy_port_and_the_ca_files_where_they_are(tmp_path):
    public = {"ca": tmp_path / "ca.pem", "bundle": tmp_path / "bundle.pem"}
    env = box.box_environment({"NO_PROXY": "internal.example", "PATH": "/usr/bin"}, "egs_1", port=40123, public=public)
    assert env["HTTPS_PROXY"] == env["http_proxy"] == "http://127.0.0.1:40123"
    assert "NO_PROXY" not in env and "no_proxy" not in env       # everything goes to the proxy, even loopback
    assert env["SSL_CERT_FILE"] == env["CURL_CA_BUNDLE"] == str(public["bundle"])
    assert env["NODE_EXTRA_CA_CERTS"] == str(public["ca"]) and env["AQT_AGENT_SESSION"] == "egs_1"


# -- real runs, macOS only -------------------------------------------------------------------------------------
SCRIPT = r"""
set -u
say() { echo "$1=$2"; }
say curl "$(curl -sS -o /dev/null -w '%{http_code}' https://upstream.test/from-curl 2>&1)"
say direct_ip "$(curl -sS --noproxy '*' -m 5 -o /dev/null -w '%{http_code}' https://203.0.113.10/ 2>&1 | tail -1)"
say direct_name "$(curl -sS --noproxy '*' -m 5 -o /dev/null -w '%{http_code}' https://upstream.test/ 2>&1 | tail -1)"
say other_loopback "$(curl -sS --noproxy '*' -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$OTHER_PORT/" 2>&1 | tail -1)"
python3 - <<'EOF'
import os, socket, urllib.request
print("python=" + str(urllib.request.urlopen("https://upstream.test/from-python").status))
def attempt(name, action):
    try:
        action(); print(f"{name}=allowed")
    except OSError as error:
        print(f"{name}=refused:{error.errno}")
attempt("tcp_out", lambda: socket.create_connection(("203.0.113.10", 443), timeout=5))
attempt("udp_dns", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("8.8.8.8", 53)))
attempt("lookup", lambda: socket.getaddrinfo("example.com", 443))
attempt("mdns_socket", lambda: socket.socket(socket.AF_UNIX).connect("/private/var/run/mDNSResponder"))
attempt("bind_tcp", lambda: socket.create_server(("127.0.0.1", 0)))
EOF
cat "$XDG_STATE_HOME/aqt/egress/ca/mitmproxy-ca.pem" >/dev/null 2>&1 && say ca_key readable || say ca_key hidden
ls "$XDG_STATE_HOME/aqt/egress/bodies" >/dev/null 2>&1 && say bodies visible || say bodies hidden
kill -0 "$AQT_TEST_RUNNER_PID" 2>/dev/null && say runner_signal yes || say runner_signal no
touch "$XDG_STATE_HOME/aqt/trail/x" 2>/dev/null && say trail_state writable || say trail_state read-only
mv "$XDG_STATE_HOME" "$XDG_STATE_HOME.moved" 2>/dev/null && say state_moved yes || say state_moved no
ln "$XDG_STATE_HOME/aqt/trail/trail.jsonl" "$PWD/trail-link" 2>/dev/null && say trail_link made || say trail_link refused
touch "$PWD/written-in-project" && say project writable
launchctl submit -l io.github.benediktneumayer2tech.aqt.egress-escape-test -- /usr/bin/true 2>/dev/null \
    && say launchd_job created || say launchd_job refused
written=""
for dir in $AQT_TEST_INSTALL; do touch "$dir/.aqt-egress-probe" 2>/dev/null && written="$written $dir"; done
say install_writable "${written:-none}"
say env_proxy "$HTTPS_PROXY"
"""


def run_box(env_dir: Path, upstream, script: str = SCRIPT, *args) -> tuple:
    environ = {**os.environ, "OTHER_PORT": str(upstream.http_port), "AQT_TEST_RUNNER_PID": str(os.getpid())}
    environ["AQT_EGRESS_TEST"] = json.dumps({
        "hosts": {"upstream.test": f"127.0.0.1:{upstream.https_port}"}, "upstream_ca": upstream.ca})
    environ["AQT_TEST_INSTALL"] = " ".join(box.installation())
    done = subprocess.run([sys.executable, "-m", "aqt_egress.cli", "run", "--project", str(env_dir), *args, "--",
                           "sh", "-c", script], env=environ, capture_output=True, text=True, timeout=180)
    results = dict(line.split("=", 1) for line in done.stdout.splitlines() if "=" in line)
    return done, results


@pytest.fixture
def trail(env):
    subprocess.run([sys.executable, "-m", "aqt_trail.cli", "init"], check=True, capture_output=True, timeout=60)
    writer = subprocess.Popen([sys.executable, "-m", "aqt_trail.cli", "serve"], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    socket_path = Path(os.environ["XDG_RUNTIME_DIR"]) / "aqt" / "trail.sock"
    deadline = time.monotonic() + 20
    while not socket_path.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert socket_path.exists(), "the trail writer did not start"
    yield Path(os.environ["XDG_STATE_HOME"]) / "aqt" / "trail" / "trail.jsonl"
    writer.terminate()
    writer.wait(10)


@MACOS
def test_macos_box_records_through_the_proxy_and_refuses_everything_else(env, upstream, trail):
    done, results = run_box(env, upstream)
    assert done.returncode == 0, done.stdout + done.stderr
    # through the proxy: works and is recorded with the program that sent it
    assert results["curl"] == "200" and results["python"] == "200", done.stdout + done.stderr
    records = list(read_jsonl(trail))
    [started] = [r["data"] for r in records if r["type"] == "egress.session" and r["action"] == "started"]
    requests = {r["data"].get("path"): r["data"] for r in records
                if r["type"] == "egress.request" and r["action"] == "observed"}
    curl = requests["/from-curl"]
    assert curl["process"]["chain"][0]["comm"] == "curl" and curl["process"]["chain_status"] == "complete"
    assert curl["process"]["chain"][-1]["comm"] in ("sh", "bash", "dash")      # the box's root: sh -c SCRIPT
    assert curl["tls"]["mode"] == "intercepted"
    assert requests["/from-python"]["process"]["chain"][0]["comm"].lower().startswith("python")
    port = int(started["box"]["network"]["listeners"]["proxy"].rsplit(":", 1)[1])
    assert results["env_proxy"] == f"http://127.0.0.1:{port}" and started["box"]["sandbox"] == "seatbelt"
    assert started["box"]["tools"]["sandbox-exec"]["sha256"].startswith("sha256:")
    # around the proxy: nothing leaves, nothing is looked up
    assert results["direct_ip"] == "000" and results["direct_name"] == "000" and results["other_loopback"] == "000"
    assert results["tcp_out"] == "refused:1" and results["udp_dns"] == "refused:1"
    assert results["lookup"].startswith("refused") and results["mdns_socket"] == "refused:1"
    assert results["bind_tcp"] == "refused:1"
    # the AQT folders and the proxy
    assert results["ca_key"] == "hidden" and results["bodies"] == "hidden" and results["runner_signal"] == "no"
    assert results["trail_state"] == "read-only" and results["state_moved"] == "no"
    assert results["trail_link"] == "refused" and results["install_writable"] == "none"
    assert results["project"] == "writable" and results["launchd_job"] == "refused"
    verify = subprocess.run([sys.executable, "-m", "aqt_trail.cli", "verify"], capture_output=True, text=True,
                            timeout=60)
    assert verify.returncode == 0 and verify.stdout.startswith("intact"), verify.stdout + verify.stderr


@MACOS
def test_macos_box_local_endpoint_through_the_proxy_and_no_private_tmp(env, upstream):
    script = (f"curl -sS -o /dev/null -w 'local=%{{http_code}}\\n' http://127.0.0.1:{upstream.http_port}/v1/models; "
              f"curl -sS -o /dev/null -w 'other=%{{http_code}}\\n' http://127.0.0.1:{upstream.https_port}/")
    done, results = run_box(env, upstream, script, "--local-endpoint", f"127.0.0.1:{upstream.http_port}")
    assert done.returncode == 0, done.stdout + done.stderr
    assert results["local"] == "200" and results["other"] == "502"     # the proxy refuses the host's loopback
    done, _ = run_box(env, upstream, "true", "--private-tmp")
    assert done.returncode != 0 and "--private-tmp is not available on macOS" in done.stderr


@MACOS
@pytest.mark.skipif(os.environ.get("GITHUB_ACTIONS") != "true", reason="needs the internet: CI runners only")
def test_macos_box_internet_through_the_proxy_only(env):
    script = ("say() { echo \"$1=$2\"; }; "
              "say proxied \"$(curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/ 2>&1 | tail -1)\"; "
              "say direct \"$(curl -sS -m 20 --noproxy '*' -o /dev/null -w '%{http_code}' https://example.com/ 2>&1"
              " | tail -1)\"")
    done = subprocess.run([sys.executable, "-m", "aqt_egress.cli", "run", "--project", str(env), "--", "sh", "-c",
                           script], capture_output=True, text=True, timeout=180)
    results = dict(line.split("=", 1) for line in done.stdout.splitlines() if "=" in line)
    assert results.get("proxied") == "200" and results.get("direct") == "000", done.stdout + done.stderr
