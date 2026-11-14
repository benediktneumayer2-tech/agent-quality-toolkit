"""Set up the box's network from the host and open the proxy's listeners inside it.

Run as ``python -m aqt_egress.netns USERNS_FD NETNS_FD CHANNEL_FD [PORT ...]`` by the launcher, before the
boxed command starts. It joins the user namespace that owns the box's network namespace (the
user owns it, so this needs no privileges on the host), then that network namespace, and:

1. waits until bubblewrap has brought the loopback interface up;
2. loads an nftables table that sends every TCP connection to a non-local address to the
   transparent listener, every UDP query to port 53 to the resolver, and drops all other
   traffic to non-local addresses (where nftables or iproute2 is missing this step fails and
   is reported: such connections then fail with "network unreachable");
3. adds a box address and default routes over loopback, so that such connections reach the
   redirect instead of failing at once;
4. creates and binds the listening sockets and sends them to the launcher over CHANNEL_FD
   (SCM_RIGHTS), with a JSON summary. It then exits: no process of ours stays inside the box.

Each PORT is a configured local inference endpoint: the box gets a listener on its own loopback at
that port (IPv4 and IPv6), which the proxy forwards to the endpoint on the host.

The sockets belong to the box's network namespace, but the proxy on the host accepts on them.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import time

try:
    import fcntl          # Linux: the box's network (box.unsupported() says why not elsewhere)
except ImportError:
    fcntl = None

PROXY_PORT = 3128          # HTTP_PROXY / HTTPS_PROXY / ALL_PROXY (127.0.0.1)
REDIRECT_PORT = 15001      # TCP redirected by nftables (original destination via SO_ORIGINAL_DST)
DIRECT_PORTS = (80, 443)   # clients that ignore the proxy variables and follow the resolver's answer
DNS_PORT = 53
BOX_ADDRESS = "192.0.2.1"  # TEST-NET-1: source address for redirected connections
NS_GET_USERNS = 0xB701
SIOCGIFFLAGS = 0x8913
IFF_UP = 0x1

RULES = f"""table inet aqt_egress {{
    chain nat_out {{
        type nat hook output priority -100; policy accept;
        fib daddr type local return
        meta l4proto tcp redirect to :{REDIRECT_PORT}
        udp dport {DNS_PORT} redirect to :{DNS_PORT}
    }}
    chain filter_out {{
        type filter hook output priority 0; policy accept;
        fib daddr type local accept
        drop
    }}
}}
"""



SYSTEM_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")


def system_tool(name: str) -> str | None:
    """``name`` from a system folder only, never from PATH: the file and its folder must belong to root
    and be writable by nobody else (the box shares the user's files, so a tool in a folder the user can
    write could have been replaced by an earlier session)."""
    for folder in SYSTEM_DIRS:
        path = os.path.join(folder, name)
        try:
            info, parent = os.stat(path), os.stat(os.path.realpath(os.path.dirname(os.path.realpath(path))))
            real = os.stat(os.path.realpath(path))
        except OSError:
            continue
        if all(item.st_uid == 0 and not item.st_mode & 0o022 for item in (info, real, parent)) \
                and os.access(path, os.X_OK):
            return path
    return None




def _run(argv: list[str], text: str | None = None) -> str | None:
    """None on success, else the error."""
    try:
        done = subprocess.run(argv, input=text, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        return str(error)
    return None if done.returncode == 0 else (done.stderr.strip() or f"exit {done.returncode}")


def _lo_up(timeout: float = 3.0) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raw = fcntl.ioctl(probe.fileno(), SIOCGIFFLAGS, struct.pack("16sH14x", b"lo", 0))
            if struct.unpack("16sH14x", raw)[1] & IFF_UP:
                return True
            time.sleep(0.01)
        return False
    finally:
        probe.close()


def _ipv6() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
            probe.bind(("::1", 0))
        return True
    except OSError:
        return False


def _tcp(port: int, *, any_address: bool, ipv6: bool) -> socket.socket:
    if any_address and ipv6:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        address = ("::", port)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        address = ("0.0.0.0" if any_address else "127.0.0.1", port)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(address)
    sock.listen(512)
    return sock


def _udp(port: int, *, ipv6: bool) -> socket.socket:
    """Bound to the loopback address itself, not a wildcard: answers then leave from the address the
    redirect sent the query to, so the kernel turns their source back into the server the client asked."""
    sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("::1" if ipv6 else "127.0.0.1", port))
    return sock


def setup(local_ports: list[int] = (), tools: tuple = (None, None)) -> tuple[dict, dict[str, socket.socket]]:
    facts: dict = {"loopback": _lo_up()}
    ipv6 = facts["ipv6"] = _ipv6()
    nft, ip = tools
    if not nft or not ip:
        facts["redirect"] = False
        facts["redirect_error"] = "nft and ip (iproute2) are needed for the redirect; not found"
    else:
        error = _run([nft, "-f", "-"], RULES)
        if error is None:
            try:   # what the kernel holds now, as evidence (not what was meant to be loaded)
                facts["nft_table"] = subprocess.run([nft, "list", "table", "inet", "aqt_egress"], capture_output=True,
                                                    text=True, timeout=10).stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                pass
            for argv in ([ip, "addr", "add", f"{BOX_ADDRESS}/32", "dev", "lo"],
                         [ip, "route", "add", "default", "dev", "lo", "src", BOX_ADDRESS],
                         *([[ip, "-6", "route", "add", "default", "dev", "lo"]] if ipv6 else [])):
                error = error or _run(argv)
        facts["redirect"] = error is None
        if error:
            facts["redirect_error"] = error
    sockets = {
        "proxy": _tcp(PROXY_PORT, any_address=False, ipv6=ipv6),
        "redirect": _tcp(REDIRECT_PORT, any_address=True, ipv6=ipv6),
        **{f"direct{port}": _tcp(port, any_address=True, ipv6=ipv6) for port in DIRECT_PORTS},
        "dns": _udp(DNS_PORT, ipv6=False),
        **({"dns6": _udp(DNS_PORT, ipv6=True)} if ipv6 else {}),
    }
    for port in local_ports:
        sockets[f"local4:{port}"] = _tcp(port, any_address=False, ipv6=False)
        if ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("::1", port))
            sock.listen(512)
            sockets[f"local6:{port}"] = sock
    facts["sockets"] = list(sockets)
    facts["listeners"] = {"proxy": f"127.0.0.1:{PROXY_PORT}", "redirect": REDIRECT_PORT,
                          "direct": list(DIRECT_PORTS), "dns": DNS_PORT}
    return facts, sockets


def main(argv: list[str]) -> int:
    userns, netns, channel, *ports = (int(value) for value in argv)
    chan = socket.socket(fileno=channel)
    # found before joining: in the box's user namespace root's files belong to nobody
    tools = (system_tool("nft"), system_tool("ip"))
    try:
        os.setns(userns, os.CLONE_NEWUSER)
        os.setns(netns, os.CLONE_NEWNET)
        facts, sockets = setup(ports, tools)
    except Exception as error:  # noqa: BLE001 - reported to the launcher
        chan.sendall(json.dumps({"error": f"{type(error).__name__}: {error}"}).encode())
        return 1
    socket.send_fds(chan, [json.dumps(facts).encode()], [sock.fileno() for sock in sockets.values()])
    return 0


def userns_of(netns_fd: int) -> int:
    """The user namespace that owns a network namespace (ioctl NS_GET_USERNS)."""
    return fcntl.ioctl(netns_fd, NS_GET_USERNS)


def open_listeners(init_pid: int, *, local_ports=(), proc: str = "/proc") -> tuple[dict, dict[str, socket.socket]]:
    """Launcher side: run the helper for the box whose first process is ``init_pid``."""
    netns = os.open(f"{proc}/{init_pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    userns = userns_of(netns)
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        done = subprocess.run([sys.executable, "-I", "-m", "aqt_egress.netns", str(userns), str(netns),
                               str(theirs.fileno()), *map(str, local_ports)], pass_fds=(userns, netns, theirs.fileno()),
                              capture_output=True, text=True, timeout=30,
                              env={key: value for key, value in os.environ.items() if key in ("PATH", "LANG")})
        theirs.close()
        ours.settimeout(1)
        try:
            message, fds, _flags, _addr = socket.recv_fds(ours, 65536, 16 + 2 * len(local_ports))
        except OSError:
            raise OSError(f"could not set up the box network: {done.stderr.strip() or 'no answer'}") from None
    finally:
        os.close(netns)
        os.close(userns)
        ours.close()
    facts = json.loads(message or b"{}")
    names = facts.pop("sockets", [])
    if "error" in facts or len(fds) != len(names):
        for fd in fds:
            os.close(fd)
        raise OSError(f"could not set up the box network: {facts.get('error') or done.stderr.strip()}")
    return facts, {name: socket.socket(fileno=fd) for name, fd in zip(names, fds)}


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
