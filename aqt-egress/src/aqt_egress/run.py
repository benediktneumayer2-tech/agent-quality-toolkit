"""``aqt egress run``: start the box, open the listeners in it, serve them, record the session."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from aqt_evidence import new_id, resolve_sink
from aqt_evidence import platform as aqt_platform

from .attribution import Box, MacBox
from .box import BoxProcess, box_environment, write_public
from .mask import load_key, masked_argv
from .netns import open_listeners
from .proxy import Egress, ensure_ca, host_addresses, make_master, serve_listeners
from .records import RecordWriter, drain_spool
from .resolver import Lookups, ResolverProtocol, UNCLAIMED_S
from .settings import Settings, egress_state, private_dir, project_settings
from .store import BodyStore

LAST_SESSION = "last-session.json"
POLICY_VERSION = "none"          # stage 6 observes only; the task policy comes in a later stage


def _test_options() -> dict:
    """``AQT_EGRESS_TEST`` (JSON, tests only): ``hosts`` (``name[:port]`` -> ``host[:port]``), ``allow_loopback``
    (the proxy may reach a test server on the host's loopback), ``upstream_ca`` (the test server's CA)."""
    raw = os.environ.get("AQT_EGRESS_TEST")
    return json.loads(raw) if raw else {}


def host_listener() -> tuple[dict, dict[str, socket.socket]]:
    """macOS: the proxy's listener on a free port of the host's loopback (the only port the box may reach)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(512)
    port = sock.getsockname()[1]
    return ({"redirect": False, "sandbox": "seatbelt", "listeners": {"proxy": f"127.0.0.1:{port}"},
             "dns": "no resolver in the box: the proxy resolves the names it is asked for"}, {"proxy": sock})


def _log_to(path: Path):
    handler = logging.FileHandler(path)
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    for name, level in (("mitmproxy", logging.WARNING), ("aqt_egress", logging.INFO)):
        logger = logging.getLogger(name)       # never onto the boxed command's terminal
        logger.handlers[:] = [handler]
        logger.setLevel(level)
        logger.propagate = False
    return logging.getLogger("aqt_egress").warning


class Terminated(SystemExit):
    """SIGTERM or SIGHUP before the proxy took over the signals: end the box, then exit."""


def _terminate(signum, _frame):
    raise Terminated(128 + signum)


def run(command: list[str], *, project: Path, settings: Settings, private_tmp: bool = False, say=print) -> int:
    if not command:
        raise ValueError("no command given (aqt egress run -- COMMAND ...)")
    # from the start: a SIGTERM/SIGHUP while the box is being set up ends the box (the except below),
    # instead of killing this process with no cleanup
    previous = {signum: signal.signal(signum, _terminate) for signum in (signal.SIGTERM, signal.SIGHUP)}
    try:
        return _run(command, project=project, settings=settings, private_tmp=private_tmp, say=say)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _run(command: list[str], *, project: Path, settings: Settings, private_tmp: bool, say) -> int:
    project = project.resolve()
    facts_project = project_settings(project)
    session = "egs_" + new_id()[4:]
    state = private_dir(egress_state())
    ca_dir = private_dir(state / "ca")
    session_dir = private_dir(private_dir(state / "sessions") / session)
    ca_cert, ca_fingerprint = ensure_ca(ca_dir)
    key = load_key(state / "fingerprint.key")
    public = write_public(session_dir / "public", ca_cert)
    log = _log_to(session_dir / "proxy.log")
    route = resolve_sink()
    if route.get("warning"):
        say(f"aqt-egress: {route['warning']}", file=sys.stderr)
    store = BodyStore(state / "bodies").ensure() if settings.store == "full" else None
    test = _test_options()
    if test:
        say(f"aqt-egress: test options in effect ({', '.join(sorted(test))}); this session's records say so",
            file=sys.stderr)

    if aqt_platform.IS_MACOS:                      # the listener first: the box's profile names its port
        net, sockets = host_listener()
        port = sockets["proxy"].getsockname()[1]
        environ = box_environment(os.environ, session, port=port, public=public)
        try:
            box = BoxProcess(command, project=project, public=public, env=environ, private_tmp=private_tmp,
                             port=port, profile_path=session_dir / "box.sb")
        except BaseException:
            sockets["proxy"].close()
            raise
    else:
        environ = box_environment(os.environ, session)
        if private_tmp and environ.get("TMPDIR", "").startswith("/tmp/"):
            environ["TMPDIR"] = "/tmp"             # the host's folder under /tmp is not in the box
        box = BoxProcess(command, project=project, public=public, env=environ, private_tmp=private_tmp)
    try:                                           # until the box is released, any failure ends it
        if aqt_platform.IS_MACOS:
            attribution = MacBox(box.init_pid)
        else:
            net, sockets = open_listeners(box.init_pid, local_ports=[port for _ip, port in settings.local_endpoints])
            attribution = Box(box.init_pid)
        writer = RecordWriter(log=log)
        drained = drain_spool(writer.sink)
        started = time.time()
        session_data = {
            "session": session, "command": masked_argv(command, limit=32), "project": facts_project,
            "mode": "observe", "store": settings.store, "excerpt_chars": settings.excerpt_chars,
            "retention_days": settings.retention_days if settings.retention_days is not None else "forever",
            "ca_fingerprint": ca_fingerprint, "policy_version": POLICY_VERSION,
            "llm_hosts": settings.llm_hosts, "local_endpoints": [f"{ip}:{port}" for ip, port in settings.local_endpoints],
            "box": {**box.facts, "network": net, "init_pid": box.init_pid},
            "test_options": sorted(test) or None, "spool_drained": drained.get("drained") or None,
        }
        if not net.get("redirect") and not aqt_platform.IS_MACOS:
            say("aqt-egress: no nftables redirect in the box "
                f"({net.get('redirect_error', 'unavailable')}); only proxy-aware clients and ports 80/443 work",
                file=sys.stderr)
        session_record = writer.record("egress.session", "started", {k: v for k, v in session_data.items()
                                                                     if v is not None},
                                       subject={"kind": "egress.session", "ref": session})
        writer.append_now(session_record)
        lookups = Lookups()
        addon = Egress(session=session, session_record=session_record["id"], writer=writer, settings=settings,
                       key=key, attribute=attribution.attribute, lookups=lookups, store=store,
                       test_hosts=test.get("hosts"), allow_loopback=bool(test.get("allow_loopback")),
                       own_addresses=host_addresses())
    except BaseException:
        box.kill()
        raise
    outcome: dict = {}
    try:
        code = asyncio.run(_serve(box, sockets, addon, ca_dir, test.get("upstream_ca"), log, outcome))
    finally:
        for sock in sockets.values():
            sock.close()
        if box.process.poll() is None:
            box.kill()
    addon.flush_lookups(older_than=0)
    writer.close()                                 # everything queued is written (or counted as lost) first
    ended = {"session": session, "exit_code": code, "duration_ms": int((time.time() - started) * 1000),
             "counts": {**addon.counts, "lookups": lookups.total},
             "records": {**writer.routes, "failed": writer.failed}}
    if outcome.get("proxy_stopped"):
        ended["proxy_stopped"] = outcome["proxy_stopped"]
    writer.append_now(writer.record("egress.session", "ended", ended, subject={"kind": "egress.session", "ref": session},
                                    links=[{"rel": "session", "ref": session_record["id"]}]))
    drain_spool(writer.sink)
    writer.report()
    summary = {"session": session, "command": session_data["command"], "project": str(project),
               "started": _iso(started), "ended": _iso(time.time()), "exit_code": code,
               "requests": addon.counts["requests"], "store": settings.store,
               "records_failed": writer.failed}
    (state / LAST_SESSION).write_text(json.dumps(summary, indent=2) + "\n")
    os.chmod(state / LAST_SESSION, 0o600)
    return code


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _serve(box: BoxProcess, sockets: dict, addon: Egress, ca_dir: Path, upstream_ca, log,
                 outcome: dict) -> int:
    loop = asyncio.get_running_loop()
    master = make_master(ca_dir, addon, upstream_ca=upstream_ca)
    running = asyncio.create_task(master.run())
    await asyncio.sleep(0)
    servers = await serve_listeners(master, addon, sockets)
    transports = [(await loop.create_datagram_endpoint(lambda: ResolverProtocol(addon.on_lookup), sock=sockets[name]))[0]
                  for name in ("dns", "dns6") if name in sockets]
    loop.add_signal_handler(signal.SIGINT, lambda: None)        # the terminal's Ctrl-C is for the boxed command
    for signum in (signal.SIGTERM, signal.SIGHUP):
        loop.add_signal_handler(signum, box.process.terminate)

    async def flush():
        while True:
            await asyncio.sleep(UNCLAIMED_S / 3)
            addon.flush_lookups(UNCLAIMED_S)
            addon.refresh_addresses(await loop.run_in_executor(None, host_addresses))   # a VPN may have come up

    flusher = asyncio.create_task(flush())
    box.release()
    waiting = asyncio.ensure_future(loop.run_in_executor(None, box.process.wait))
    await asyncio.wait({waiting, running}, return_when=asyncio.FIRST_COMPLETED)
    if not waiting.done():                     # the proxy ended before the box: end the box, and say why
        error = running.exception() if not running.cancelled() else None
        outcome["proxy_stopped"] = f"{type(error).__name__}: {error}" if error else "the proxy stopped"
        log(f"proxy stopped early: {outcome['proxy_stopped']}")
        box.process.terminate()
    code = await waiting
    deadline = time.monotonic() + 2.0          # let the hooks of connections that just closed finish
    while addon.conns and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    flusher.cancel()
    for server in servers:
        server.close()
    for transport in transports:
        transport.close()
    master.shutdown()
    try:
        if not running.done():
            await asyncio.wait_for(running, 5)
    except (asyncio.TimeoutError, Exception) as error:  # noqa: BLE001 - shutting down anyway
        log(f"proxy shutdown: {error!r}")
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        loop.remove_signal_handler(signum)
    return code
