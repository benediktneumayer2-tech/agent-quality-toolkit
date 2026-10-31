"""``aqt egress report``: who talked to whom, per session, destination and process.

Destinations are where the proxy connected; a different Host header or TLS server name the client
claimed is counted as ``claimed_other``. Only records the trail writer observed coming from the
session's own proxy process count: an ``egress.*`` record of a session sent by another process (for
example from inside the box, through the trail socket) is listed as ``unverified`` and left out.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from aqt_evidence import iter_evidence

TYPES = ("egress.session", "egress.request", "egress.lookup")


def parse_since(text: str, *, now: datetime | None = None) -> str:
    """``7d``, ``24h``, ``30m`` or an ISO date/time -> RFC 3339 UTC lower bound."""
    now = now or datetime.now(UTC)
    match = re.fullmatch(r"(\d+)([dhm])", text.strip())
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        moment = now - timedelta(**{{"d": "days", "h": "hours", "m": "minutes"}[unit]: amount})
    else:
        try:
            moment = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"--since takes 7d, 24h, 30m or a date such as 2026-10-31, not {text!r}") from None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def chain_text(process: dict | None) -> str:
    chain = (process or {}).get("chain") or []
    if not chain:
        return f"(unattributed: {(process or {}).get('chain_detail', 'unknown')})"
    return " < ".join(entry.get("comm", "?") for entry in chain)


def _sender(record: dict):
    return (record.get("observed") or {}).get("pid")


def build(records, *, session: str | None = None, since: str | None = None) -> dict:
    records = [record for record in records if record.get("type") in TYPES]
    launchers = {record["data"].get("session"): _sender(record) for record in records
                 if record["type"] == "egress.session" and record.get("action") == "started"
                 and isinstance(record.get("data"), dict)}
    unverified: dict[str, list] = {}
    kept = []
    for record in records:
        sid = (record.get("data") or {}).get("session")
        launcher, sender = launchers.get(sid), _sender(record)
        if (launcher and sender and sender != launcher) or record.get("actor", {}).get("id") != "service:aqt-egress":
            unverified.setdefault(sid, []).append({"id": record.get("id"), "type": record.get("type"),
                                                   "sender_pid": sender})
        else:
            kept.append(record)
    records = kept
    opened = {record["id"]: record for record in records
              if record["type"] == "egress.request" and record.get("action") == "opened"}
    completed = {link.get("ref") for record in records if record.get("action") == "observed"
                 for link in record.get("links") or [] if link.get("rel") == "opened"}
    first_seen: dict[str, str] = {}
    for record in records:
        if record["type"] == "egress.request" and record.get("action") != "opened":
            dest = record.get("data", {}).get("destination", {})
            key = f"{dest.get('host')}:{dest.get('port')}"
            if key not in first_seen or record["time"] < first_seen[key]:
                first_seen[key] = record["time"]
    sessions: dict[str, dict] = {}

    def entry(sid: str) -> dict:
        return sessions.setdefault(sid, {"session": sid, "requests": 0, "destinations": {}, "lookups": [],
                                         "unverified": unverified.get(sid, []), "unfinished": 0})

    for record in records:
        data = record.get("data", {})
        sid = data.get("session")
        if not sid:
            continue
        item = entry(sid)
        if record["type"] == "egress.session":
            if record.get("action") == "started":
                item.update(started=record["time"], command=data.get("command"), store=data.get("store"),
                            project=(data.get("project") or {}).get("path"))
            elif record.get("action") == "ended":
                item.update(ended=record["time"], exit_code=data.get("exit_code"))
        elif record["type"] == "egress.request" and record.get("action") == "opened":
            item["unfinished"] += 0 if record["id"] in completed else 1
        elif record["type"] == "egress.lookup":
            item["lookups"].append({"name": data.get("name"), "types": data.get("types", []),
                                    "count": data.get("count", 1), "process": chain_text(data.get("process"))})
        else:
            item["requests"] += 1
            dest = data.get("destination", {})
            key = f"{dest.get('host')}:{dest.get('port')}"
            target = item["destinations"].setdefault(key, {
                "host": dest.get("host"), "port": dest.get("port"), "requests": 0, "methods": {}, "bytes_up": 0,
                "bytes_down": 0, "processes": {}, "statuses": {}, "errors": 0, "refused": 0, "via": [],
                "claimed_other": 0, "first_time": record["time"]})
            target["claimed_other"] += 1 if dest.get("host_header") else 0
            target["requests"] += 1
            method = data.get("method") or data.get("protocol") or "?"
            target["methods"][method] = target["methods"].get(method, 0) + 1
            target["bytes_up"] += (data.get("request") or {}).get("bytes", 0)
            target["bytes_down"] += (data.get("response") or {}).get("bytes", 0)
            chain = chain_text(data.get("process"))
            target["processes"][chain] = target["processes"].get(chain, 0) + 1
            status = (data.get("response") or {}).get("status")
            if status is not None:
                target["statuses"][str(status)] = target["statuses"].get(str(status), 0) + 1
            target["errors"] += 1 if data.get("error") else 0
            target["refused"] += 1 if data.get("decision") == "refused" else 0
            if dest.get("via") and dest["via"] not in target["via"]:
                target["via"].append(dest["via"])
            target["first_time"] = min(target["first_time"], record["time"])
    result = []
    for item in sessions.values():
        if session and not item["session"].startswith(session):
            continue
        if since and (item.get("started") or "") < since:
            continue
        for key, target in item["destinations"].items():
            target["new"] = first_seen.get(key) == target.pop("first_time")
        item["destinations"] = sorted(item["destinations"].values(),
                                      key=lambda dest: (-dest["requests"], str(dest["host"])))
        result.append(item)
    result.sort(key=lambda item: item.get("started") or "")
    return {"sessions": result}


def load(paths=None) -> list[dict]:
    return [record for record in iter_evidence(paths) if isinstance(record, dict)]


def _size(count: int) -> str:
    for unit in ("B", "kB", "MB", "GB"):
        if count < 1000 or unit == "GB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1000
    return str(count)


def render(report: dict) -> str:
    if not report["sessions"]:
        return "no egress sessions in the evidence"
    lines = []
    for item in report["sessions"]:
        command = " ".join(item.get("command") or ["?"])
        when = f"{(item.get('started') or '?')[:19]} -> {(item.get('ended') or 'no end')[:19]}"
        lines.append(f"session {item['session']}  {when}  exit {item.get('exit_code', '-')}  "
                     f"{item['requests']} request(s)  store {item.get('store', '?')}")
        lines.append(f"  command: {command}")
        for dest in item["destinations"]:
            methods = " ".join(f"{name}x{count}" for name, count in sorted(dest["methods"].items()))
            flags = [flag for flag, on in (("NEW", dest["new"]), (f"{dest['errors']} error(s)", dest["errors"]),
                                          (f"{dest['refused']} refused", dest["refused"]),
                                          (f"{dest['claimed_other']} claimed another host", dest["claimed_other"]))
                     if on]
            lines.append(f"  {dest['host']}:{dest['port']}  {dest['requests']} req  {methods}  "
                         f"up {_size(dest['bytes_up'])} / down {_size(dest['bytes_down'])}"
                         + (f"  [{', '.join(flags)}]" if flags else ""))
            for chain, count in sorted(dest["processes"].items(), key=lambda pair: -pair[1]):
                lines.append(f"      {count}x  {chain}")
        if item.get("started") and not item.get("ended"):
            lines.append("  no end record: still running, or the proxy stopped before it could write one")
        if item["unfinished"]:
            lines.append(f"  {item['unfinished']} connection(s) opened without a completing record")
        if item["unverified"]:
            lines.append(f"  {len(item['unverified'])} record(s) not from this session's proxy process, left out: "
                         + ", ".join(entry["id"] or "?" for entry in item["unverified"][:5]))
        if item["lookups"]:
            lines.append("  name lookups without a request:")
            for lookup in item["lookups"]:
                lines.append(f"      {lookup['name']}  {'/'.join(lookup['types'])}  {lookup['count']}x  "
                             f"{lookup['process']}")
        lines.append("")
    return "\n".join(lines).rstrip()
