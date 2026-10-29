"""``aqt-trail``: tamper-evident audit trail, verification, ALCOA++ report and audit-trail review.

Exit codes: 0 ok, 1 check failed or refused, 2 usage or runtime error.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from aqt_evidence import (HumanCheckError, SinkError, actor, detect_agent_context, load_public_key, load_signer,
                          new_id, new_record, require_human, state_dir, subject)

from . import __version__, anchors, importers
from .alcoa import alcoa_report, export_dry_run, render as render_alcoa
from .client import TrailClient, TrailRefused, locked_spool
from .config import load_config, spool_path
from .export import export_bundle, render_html, render_markdown, row, select, verify_bundle
from .review import (ReviewRefused, anchored_seq, build_review, check_worksheet, load_profile, refusal_record,
                     run_review, save_worksheet)
from .server import drain_local_spool, run_service
from .signers import key_file, load_registry, registry_keys
from .state import init_state, open_writer, read_records, service_keys
from .text import printable
from .tsa import load_ca
from .verify import load_lines, signature_status, verify_trail
from .writer import LogBroken, WriterBusy


class CliError(Exception):
    pass


def _out(args, value, text: str | None = None) -> None:
    if args.json:
        print(json.dumps(value, indent=None if isinstance(value, list) else 2, sort_keys=True, default=str))
    else:  # text may carry strings a client wrote: never pass control characters to the terminal
        print(printable(text if text is not None else value, keep_newlines=True))


def _lines(items) -> str:
    """One output line per item; a newline inside an item is escaped, so it cannot fake another line."""
    return "\n".join(printable(item) for item in items)


def _client(config, timeout: float = 5.0) -> TrailClient:
    return TrailClient(config.socket_path, timeout=timeout)


def _service_up(config) -> bool:
    try:
        return bool(_client(config, 2.0).request({"op": "ping"}).get("ok"))
    except SinkError:
        return False


def _default_actor(explicit: str | None) -> dict:
    ident = explicit or os.environ.get("AQT_ACTOR")
    context = detect_agent_context()
    if not ident:
        ident = f"agent:{context.harness}:unknown" if context.is_agent else f"human:{getpass.getuser()}"
    kind = ident.split(":", 1)[0]
    return actor(kind if kind in ("human", "agent", "service") else "human", ident)


def _records(config, path=None) -> list[dict]:
    return read_records(path or config.trail_path)


def _send(config, records, *, timeout=5.0) -> tuple[int, int, list[str]]:
    client, stored, spooled, refused = _client(config, timeout), 0, 0, []
    for record in records:
        try:
            client.append(record)
        except TrailRefused as error:
            refused.append(f"{record.get('id')}: {error}")
            continue
        if client.last_spooled:
            spooled += 1
        else:
            stored += 1
    return stored, spooled, refused


# -- commands ----------------------------------------------------------------------------
def cmd_init(args, config):
    meta = init_state(config, log_id=args.log_id)
    _out(args, {**meta, "state": str(config.state), "socket": str(config.socket_path)},
         f"trail {meta['log_id']} in {config.state}\nservice key {meta['key_id']}\n"
         f"start the writer with: aqt-trail serve   (clients: AQT_SINK=unix:{config.socket_path})")
    return 0


def cmd_serve(args, config):
    return run_service(config)


def cmd_status(args, config):
    up = _service_up(config)
    head = _client(config).request({"op": "head"}) if up else None
    records = _records(config)
    anchors_ = [r for r in records if anchored_seq(r) is not None]
    with locked_spool() as (entries, _clear):
        pending = len(entries)
    value = {"writer": "running" if up else "not running", "socket": str(config.socket_path),
             "records": len(records), "head_seq": records[-1]["chain"]["seq"] if records else None,
             "spooled": pending, "last_anchor": anchors_[-1]["time"] if anchors_ else None}
    if head:
        value["head"] = head.get("head")
    _out(args, value, "\n".join(f"{k}: {v}" for k, v in value.items()))
    return 0


def _read_input(source: str) -> list[dict]:
    raw = sys.stdin.read() if source == "-" else Path(source).read_text()
    raw = raw.strip()
    if not raw:
        return []
    try:
        value = json.loads(raw)
        return value if isinstance(value, list) else [value]
    except ValueError:
        return [json.loads(line) for line in raw.splitlines() if line.strip()]


def cmd_append(args, config):
    records = _read_input(args.file)
    stored, spooled, refused = _send(config, records)
    for line in refused:
        print(f"refused {line}", file=sys.stderr)
    _out(args, {"stored": stored, "spooled": spooled, "refused": len(refused)},
         f"stored {stored}, spooled {spooled}, refused {len(refused)}")
    return 1 if refused else 0


def cmd_event(args, config):
    data = json.loads(args.data) if args.data else None
    sub = None
    if args.subject:
        kind, _, ref = args.subject.partition(":")
        sub = subject(kind, ref or kind)
    record = new_record("trail.event", _default_actor(args.actor), args.action, reason=args.reason, data=data,
                        subject=sub)
    stored, spooled, refused = _send(config, [record])
    if refused:
        print(f"refused {refused[0]}", file=sys.stderr)
        return 1
    _out(args, {"id": record["id"], "spooled": bool(spooled)}, f"{record['id']} {'spooled' if spooled else 'stored'}")
    return 0


def cmd_hook(args, config):
    """Never block the agent: always exit 0; problems go to stderr (and the spool)."""
    try:
        raw = sys.stdin.buffer.read()
        session = importers.claude_hook(raw, excerpt_chars=int(config.section("import")["excerpt_chars"]))
        records, _ = importers.to_records(session)
        for record in records:
            record["id"] = new_id()  # each hook call is one event; no derived id needed
        _, _, refused = _send(config, records, timeout=2.0)
        for line in refused:
            print(f"aqt-trail hook: refused {line}", file=sys.stderr)
    except Exception as error:  # noqa: BLE001 - a hook must not fail the agent
        print(f"aqt-trail hook: {error}", file=sys.stderr)
    return 0


def cmd_import(args, config):
    known = importers.known_source_hashes(_records(config))
    with locked_spool() as (entries, _clear):
        known |= importers.known_source_hashes(entries)
    reader = importers.READERS[args.kind]
    total_new, total_skipped, results = 0, 0, []
    excerpt_chars = int(config.section("import")["excerpt_chars"])
    for path in args.paths:
        session = reader(path, excerpt_chars=excerpt_chars)
        records, skipped = importers.to_records(session, known=known)
        stored = spooled = 0
        refused: list[str] = []
        if not args.dry_run:
            stored, spooled, refused = _send(config, records)
        results.append({"path": str(path), "session": session.id, "new": len(records), "skipped": skipped,
                        "stored": stored, "spooled": spooled, "refused": len(refused)})
        total_new, total_skipped = total_new + len(records), total_skipped + skipped
        for line in refused:
            print(f"refused {line}", file=sys.stderr)
    _out(args, results, "\n".join(f"{r['path']}: session {r['session']}: {r['new']} new, {r['skipped']} already "
                                    f"imported{' (dry run)' if args.dry_run else ''}" for r in results))
    return 1 if any(r["refused"] for r in results) else 0


def _direct(config):
    try:
        return open_writer(config)
    except WriterBusy as error:
        raise CliError(f"{error}, but its socket {config.socket_path} does not answer") from error


def cmd_checkpoint(args, config):
    tsa_url = args.tsa or config.section("anchor").get("tsa_url", "")
    if args.anchor and not tsa_url:
        raise CliError("no TSA configured: set [anchor] tsa_url or pass --tsa URL (test:<dir> for the TEST TSA)")
    if _service_up(config):
        response = _client(config, 30.0).request({"op": "checkpoint", "anchor": args.anchor, "tsa_url": tsa_url})
        if not response.get("ok"):
            raise CliError(response.get("message", "checkpoint failed"))
        point, anchor = response["checkpoint"], response.get("anchor")
    else:
        with _direct(config) as writer:
            point, anchor = anchors.checkpoint(writer, tsa_url=tsa_url if args.anchor else "",
                                               timeout=float(config.section("anchor")["timeout_s"]),
                                               test_dir=config.state / "test-tsa")
    _out(args, {"checkpoint": point, "anchor": anchor["id"] if anchor else None},
         f"checkpoint seq {point['seq']} {point['head']}" + (f"\nanchor {anchor['id']} "
                                                             f"(RFC 3161 {anchor['data']['tsa']['gen_time']})" if anchor else ""))
    return 0


def cmd_head(args, config):
    if _service_up(config):
        if args.export:
            response = _client(config).request({"op": "checkpoint", "export": True})
            print(json.dumps(response["checkpoint"], sort_keys=True))
            return 0
        response = _client(config).request({"op": "head"})
        _out(args, response, f"seq {response['seq']} {response['head']}")
        return 0
    with _direct(config) as writer:
        if args.export:
            point = anchors.current_checkpoint(writer)
            anchors.save_checkpoint(writer, point)
            anchors.record_external_head(writer, point)
            print(json.dumps(point, sort_keys=True))
            return 0
        _out(args, {"log_id": writer.log_id, "seq": writer.seq, "head": writer.head},
             f"seq {writer.seq} {writer.head}")
    return 0


def cmd_drain(args, config):
    if _service_up(config):
        with locked_spool() as (entries, clear):
            if not entries:
                _out(args, {"appended": 0}, "spool is empty")
                return 0
            response = _client(config, 30.0).request({"op": "drain", "records": entries, "source": str(spool_path())})
            if not response.get("ok"):
                raise CliError(response.get("message", "drain failed"))
            clear()
        _out(args, response, f"appended {response['appended']}, already stored {response['already_stored']}, "
                             f"refused {response['refused']}")
        return 0
    with _direct(config) as writer:
        result = drain_local_spool(writer)
    value = {"appended": len(result.appended) if result else 0,
             "already_stored": len(result.already_stored) if result else 0,
             "refused": len(result.refused) if result else 0}
    _out(args, value, f"appended {value['appended']}, already stored {value['already_stored']}, "
                      f"refused {value['refused']}")
    return 0


def _signers(args):
    path = getattr(args, "signers", None)
    return load_registry(path) if path else load_registry()


def _tsa_ca(args, config):
    ca_path = getattr(args, "tsa_ca", None) or config.section("anchor").get("tsa_ca")
    return load_ca(ca_path) if ca_path else None


def _verify(args, config):
    """Verification with the trust anchors from the command line and the configuration, never from the data."""
    pin_key = getattr(args, "pin_key", None)
    if getattr(args, "bundle", None):
        return verify_bundle(args.bundle, heads=getattr(args, "heads", None), pin_key=pin_key,
                             tsa_ca=load_ca(args.tsa_ca) if getattr(args, "tsa_ca", None) else None,
                             signers=_signers(args), test_tsa=bool(getattr(args, "test_tsa", False)))
    if pin_key:
        keys = dict([load_public_key(pin_key)])
    elif getattr(args, "key", None):
        keys = dict(load_public_key(path) for path in args.key)
    else:
        keys = service_keys(config)
    ca = _tsa_ca(args, config)
    if ca is None and (config.state / "test-tsa" / "ca.pem").exists() and getattr(args, "test_tsa", False):
        ca = load_ca(config.state / "test-tsa" / "ca.pem")
    log_id = config.meta()["log_id"] if config.meta_path.exists() else None
    return verify_trail(getattr(args, "trail", None) or config.trail_path, keys=keys,
                        checkpoints=config.checkpoints_path, heads=getattr(args, "heads", None), tsa_ca=ca,
                        signer_keys=registry_keys(_signers(args)), log_id=log_id, pinned=bool(pin_key))


def cmd_verify(args, config):
    report = _verify(args, config)
    text = [report.summary()] + [f"problem: {p}" for p in report.problems] + [f"warning: {w}" for w in report.warnings]
    _out(args, report.as_dict(), _lines(text))
    return 0 if report.ok else 1


def _filters(args) -> dict:
    return {key: getattr(args, key) for key in ("since", "until", "actor", "type", "action", "subject", "session")}


def cmd_list(args, config):
    records = select(_records(config), **_filters(args))
    if args.json:
        for record in records:
            print(json.dumps(record, sort_keys=True))
        return 0
    for record in records:
        values = row(record)
        print(f"{printable(values['seq']):>6} {printable(values['time'])} {printable(values['type']):<16} "
              f"{printable(values['action']):<18} {printable(values['actor'])}"
              + (f"  — {printable(values['reason'])}" if values["reason"] else ""))
    return 0


def cmd_show(args, config):
    for record in _records(config):
        if record["id"] == args.id or str(record["chain"]["seq"]) == args.id:
            print(json.dumps(record, indent=2, sort_keys=True))
            return 0
    raise CliError(f"no record {args.id}")


def cmd_report(args, config):
    records = select(_records(config), **_filters(args))
    summary = _verify(args, config).summary()
    title = f"Audit trail {config.meta()['log_id']}"
    text = (render_html if args.format == "html" else render_markdown)(records, title=title, summary=summary)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_export(args, config):
    path = export_bundle(config, args.out, tar=args.tar)
    print(f"exported {path}")
    return 0


def cmd_alcoa(args, config):
    records = select(_records(config), since=args.since, until=args.until)
    report = _verify(args, config)        # the whole trail, with the same trust options as verify
    params = config.section("review")
    results = alcoa_report(records, report, skew_ms=int(params["skew_ms"]),
                           unanchored_hours=int(params["unanchored_hours"]),
                           export_check=lambda: export_dry_run(config))
    if args.json or args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        sys.stdout.write(render_alcoa(results, "md" if args.format == "md" else "text"))
    return 1 if any(r["status"] == "fail" for r in results) else 0


def _reviews_dir(config, out: str | None) -> Path:
    """``--out``, else ``<state>/reviews`` when writable, else the user's own state directory (separate-user
    mode: the trail's state belongs to the writer's account). Where a worksheet lives does not matter for its
    integrity: signing recomputes it from the trail."""
    if out:
        return Path(out)
    target = config.state / "reviews"
    if os.access(target if target.exists() else config.state, os.W_OK):
        return target
    return state_dir() / "trail-reviews"


def cmd_review_run(args, config):
    profile = load_profile(args.profile, config.section("review"))
    sheet = run_review(_records(config), profile, log_id=config.meta()["log_id"], since=args.since,
                       until=args.until, trail=str(config.trail_path))
    path = save_worksheet(sheet, _reviews_dir(config, args.out))
    counts = {}
    for finding in sheet["findings"]:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    _out(args, {"worksheet": str(path), "id": sheet["id"], "findings": len(sheet["findings"]), "by_severity": counts},
         f"worksheet {path}\n{len(sheet['findings'])} finding(s) {counts}\nread {path.with_suffix('.md')}")
    return 0


def _pairs(values: list[str] | None, label: str) -> dict:
    result = {}
    for value in values or []:
        key, sep, rest = value.partition("=")
        if not sep:
            raise CliError(f"--{label} needs ID=VALUE, got {value!r}")
        result[key.strip()] = rest.strip()
    return result


def _refuse_review(config, reviewer, code, message, markers=None):
    try:
        _send(config, [refusal_record(reviewer, code, message, markers)], timeout=2.0)
    finally:
        print(f"refused: {message}", file=sys.stderr)
    return 1


def _trail_records(config) -> list[dict]:
    """The trail itself, strictly parsed (a review is checked against it, never against a copy)."""
    records, _bad_line = load_lines(config.trail_path) if config.trail_path.exists() else ([], None)
    return records


def _describe(sheet: dict) -> str:
    scope, profile = sheet["scope"], sheet["profile"]
    lines = [f"Signing a review of log {sheet['log_id']}, seq {scope['from_seq']}–{scope['to_seq']} "
             f"({scope['count']} records), period {scope['since'] or 'start'} – {scope['until'] or 'now'}",
             f"profile {profile['name']} ({profile['sha256']}), queries: {', '.join(profile['queries'])}",
             f"actors in scope: {', '.join(sheet['actors_reviewed']) or 'none'}",
             f"{len(sheet['findings'])} finding(s)"]
    lines += [f"  {f['id']} {f['severity']} {f['query']}: {f['explanation']}" for f in sheet["findings"]]
    return _lines(lines)


def cmd_review_sign(args, config):
    try:
        require_human()
    except HumanCheckError as error:
        return _refuse_review(config, args.reviewer, "agent_context", str(error), error.context.markers)
    sheet = json.loads(Path(args.worksheet).read_text())
    records = _trail_records(config)            # never the 'trail' path written in the worksheet
    keys = service_keys(config)
    log_id = config.meta()["log_id"] if config.meta_path.exists() else None
    try:
        fresh = check_worksheet(sheet, records, log_id=log_id, keys=keys)
    except ReviewRefused as refused:
        return _refuse_review(config, args.reviewer, refused.code, refused.message)
    print(_describe(fresh), file=sys.stderr)
    key_path = Path(args.key) if args.key else key_file(args.reviewer)
    if not key_path.exists():
        raise CliError(f"no key at {key_path}; pass --key PEM or enrol the reviewer with aqt-signoff")
    pem = key_path.read_bytes()
    passphrase = None
    if b"ENCRYPTED" in pem:
        passphrase = getpass.getpass(f"Passphrase for {args.reviewer}: ").encode()
    else:
        print("warning: the reviewer key is not passphrase-protected (no re-authentication)", file=sys.stderr)
    try:
        signer = load_signer(key_path, passphrase=passphrase)
    except (ValueError, TypeError) as error:
        return _refuse_review(config, args.reviewer, "auth_failed", f"could not unlock the key: {error}")
    try:
        record = build_review(sheet, records, reviewer_id=args.reviewer, signer=signer,
                              dispositions=_pairs(args.disposition, "disposition"), notes=_pairs(args.note, "note"),
                              reason=args.reason, conclusion=args.conclusion, registry=load_registry(),
                              name=args.name, role=args.role, tz=args.tz or config.section("review")["timezone"],
                              log_id=log_id, keys=keys)
    except ReviewRefused as refused:
        return _refuse_review(config, args.reviewer, refused.code, refused.message)
    except ValueError as error:
        raise CliError(str(error)) from error
    stored, spooled, refused = _send(config, [record])
    if refused:
        print(f"refused {printable(refused[0])}", file=sys.stderr)
        return 1
    _out(args, {"id": record["id"], "spooled": bool(spooled)},
         f"review {record['id']} signed by {args.reviewer} ({'spooled' if spooled else 'stored'})")
    return 0


def cmd_review_list(args, config):
    """Every ``trail.review`` with the state of its signature (only ``valid`` reviews count as signed)."""
    signers = load_registry()
    rows = []
    for record in _records(config):
        if record.get("type") != "trail.review":
            continue
        data = record.get("data") if isinstance(record.get("data"), dict) else {}
        scope = data.get("scope") if isinstance(data.get("scope"), dict) else {}
        status, detail = signature_status(record, signers=signers)
        rows.append({"id": record.get("id"), "time": record.get("time"), "reviewer": row(record)["actor"],
                     "scope": scope, "findings": len(data.get("findings") or []), "signature": status,
                     "detail": detail})
    _out(args, rows, _lines(f"{x['time']} {x['id']} {x['reviewer']} seq {x['scope'].get('from_seq')}–"
                            f"{x['scope'].get('to_seq')} findings {x['findings']} signature {x['signature']}"
                            + (f" ({x['detail']})" if x["detail"] and x["signature"] != "valid" else "")
                            for x in rows) or "no reviews")
    return 0


# -- parser ------------------------------------------------------------------------------
def _add_filters(parser):
    for name in ("since", "until", "actor", "type", "action", "subject", "session"):
        parser.add_argument(f"--{name}")


def build_parser() -> argparse.ArgumentParser:
    def options(suppress: bool) -> argparse.ArgumentParser:
        # Accepted before or after the subcommand; sub-level copies must not reset the top-level values.
        default = {"default": argparse.SUPPRESS} if suppress else {}
        group = argparse.ArgumentParser(add_help=False)
        group.add_argument("--state", help="trail state directory (default $XDG_STATE_HOME/aqt/trail)", **default)
        group.add_argument("--config", help="config TOML (default $XDG_CONFIG_HOME/aqt/trail.toml)", **default)
        group.add_argument("--json", action="store_true", help="machine-readable output", **default)
        return group

    common = options(True)
    parser = argparse.ArgumentParser(prog="aqt-trail", description=__doc__, parents=[options(False)],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name, func, help):
        p = sub.add_parser(name, help=help, parents=[common])
        p.set_defaults(func=func)
        return p

    add("init", cmd_init, "create the state directory and the service key").add_argument("--log-id")
    add("serve", cmd_serve, "run the writer service on the Unix socket")
    add("status", cmd_status, "writer, head, spool and anchor status")
    add("append", cmd_append, "append records (JSON or JSONL) from a file or stdin").add_argument("file", nargs="?", default="-")
    p = add("event", cmd_event, "append a trail.event")
    p.add_argument("--action", required=True)
    p.add_argument("--reason")
    p.add_argument("--subject", help="KIND:REF")
    p.add_argument("--data", help="JSON object")
    p.add_argument("--actor", help="actor id (default $AQT_ACTOR, else detected)")
    add("hook", cmd_hook, "record a Claude Code hook event from stdin (always exits 0)").add_argument(
        "harness", choices=["claude-code"])
    p = add("import", cmd_import, "import agent session files")
    p.add_argument("kind", choices=sorted(importers.READERS))
    p.add_argument("paths", nargs="+")
    p.add_argument("--dry-run", action="store_true")
    p = add("checkpoint", cmd_checkpoint, "sign the head; --anchor adds an RFC 3161 time stamp")
    p.add_argument("--anchor", action="store_true")
    p.add_argument("--tsa", help="TSA URL (overrides config); test:<dir> for the TEST ONLY authority")
    add("head", cmd_head, "print the head; --export prints a signed head to store elsewhere").add_argument(
        "--export", action="store_true")
    add("drain", cmd_drain, "append spooled records now (after a trail.gap marker)")
    p = add("verify", cmd_verify, "verify chain, signatures, checkpoints, anchors and external heads")
    p.add_argument("--trail")
    p.add_argument("--key", action="append", help="service public key PEM (repeatable)")
    p.add_argument("--pin-key", help="accept only this service key")
    p.add_argument("--heads", help="file of exported heads (JSON lines)")
    p.add_argument("--tsa-ca", help="PEM with the TSA's CA certificate(s)")
    p.add_argument("--test-tsa", action="store_true", help="trust the local TEST ONLY authority's CA")
    p.add_argument("--bundle", help="verify an export bundle directory (its own CA and signer files are not trusted)")
    p.add_argument("--signers", help="signer registry to trust (default: $AQT_SIGNERS or the shared signers.json)")
    _add_filters(add("list", cmd_list, "list records"))
    add("show", cmd_show, "show one record by id or seq").add_argument("id")
    p = add("report", cmd_report, "Markdown or HTML record view")
    p.add_argument("--format", choices=["md", "html"], default="md")
    p.add_argument("--out")
    _add_filters(p)
    p = add("export", cmd_export, "write a verification bundle")
    p.add_argument("--out", required=True)
    p.add_argument("--tar", action="store_true")
    p = add("alcoa", cmd_alcoa, "ALCOA++ report (exit 1 if an attribute fails)")
    p.add_argument("--since")
    p.add_argument("--until")
    p.add_argument("--format", choices=["text", "md", "json"], default="text")
    p.add_argument("--test-tsa", action="store_true", help="trust the local TEST ONLY authority's CA")
    p.add_argument("--key", action="append", help="service public key PEM (repeatable)")
    p.add_argument("--pin-key", help="accept only this service key")
    p.add_argument("--heads", help="file of exported heads (JSON lines)")
    p.add_argument("--tsa-ca", help="PEM with the TSA's CA certificate(s)")
    p.add_argument("--signers", help="signer registry to trust (default: the shared signers.json)")
    review = sub.add_parser("review", help="audit-trail review").add_subparsers(dest="review", required=True)
    p = review.add_parser("run", help="run risk queries and write a worksheet", parents=[common])
    p.set_defaults(func=cmd_review_run)
    p.add_argument("--since")
    p.add_argument("--until")
    p.add_argument("--profile", default="default")
    p.add_argument("--out", help="folder for the worksheet (default <state>/reviews, or your own state folder "
                                 "when that is not writable)")
    p = review.add_parser("sign", help="sign a worksheet as an independent human reviewer", parents=[common])
    p.set_defaults(func=cmd_review_sign)
    p.add_argument("worksheet")
    p.add_argument("--reviewer", required=True, help="human:<id>")
    p.add_argument("--key", help="reviewer private key PEM (default: the shared key directory)")
    p.add_argument("--disposition", action="append", help="F1=ok|explained|deviation, or all=ok")
    p.add_argument("--note", action="append", help="F1=text (needed for explained and deviation)")
    p.add_argument("--reason", required=True)
    p.add_argument("--conclusion", default="audit trail reviewed; dispositions as listed")
    p.add_argument("--name")
    p.add_argument("--role")
    p.add_argument("--tz")
    p = review.add_parser("list", help="list signed reviews", parents=[common])
    p.set_defaults(func=cmd_review_list)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config, state=args.state)
        return args.func(args, config)
    except (CliError, FileNotFoundError, FileExistsError, importers.ImportError_, SinkError, WriterBusy, LogBroken,
            ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
