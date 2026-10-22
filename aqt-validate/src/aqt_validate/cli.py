"""Command line: ``aqt-validate``. Exit 0 ok / meets / valid, 1 check failed, 2 usage or runtime error."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from aqt_evidence import HumanCheckError, SinkError

from . import __version__, evidence
from .adapters import AdapterError, available_plugins
from .config import get_sink, human_id, invoking_actor, load_config, records, validate_state_dir
from .data import DataError, compose, read_items, stats, write_items
from .decisions import DecisionError, check, qualify
from .detector import RunRefused, run_detector
from .loaders import FORMATS, load
from .protocol import ProtocolError, configuration_hash, load_protocol, template
from .reviewer import GitError, build_cases, run_reviewer
from aqt_evidence import actor as make_actor

ERRORS = (DataError, ProtocolError, RunRefused, AdapterError, GitError, DecisionError, HumanCheckError, SinkError,
          OSError)


def _out(args, payload: dict, text: str) -> None:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aqt-validate", description="Validation of AI controls: detector "
                                     "calibration and AI reviewer qualification with evidence records.")
    parser.add_argument("--version", action="version", version=f"aqt-validate {__version__}")
    parser.add_argument("--json", action="store_true", help="machine-readable output (before or after the subcommand)")
    common = argparse.ArgumentParser(add_help=False)
    # SUPPRESS: a --json given after the subcommand sets it; otherwise the top-level value stays
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable output")
    common.add_argument("--config", help="config TOML (default $XDG_CONFIG_HOME/aqt/validate.toml)")
    common.add_argument("--state-dir", help="state directory (default $XDG_STATE_HOME/aqt/validate)")
    common.add_argument("--sink", help="evidence sink: file:/path.jsonl or unix:/path.sock (default AQT_SINK)")
    common.add_argument("--evidence", action="append", help="evidence JSONL to read (repeatable)")
    sub = parser.add_subparsers(dest="command", required=True)

    data = sub.add_parser("data", help="datasets").add_subparsers(dest="action", required=True)
    p = data.add_parser("import", parents=[common], help="convert a benchmark to generic JSONL")
    p.add_argument("src")
    p.add_argument("--format", required=True, choices=FORMATS)
    p.add_argument("--out", required=True)
    p.add_argument("--what", choices=("attacks", "benign"), default="attacks")
    p.add_argument("--dataset-version", default="unknown", help="benchmark version or commit")
    p.add_argument("--license", default="MIT")
    p.add_argument("--seed", type=int, default=36)
    p.add_argument("--templates-per-goal", type=int, default=2, help="AgentDojo: templates per goal (0 = all)")
    p = data.add_parser("compose", parents=[common], help="embed attack payloads into benign host items")
    p.add_argument("--hosts", required=True)
    p.add_argument("--attacks", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--seed", type=int, default=36)
    p.add_argument("--per-payload", type=int, default=1)
    p = data.add_parser("stats", parents=[common], help="counts by label, family, category and split")
    p.add_argument("files", nargs="+")

    proto = sub.add_parser("protocol", help="validation protocols").add_subparsers(dest="action", required=True)
    p = proto.add_parser("init", parents=[common], help="print an annotated protocol template")
    p.add_argument("--kind", choices=("detector", "reviewer"), required=True)
    p.add_argument("--out", help="write to this file instead of stdout")
    p = proto.add_parser("lock", parents=[common], help="record the protocol hash before the test readout")
    p.add_argument("protocol")
    p.add_argument("--reason", required=True)

    det = sub.add_parser("detector", help="detector validation").add_subparsers(dest="action", required=True)
    p = det.add_parser("run", parents=[common], help="calibrate and validate detectors")
    p.add_argument("protocol")
    p.add_argument("--split", choices=("dev", "test"), default="test")
    p.add_argument("--out", help="run directory (default under the state directory)")
    det.add_parser("plugins", parents=[common], help="list detector plugins (entry points aqt.detectors)")

    rev = sub.add_parser("reviewer", help="AI reviewer qualification").add_subparsers(dest="action", required=True)
    p = rev.add_parser("build-cases", parents=[common], help="seeded defects and clean diffs from git history")
    p.add_argument("--repo", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--since")
    p.add_argument("--max", type=int, default=50, dest="max_cases")
    p.add_argument("--max-clean", type=int)
    p.add_argument("--max-lines", type=int, default=40)
    p.add_argument("--fix-pattern")
    p.add_argument("--clean-pattern")
    p.add_argument("--defects", help="folder of user-supplied seeded defects (*.json + diff)")
    p = rev.add_parser("run", parents=[common], help="run the reviewer on the cases and score it")
    p.add_argument("protocol")
    p.add_argument("--split", choices=("dev", "test"), default="test", help="dev = trial on a few cases, no lock")
    p.add_argument("--limit", type=int, help="dev trial: number of cases (default 3)")
    p.add_argument("--retry-errors", action="store_true", help="rerun cached failed runs")
    p.add_argument("--out")

    p = sub.add_parser("report", parents=[common], help="print a run's report")
    p.add_argument("run_dir")
    p.add_argument("--format", choices=("md", "html"), default="md")

    p = sub.add_parser("qualify", parents=[common], help="human decision on a test run (approve or reject)")
    p.add_argument("run_dir")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--approve", action="store_true")
    group.add_argument("--reject", action="store_true")
    p.add_argument("--reason", required=True)
    p.add_argument("--valid-days", type=int)
    p.add_argument("--accept-deviation", action="store_true",
                   help="approve although the conclusion is not 'meets' (the reason must justify it)")

    p = sub.add_parser("check", parents=[common], help="is the last qualification still valid?")
    p.add_argument("--protocol", required=True, help="the protocol describing the current configuration")
    p.add_argument("--thresholds", help="the thresholds file in use")
    p.add_argument("--observed-fp", help="observed benign false positives as K/N (drift check)")
    p.add_argument("--now", help="evaluate at this time (ISO 8601; for testing and back-dating)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return dispatch(args)
    except ERRORS as error:
        print(f"aqt-validate: {error}", file=sys.stderr)
        return 2


def dispatch(args) -> int:
    config = load_config(args.config)
    state = validate_state_dir(config, args.state_dir)
    cmd = (args.command, getattr(args, "action", None))

    if cmd == ("data", "import"):
        items = load(args.format, args.src, what=args.what, version=args.dataset_version, license=args.license,
                     seed=args.seed, templates_per_goal=args.templates_per_goal)
        count = write_items(args.out, items)
        _out(args, {"items": count, "out": args.out}, f"wrote {count} items to {args.out}")
        return 0
    if cmd == ("data", "compose"):
        items = compose(read_items(args.hosts), read_items(args.attacks), seed=args.seed, per_payload=args.per_payload)
        count = write_items(args.out, items)
        _out(args, {"items": count, "out": args.out}, f"wrote {count} composed attack items to {args.out}")
        return 0
    if cmd == ("data", "stats"):
        items = [i for f in args.files for i in read_items(f)]
        summary = stats(items)
        lines = [f"{summary['items']} items {summary['by_label']}; benign groups {summary['groups']}; "
                 f"hard benign {summary['hard_benign']}"]
        lines += [f"  {r['label']:7} {r['family']:16} {r['category']:16} {r['split']:8} {r['count']}" for r in summary["rows"]]
        _out(args, summary, "\n".join(lines))
        return 0
    if cmd == ("protocol", "init"):
        text = template(args.kind)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            _out(args, {"out": args.out}, f"wrote {args.out}")
        else:
            sys.stdout.write(text)
        return 0
    sink = get_sink(config, args.sink)
    who = invoking_actor(config)
    found = lambda: records(config, args.evidence, args.sink)  # noqa: E731

    if cmd == ("protocol", "lock"):
        protocol = load_protocol(args.protocol)
        existing = evidence.find_lock(found(), protocol.sha256)
        if existing:
            _out(args, {"record": existing["id"], "sha256": protocol.sha256, "already_locked": True},
                 f"already locked: {protocol.sha256} ({existing['id']})")
            return 0
        record = evidence.emit(sink, evidence.RUN, who, "protocol-locked", reason=args.reason,
                               data={"kind": protocol.kind, "protocol": protocol.ref, "subject_id": protocol.subject,
                                     "configuration_hash": configuration_hash(protocol),
                                     "criteria": len(protocol.criteria)})
        _out(args, {"record": record["id"], "sha256": protocol.sha256},
             f"locked {protocol.path.name}: {protocol.sha256}\nrecord {record['id']}")
        return 0
    if cmd == ("detector", "plugins"):
        names = available_plugins()
        _out(args, {"plugins": names}, "\n".join(names) or "no detector plugins installed (entry points aqt.detectors)")
        return 0
    if cmd == ("detector", "run"):
        protocol = load_protocol(args.protocol)
        result = run_detector(protocol, split=args.split, state_dir=state, sink=sink, records=found(), actor=who,
                              out_dir=Path(args.out) if args.out else None)
        res = result.results
        lines = [f"conclusion: {res['conclusion']}  (split {res['split_read']})", f"run dir: {result.run_dir}"]
        for band in res["bands"]:
            lines.append(f"band {band['name']}: TPR {band['tpr'].get('k', 0)}/{band['tpr'].get('n', 0)}, "
                         f"held-out FP {band['fpr_heldout'].get('k', 0)}/{band['fpr_heldout'].get('n', 0)}, "
                         f"thresholds {band['thresholds']}")
        lines += [f"{c['id']} {c['metric']}: {c['status']}" for c in res["criteria"]]
        lines += [f"deviation: {d}" for d in res["deviations"]]
        _out(args, {"conclusion": res["conclusion"], "run_dir": str(result.run_dir),
                    "run_record": result.run_record["id"], "report_record": result.report_record["id"],
                    "criteria": res["criteria"]}, "\n".join(lines))
        return result.exit_code
    if cmd == ("reviewer", "build-cases"):
        kwargs = {k: v for k, v in (("fix_pattern", args.fix_pattern), ("clean_pattern", args.clean_pattern)) if v}
        manifest = build_cases(args.repo, args.out, since=args.since, max_cases=args.max_cases,
                               max_clean=args.max_clean, max_lines=args.max_lines, defects_dir=args.defects, **kwargs)
        _out(args, manifest, f"built {manifest['counts']['seeded']} seeded and {manifest['counts']['clean']} clean "
                             f"cases in {args.out}")
        return 0
    if cmd == ("reviewer", "run"):
        protocol = load_protocol(args.protocol)
        result = run_reviewer(protocol, split=args.split, state_dir=state, sink=sink, records=found(), actor=who,
                              retry_errors=args.retry_errors, limit=args.limit,
                              out_dir=Path(args.out) if args.out else None)
        res, m = result.results, result.results["metrics"]
        lines = [f"conclusion: {res['conclusion']}  (split {res['split_read']})", f"run dir: {result.run_dir}",
                 f"detection {m['detection_rate'].get('k', 0)}/{m['detection_rate'].get('n', 0)}, "
                 f"false alarms {m['false_alarm_rate'].get('k', 0)}/{m['false_alarm_rate'].get('n', 0)}, "
                 f"agreement {m['agreement']}, kappa {m['kappa']}, failed runs {m['errors']}"]
        lines += [f"{c['id']} {c['metric']}: {c['status']}" for c in res["criteria"]]
        lines += [f"deviation: {d}" for d in res["deviations"]]
        _out(args, {"conclusion": res["conclusion"], "run_dir": str(result.run_dir),
                    "run_record": result.run_record["id"], "report_record": result.report_record["id"],
                    "metrics": m, "criteria": res["criteria"]}, "\n".join(lines))
        return result.exit_code
    if cmd[0] == "report":
        path = Path(args.run_dir) / f"report.{args.format}"
        text = path.read_text(encoding="utf-8")
        _out(args, {"path": str(path), "content": text}, text)
        return 0
    if cmd[0] == "qualify":
        record = qualify(args.run_dir, decision="approve" if args.approve else "reject", reason=args.reason,
                         sink=sink, records=found(), human=make_actor("human", human_id(config)), claimed_actor=who,
                         valid_days=args.valid_days, accept_deviation=args.accept_deviation)
        _out(args, {"record": record["id"], "valid_until": record["data"]["valid_until"]},
             f"recorded {record['action']} ({record['id']}), valid until {record['data']['valid_until']}")
        return 0
    if cmd[0] == "check":
        protocol = load_protocol(args.protocol)
        observed = None
        if args.observed_fp:
            try:
                k, n = (int(x) for x in args.observed_fp.split("/"))
                if not 0 <= k <= n:
                    raise ValueError
            except ValueError:
                raise DecisionError("--observed-fp must look like K/N with 0 <= K <= N") from None
            observed = (k, n)
        now = datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else None
        result = check(protocol, records=found(), sink=sink, actor=who, thresholds=args.thresholds,
                       observed_fp=observed, now=now)
        lines = [f"{result.status}: {result.message}"] + [f"  {f['trigger']}: {f['detail']}" for f in result.fired]
        _out(args, result.as_dict(), "\n".join(lines))
        return result.exit_code
    raise ProtocolError(f"unknown command {cmd}")


if __name__ == "__main__":
    sys.exit(main())
