"""AI reviewer qualification: seeded defects from git history, repeated runs, scoring.

Seeded defect: a fix commit C (parent P) whose message matches the fix pattern. The case
diff is the *inverted* fix (``git diff C P``): it reintroduces the bug. The reviewer works
on a snapshot of C's tree with the fixed files put back to P's version, created in a
temporary directory; the user's repository is never changed.

Clean case: a non-fix commit (message matches the clean pattern) whose files no later fix
touched; the diff ``git diff P C`` is presented as is. Clean diffs can still contain real
bugs: the false-alarm rate is an upper estimate.

User-supplied defects: ``DEFECTS/<name>.json`` with ``{"base": "<commit>", "diff": "<file>",
"expected": [{"file", "start", "end"}]}``.
"""

from __future__ import annotations

import io
import json
import math
import os
import re
import shutil
import string
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from aqt_evidence import bytes_hash, content_hash, subject

from . import evidence
from .detector import RunRefused, _criteria_data, _write_json, _write_lines, new_run_id
from .protocol import Protocol, ProtocolError, configuration_hash, conclusion, evaluate_criterion
from .report import CRITERIA_HEADERS, NON_COMPLIANCE, Report, criteria_rows, fmt_bound, fmt_rate
from .stats import fleiss_kappa, rate

FIX_PATTERN = r"\b(fix|fixes|fixed|bug|bugfix|hotfix|regression|crash|wrong|incorrect)\b"
CLEAN_PATTERN = r"\b(refactor|rename|cleanup|clean up|docs?|chore|style|feat|feature|add|adds|added)\b"
EXCLUDE_PATTERN = (r"(^|/)(tests?|docs?|examples?)/|(^|/)test_[^/]*$|_test\.[A-Za-z]+$|"
                   r"\.(md|rst|txt|lock|json|ya?ml|toml|cfg|ini|csv|svg|png|jpg)$")
SEVERITY = {"info": 0, "note": 0, "nit": 0, "low": 1, "minor": 1, "medium": 2, "moderate": 2,
            "major": 3, "high": 3, "critical": 4, "blocker": 4}
DEFAULT_PROMPT = """You are reviewing a code change. Report real defects only (bugs, wrong behaviour, \
security problems), not style.

The repository snapshot after the change is in: ${workdir}
The change (unified diff) is:

${diff_text}

Answer with JSON only:
{"findings": [{"file": "path/relative/to/repo", "line": 1, "end_line": 1, "severity": "low|medium|high", \
"summary": "..."}]}
Return {"findings": []} if you find no defect.
"""


class GitError(RuntimeError):
    pass


def git(repo: Path, *args: str, binary: bool = False):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=env)
    if done.returncode != 0:
        raise GitError(f"git {' '.join(args[:3])}: {done.stderr.decode(errors='replace').strip()[:300]}")
    return done.stdout if binary else done.stdout.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- diff parsing

def changed_lines(diff: str) -> list[dict]:
    """Per file, the line range of changes on the new side of a unified diff."""
    ranges: dict[str, list[int]] = {}
    current, new_line = None, 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            current = None if path == "/dev/null" else re.sub(r"^b/", "", path)
        elif line.startswith("--- "):
            continue
        elif line.startswith("@@"):
            match = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            new_line = int(match.group(1)) if match else 0
        elif current is None:
            continue
        elif line.startswith("+"):
            ranges.setdefault(current, []).append(new_line)
            new_line += 1
        elif line.startswith("-"):
            ranges.setdefault(current, []).append(max(new_line, 1))  # where the removed text was
        elif line.startswith(" ") or line == "":
            new_line += 1
    return [{"file": f, "start": min(v), "end": max(v)} for f, v in sorted(ranges.items())]


def count_changes(diff: str) -> int:
    return sum(1 for line in diff.splitlines()
               if (line.startswith("+") or line.startswith("-")) and not line.startswith(("+++", "---")))


# --------------------------------------------------------------------------- building cases

@dataclass
class Commit:
    sha: str
    parents: list[str]
    date: str
    subject: str


def commits(repo: Path, since: str | None = None) -> list[Commit]:
    args = ["log", "--no-merges", "--format=%H%x1f%P%x1f%cI%x1f%s"]
    if since:
        args.append(f"--since={since}")
    out = []
    for line in git(repo, *args).splitlines():
        parts = line.split("\x1f")
        if len(parts) == 4:
            out.append(Commit(parts[0], parts[1].split(), parts[2], parts[3]))
    return out  # newest first


def _code_files(repo: Path, parent: str, sha: str, exclude: re.Pattern) -> list[str]:
    files = []
    for line in git(repo, "diff", "--name-status", "--no-renames", parent, sha).splitlines():
        status, _, path = line.partition("\t")
        if status == "M" and not exclude.search(path):
            files.append(path)
    return files


def build_cases(repo: str | Path, out_dir: str | Path, *, since: str | None = None, max_cases: int = 50,
                max_clean: int | None = None, fix_pattern: str = FIX_PATTERN, clean_pattern: str = CLEAN_PATTERN,
                exclude_pattern: str = EXCLUDE_PATTERN, max_lines: int = 40,
                defects_dir: str | Path | None = None) -> dict:
    repo, out_dir = Path(repo), Path(out_dir)
    fix_re, clean_re = re.compile(fix_pattern, re.I), re.compile(clean_pattern, re.I)
    exclude = re.compile(exclude_pattern)
    history = commits(repo, since)
    fixed_files_after: dict[str, set] = {}
    seen_fix_files: set[str] = set()
    seeded, clean = [], []
    for c in history:  # newest first: files fixed later are known when older commits are visited
        fixed_files_after[c.sha] = set(seen_fix_files)
        if len(c.parents) != 1:
            continue
        files = _code_files(repo, c.parents[0], c.sha, exclude)
        is_fix = bool(fix_re.search(c.subject))
        if is_fix:
            seen_fix_files.update(files)
        if not files:
            continue
        if is_fix and len(seeded) < max_cases:
            diff = git(repo, "diff", "-U3", "--no-renames", c.sha, c.parents[0], "--", *files)
            if 0 < count_changes(diff) <= max_lines:
                seeded.append((c, files, diff))
        elif not is_fix and clean_re.search(c.subject) and len(clean) < (max_clean or max_cases):
            if not set(files) & fixed_files_after[c.sha]:
                diff = git(repo, "diff", "-U3", "--no-renames", c.parents[0], c.sha, "--", *files)
                if 0 < count_changes(diff) <= max_lines * 3:
                    clean.append((c, files, diff))
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = []
    for kind, rows in (("seeded", seeded), ("clean", clean)):
        for c, files, diff in rows:
            case = {"id": f"{'fix' if kind == 'seeded' else 'clean'}-{c.sha[:12]}", "kind": kind, "commit": c.sha,
                    "parent": c.parents[0], "date": c.date, "files": files,
                    "expected": changed_lines(diff) if kind == "seeded" else [],
                    "diff_sha256": bytes_hash(diff.encode("utf-8")), "source": "history"}
            _write_case(out_dir, case, diff)
            cases.append(case)
    if defects_dir:
        for spec_path in sorted(Path(defects_dir).glob("*.json")):
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
            diff = (spec_path.parent / spec["diff"]).read_text(encoding="utf-8")
            base = git(repo, "rev-parse", spec["base"]).strip()
            date = git(repo, "show", "-s", "--format=%cI", base).strip()
            case = {"id": f"user-{spec_path.stem}", "kind": "seeded", "commit": base, "parent": None, "date": date,
                    "files": sorted({e["file"] for e in spec["expected"]}), "expected": spec["expected"],
                    "diff_sha256": bytes_hash(diff.encode("utf-8")), "source": "user", "apply": True}
            _write_case(out_dir, case, diff)
            cases.append(case)
    manifest = {"cases": [c["id"] for c in cases], "repo_head": git(repo, "rev-parse", "HEAD").strip(),
                "built": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "params": {"since": since, "max_cases": max_cases, "fix_pattern": fix_pattern,
                           "clean_pattern": clean_pattern, "exclude_pattern": exclude_pattern, "max_lines": max_lines},
                "counts": {"seeded": sum(c["kind"] == "seeded" for c in cases),
                           "clean": sum(c["kind"] == "clean" for c in cases)}}
    _write_json(out_dir / "cases.json", manifest)
    return manifest


def _write_case(out_dir: Path, case: dict, diff: str) -> None:
    folder = out_dir / case["id"]
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "diff.patch").write_text(diff, encoding="utf-8")
    _write_json(folder / "case.json", case)


def load_cases(cases_dir: Path) -> tuple[dict, list[tuple[dict, str]]]:
    manifest_path = cases_dir / "cases.json"
    if not manifest_path.exists():
        raise ProtocolError(f"{cases_dir}: no cases.json (run `aqt-validate reviewer build-cases` first)")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = []
    for case_id in manifest["cases"]:
        case = json.loads((cases_dir / case_id / "case.json").read_text(encoding="utf-8"))
        diff = (cases_dir / case_id / "diff.patch").read_text(encoding="utf-8")
        if bytes_hash(diff.encode("utf-8")) != case["diff_sha256"]:
            raise ProtocolError(f"case {case_id}: diff.patch changed since the case was built")
        cases.append((case, diff))
    return manifest, cases


# --------------------------------------------------------------------------- snapshots and runner

def make_snapshot(repo: Path, case: dict, diff: str, workdir: Path) -> None:
    archive = git(repo, "archive", "--format=tar", case["commit"], binary=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        try:
            tar.extractall(workdir, filter="data")
        except TypeError:  # Python without extraction filters
            tar.extractall(workdir)
    if case.get("apply"):
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(workdir.parent))
        done = subprocess.run(["git", "apply", "-"], input=diff.encode("utf-8"), cwd=workdir,
                              capture_output=True, env=env)
        if done.returncode != 0:
            raise GitError(f"case {case['id']}: diff does not apply: {done.stderr.decode(errors='replace')[:200]}")
    elif case["kind"] == "seeded":
        for path in case["files"]:
            content = git(repo, "show", f"{case['parent']}:{path}", binary=True)
            (workdir / path).write_bytes(content)


def parse_findings(stdout: str) -> list[dict]:
    """Findings from reviewer output: JSON, possibly wrapped (``{"result": "..."}``) or in prose."""
    def search(text: str, depth: int = 0):
        decoder = json.JSONDecoder()
        for match in re.finditer(r"\{", text):
            try:
                value, _ = decoder.raw_decode(text, match.start())
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                if isinstance(value.get("findings"), list):
                    return value["findings"]
                if depth < 2:
                    for key in ("result", "output", "content", "text", "message"):
                        if isinstance(value.get(key), str):
                            inner = search(value[key], depth + 1)
                            if inner is not None:
                                return inner
        return None
    found = search(stdout)
    if found is None:
        raise ValueError("no JSON object with a findings list in the reviewer output")
    return [f for f in found if isinstance(f, dict)]


def run_reviewer_once(protocol: Protocol, case: dict, diff: str, repo: Path | None, tmp_root: Path) -> dict:
    r = protocol.raw["reviewer"]
    tmp_root.mkdir(parents=True, exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="review-", dir=tmp_root))
    workdir = base / "work"
    workdir.mkdir()
    started = time.perf_counter()
    try:
        if repo is not None:
            make_snapshot(repo, case, diff, workdir)
        diff_path, prompt_path = base / "review.diff", base / "prompt.md"
        diff_path.write_text(diff, encoding="utf-8")
        template = (protocol.resolve(r["prompt_template"]).read_text(encoding="utf-8")
                    if r.get("prompt_template") else DEFAULT_PROMPT)
        prompt = string.Template(template).safe_substitute(diff_text=diff, diff_path=str(diff_path),
                                                           workdir=str(workdir))
        prompt_path.write_text(prompt, encoding="utf-8")
        values = {"{diff}": str(diff_path), "{workdir}": str(workdir), "{prompt}": str(prompt_path)}
        argv = []
        for arg in r["argv"]:
            for key, value in values.items():
                arg = arg.replace(key, value)
            argv.append(arg)
        stdin = {"prompt": prompt, "diff": diff, "none": None}[r.get("stdin", "prompt")]
        done = subprocess.run(argv, input=stdin, capture_output=True, text=True, cwd=workdir,
                              timeout=float(r.get("timeout_s", 900)))
        duration = round((time.perf_counter() - started) * 1000)
        if done.returncode != 0:
            return {"status": "error", "error": f"exit {done.returncode}: {done.stderr.strip()[:300]}",
                    "duration_ms": duration}
        return {"status": "ok", "findings": parse_findings(done.stdout), "duration_ms": duration}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "timeout", "duration_ms": round((time.perf_counter() - started) * 1000)}
    except (OSError, ValueError, GitError) as error:
        return {"status": "error", "error": f"{type(error).__name__}: {error}"[:300],
                "duration_ms": round((time.perf_counter() - started) * 1000)}
    finally:
        shutil.rmtree(base, ignore_errors=True)


# --------------------------------------------------------------------------- matching and scoring

def _norm(path: str) -> str:
    path = path.strip().replace("\\", "/")
    for prefix in ("./", "a/", "b/"):
        if path.startswith(prefix):
            path = path[len(prefix):]
    return path


def same_file(a: str, b: str) -> bool:
    a, b = _norm(a), _norm(b)
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def qualifying(findings: list[dict], min_severity: str) -> list[dict]:
    floor = SEVERITY.get(min_severity, 2)
    return [f for f in findings if SEVERITY.get(str(f.get("severity", "medium")).lower(), 2) >= floor]


def detects(findings: list[dict], expected: list[dict], *, min_severity: str, tolerance: int) -> bool:
    for f in qualifying(findings, min_severity):
        if not isinstance(f.get("file"), str) or not isinstance(f.get("line"), int):
            continue
        start, end = f["line"], f.get("end_line") if isinstance(f.get("end_line"), int) else f["line"]
        for e in expected:
            if same_file(f["file"], e["file"]) and start <= e["end"] + tolerance and end >= e["start"] - tolerance:
                return True
    return False


@dataclass
class ReviewerRun:
    run_dir: Path
    results: dict
    run_record: dict
    report_record: dict

    @property
    def exit_code(self) -> int:
        return 0 if self.results["conclusion"] == "meets" else 1


def run_reviewer(protocol: Protocol, *, split: str, state_dir: Path, sink, records: list[dict], actor: dict,
                 retry_errors: bool = False, limit: int | None = None, out_dir: Path | None = None) -> ReviewerRun:
    if protocol.kind != "reviewer":
        raise ProtocolError("this protocol is not a reviewer protocol")
    lock = evidence.find_lock(records, protocol.sha256)
    if split == "test" and lock is None:
        raise RunRefused("the test run needs a locked protocol: run `aqt-validate protocol lock` for this exact file "
                         f"first ({protocol.sha256})")
    r = protocol.raw["reviewer"]
    cases_cfg = protocol.raw["cases"]
    cases_dir = protocol.resolve(cases_cfg["dir"])
    manifest_cases, cases = load_cases(cases_dir)
    if split == "dev":
        cases = cases[: limit or 3]
    repo = protocol.resolve(cases_cfg["repo"]) if cases_cfg.get("repo") else None
    runs = int(r.get("runs", 3))
    min_severity = str(r.get("min_severity", "medium"))
    tolerance = int(r.get("line_tolerance", 3))
    detect_min = int(r.get("detect_min_runs", math.ceil(runs / 2)))
    config_hash = configuration_hash(protocol)
    data_sha = content_hash(sorted(c["diff_sha256"] for c, _ in cases))
    readout = evidence.test_readouts(records, data_sha) + 1 if split == "test" else 0
    cache_dir = state_dir / "cache" / "reviewer"
    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    per_case = []
    error_runs = 0
    for case, diff in cases:
        outcomes = []
        for index in range(runs):
            key = content_hash({"configuration": config_hash, "case": case["id"], "diff": case["diff_sha256"],
                                "run": index, "split": split})[7:]
            cached = cache_dir / f"{key}.json"
            result = json.loads(cached.read_text()) if cached.exists() else None
            if result is None or (result["status"] == "error" and retry_errors):
                result = run_reviewer_once(protocol, case, diff, repo, state_dir / "tmp")
                _write_json(cached, result)
            if result["status"] == "ok":
                hit = (detects(result["findings"], case["expected"], min_severity=min_severity, tolerance=tolerance)
                       if case["kind"] == "seeded" else bool(qualifying(result["findings"], min_severity)))
                outcomes.append(hit)
            else:
                outcomes.append(None)
                error_runs += 1
        ok = all(o is not None for o in outcomes)
        per_case.append({"id": case["id"], "kind": case["kind"], "date": case.get("date"), "outcomes": outcomes,
                         "ok": ok, "positive": ok and sum(outcomes) >= detect_min, "positive_runs": sum(bool(o) for o in outcomes)})

    conf = protocol.confidence
    cutoff = r.get("knowledge_cutoff") or protocol.raw["protocol"].get("knowledge_cutoff")

    def period_of(c: dict) -> str | None:
        if not cutoff or not c.get("date"):
            return None
        return "after-cutoff" if c["date"][:10] > str(cutoff) else "before-cutoff"

    def case_rate(kind: str, period: str | None = None) -> dict:
        pool = [c for c in per_case if c["kind"] == kind and c["ok"] and (period is None or period_of(c) == period)]
        return rate(sum(c["positive"] for c in pool), len(pool), conf)

    def run_rate(kind: str) -> dict:
        values = [o for c in per_case if c["kind"] == kind for o in c["outcomes"] if o is not None]
        return rate(sum(values), len(values), conf)

    complete = [c for c in per_case if c["ok"]]
    agreement = (sum(1 for c in complete if len(set(c["outcomes"])) == 1) / len(complete)
                 if complete and runs >= 2 else None)
    kappa = fleiss_kappa([[sum(c["outcomes"]), runs - sum(c["outcomes"])] for c in complete]) \
        if complete and runs >= 2 else None
    metrics = {
        "detection_rate": case_rate("seeded"), "false_alarm_rate": case_rate("clean"),
        "detection_runs": run_rate("seeded"), "false_alarm_runs": run_rate("clean"),
        "agreement": agreement, "kappa": kappa, "errors": error_runs,
        "by_period": {p: case_rate("seeded", p) for p in ("before-cutoff", "after-cutoff")} if cutoff else {},
    }
    criteria = []
    for c in protocol.criteria:
        metric = c["metric"]
        if metric in ("detection_rate", "false_alarm_rate"):
            observed = case_rate("seeded" if metric == "detection_rate" else "clean", c.get("period"))
        else:
            observed = metrics[metric]
        criteria.append(evaluate_criterion(c, observed, conf))
    criteria.append(evaluate_criterion({"id": "E0", "metric": "errors", "op": "<=", "bound": "point",
                                        "target": protocol.max_errors}, error_runs, conf))
    verdict = conclusion(criteria)
    deviations = []
    if error_runs:
        deviations.append(f"{error_runs} reviewer run(s) failed and are excluded from the rates")
    if split == "test" and readout > 1:
        deviations.append(f"these cases have now been read {readout} times")
    if split == "dev":
        deviations.append(f"dev trial on {len(cases)} case(s): not usable for qualification")
    for c in criteria:
        if c["status"] == "inconclusive":
            deviations.append(f"criterion {c['id']} is inconclusive ({c.get('note', '')})")
    if not any(c["kind"] == "clean" for c in per_case):
        deviations.append("no clean cases: the false-alarm rate is not measured")

    run_id = new_run_id()
    run_dir = out_dir or state_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    reviewer_info = {k: r[k] for k in ("id", "harness", "model", "version") if k in r}
    results = {"kind": "reviewer", "split_read": split, "conclusion": verdict, "confidence": conf,
               "criteria": criteria, "metrics": metrics, "runs_per_case": runs, "detect_min_runs": detect_min,
               "min_severity": min_severity, "line_tolerance": tolerance, "cases": per_case,
               "counts": {"seeded": sum(c["kind"] == "seeded" for c in per_case),
                          "clean": sum(c["kind"] == "clean" for c in per_case), "error_runs": error_runs},
               "deviations": deviations, "reviewer": reviewer_info}
    datasets = [{"name": "cases.json", "sha256": bytes_hash((cases_dir / "cases.json").read_bytes()),
                 "items": len(cases)}]
    manifest = {"run_id": run_id, "kind": "reviewer", "protocol": dict(protocol.ref, file=protocol.path.name),
                "subject_id": protocol.subject, "split_read": split, "configuration_hash": config_hash,
                "datasets": datasets, "data_sha256": data_sha, "test_readouts": readout,
                "lock_record": lock["id"] if lock else None, "repo_head": manifest_cases.get("repo_head"),
                "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "validity_days": protocol.validity_days, "triggers": protocol.triggers}
    _write_json(run_dir / "manifest.json", manifest)
    _write_json(run_dir / "results.json", results)
    _write_lines(run_dir / "outcomes.jsonl", ({"id": c["id"], "kind": c["kind"], "outcomes": c["outcomes"]}
                                              for c in per_case))
    results_sha = bytes_hash((run_dir / "results.json").read_bytes())
    data = {"kind": "reviewer", "protocol": protocol.ref, "subject_id": protocol.subject,
            "configuration_hash": config_hash, "datasets": datasets, "data_sha256": data_sha, "split_read": split,
            "test_readouts": readout, "results_sha256": results_sha, "conclusion": verdict,
            "headline": {k: metrics[k] for k in ("detection_rate", "false_alarm_rate")},
            "agreement_ppm": None if agreement is None else round(agreement * 1_000_000),
            "kappa_ppm": None if kappa is None else round(kappa * 1_000_000),
            "errors": error_runs, "run_id": run_id, "reviewer": reviewer_info}
    data = {k: v for k, v in data.items() if v is not None}
    links = [{"rel": "protocol-lock", "ref": lock["id"]}] if lock else None
    run_record = evidence.emit(sink, evidence.RUN, actor, "completed", data=data, links=links,
                               subject=subject("validation-run", run_id, sha256=results_sha))
    report = build_report(protocol, manifest, results, run_record["id"])
    (run_dir / "report.md").write_text(report.markdown(), encoding="utf-8")
    (run_dir / "report.html").write_text(report.html(f"Reviewer qualification {protocol.id}"), encoding="utf-8")
    report_record = evidence.emit(
        sink, evidence.REPORT, actor, "issued",
        subject=subject("validation-report", f"{run_id}/report.md", sha256=bytes_hash((run_dir / "report.md").read_bytes())),
        links=[{"rel": "run", "ref": run_record["id"]}],
        data={"kind": "reviewer", "run": run_record["id"], "conclusion": verdict, "criteria": _criteria_data(criteria),
              "deviations": deviations, "configuration_hash": config_hash, "subject_id": protocol.subject,
              "split_read": split, "html_sha256": bytes_hash((run_dir / "report.html").read_bytes())})
    manifest.update({"run_record": run_record["id"], "report_record": report_record["id"]})
    _write_json(run_dir / "manifest.json", manifest)
    return ReviewerRun(run_dir, results, run_record, report_record)


def build_report(protocol: Protocol, manifest: dict, results: dict, run_record_id: str) -> Report:
    r = Report()
    conf = results["confidence"]
    m = results["metrics"]
    rev = results["reviewer"]
    r.h(1, f"Reviewer qualification report: {protocol.id}")
    r.p(f"Conclusion: {results['conclusion'].upper()} (split read: {results['split_read']}; confidence {conf:.0%}).")
    r.p(NON_COMPLIANCE)
    r.h(2, "1. Intended use")
    r.p(protocol.intended_use)
    r.h(2, "2. Configuration under test")
    r.items([f"Reviewer: {rev.get('id')} (harness {rev.get('harness', '–')}, model {rev.get('model', '–')}, "
             f"version {rev.get('version', '–')})",
             f"Runs per case: {results['runs_per_case']}; a case counts as found/alarmed when at least "
             f"{results['detect_min_runs']} runs agree; minimum severity {results['min_severity']}; "
             f"line tolerance ±{results['line_tolerance']}",
             f"Protocol: {protocol.path.name} ({protocol.sha256}); lock record: {manifest.get('lock_record') or 'none'}",
             f"Configuration hash: {manifest['configuration_hash']}; run record: {run_record_id}",
             f"Cases: {results['counts']['seeded']} seeded defects, {results['counts']['clean']} clean diffs "
             f"(repository HEAD {manifest.get('repo_head') or '–'}); test readouts: {manifest['test_readouts']}"])
    r.h(2, "3. Acceptance criteria and results")
    headers = list(CRITERIA_HEADERS)
    headers[6] = f"Observed ({conf:.0%} CI)"
    r.table(headers, criteria_rows(results["criteria"]))
    r.h(2, "4. Results")
    rows = [["Detection rate (cases)", fmt_rate(m["detection_rate"]), fmt_bound(m["detection_rate"], "lower")],
            ["False-alarm rate (clean cases)", fmt_rate(m["false_alarm_rate"]), fmt_bound(m["false_alarm_rate"], "upper")],
            ["Detection per run (runs not independent)", fmt_rate(m["detection_runs"]), "–"],
            ["False alarms per run (runs not independent)", fmt_rate(m["false_alarm_runs"]), "–"]]
    rows += [[f"Detection rate, {p}", fmt_rate(v), fmt_bound(v, "lower")] for p, v in m["by_period"].items()]
    r.table(["Measure", f"Rate [{conf:.0%} two-sided CI]", "One-sided bound"], rows)
    agreement = "–" if m["agreement"] is None else format(m["agreement"], ".3f")
    kappa = "–" if m["kappa"] is None else format(m["kappa"], ".3f")
    r.items([f"Agreement (all runs identical): {agreement}", f"Fleiss' kappa: {kappa}",
             f"Failed runs: {m['errors']}"])
    r.table(["Case", "Kind", "Outcomes per run", "Counted as"],
            [[c["id"], c["kind"], " ".join("E" if o is None else ("1" if o else "0") for o in c["outcomes"]),
              "error" if not c["ok"] else ("found" if c["kind"] == "seeded" and c["positive"] else
                                           "missed" if c["kind"] == "seeded" else
                                           "false alarm" if c["positive"] else "quiet")]
             for c in results["cases"]])
    r.h(2, "5. Deviations")
    r.items(results["deviations"] or ["None."])
    r.h(2, "6. Limits")
    r.items(["Seeded defects come from fixes that were found: a biased sample of the defects that matter.",
             "Location matching is approximate (file plus line range with tolerance).",
             "Clean diffs may contain real defects, so the false-alarm rate is an upper estimate.",
             "Public fixes may be memorised by the model; compare before/after the knowledge cutoff.",
             "The result is specific to this repository, reviewer configuration and prompt."])
    r.h(2, "7. Conclusion, validity and requalification")
    r.p(f"Conclusion: {results['conclusion']}. Proposed validity: {protocol.validity_days} days after qualification. "
        f"Requalify on: {', '.join(protocol.triggers)}. Qualification is a separate, human decision.")
    r.h(2, "References")
    r.items(["annex22-2025d:1 (human in the loop)", "annex22-2025d:4 (acceptance criteria)",
             "iso9001-2015:7.1.5.1 (resources fit for the monitoring purpose)",
             "annex22-2025d:10.1 (change control of the AI configuration)"])
    return r
