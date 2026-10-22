"""Stub AI reviewer for tests. Usage: stub_reviewer.py MODE DIFF_PATH [STATE_FILE].

MODE perfect: flag every added line containing "oops"; always: flag every added line;
silent: no findings; alternate: like perfect on odd calls, silent on even calls (counter in
STATE_FILE); crash: exit 3; wrapped: perfect output wrapped like `claude -p --output-format json`.
"""
import json
import re
import sys
from pathlib import Path

mode, diff_path = sys.argv[1], Path(sys.argv[2])
if mode == "crash":
    print("boom", file=sys.stderr)
    sys.exit(3)
if len(sys.argv) > 3:
    counter = Path(sys.argv[3])
    calls = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(calls))
else:
    calls = 1


def added_lines(diff: str):
    current, line_no = None, 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current = line[4:].strip()
            current = current[2:] if current.startswith("b/") else current
        elif line.startswith("@@"):
            line_no = int(re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line).group(1))
        elif line.startswith("+") and current:
            yield current, line_no, line[1:]
            line_no += 1
        elif line.startswith("-"):
            continue
        else:
            line_no += 1


diff = diff_path.read_text()
findings = []
if mode in ("perfect", "wrapped") or (mode == "alternate" and calls % 2 == 1):
    findings = [{"file": f, "line": n, "severity": "high", "summary": "suspicious change"}
                for f, n, text in added_lines(diff) if "oops" in text]
elif mode == "always":
    findings = [{"file": f, "line": n, "severity": "high", "summary": "looks wrong"} for f, n, _ in added_lines(diff)]
out = {"findings": findings}
if mode == "wrapped":
    print(json.dumps({"type": "result", "result": "Review done.\n" + json.dumps(out)}))
else:
    print(json.dumps(out))
