#!/bin/sh
# Offline quick start: plan -> begin -> edit + reconcile -> run -> review -> finish -> report -> gate GO,
# then a code change makes the receipt stale and the gate turns NO-GO.
# Usage: sh examples/quickstart.sh   (needs git and aqt-change on PATH, or AQT_CHANGE=/path/to/aqt-change)
set -eu
AC=${AQT_CHANGE:-aqt-change}
WORK=$(mktemp -d)
export AQT_SINK="file:$WORK/evidence.jsonl" XDG_STATE_HOME="$WORK/state" XDG_CONFIG_HOME="$WORK/config"
cd "$WORK"
git init -q -b main demo && cd demo
git config user.email demo@example.invalid && git config user.name "Demo User"
mkdir -p src tests plans
printf 'def add(a, b):\n    return a + b\n' > src/calc.py
cat > tests/check.py <<'PY'
import sys
sys.path.insert(0, "src")
import calc
ok = calc.add(2, 3) == 5 and getattr(calc, "sub", lambda a, b: None)(5, 3) == 2
print("2 passed in 0.01s" if ok else "1 failed, 1 passed in 0.01s")
sys.exit(0 if ok else 1)
PY
git add -A && git commit -qm "initial"

echo "== 1. a new plan (template), then define tasks and checks"
$AC plan new plans/s01.md --id s01 --title "Subtraction" --implementation calc
python3 - <<'PY'
from pathlib import Path
p = Path("plans/s01.md"); s = p.read_text()
s = s.replace("  paths: []", "  paths:\n    - src/**\n    - tests/**")
s = s.replace("<!-- Add work tasks as: - [ ] [T01] Description -->", "- [ ] [T01] Implement sub")
s = s.replace("<!-- Add checks as: - [ ] [V01] Unit tests pass `$ python -m pytest -q` -->",
              "- [ ] [V01] Checks pass `$ python3 tests/check.py`")
p.write_text(s)
PY
$AC plan status || true
echo "== 2. reconcile the edit (editorial is refused: the structure changed)"
$AC reconcile plans/s01.md --kind editorial --reason "typo" || true
$AC reconcile plans/s01.md --kind semantic --reason "define task and check"
git add plans && git commit -qm "plan s01"
$AC begin plans/s01.md

echo "== 3. implement, run the declared check (runner-captured receipt)"
printf 'def add(a, b):\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n' > src/calc.py
sed -i 's/- \[ \] \[T01\]/- [x] [T01]/' plans/s01.md
$AC run --plan plans/s01.md --all --quiet

echo "== 4. review, finish (scoped commit with trailers), report and gate"
$AC review add plans/s01.md --reviewer agent:codex:demo --independence different-model --verdict PASS --reason "looks right"
$AC finish plans/s01.md --key s01-finish --summary "sub() added" --path src/calc.py
git log -1 --format=%B
$AC report plans/s01.md --out "$WORK/report.md" --gate "$WORK/gate.json"
$AC gate plans/s01.md > /dev/null && echo "gate: GO"

echo "== 5. a later code change makes the receipt stale"
printf '\n# drive-by edit\n' >> src/calc.py
if $AC gate plans/s01.md > "$WORK/gate2.json"; then echo "unexpected GO"; exit 1; fi
python3 -c "import json, sys; d=json.load(open(sys.argv[1])); print('gate:', d['decision'], [r['code'] for r in d['reasons']])" "$WORK/gate2.json"
echo "work directory: $WORK"
