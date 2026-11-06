"""Check a run directory against the schemas and the six trace invariants.

    uv run python -m sio2.check runs/radicale-full

Exits 0 when every check passes. This is the same list graders check, so we
run it on every run we cite.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema

from sio2.config import load_schema
from sio2.trace import Usage, read_events

def check_run(run_dir: Path) -> list[str]:
    problems: list[str] = []
    report = json.loads((run_dir / "report.json").read_text())
    events = read_events(run_dir / "trace.jsonl")

    # report.json: schema and the rules the schema cannot express
    try:
        jsonschema.validate(report, load_schema("report.schema.json"))
    except jsonschema.ValidationError as exc:
        problems.append(f"report.json fails the schema: {exc.message}")
    rows = report["alerts"]
    if len(rows) != report["scan"]["alert_count"]:
        problems.append("len(alerts) != scan.alert_count")
    keys = [(r["path"], r["line"], r["test_id"]) for r in rows]
    if keys != sorted(keys):
        problems.append("rows are not ordered by path, line, test_id")
    if len({r["alert_id"] for r in rows}) != len(rows):
        problems.append("alert_id is not unique")

    # 1. every line validates
    schema = load_schema("trace.schema.json")
    for e in events:
        try:
            jsonschema.validate(e, schema)
        except jsonschema.ValidationError as exc:
            problems.append(f"step {e.get('step')}: fails trace schema: {exc.message}")
    # 2. steps 1..n
    if [e["step"] for e in events] != list(range(1, len(events) + 1)):
        problems.append("step does not start at 1 and increase by 1")
    # 3. one terminal, last
    terms = [i for i, e in enumerate(events) if e["kind"] == "terminal"]
    if terms != [len(events) - 1]:
        problems.append(f"terminal events at {terms}, want exactly one, last")
    # 4. usage_total and used_tokens
    calls = [e for e in events if e["kind"] == "model_call"]
    if terms:
        total = events[terms[-1]]["usage_total"]
        for c in Usage.counters():
            s = sum(e["usage"].get(c, 0) for e in calls)
            if total.get(c, 0) != s:
                problems.append(f"usage_total.{c}={total.get(c, 0)} but model_call sum={s}")
    charge = sum(e["usage"]["input"] + e["usage"]["output"] for e in calls)
    if report["budget"]["used_tokens"] != charge:
        problems.append(f"budget.used_tokens={report['budget']['used_tokens']} but trace charge={charge}")
    # 5. one settling state_change per row, matching it
    settles: dict[str, list[dict]] = {}
    for e in events:
        if e["kind"] == "state_change" and "alert_status" in e:
            settles.setdefault(e["alert_id"], []).append(e)
    for r in rows:
        got = settles.get(r["alert_id"], [])
        if len(got) != 1:
            problems.append(f"{r['alert_id']}: {len(got)} settling state_change events, want 1")
        elif (got[0]["alert_status"], got[0]["label"]) != (r["status"], r["label"]):
            problems.append(f"{r['alert_id']}: state_change disagrees with the row")
    extra = set(settles) - {r["alert_id"] for r in rows}
    if extra:
        problems.append(f"state_change settles alerts with no row: {sorted(extra)}")
    # 6. tool_request immediately followed by its tool_result
    for i, e in enumerate(events):
        if e["kind"] == "tool_request":
            nxt = events[i + 1] if i + 1 < len(events) else None
            if not nxt or nxt["kind"] != "tool_result" or nxt["tool"] != e["tool"]:
                problems.append(f"step {e['step']}: tool_request not immediately followed by its tool_result")
    return problems


def summary(run_dir: Path) -> str:
    report = json.loads((run_dir / "report.json").read_text())
    events = read_events(run_dir / "trace.jsonl")
    rows = report["alerts"]
    ones = sum(r["label"] == 1 for r in rows)
    zeros = sum(r["label"] == 0 for r in rows)
    nulls = sum(r["label"] is None for r in rows)
    term = events[-1]
    return (f"{run_dir}: {len(rows)} rows, label1={ones} label0={zeros} null={nulls}; "
            f"terminal={term.get('status')}; used_tokens={report['budget']['used_tokens']}"
            f"/{report['budget']['max_tokens']}; {len(events)} events")


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    bad = 0
    for d in argv:
        p = check_run(Path(d))
        print(summary(Path(d)))
        for x in p:
            print("  FAIL", x)
        print("  all checks pass" if not p else f"  {len(p)} problem(s)")
        bad += bool(p)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
