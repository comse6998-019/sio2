"""The C2 tables, computed from the committed runs (never typed by hand).

    uv run python scripts/summarise_runs.py runs/owasp-full runs/owasp-low ...
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path


def summarise(run: Path) -> dict:
    report = json.loads((run / "report.json").read_text())
    events = [json.loads(line) for line in (run / "trace.jsonl").read_text().splitlines()]
    rows = report["alerts"]
    per_alert: dict[str, dict] = {}
    for e in events:
        aid = e.get("alert_id")
        if not aid:
            continue
        a = per_alert.setdefault(aid, {"calls": 0, "tokens": 0, "t0": e["ts"], "t1": e["ts"], "tools": 0,
                                       "refused": 0})
        a["t1"] = e["ts"]
        if e["kind"] == "model_call":
            a["calls"] += 1
            a["tokens"] += e["usage"]["input"] + e["usage"]["output"]
        if e["kind"] == "tool_result" and e["tool"] != "bandit":
            a["tools"] += 1
            a["refused"] += not e["ok"]
    classified = [per_alert[r["alert_id"]] for r in rows if r["status"] == "classified"]
    med = (lambda xs: statistics.median(xs) if xs else 0)
    return {
        "run": run.name, "rows": len(rows),
        "label1": sum(r["label"] == 1 for r in rows), "label0": sum(r["label"] == 0 for r in rows),
        "null": sum(r["label"] is None for r in rows),
        "statuses": {s: sum(r["status"] == s for r in rows) for s in ("classified", "error", "budget_exhausted")},
        "terminal": events[-1]["status"],
        "used": report["budget"]["used_tokens"], "max": report["budget"]["max_tokens"],
        "model_calls": sum(e["kind"] == "model_call" for e in events),
        "refusals": sum(e["kind"] == "tool_result" and not e["ok"] for e in events),
        "wall_s": events[-1]["ts"] - events[0]["ts"],
        "med_calls": med([a["calls"] for a in classified]),
        "med_tokens": med([a["tokens"] for a in classified]),
        "med_seconds": med([a["t1"] - a["t0"] for a in classified]),
    }


def main(argv=None) -> int:
    runs = [summarise(Path(p)) for p in (argv if argv is not None else sys.argv[1:])]
    print("| Run | Rows | Label 1 | Label 0 | `null` | Statuses | Terminal | used / max tokens | Model calls | Refusals | Wall time |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in runs:
        st = ", ".join(f"{k} {v}" for k, v in r["statuses"].items() if v)
        print(f"| `{r['run']}` | {r['rows']} | {r['label1']} | {r['label0']} | {r['null']} | {st} | "
              f"`{r['terminal']}` | {r['used']:,} / {r['max']:,} | {r['model_calls']} | {r['refusals']} | "
              f"{r['wall_s'] / 60:.1f} min |")
    print()
    print("| Run | Median model calls per classified alert | Median tokens per classified alert | Median seconds per classified alert |")
    print("|---|---|---|---|")
    for r in runs:
        print(f"| `{r['run']}` | {r['med_calls']:g} | {r['med_tokens']:,.0f} | {r['med_seconds']:.0f} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
