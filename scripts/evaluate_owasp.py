"""Score an OWASP BenchmarkPython report against the benchmark's own labels.

    uv run python scripts/evaluate_owasp.py runs/owasp-full/report.json targets/owasp-benchmark-python

Developer tool, never part of the agent. It reads expectedresults-0.1.csv from
the real checkout, which the agent's workspace withholds. The truth for a row is
the benchmark's "real vulnerability" flag for the test case its file belongs to.

Precision and recall treat label 1 as the positive class and count only
classified rows; budget_exhausted and error rows are listed separately.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path, PurePosixPath


def load_key(checkout: Path) -> dict[str, bool]:
    key = {}
    with (checkout / "expectedresults-0.1.csv").open() as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            key[row[0].strip()] = row[2].strip().lower() == "true"
    return key


def score(report: dict, key: dict[str, bool]) -> dict:
    tp = fp = tn = fn = 0
    rows = []
    for r in report["alerts"]:
        case = PurePosixPath(r["path"]).stem
        truth = int(key[case])
        rows.append((r["alert_id"], r["test_id"], truth, r["label"], r["status"]))
        if r["status"] != "classified":
            continue
        if r["label"] == 1:
            tp += truth
            fp += 1 - truth
        else:
            fn += truth
            tn += 1 - truth
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": prec, "recall": rec,
            "accuracy": (tp + tn) / max(1, tp + fp + tn + fn),
            "unclassified": sum(1 for x in rows if x[4] != "classified"), "rows": rows}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    report = json.loads(Path(argv[0]).read_text())
    s = score(report, load_key(Path(argv[1])))
    print(f"{'alert':<46} {'test':<5} truth label status")
    for aid, tid, truth, label, status in s["rows"]:
        mark = "" if status != "classified" else ("ok" if truth == label else "WRONG")
        print(f"{aid:<46} {tid:<5} {truth:>5} {str(label):>5} {status} {mark}")
    print(f"\nTP={s['tp']} FP={s['fp']} TN={s['tn']} FN={s['fn']} unclassified={s['unclassified']}")
    print(f"precision={s['precision']:.3f} recall={s['recall']:.3f} accuracy={s['accuracy']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
