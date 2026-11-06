"""Draw one alert's trajectory from a trace as a Mermaid sequence diagram.

    uv run python -m sio2.trajectory runs/radicale-full/trace.jsonl <alert_id>
    uv run python -m sio2.trajectory runs/radicale-full/trace.jsonl --list

Participants:
    Classifier   the model, proposing one action per turn
    Runtime      graph edges, the budget gate, the dispatcher, settle
    Workspace    the disposable copy of the target

An arrow leaving the Classifier is a proposal. Everything that returns to it is
an observation the runtime wrote.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sio2.trace import read_events


def _short(text, width=60) -> str:
    text = " ".join(str(text).split()).replace(";", ",").replace('"', "'").replace("#", "")
    return text if len(text) <= width else text[:width - 1] + "…"


def to_mermaid(events: list[dict], alert_id: str) -> str:
    ev = [e for e in events if e.get("alert_id") == alert_id]
    if not ev:
        raise SystemExit(f"no events for {alert_id}")
    t0 = ev[0]["ts"]
    out = ["sequenceDiagram",
           "    participant M as Classifier (model)",
           "    participant R as Runtime",
           "    participant W as Workspace (copy)",
           f"    Note over M,W: {_short(alert_id, 80)}"]
    for e in ev:
        k, at = e["kind"], f"t+{e['ts'] - t0:.0f}s s{e['step']}"
        if k == "model_call":
            u = e["usage"]
            out.append(f"    Note over M: {at} model_call in={u['input']} out={u['output']}")
        elif k == "routing":
            arrow = "M->>R" if e["by"] == "model" else "R->>R"
            extra = f" calls={','.join(e['tool_calls'])}" if e.get("tool_calls") else ""
            if e["decision"] == "classify":
                extra = f" remaining={e.get('remaining')} required={e.get('required')}"
            out.append(f"    {arrow}: {at} route {e['decision']} (by {e['by']}) {_short(extra, 50)}")
        elif k == "tool_request":
            who = "R" if e.get("requested_by") == "runtime" else "M"
            out.append(f"    {who}->>R: {at} {e['tool']}({_short(json.dumps(e['args'])[1:-1], 70)})")
            if e["tool"] != "submit_label":
                out.append(f"    R->>W: {e['tool']}")
        elif k == "tool_result":
            if e["ok"]:
                out.append(f"    R-->>M: {at} observation ok ({e.get('chars', 0)} chars)")
            else:
                out.append(f"    R-->>M: {at} REFUSED {_short(e['error'], 60)}")
        elif k == "state_change":
            if "alert_status" in e:
                out.append(f"    Note over R: {at} {e['node']}: {e['alert_status']}, label={e['label']}")
            else:
                out.append(f"    Note over R: {at} {e['node']}")
    return "\n".join(out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("trace", type=Path)
    p.add_argument("alert_id", nargs="?")
    p.add_argument("--list", action="store_true", help="list alert ids in the trace")
    a = p.parse_args(argv)
    events = read_events(a.trace)
    if a.list or not a.alert_id:
        ids = list(dict.fromkeys(e["alert_id"] for e in events if e.get("alert_id")))
        print("\n".join(ids))
        return 0
    print(to_mermaid(events, a.alert_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
