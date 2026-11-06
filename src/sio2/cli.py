"""Command line entry point.

    sio2 --input targets/radicale --output runs/radicale-full --config configs/full.toml

Whatever happens inside the graph, this module writes report.json and ends the
trace with exactly one terminal event: an exception that escapes the graph
settles every unsettled row as `error`, writes the report, and ends the trace
with status `error`.
"""
from __future__ import annotations

import argparse
import json
import signal
import subprocess
import sys
import time
import traceback
import uuid
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path

import jsonschema

from sio2.config import Config, ConfigError, load_config, load_schema
from sio2.graph import Agent, charged, make_row
from sio2.llm import OllamaChat, OpenAIChat
from sio2.repair import RepairWorkflow
from sio2.trace import AlertStatus, EventKind, TerminalStatus, Trace
from sio2.workspace import Workspace
from sio2.utils import target_commit

def build_report(input_arg: str, commit: str, cfg, state: dict, usage: dict) -> dict:
    alerts = state.get("alerts") or []
    rows = state.get("rows") or {}
    out_rows = []
    for a in alerts:   # alerts are already in report order (scan.parse_results)
        out_rows.append(rows[a.alert_id])
    used = charged(usage)
    return {
        "target": {"input": input_arg, "commit": commit},
        "scan": {"bandit_version": cfg.scan.bandit_version, "min_severity": cfg.scan.min_severity,
                 "alert_count": len(alerts)},
        "budget": {"max_tokens": cfg.budget.max_tokens, "used_tokens": used,
                   "exhausted": state.get("status") == TerminalStatus.BUDGET_EXHAUSTED},
        "alerts": out_rows,
    }


def echo(record: dict) -> None:
    k = record["kind"]
    aid = record.get("alert_id") or "-"
    if k == "model_call":
        u = record["usage"]
        msg = f"model  in={u['input']} out={u['output']} calls={record.get('tool_calls')}"
    elif k == "tool_request":
        msg = f"tool → {record['tool']} {json.dumps(record['args'])[:100]}"
    elif k == "tool_result":
        msg = f"tool ← {record['tool']} ok={record['ok']}" + ("" if record["ok"] else f" {record['error'][:100]}")
    elif k == "routing":
        msg = f"route  {record['decision']} (by {record['by']})"
    elif k == "state_change":
        msg = f"state  {record['node']}" + (f" {record['alert_status']} label={record['label']}"
                                            if "alert_status" in record else "")
    else:
        msg = f"END    {record['status']} usage={record['usage_total']}"
    print(f"[{record['step']:>4}] {aid[:48]:<48} {msg}", file=sys.stderr, flush=True)


class Terminated(BaseException):
    """SIGTERM, turned into an exception so the crash path writes the report and terminal event."""


@contextmanager
def sigterm_raises():
    """While the block runs, SIGTERM raises Terminated instead of killing the process."""
    def handler(signum, frame):
        raise Terminated(f"received signal {signum}")
    try:
        previous = signal.signal(signal.SIGTERM, handler)
    except ValueError:   # not the main thread (e.g. some test runners): keep the default
        previous = None
    try:
        yield
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)


def model_client(cfg: Config, llm=None, output_allowance: int | None = None):
    """The model as a context manager: Ollama or an OpenAI-compatible server by [model].provider,
    or an injected stand-in (tests)."""
    if llm is not None:
        return nullcontext(llm)
    client = OllamaChat if cfg.model.provider == "ollama" else OpenAIChat
    return client(cfg.model, cfg.budget.output_allowance if output_allowance is None else output_allowance)


def settle_after_crash(trace: Trace, state: dict, agent: Agent | None, reason: str) -> dict:
    """Every row the crash left unsettled becomes `error`, with its own state_change."""
    rows = dict(state.get("rows") or {})
    if agent is not None:
        # Rows a node settled in the trace before the crash, but LangGraph never committed.
        rows.update({k: v for k, v in agent.written_rows.items() if k not in rows})
    alerts = state.get("alerts") or (agent.discovered if agent is not None else [])
    for a in alerts:
        if a.alert_id not in rows:
            trace.event(EventKind.STATE_CHANGE, a.alert_id, node="crash",
                        alert_status=AlertStatus.ERROR, label=None)
            rows[a.alert_id] = make_row(a, AlertStatus.ERROR, None,
                                        f"run crashed before this alert was classified: {reason}", [])
    return {**state, "alerts": alerts, "rows": rows}


def write_report(output: Path, report: dict) -> None:
    """Validate, then replace report.json atomically, so a reader never sees half a file."""
    jsonschema.validate(report, load_schema("report.schema.json"))
    tmp = output / "report.json.tmp"
    tmp.write_text(json.dumps(report, indent=2) + "\n")
    tmp.replace(output / "report.json")


def run(input_arg: str, output: Path, config: Path, quiet: bool = False, llm=None,
        repair: bool = False) -> int:
    cfg = load_config(config)
    output.mkdir(parents=True, exist_ok=True)
    run_id = f"{cfg.target}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    input_root = Path(input_arg)
    commit = target_commit(input_root)

    with sigterm_raises(), Trace(output / "trace.jsonl", run_id, echo=None if quiet else echo) as trace:
        state: dict = {}
        agent: Agent | None = None
        repairs: RepairWorkflow | None = None
        status, reason = TerminalStatus.ERROR, ""
        try:
            with Workspace(input_root, cfg.target, keep=cfg.agent.keep_workspace) as ws, \
                    model_client(cfg, llm) as model, ExitStack() as lifetime:
                trace.event(EventKind.STATE_CHANGE, None, node="start", input=input_arg, commit=commit,
                            config=str(config), model=cfg.model.name, provider=cfg.model.provider,
                            max_tokens=cfg.budget.max_tokens,
                            output_allowance=cfg.budget.output_allowance,
                            max_steps=cfg.budget.max_steps, workspace=str(ws.root),
                            withheld_for_run=ws.withheld())
                if repair:
                    repair_model = lifetime.enter_context(model_client(cfg, llm, cfg.repair.output_allowance))
                    repairs = lifetime.enter_context(RepairWorkflow(
                        cfg, ws, trace, repair_model, output, {"input": input_arg, "commit": commit}))
                agent = Agent(cfg, ws, trace, model, repairs=repairs)
                # LangGraph's own recursion limit sits above our max_steps so ours fires first.
                for chunk in agent.build().stream({}, {"recursion_limit": cfg.budget.max_steps + 100},
                                                  stream_mode="values"):
                    state = chunk
                status = state.get("status") or TerminalStatus.COMPLETED
                reason = state.get("status_reason", "")
        except BaseException as exc:  # KeyboardInterrupt included: the run still states how it ended
            status, reason = TerminalStatus.ERROR, f"{type(exc).__name__}: {exc}"
            trace.event(EventKind.STATE_CHANGE, None, node="crash", exception=type(exc).__name__,
                        message=str(exc)[:2000], traceback=traceback.format_exc()[-4000:])
            state = settle_after_crash(trace, state, agent, reason)
        finally:
            try:
                repair_report = repairs.finalize(state, status, reason) if repairs is not None else None
                if repair_report is not None and repair_report["status"] in ("blocked", "error"):
                    status = TerminalStatus.ERROR
                    reason = reason or f"repair ended with {repair_report['status']}"
                state = {**state, "status": status}
                report = build_report(input_arg, commit, cfg, state, trace.usage.as_dict(keep_zero_cache=True))
                if repair_report is not None:
                    report["repairs"] = repair_report
                write_report(output, report)
            except Exception as exc:
                status, reason = TerminalStatus.ERROR, f"report could not be written: {exc}"
                print(reason, file=sys.stderr)
            trace.terminal(status, reason=reason, steps=trace.step + 1)

    if not quiet:
        print(f"{status}: wrote {output / 'report.json'} and {output / 'trace.jsonl'}", file=sys.stderr)
    return 0 if status in (TerminalStatus.COMPLETED, TerminalStatus.BUDGET_EXHAUSTED) else 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sio2",
                                description="Scan a pinned Python repository with Bandit and label each alert.")
    p.add_argument("--input", required=True, help="root of the target checkout")
    p.add_argument("--output", required=True, type=Path, help="directory for report.json and trace.jsonl")
    p.add_argument("--config", required=True, type=Path, help="TOML config (see configs/)")
    p.add_argument("--quiet", action="store_true", help="do not print the trace to stderr")
    p.add_argument("--repair", action="store_true", help="include patch and validation nodes in the same workflow")
    a = p.parse_args(argv)
    try:
        return run(a.input, a.output, a.config, quiet=a.quiet, repair=a.repair)
    except ConfigError as exc:
        # No run starts without a valid config, so there is no trace to write.
        print(f"config error: {exc}", file=sys.stderr)
        return 1
