"""The agent's state machine, built with LangGraph.

    discover ──► next_alert ──► gate ──► classify ──► act ──► (gate | settle)
                   ▲   │          │          │                     │
                   │   ▼          ▼          ▼                     │
                   │ finish    cutoff     nudge ──► gate           │
                   │           alert_error ─┐                      │
                   └────────────────────────┴──────────────────────┘

REPORT.md (A2, A3) has the full diagram and the edge table. Every conditional
edge function writes one `routing` event saying what it chose and who decided:
`model` when the choice follows from what the model asked for, `runtime` when
the runtime chose (budget, failsafes, refusals, end of queue).

Only the runtime writes classification rows. The model proposes a label through
submit_label. The dispatcher validates it. The settle node writes the row and
its state_change.

With repair enabled, settle routes vulnerable labels into repair nodes on this
same graph. Patch application, syntax checks, Bandit, tests, and retries finish
before next_alert. Both phases use the same trace and workflow token budget.
"""
from __future__ import annotations

import json
import math
import operator
from enum import StrEnum
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

from sio2 import prompts
from sio2.config import Config
from sio2.dispatch import Dispatcher, parse_arguments
from sio2.llm import ModelError
from sio2.repair import RepairNode, RepairWorkflow
from sio2.tools import SubmitLabel, Toolbox
from sio2.tools.scan import Alert, BanditScan
from sio2.trace import AlertStatus, Decider, EventKind, TerminalStatus, Trace
from sio2.workspace import Workspace


class Node(StrEnum):
    """The graph's nodes. Also the `node` field of every state_change they write."""

    DISCOVER = "discover"
    NEXT_ALERT = "next_alert"
    GATE = "gate"
    CLASSIFY = "classify"
    ACT = "act"
    NUDGE = "nudge"
    SETTLE = "settle"
    ALERT_ERROR = "alert_error"
    CUTOFF = "cutoff"
    MAX_STEPS = "max_steps"
    NO_PROGRESS = "no_progress"
    HALT = "halt"


class Route(StrEnum):
    """What a conditional edge can decide: the `decision` field of a routing event."""

    NEXT_ALERT = "next_alert"
    END = "end"
    GATE = "gate"
    CLASSIFY = "classify"
    CUTOFF = "cutoff"
    MAX_STEPS = "max_steps"
    ALERT_ERROR = "alert_error"
    TOOLS = "tools"
    SUBMIT = "submit"
    NUDGE = "nudge"
    SETTLE = "settle"
    NO_PROGRESS = "no_progress"
    REPAIR_BASELINE = "repair_baseline"


# --- reducers ---------------------------------------------------------------

def merge_rows(old: dict, new: dict) -> dict:
    """Rows are keyed by alert_id. Settling a row twice is a bug, so it raises."""
    out = dict(old or {})
    for k, v in (new or {}).items():
        if k in out:
            raise RuntimeError(f"row {k} settled twice")
        out[k] = v
    return out


class NewConversation(list):
    """Messages that replace the conversation instead of extending it: a new alert's opening."""


def append_or_reset(old: list, new: list) -> list:
    """Append messages; a NewConversation replaces them."""
    if isinstance(new, NewConversation):
        return list(new)
    return (old or []) + (new or [])


def add_usage(old: dict, new: dict) -> dict:
    out = dict(old or {})
    for k, v in (new or {}).items():
        out[k] = out.get(k, 0) + v
    return out



class AgentState(TypedDict, total=False):
    alerts: list[Alert]                                 # Discovery replaces the queue.
    cursor: int                                         # Position in the queue.
    rows: Annotated[dict, merge_rows]                   # Write-once classification rows.
    messages: Annotated[list, append_or_reset]          # Reset per alert.
    usage: Annotated[dict, add_usage]                   # All provider counters.

    steps: Annotated[int, operator.add]                 # Every node adds one.
    turns: int                                          # Classifier calls for this alert.
    stale: int                                          # Turns without new observations.
    signatures: list[str]                               # Tool requests for this alert.
    pending: list[dict]                                 # Requested classifier tools.

    submission: dict | None                             # Accepted label arguments.
    alert_reason: str                                   # Classification failure reason.
    status: str | None                                  # Workflow terminal status.
    status_reason: str                                  # Workflow terminal reason.

    repair_rows: Annotated[dict, merge_rows]             # Write-once repair outcomes.
    repair_usage: Annotated[dict, add_usage]             # Repair subset of usage.
    repair_baseline: dict
    repair_attempt: int
    repair_current: dict
    repair_messages: list[dict]
    repair_pending: dict | None
    repair_validation: dict
    repair_feedback: dict | None
    repair_stop: str


def make_row(alert: Alert, status: AlertStatus, label, rationale: str, evidence: list) -> dict:
    """One report.json row. The only place a row is built, in the graph or after a crash."""
    return {"alert_id": alert.alert_id, "test_id": alert.test_id, "path": alert.path,
            "line": alert.line, "severity": alert.severity, "confidence": alert.confidence,
            "label": label, "status": status, "rationale": rationale, "evidence": evidence}


def charged(usage: dict) -> int:
    return int(usage.get("input", 0)) + int(usage.get("output", 0))


class Agent:
    """Holds the run's services; its methods are the graph's nodes and edges."""

    def __init__(self, cfg: Config, ws: Workspace, trace: Trace, llm,
                 repairs: RepairWorkflow | None = None):
        self.cfg = cfg
        self.ws = ws
        self.trace = trace
        self.llm = llm
        self.repairs = repairs
        self.dispatch = Dispatcher(trace)
        self.toolbox: Toolbox | None = None   # the current alert's tools and evidence ledger
        # Every row whose settling state_change is already in the trace. If the
        # graph dies before LangGraph commits a node's update, the crash handler
        # takes rows from here, so no alert is settled twice in the trace.
        self.written_rows: dict[str, dict] = {}
        # The alerts discovery found, kept here as well as in state, so a crash
        # before LangGraph commits discover's update still reports every row.
        self.discovered: list = []

    # helpers -----------------------------------------------------------------

    def _alert(self, s: AgentState) -> Alert | None:
        c = s.get("cursor", -1)
        alerts = s.get("alerts") or []
        return alerts[c] if 0 <= c < len(alerts) else None

    def _aid(self, s: AgentState) -> str | None:
        a = self._alert(s)
        return a.alert_id if a else None

    def _route(self, s: AgentState, decision: Route, by: Decider, **extra) -> Route:
        self.trace.event(EventKind.ROUTING, self._aid(s), decision=decision, by=by, **extra)
        return decision

    def _row(self, s: AgentState, alert: Alert, status: AlertStatus, label, rationale: str,
             evidence: list, node: Node) -> dict:
        row = make_row(alert, status, label, rationale, evidence)
        self.trace.event(EventKind.STATE_CHANGE, alert.alert_id, node=node,
                         alert_status=status, label=label)
        self.written_rows[alert.alert_id] = row
        return {alert.alert_id: row}

    def _submit_only(self, s: AgentState) -> bool:
        """The alert's last `submit_only_turns` model turns offer only submit_label."""
        return s.get("turns", 0) >= self.cfg.agent.max_turns_per_alert - self.cfg.agent.submit_only_turns

    def _tools_for_turn(self, s: AgentState) -> list[dict]:
        return Toolbox.schemas(submit_only=self._submit_only(s))

    def _turns_left(self, s: AgentState) -> int:
        return self.cfg.agent.max_turns_per_alert - s.get("turns", 0)

    def _estimate(self, s: AgentState) -> int:
        """Tokens the next call may charge, for the pre-call check only. Never charged."""
        tools = self._tools_for_turn(s)
        chars = len(json.dumps(s.get("messages", []))) + len(json.dumps(tools))
        if self._submit_only(s):   # classify adds the submit-now instruction
            chars += len(json.dumps({"role": "user", "content": prompts.final_turns(self._turns_left(s))}))
        return math.ceil(chars / self.cfg.agent.chars_per_token) + self.cfg.budget.output_allowance

    # nodes -------------------------------------------------------------------

    def discover(self, s: AgentState) -> dict:
        scan = self.cfg.scan
        bandit = BanditScan(self.ws.root, scan.bandit_version, self.cfg.target)
        res = self.dispatch.run(None, bandit.name,
                                {"paths": list(scan.paths), "exclude": list(scan.exclude),
                                 "min_severity": scan.min_severity},
                                None, requested_by=Decider.RUNTIME, runtime_tools={bandit.name: bandit})
        if not res.ok:
            return {"steps": 1, "alerts": [], "cursor": -1, "status": TerminalStatus.ERROR,
                    "status_reason": res.text}
        alerts = bandit.found["alerts"]
        self.discovered = list(alerts)
        self.trace.event(EventKind.STATE_CHANGE, None, node=Node.DISCOVER,
                         alert_count=len(alerts), alert_ids=[a.alert_id for a in alerts])
        return {"steps": 1, "alerts": alerts, "cursor": -1, "rows": {}, "usage": {}}

    def next_alert(self, s: AgentState) -> dict:
        settled = s.get("rows") or {}
        alerts = s.get("alerts") or []
        c = s.get("cursor", -1) + 1
        while c < len(alerts) and alerts[c].alert_id in settled:
            c += 1
        if c >= len(alerts):
            self.ws.unfocus()
            return {"steps": 1, "cursor": c}
        alert = alerts[c]
        withheld = self.ws.focus(alert.path)
        self.toolbox = Toolbox(self.ws, self.cfg.agent.read_max_lines,
                               self.cfg.agent.search_max_hits, self.cfg.agent.list_max_entries)
        self.trace.event(EventKind.STATE_CHANGE, alert.alert_id, node=Node.NEXT_ALERT,
                         index=c, test_id=alert.test_id, path=alert.path, line=alert.line,
                         withheld_count=len(withheld) + len(self.ws._run_moved))
        # The opening observation: the runtime reads the code around the alert
        # through the same dispatcher and path check the model's tools use.
        n = self.cfg.agent.context_lines
        start = max(1, min(alert.line_range) - n)
        end = max(alert.line_range) + n
        res = self.dispatch.run(alert.alert_id, "read_file",
                                {"path": alert.path, "start_line": start, "end_line": end},
                                self.toolbox, requested_by=Decider.RUNTIME)
        first = NewConversation([
            {"role": "system", "content": prompts.system()},
            {"role": "user", "content": prompts.alert_message(
                alert, res.text, self.cfg.agent.max_turns_per_alert)}])
        return {"steps": 1, "cursor": c, "messages": first, "turns": 0, "stale": 0,
                "signatures": [], "pending": [], "submission": None, "alert_reason": "",
                "repair_attempt": 0, "repair_current": {}, "repair_messages": [], "repair_pending": None,
                "repair_validation": {}, "repair_feedback": None, "repair_stop": ""}

    def gate(self, s: AgentState) -> dict:
        """Runs before every model call. Its edge function makes the checks."""
        return {"steps": 1}

    def classify(self, s: AgentState) -> dict:
        tools = self._tools_for_turn(s)
        submit_only = self._submit_only(s)
        msgs = list(s["messages"])
        if submit_only:
            msgs.append({"role": "user", "content": prompts.final_turns(self._turns_left(s))})
        try:
            reply = self.llm.chat(msgs, tools)
        except ModelError as exc:
            return {"steps": 1, "turns": s.get("turns", 0) + 1, "pending": [],
                    "alert_reason": f"model call failed: {exc}"}
        calls = [{"name": c["name"], "arguments": parse_arguments(c["arguments"])}
                 for c in reply.tool_calls]
        self.trace.event(EventKind.MODEL_CALL, self._aid(s), role="classifier",
                         model=self.cfg.model.name, usage=reply.usage,
                         tool_calls=[c["name"] for c in calls], done_reason=reply.done_reason,
                         submit_only=submit_only)
        assistant = {"role": "assistant", "content": reply.content}
        if reply.tool_calls:
            assistant["tool_calls"] = [{"function": {"name": c["name"], "arguments": c["arguments"]}}
                                       for c in reply.tool_calls]
        new_msgs = ([msgs[-1]] if submit_only else []) + [assistant]
        return {"steps": 1, "turns": s.get("turns", 0) + 1, "usage": reply.usage,
                "messages": new_msgs, "pending": calls,
                "alert_reason": "" if calls else
                ("reply hit the output allowance" if reply.done_reason == "length"
                 else "reply did not call a tool")}

    def act(self, s: AgentState) -> dict:
        """Dispatch every requested call in order; stop after an accepted submission."""
        aid = self._aid(s)
        seen = list(s.get("signatures") or [])
        msgs, progress, submission = [], False, None
        last_refusal = s.get("alert_reason", "")
        pending = s.get("pending") or []
        self.toolbox.ledger.start_reply()
        # The turn these calls came from; classify has already counted it.
        offered = {SubmitLabel.name} if s.get("turns", 0) - 1 >= (
            self.cfg.agent.max_turns_per_alert - self.cfg.agent.submit_only_turns) else None
        for i, call in enumerate(pending):
            name, args = call["name"], call["arguments"]
            sig = f"{name}:{json.dumps(args, sort_keys=True, default=str)}"
            res = self.dispatch.run(aid, name, args, self.toolbox, offered=offered)
            msgs.append({"role": "tool", "tool_name": name, "content": res.text})
            if res.ok and name == SubmitLabel.name:
                submission = res.meta
                progress = True
                rest = [c["name"] for c in pending[i + 1:]]
                if rest:
                    self.trace.event(EventKind.STATE_CHANGE, aid, node=Node.ACT, skipped_calls=rest,
                                     reason="calls after an accepted submit_label are not run")
                break
            if res.ok and sig not in seen:
                progress = True
            if not res.ok:
                last_refusal = f"{name} refused: {res.text[len('REFUSED: '):][:300]}"
            seen.append(sig)
        if submission is None and msgs:
            # The runtime's own note, so the model can pace itself.
            msgs[-1] = {**msgs[-1], "content": msgs[-1]["content"] + prompts.turn_note(
                s.get("turns", 0), self.cfg.agent.max_turns_per_alert, self.cfg.agent.submit_only_turns)}
        stale = 0 if progress else s.get("stale", 0) + 1
        if not progress:
            self.trace.event(EventKind.STATE_CHANGE, aid, node=Node.ACT, stale=stale,
                             reason="no new observation this turn")
        return {"steps": 1, "messages": msgs, "signatures": seen, "stale": stale,
                "submission": submission, "pending": [], "alert_reason": last_refusal}

    def nudge(self, s: AgentState) -> dict:
        text = prompts.nudge(cut_off="allowance" in s.get("alert_reason", ""))
        stale = s.get("stale", 0) + 1
        self.trace.event(EventKind.STATE_CHANGE, self._aid(s), node=Node.NUDGE, stale=stale,
                         reason=s.get("alert_reason", ""))
        return {"steps": 1, "messages": [{"role": "user", "content": text}], "stale": stale}

    def settle(self, s: AgentState) -> dict:
        sub = s["submission"]
        row = self._row(s, self._alert(s), AlertStatus.CLASSIFIED, sub["label"], sub["rationale"],
                        sub["evidence"], node=Node.SETTLE)
        return {"steps": 1, "rows": row}

    def alert_error(self, s: AgentState) -> dict:
        reason = s.get("alert_reason") or ""
        if s.get("turns", 0) >= self.cfg.agent.max_turns_per_alert:
            reason = (f"no accepted submit_label after {s['turns']} model turns "
                      f"(max_turns_per_alert); last refusal or reason: {reason or 'none'}")
        reason = reason or "alert ended without a classification"
        row = self._row(s, self._alert(s), AlertStatus.ERROR, None, reason, [], node=Node.ALERT_ERROR)
        return {"steps": 1, "rows": row}

    def cutoff(self, s: AgentState) -> dict:
        """The budget cannot cover the next call: every unsettled row becomes budget_exhausted."""
        self.ws.unfocus()   # anything that can fail runs before the first settling event
        rows = {}
        settled = s.get("rows") or {}
        for alert in s.get("alerts") or []:
            if alert.alert_id not in settled:
                rows.update(self._row(s, alert, AlertStatus.BUDGET_EXHAUSTED, None, "", [], node=Node.CUTOFF))
        return {"steps": 1, "rows": rows, "status": TerminalStatus.BUDGET_EXHAUSTED,
                "status_reason": "token budget cannot cover the next model call"}

    def halt(self, s: AgentState) -> dict:
        """A failsafe fired: settle every unsettled row as error, with the reason."""
        status = s["status"]
        self.ws.unfocus()   # before the first settling event, as in cutoff
        rows = {}
        settled = s.get("rows") or {}
        for alert in s.get("alerts") or []:
            if alert.alert_id not in settled:
                rows.update(self._row(s, alert, AlertStatus.ERROR, None,
                                      f"run stopped by the {status} failsafe before this alert was classified",
                                      [], node=Node.HALT))
        return {"steps": 1, "rows": rows}

    # edges -------------------------------------------------------------------

    def after_discover(self, s: AgentState) -> Route:
        if s.get("status") == TerminalStatus.ERROR:
            return self._route(s, Route.END, Decider.RUNTIME, reason=s.get("status_reason", ""))
        return self._route(s, Route.NEXT_ALERT, Decider.RUNTIME, alerts=len(s.get("alerts") or []))

    def after_next_alert(self, s: AgentState) -> Route:
        if s["cursor"] >= len(s.get("alerts") or []):
            return self._route(s, Route.END, Decider.RUNTIME, reason="every alert is settled")
        return self._route(s, Route.GATE, Decider.RUNTIME)

    def after_gate(self, s: AgentState) -> Route:
        if s.get("steps", 0) >= self.cfg.budget.max_steps:
            return self._route(s, Route.MAX_STEPS, Decider.RUNTIME, steps=s["steps"],
                               max_steps=self.cfg.budget.max_steps)
        used = charged(s.get("usage") or {})
        remaining = self.cfg.budget.max_tokens - used
        required = self._estimate(s)
        if required > remaining:
            return self._route(s, Route.CUTOFF, Decider.RUNTIME, used=used, remaining=remaining,
                               required=required)
        if s.get("turns", 0) >= self.cfg.agent.max_turns_per_alert:
            return self._route(s, Route.ALERT_ERROR, Decider.RUNTIME,
                               reason=f"no accepted submission after {s['turns']} model turns")
        return self._route(s, Route.CLASSIFY, Decider.RUNTIME, remaining=remaining, required=required)

    def after_classify(self, s: AgentState) -> Route:
        if s.get("pending"):
            names = [c["name"] for c in s["pending"]]
            return self._route(s, Route.SUBMIT if SubmitLabel.name in names else Route.TOOLS,
                               Decider.MODEL, tool_calls=names)
        if s.get("alert_reason", "").startswith("model call failed"):
            return self._route(s, Route.ALERT_ERROR, Decider.RUNTIME, reason=s["alert_reason"])
        return self._route(s, Route.NUDGE, Decider.RUNTIME, reason=s.get("alert_reason", ""))

    def after_act(self, s: AgentState) -> Route:
        if s.get("submission"):
            return self._route(s, Route.SETTLE, Decider.RUNTIME, reason="submission accepted")
        if s.get("stale", 0) >= self.cfg.agent.no_progress_limit:
            return self._route(s, Route.NO_PROGRESS, Decider.RUNTIME, stale=s["stale"])
        return self._route(s, Route.GATE, Decider.RUNTIME)

    def after_settle(self, s: AgentState) -> Route:
        if self.repairs is not None and s["submission"]["label"] == 1:
            return self._route(s, Route.REPAIR_BASELINE, Decider.RUNTIME)
        return self._route(s, Route.NEXT_ALERT, Decider.RUNTIME)

    def after_nudge(self, s: AgentState) -> Route:
        if s.get("stale", 0) >= self.cfg.agent.no_progress_limit:
            return self._route(s, Route.NO_PROGRESS, Decider.RUNTIME, stale=s["stale"])
        return self._route(s, Route.GATE, Decider.RUNTIME)

    # build -------------------------------------------------------------------

    def set_status(self, status: TerminalStatus, reason: str):
        def node(s: AgentState) -> dict:
            return {"steps": 1, "status": status, "status_reason": reason}
        return node

    def build(self):
        g = StateGraph(AgentState)
        g.add_node(Node.DISCOVER, self.discover)
        g.add_node(Node.NEXT_ALERT, self.next_alert)
        g.add_node(Node.GATE, self.gate)
        g.add_node(Node.CLASSIFY, self.classify)
        g.add_node(Node.ACT, self.act)
        g.add_node(Node.NUDGE, self.nudge)
        g.add_node(Node.SETTLE, self.settle)
        g.add_node(Node.ALERT_ERROR, self.alert_error)
        g.add_node(Node.CUTOFF, self.cutoff)
        g.add_node(Node.MAX_STEPS, self.set_status(
            TerminalStatus.MAX_STEPS, f"max_steps={self.cfg.budget.max_steps} graph steps reached"))
        g.add_node(Node.NO_PROGRESS, self.set_status(
            TerminalStatus.NO_PROGRESS,
            f"{self.cfg.agent.no_progress_limit} model turns in a row produced no new observation"))
        g.add_node(Node.HALT, self.halt)

        g.add_edge(START, Node.DISCOVER)
        g.add_conditional_edges(Node.DISCOVER, self.after_discover,
                                {Route.NEXT_ALERT: Node.NEXT_ALERT, Route.END: END})
        g.add_conditional_edges(Node.NEXT_ALERT, self.after_next_alert,
                                {Route.GATE: Node.GATE, Route.END: END})
        g.add_conditional_edges(Node.GATE, self.after_gate,
                                {Route.CLASSIFY: Node.CLASSIFY, Route.CUTOFF: Node.CUTOFF,
                                 Route.MAX_STEPS: Node.MAX_STEPS, Route.ALERT_ERROR: Node.ALERT_ERROR})
        g.add_conditional_edges(Node.CLASSIFY, self.after_classify,
                                {Route.TOOLS: Node.ACT, Route.SUBMIT: Node.ACT, Route.NUDGE: Node.NUDGE,
                                 Route.ALERT_ERROR: Node.ALERT_ERROR})
        g.add_conditional_edges(Node.ACT, self.after_act,
                                {Route.SETTLE: Node.SETTLE, Route.GATE: Node.GATE,
                                 Route.NO_PROGRESS: Node.NO_PROGRESS})
        g.add_conditional_edges(Node.NUDGE, self.after_nudge,
                                {Route.GATE: Node.GATE, Route.NO_PROGRESS: Node.NO_PROGRESS})
        if self.repairs is not None:
            self.repairs.install(g)
            g.add_conditional_edges(Node.SETTLE, self.after_settle,
                                    {Route.REPAIR_BASELINE: RepairNode.BASELINE, Route.NEXT_ALERT: Node.NEXT_ALERT})
        else:
            g.add_edge(Node.SETTLE, Node.NEXT_ALERT)
        g.add_edge(Node.ALERT_ERROR, Node.NEXT_ALERT)
        g.add_edge(Node.CUTOFF, END)
        g.add_edge(Node.MAX_STEPS, Node.HALT)
        g.add_edge(Node.NO_PROGRESS, Node.HALT)
        g.add_edge(Node.HALT, END)
        return g.compile()
