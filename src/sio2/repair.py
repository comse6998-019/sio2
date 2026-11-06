"""Repair nodes for the agent's single LangGraph workflow.

This module owns candidate lifetimes and artifacts, not an execution loop.
The existing StateGraph schedules every proposal, tool, validation check, and retry.
"""
from __future__ import annotations

import json
import math
from dataclasses import asdict
from enum import StrEnum
from pathlib import Path

from sio2 import prompts, validation
from sio2.config import Config, Target
from sio2.dispatch import Dispatcher, parse_arguments
from sio2.llm import ModelError
from sio2.tools.base import Observation, Tool
from sio2.tools.patch import PatchResult, ProposePatch
from sio2.trace import Decider, EventKind, TerminalStatus, Trace
from sio2.workspace import PathRefused, Workspace


class RepairNode(StrEnum):
    BASELINE = "repair_baseline"
    PREPARE = "repair_prepare"
    GATE = "repair_gate"
    PROPOSE = "propose_patch"
    APPLY = "apply_patch"
    SYNTAX = "validate_syntax"
    BANDIT = "rerun_bandit"
    TESTS = "run_tests"
    REVIEW = "repair_review"
    SETTLE = "repair_settle"


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _messages(alert, row: dict, source: str, previous: dict | None, target: Target) -> list[dict]:
    request = {"finding": asdict(alert), "classification": row["rationale"],
               "allowed_path": alert.path, "original_source": source}
    content = json.dumps(request, indent=2)
    if previous:
        feedback = previous
        if target == Target.OWASP and "tests" in previous:
            feedback = {**previous, "tests": {key: value for key, value in previous["tests"].items()
                                               if key != "output"}}
        content += "\nPrevious validation:\n" + json.dumps(feedback, indent=2)
    return [{"role": "system", "content": prompts.load("repair")},
            {"role": "user", "content": content}]


class RuntimeCheck(Tool):
    """Execute one runtime validation check with no model-supplied arguments."""

    properties = {}

    def __init__(self, name: str, check):
        self.name = name
        self.check = check

    def run(self) -> Observation:
        result = self.check()
        return Observation(json.dumps(result), {"validation": result})


class RepairWorkflow:
    """Install repair nodes on the existing graph and own disposable candidates."""

    def __init__(self, cfg: Config, ws: Workspace, trace: Trace, model, output: Path, target: dict):
        self.cfg, self.ws, self.trace, self.model = cfg, ws, trace, model
        self.output = Path(output)
        self.path = self.output / "repair-report.json"
        if self.path.exists():
            raise ValueError("repair-report.json already exists. Select a fresh output directory.")
        self.dispatch = Dispatcher(trace)
        self.candidate: Workspace | None = None
        self.patch: PatchResult | None = None
        self.baseline_alerts = []
        self.settled: set[str] = set()
        self.report = {"status": "running", "target": target,
                       "budget": {"max_tokens": cfg.repair.max_tokens, "used_tokens": 0},
                       "baseline": {}, "alerts": []}
        self._save()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._close_candidate()

    def _close_candidate(self):
        if self.candidate is not None:
            self.candidate.__exit__(None, None, None)
            self.candidate = None
        self.patch = None

    def _save(self):
        _write_json(self.path, self.report)

    @staticmethod
    def _alert(s):
        return s["alerts"][s["cursor"]]

    def _outcome(self, s):
        aid = self._alert(s).alert_id
        for row in self.report["alerts"]:
            if row["alert_id"] == aid:
                return row
        row = {"alert_id": aid, "status": "pending", "attempts": []}
        self.report["alerts"].append(row)
        return row

    def _entered(self, s, node: RepairNode, **fields):
        self.trace.event(EventKind.STATE_CHANGE, self._alert(s).alert_id, node=node, **fields)

    def _route(self, s, decision: str, by=Decider.RUNTIME):
        if s.get("repair_stop") and isinstance(decision, RepairNode):
            decision = RepairNode.SETTLE
        self.trace.event(EventKind.ROUTING, self._alert(s).alert_id, decision=decision, by=by)
        return decision

    def _persist_attempt(self, s, current):
        outcome = self._outcome(s)
        attempts = outcome["attempts"]
        if attempts and attempts[-1]["number"] == current["number"]:
            attempts[-1] = current
        else:
            attempts.append(current)
        outcome["status"] = current["validation"]["status"]
        _write_json(self._folder(s) / "result.json", current)
        self._save()

    def _folder(self, s):
        return self.output / "validation" / self._alert(s).alert_id / str(s["repair_attempt"])

    def _check(self, s, name, callback):
        tool = RuntimeCheck(name, callback)
        result = self.dispatch.run(self._alert(s).alert_id, name, {}, None,
                                   requested_by=Decider.RUNTIME, runtime_tools={name: tool})
        return result.meta["validation"] if result.ok else {"status": "error", "error": result.text}

    def _baseline_scan(self, s):
        scan = validation.run_bandit(self.ws.root, self.cfg.scan, self.cfg.target)
        self.baseline_alerts = scan["alerts"]
        _write_json(self.output / "validation/bandit-baseline.json", {
            "alerts": [asdict(alert) for alert in scan["alerts"]], "version": scan["version"],
            "argv": scan["argv"], "bandit_errors": scan["bandit_errors"]})
        same_ids = {a.alert_id for a in scan["alerts"]} == {a.alert_id for a in s["alerts"]}
        return {"status": "passed" if same_ids and not scan["bandit_errors"] else "error",
                "alert_count": len(scan["alerts"]), "errors": scan["bandit_errors"]}

    def baseline(self, s):
        self._entered(s, RepairNode.BASELINE)
        self._outcome(s)
        if not self.report["baseline"]:
            self.ws.unfocus()
            scan = self._check(s, "repair_baseline_scan", lambda: self._baseline_scan(s))
            tests = self._check(s, "baseline_tests", lambda: validation.run_tests(self.ws.root, self.cfg.repair)) \
                if scan["status"] == "passed" else {"status": "not_run"}
            self.report["baseline"] = {"bandit": scan, "tests": tests}
        baseline = self.report["baseline"]
        blocked = baseline["bandit"]["status"] != "passed" or baseline["tests"]["status"] not in (
            "passed", "not_configured")
        self._save()
        return {"steps": 1, "repair_baseline": baseline,
                "repair_validation": {"status": "blocked" if blocked else "pending"}}

    def prepare(self, s):
        self._close_candidate()
        self.ws.unfocus()
        self.candidate = Workspace(self.ws.root, self.cfg.target)
        self.candidate.__enter__()
        self._entered(s, RepairNode.PREPARE, candidate=str(self.candidate.root))
        try:
            alert = self._alert(s)
            self.candidate.focus(alert.path)
            full, _ = self.candidate.resolve(alert.path)
            if full.stat().st_size > 48000:
                return {"steps": 1, "repair_validation": {"status": "source_too_large"}}
            source = full.read_bytes().decode("utf-8")
            messages = _messages(alert, s["rows"][alert.alert_id], source,
                                 s.get("repair_feedback"), self.cfg.target)
        except (PathRefused, OSError, UnicodeError) as exc:
            return {"steps": 1, "repair_validation": {"status": "error", "error": str(exc)}}
        current = {"number": s.get("repair_attempt", 0) + 1, "validation": {
            "status": "pending", "syntax": {"status": "not_run"},
            "bandit": {"status": "not_run"}, "tests": {"status": "not_run"}}}
        return {"steps": 1, "repair_attempt": current["number"], "repair_current": current,
                "repair_messages": messages, "repair_validation": current["validation"], "repair_pending": None}

    def gate(self, s):
        self._entered(s, RepairNode.GATE)
        used = sum(s.get("usage", {}).get(key, 0) for key in ("input", "output"))
        required = math.ceil((len(json.dumps(s["repair_messages"])) + len(json.dumps(ProposePatch.schema()))) / 3)
        required += self.cfg.repair.output_allowance
        stop, status = "", "pending"
        if s.get("steps", 0) + 1 >= self.cfg.budget.max_steps:
            stop, status = "max_steps", "max_steps"
        elif used + required > self.cfg.budget.max_tokens:
            stop, status = "cutoff", "budget_exhausted"
        elif self.report["budget"]["used_tokens"] + required > self.cfg.repair.max_tokens:
            status = "budget_exhausted"
        return {"steps": 1, "repair_stop": stop,
                "repair_validation": {**s["repair_validation"], "status": status}}

    def propose_patch(self, s):
        self._entered(s, RepairNode.PROPOSE)
        current, usage, pending = dict(s["repair_current"]), {}, None
        checks = dict(s["repair_validation"])
        try:
            reply = self.model.chat(s["repair_messages"], [ProposePatch.schema()])
            if any(type(reply.usage.get(key)) is not int or reply.usage[key] < 0 for key in ("input", "output")):
                raise ModelError("repair reply has invalid usage counters")
            usage = reply.usage
            self.trace.event(EventKind.MODEL_CALL, self._alert(s).alert_id, role="repair", model=self.cfg.model.name,
                             usage=usage, tool_calls=[call.get("name", "") for call in reply.tool_calls],
                             done_reason=reply.done_reason)
            self.report["budget"]["used_tokens"] += usage["input"] + usage["output"]
            current["usage"] = usage
            if reply.done_reason in ("length", "max_tokens"):
                checks.update(status="rejected", patch={"status": "refused", "error": "Model output reached its limit."})
            elif len(reply.tool_calls) != 1 or reply.tool_calls[0].get("name") != ProposePatch.name:
                checks.update(status="rejected", patch={"status": "refused", "error": "Call propose_patch exactly once."})
            else:
                pending = {"name": ProposePatch.name,
                           "arguments": parse_arguments(reply.tool_calls[0].get("arguments"))}
        except (ModelError, OSError) as exc:
            checks.update(status="error", error=str(exc))
        current["validation"] = checks
        self._persist_attempt(s, current)
        return {"steps": 1, "usage": usage, "repair_usage": usage, "repair_pending": pending,
                "repair_current": current, "repair_validation": checks}

    def apply_patch(self, s):
        self._entered(s, RepairNode.APPLY)
        tool = ProposePatch(self.candidate, {self._alert(s).path})
        pending = s["repair_pending"]
        result = self.dispatch.run(self._alert(s).alert_id, pending["name"], pending["arguments"], None,
                                   offered={ProposePatch.name}, model_tools={ProposePatch.name: tool})
        current, checks = dict(s["repair_current"]), dict(s["repair_validation"])
        if result.ok:
            self.patch = tool.applied
            folder = self._folder(s)
            _write_json(folder / "proposal.json", pending["arguments"])
            (folder / "candidate.diff").write_text(self.patch.diff, encoding="utf-8")
            current["diff"] = (folder / "candidate.diff").relative_to(self.output).as_posix()
            self.candidate.unfocus()
            checks["patch"] = {"status": "passed"}
        else:
            checks.update(status="rejected", patch={"status": "refused", "error": result.text})
        current["validation"] = checks
        self._persist_attempt(s, current)
        return {"steps": 1, "repair_current": current, "repair_validation": checks, "repair_pending": None}

    def _validation_node(self, s, node, field, tool_name, callback):
        self._entered(s, node)
        checks = {**s["repair_validation"], field: self._check(s, tool_name, callback)}
        if checks[field]["status"] != "passed":
            checks["status"] = "rejected"
        current = {**s["repair_current"], "validation": checks}
        self._persist_attempt(s, current)
        return {"steps": 1, "repair_current": current, "repair_validation": checks}

    def validate_syntax(self, s):
        return self._validation_node(s, RepairNode.SYNTAX, "syntax", "validate_syntax",
                                     lambda: validation.check_syntax(self.candidate.root, self.patch))

    def rerun_bandit(self, s):
        return self._validation_node(s, RepairNode.BANDIT, "bandit", "rerun_bandit", lambda:
            validation.check_bandit(self.candidate.root, self.cfg, self.baseline_alerts, self._alert(s), self.patch))

    def run_tests(self, s):
        update = self._validation_node(s, RepairNode.TESTS, "tests", "candidate_tests",
                                       lambda: validation.run_tests(self.candidate.root, self.cfg.repair))
        checks = update["repair_validation"]
        status = checks["tests"]["status"]
        if status == "passed" and self.report["baseline"]["tests"]["status"] == "passed":
            checks["status"] = "accepted"
        elif status == "failed":
            checks["status"] = "rejected"
        else:
            checks["status"] = "unvalidated"
        self._persist_attempt(s, update["repair_current"])
        return update

    def review(self, s):
        self._entered(s, RepairNode.REVIEW, validation=s["repair_validation"])
        return {"steps": 1, "repair_feedback": s["repair_validation"]}

    def settle(self, s):
        outcome = self._outcome(s)
        outcome["status"] = s["repair_validation"]["status"]
        if outcome["status"] == "accepted":
            path = self.output / "patches" / f"{self._alert(s).alert_id}.diff"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.patch.diff, encoding="utf-8")
            outcome["patch"] = path.relative_to(self.output).as_posix()
        self._close_candidate()
        self._save()
        self.settled.add(outcome["alert_id"])
        self._entered(s, RepairNode.SETTLE, repair_status=outcome["status"])
        return {"steps": 1, "repair_rows": {outcome["alert_id"]: dict(outcome)}}

    def finalize(self, state, status, reason):
        """Save outcomes before the workflow's single terminal event."""
        self._close_candidate()
        for row in self.report["alerts"]:
            if row["alert_id"] not in self.settled:
                row["status"] = "interrupted"
                for attempt in row["attempts"]:
                    if attempt["validation"]["status"] == "pending":
                        attempt["validation"] = {**attempt["validation"], "status": "interrupted"}
                        _write_json(self.output / "validation" / row["alert_id"] / str(attempt["number"]) / "result.json", attempt)
        outcomes = {row["status"] for row in self.report["alerts"]}
        if "blocked" in outcomes:
            final = "blocked"
        elif outcomes & {"error", "interrupted"}:
            final = "error"
        elif "budget_exhausted" in outcomes:
            final = "budget_exhausted"
        else:
            final = str(status)
        self.report["status"] = final
        if reason:
            self.report["reason"] = reason
        self._save()
        self.trace.event(EventKind.STATE_CHANGE, None, node="repair_finish", repair_status=final)
        return self.report

    def after_baseline(self, s):
        return self._route(s, RepairNode.SETTLE if s["repair_validation"]["status"] == "blocked" else RepairNode.PREPARE)

    def after_prepare(self, s):
        return self._route(s, RepairNode.GATE if s["repair_validation"]["status"] == "pending" else RepairNode.SETTLE)

    def after_gate(self, s):
        return self._route(s, RepairNode.PROPOSE if s["repair_validation"]["status"] == "pending" else RepairNode.SETTLE)

    def after_propose(self, s):
        if s.get("repair_pending"):
            return self._route(s, RepairNode.APPLY, Decider.MODEL)
        return self._route(s, RepairNode.REVIEW)

    def after_apply(self, s):
        return self._route(s, RepairNode.SYNTAX if s["repair_validation"].get("patch", {}).get("status") == "passed"
                           else RepairNode.REVIEW)

    def after_syntax(self, s):
        return self._route(s, RepairNode.BANDIT if s["repair_validation"]["syntax"]["status"] == "passed"
                           else RepairNode.REVIEW)

    def after_bandit(self, s):
        return self._route(s, RepairNode.TESTS if s["repair_validation"]["bandit"]["status"] == "passed"
                           else RepairNode.REVIEW)

    def after_tests(self, s):
        return self._route(s, RepairNode.REVIEW)

    def after_review(self, s):
        retry = s["repair_validation"]["status"] == "rejected" and s["repair_attempt"] < self.cfg.repair.max_attempts
        return self._route(s, RepairNode.PREPARE if retry else RepairNode.SETTLE)

    def after_settle(self, s):
        return self._route(s, s.get("repair_stop") or "next_alert")

    def _bounded_node(self, name, function):
        def execute(s):
            if name != RepairNode.SETTLE and s.get("steps", 0) >= self.cfg.budget.max_steps:
                self._entered(s, name, reason="Workflow step limit reached.")
                checks = {**s.get("repair_validation", {}), "status": "max_steps"}
                current = {**s.get("repair_current", {}), "validation": checks}
                if current.get("usage"):
                    self._persist_attempt(s, current)
                return {"steps": 1, "repair_stop": "max_steps", "repair_validation": checks,
                        "repair_current": current}
            return function(s)
        return execute

    def install(self, graph):
        """Register nodes and edges on the caller's StateGraph. Never compile another graph."""
        nodes = {RepairNode.BASELINE: self.baseline, RepairNode.PREPARE: self.prepare,
                 RepairNode.GATE: self.gate, RepairNode.PROPOSE: self.propose_patch,
                 RepairNode.APPLY: self.apply_patch, RepairNode.SYNTAX: self.validate_syntax,
                 RepairNode.BANDIT: self.rerun_bandit, RepairNode.TESTS: self.run_tests,
                 RepairNode.REVIEW: self.review, RepairNode.SETTLE: self.settle}
        for name, function in nodes.items():
            graph.add_node(name, self._bounded_node(name, function))
        routes = {
            RepairNode.BASELINE: (self.after_baseline, [RepairNode.PREPARE, RepairNode.SETTLE]),
            RepairNode.PREPARE: (self.after_prepare, [RepairNode.GATE, RepairNode.SETTLE]),
            RepairNode.GATE: (self.after_gate, [RepairNode.PROPOSE, RepairNode.SETTLE]),
            RepairNode.PROPOSE: (self.after_propose, [RepairNode.APPLY, RepairNode.REVIEW, RepairNode.SETTLE]),
            RepairNode.APPLY: (self.after_apply, [RepairNode.SYNTAX, RepairNode.REVIEW, RepairNode.SETTLE]),
            RepairNode.SYNTAX: (self.after_syntax, [RepairNode.BANDIT, RepairNode.REVIEW, RepairNode.SETTLE]),
            RepairNode.BANDIT: (self.after_bandit, [RepairNode.TESTS, RepairNode.REVIEW, RepairNode.SETTLE]),
            RepairNode.TESTS: (self.after_tests, [RepairNode.REVIEW, RepairNode.SETTLE]),
            RepairNode.REVIEW: (self.after_review, [RepairNode.PREPARE, RepairNode.SETTLE]),
            RepairNode.SETTLE: (self.after_settle, ["next_alert", "cutoff", "max_steps"]),
        }
        for name, (router, destinations) in routes.items():
            graph.add_conditional_edges(name, router, {destination: destination for destination in destinations})


if __name__ == "__main__":
    raise SystemExit("Use sio2 --input TARGET --output RUN --config CONFIG --repair for the single workflow.")
