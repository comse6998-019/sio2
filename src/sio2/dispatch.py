"""The dispatcher: the only code that runs tools and the only author of observations.

For each request it writes `tool_request`, validates the arguments against the
tool class's own schema, runs it, and writes the matching `tool_result`
immediately after, one request at a time. Unknown tools,
bad arguments and tool refusals come back as `ok: false` observations; they are
never raised into the graph. A tool that crashes is also caught here and
reported as a refusal, so one bad file cannot end the run.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import jsonschema

from sio2.tools import Tool, Toolbox, ToolRefused
from sio2.trace import Decider, EventKind, Trace


@dataclass
class Result:
    tool: str
    args: dict
    ok: bool
    text: str           # the observation the model will read
    meta: dict


class Dispatcher:
    max_observation_chars = 12_000

    def __init__(self, trace: Trace):
        self.trace = trace

    def run(self, alert_id: str | None, tool: str, args, toolbox: Toolbox | None,
            requested_by: Decider = Decider.MODEL, runtime_tools: dict[str, Tool] | None = None,
            offered: set[str] | None = None, model_tools: dict[str, Tool] | None = None) -> Result:
        """Validate and run one request.

        `runtime_tools` are reachable only by the runtime. `offered` is the set of
        tools the model was given on this turn; a model request outside it is refused.
        """
        shown_args = args if isinstance(args, dict) else {"_raw": args}
        requested = False
        try:
            self.trace.event(EventKind.TOOL_REQUEST, alert_id, tool=str(tool) or "?",
                             args=shown_args, requested_by=requested_by)
            requested = True
            text, meta = self._execute(tool, args, toolbox, requested_by, runtime_tools or {}, offered,
                                       model_tools or {})
        except ToolRefused as exc:
            return self._result(alert_id, tool, shown_args, False, str(exc), {})
        except Exception as exc:  # a tool bug is an observation, not a crash
            if not requested:
                raise
            return self._result(alert_id, tool, shown_args, False,
                                f"tool failed: {type(exc).__name__}: {exc}", {})
        except BaseException as exc:  # Ctrl-C: pair the request with its result, then let it propagate
            if requested:
                self._result(alert_id, tool, shown_args, False, f"interrupted: {type(exc).__name__}", {})
            raise
        return self._result(alert_id, tool, shown_args, True, text, meta)

    def _execute(self, name, args, toolbox, requested_by, runtime_tools, offered, model_tools):
        if requested_by == Decider.RUNTIME and name in runtime_tools:
            tool = runtime_tools[name]
        elif requested_by == Decider.MODEL and name in model_tools:
            tool = model_tools[name]
        elif toolbox is not None and toolbox.get(name) is not None:
            tool = toolbox.get(name)
        else:
            known = ", ".join(sorted(Toolbox.names()))
            raise ToolRefused(f"unknown tool {name!r}; available tools: {known}")
        if requested_by == Decider.MODEL and offered is not None and name not in offered:
            raise ToolRefused(f"{name} is not available on this turn; available: {', '.join(sorted(offered))}")
        if not isinstance(args, dict):
            raise ToolRefused(f"arguments for {name} must be a JSON object")
        try:
            jsonschema.validate(args, tool.parameters())
        except jsonschema.ValidationError as exc:
            where = "/".join(str(p) for p in exc.absolute_path) or "arguments"
            raise ToolRefused(f"bad arguments for {name}: {where}: {exc.message}") from exc
        floats = [k for k, v in args.items() if isinstance(v, float)
                  and tool.properties.get(k, {}).get("type") == "integer"]
        if floats:   # JSON Schema's "integer" accepts 1.0; our tools want real integers
            raise ToolRefused(f"bad arguments for {name}: {', '.join(floats)} must be an integer, not a float")
        obs = tool.run(**args)
        return obs.text, obs.meta

    def _result(self, alert_id, tool, args, ok, text, meta) -> Result:
        if len(text) > self.max_observation_chars:
            text = text[:self.max_observation_chars] + "\n…[observation truncated]"
        fields = {"tool": str(tool) or "?", "ok": ok, "chars": len(text)}
        if ok:
            fields.update({k: v for k, v in meta.items() if k not in ("rationale",)})
        else:
            fields["error"] = text or "refused"
            text = f"REFUSED: {text}"
        self.trace.event(EventKind.TOOL_RESULT, alert_id, **fields)
        return Result(str(tool), args if isinstance(args, dict) else {}, ok, text, meta)


def parse_arguments(raw) -> dict | str:
    """Tool-call arguments as a dict. Ollama usually sends an object; some models send a string."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            val = json.loads(raw)
            return val if isinstance(val, dict) else raw
        except json.JSONDecodeError:
            return raw
    return raw
