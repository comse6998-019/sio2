"""The run's trajectory: trace.jsonl, one event per line.

Every component writes here and nothing else writes the file. Each event gets
the next `step`, a wall-clock `ts`, the `run_id` and its `alert_id`, and is
flushed before `event()` returns, so a crashed run leaves the trace that
explains the crash.

`usage_total` is accumulated from the model_call events as they are written, so
the terminal event cannot disagree with the lines above it. The budget charge
(`input + output`) is derived from the same counters.

    with Trace(path, run_id) as trace:
        trace.event(EventKind.ROUTING, alert_id, decision="tools", by=Decider.MODEL)
        trace.terminal(TerminalStatus.COMPLETED)

Leaving the `with` block closes the file. A block left by an exception before
any terminal event writes `error` as the last line, so even a run that dies
outside the CLI's own crash handling states how it ended.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, fields
from enum import StrEnum
from pathlib import Path


class EventKind(StrEnum):
    MODEL_CALL = "model_call"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    ROUTING = "routing"
    STATE_CHANGE = "state_change"
    TERMINAL = "terminal"


class TerminalStatus(StrEnum):
    """How a run ends. Closed and mutually exclusive; see REPORT.md, A6."""

    COMPLETED = "completed"                # every alert settled by its own path
    BUDGET_EXHAUSTED = "budget_exhausted"  # the token budget could not cover the next model call
    MAX_STEPS = "max_steps"                # the graph-step failsafe fired
    NO_PROGRESS = "no_progress"            # too many turns in a row produced nothing new
    ERROR = "error"                        # discovery failed, or an exception escaped the graph


class AlertStatus(StrEnum):
    """How one report row was settled."""

    CLASSIFIED = "classified"
    BUDGET_EXHAUSTED = "budget_exhausted"
    ERROR = "error"


class Decider(StrEnum):
    """Who made a routing decision, or asked for a tool: the `by` and `requested_by` fields."""

    MODEL = "model"
    RUNTIME = "runtime"


@dataclass
class Usage:
    """Provider-reported counters, kept apart. There is no summed total."""

    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_write: int = 0

    @classmethod
    def counters(cls) -> list[str]:
        return [f.name for f in fields(cls)]

    def add(self, counts: dict) -> None:
        for name, value in counts.items():
            if name not in self.counters():
                raise ValueError(f"unknown token counter {name!r}")
            setattr(self, name, getattr(self, name) + int(value))

    @property
    def charged(self) -> int:
        """The budget charge: input + output. Cache counters are never charged."""
        return self.input + self.output

    def as_dict(self, keep_zero_cache: bool = False) -> dict:
        d = asdict(self)
        if not keep_zero_cache:
            # Report a cache counter only if some call reported it.
            for k in ("cache_read", "cache_write"):
                if not self._seen.get(k):
                    d.pop(k)
        return d

    def __post_init__(self):
        self._seen: dict[str, bool] = {}


class Trace:
    """Append-only JSONL writer for one run."""

    def __init__(self, path: Path, run_id: str, echo=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self._fh = self.path.open("w", encoding="utf-8")
        self._step = 0
        self.usage = Usage()
        self.terminal_status: str | None = None
        self.echo = echo  # optional console spectator; it never changes what is written

    @property
    def step(self) -> int:
        return self._step

    def event(self, kind: EventKind | str, alert_id: str | None = None, **fields) -> dict:
        kind = EventKind(kind).value
        if self.terminal_status is not None:
            raise RuntimeError(f"run already ended with {self.terminal_status!r}")
        if kind == EventKind.MODEL_CALL.value:
            self.usage.add(fields["usage"])
            for k in ("cache_read", "cache_write"):
                if k in fields["usage"]:
                    self.usage._seen[k] = True
        self._step += 1
        record = {"step": self._step, "ts": time.time(), "run_id": self.run_id,
                  "alert_id": alert_id, "kind": kind, **fields}
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()
        if self.echo is not None:
            try:
                self.echo(record)
            except Exception:
                pass
        return record

    def terminal(self, status: TerminalStatus | str, **fields) -> dict:
        status = TerminalStatus(status).value
        record = self.event(EventKind.TERMINAL, None, status=status,
                            usage_total=self.usage.as_dict(), **fields)
        self.terminal_status = status
        return record

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "Trace":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is not None and self.terminal_status is None:
                self.terminal(TerminalStatus.ERROR, reason=f"{exc_type.__name__}: {exc}")
        finally:
            self.close()


def read_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
