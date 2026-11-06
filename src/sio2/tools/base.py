"""A tool: its arguments, its limits, its work, and what the model is shown.

A subclass sets `name`, a one-line docstring (the description the model reads),
`properties` and `required` (the JSON Schema of its arguments), and writes
`run`. `schema()` builds what the model is shown from the same class that runs
the tool, so a description cannot drift from the code behind it.

A tool signals a refusal by raising `ToolRefused`. It never writes the trace and
never catches its own failures: turning a refusal or a crash into an
observation is the dispatcher's job, because only the dispatcher records it.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from sio2.workspace import PathRefused, Workspace


class ToolRefused(Exception):
    """A tool declined the request. The message becomes the observation."""


@dataclass
class Observation:
    text: str                                   # what the model reads
    meta: dict = field(default_factory=dict)    # what the trace records


class EvidenceLedger:
    """The line ranges this alert's observations have shown the model.

    `submit_label` checks evidence against it, so a rationale cannot cite lines
    the model never saw. `start_reply()` freezes the ledger as it stood when the
    model wrote its current reply: a read in the same reply as the submission
    does not count, because the model had not seen that read's output yet.
    """

    def __init__(self):
        self.seen: dict[str, list[tuple[int, int]]] = {}
        self.shown_before_reply: dict[str, list[tuple[int, int]]] | None = None

    def start_reply(self) -> None:
        self.shown_before_reply = {k: list(v) for k, v in self.seen.items()}

    def note(self, path: str, start: int, end: int) -> None:
        self.seen.setdefault(path, []).append((start, end))

    def shown(self, path: str) -> list[tuple[int, int]]:
        """The ranges a submission may cite in `path`."""
        ledger = self.seen if self.shown_before_reply is None else self.shown_before_reply
        return ledger.get(path, [])

    def covers(self, path: str, start: int, end: int) -> bool:
        """True when the union of the ranges shown before this reply covers start..end."""
        covered = start
        for s, e in sorted(self.shown(path)):
            if s > covered:
                break
            covered = max(covered, e + 1)
            if covered > end:
                return True
        return False


class Tool(ABC):
    name: ClassVar[str]
    properties: ClassVar[dict]
    required: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def run(self, **args) -> Observation:
        """The work. Raise ToolRefused to decline; the dispatcher records it."""

    @classmethod
    def parameters(cls) -> dict:
        """The JSON Schema the dispatcher validates the model's arguments against."""
        return {"type": "object", "properties": cls.properties, "required": list(cls.required),
                "additionalProperties": False}

    @classmethod
    def schema(cls) -> dict:
        """What the model is shown: name, description and parameters."""
        return {"type": "function", "function": {
            "name": cls.name, "description": cls.__doc__, "parameters": cls.parameters()}}


class WorkspaceTool(Tool):
    """A model tool bound to one alert's workspace and evidence ledger."""

    max_file_bytes: ClassVar[int] = 2_000_000
    max_line_chars: ClassVar[int] = 300

    def __init__(self, ws: Workspace, ledger: EvidenceLedger):
        self.ws = ws
        self.ledger = ledger

    def resolve(self, path: str) -> tuple[Path, str]:
        """The workspace's one path check, with its refusal turned into a tool refusal."""
        try:
            return self.ws.resolve(path)
        except PathRefused as exc:
            raise ToolRefused(str(exc)) from exc

    def text_lines(self, path: str) -> tuple[str, list[str]]:
        full, rel = self.resolve(path)
        if not full.exists():
            raise ToolRefused(f"{path!r} does not exist")
        if full.is_dir():
            raise ToolRefused(f"{path!r} is a directory; use list_dir")
        if full.stat().st_size > self.max_file_bytes:
            raise ToolRefused(f"{path!r} is larger than {self.max_file_bytes} bytes")
        raw = full.read_bytes()
        if b"\x00" in raw[:8192]:
            raise ToolRefused(f"{path!r} is a binary file")
        return rel, raw.decode("utf-8", errors="replace").splitlines()

    def clip(self, line: str) -> str:
        n = self.max_line_chars
        return line if len(line) <= n else line[:n] + " …[truncated]"
