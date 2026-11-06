"""The tools, as classes, and the toolbox that binds the model's tools to one alert.

    toolbox = Toolbox(ws, read_max_lines=120, search_max_hits=30, list_max_entries=150)
    toolbox.get("read_file")          # a bound ReadFile, or None
    Toolbox.schemas(submit_only=True)  # what the model is shown on a submit-only turn

Model tools: `ReadFile`, `Search`, `ListDir` (files.py) and `SubmitLabel`
(submit.py). The runtime tool `BanditScan` (scan.py) is deliberately not in the
toolbox: a model request for it is an unknown tool, which is a refusal.
"""
from __future__ import annotations

from sio2.tools.base import EvidenceLedger, Observation, Tool, ToolRefused, WorkspaceTool
from sio2.tools.files import ListDir, ReadFile, Search
from sio2.tools.submit import SubmitLabel
from sio2.workspace import Workspace

__all__ = ["EvidenceLedger", "ListDir", "Observation", "ReadFile", "Search", "SubmitLabel",
           "Tool", "ToolRefused", "Toolbox", "WorkspaceTool"]


class Toolbox:
    """The model's tools for one alert, bound to its workspace and a fresh evidence ledger."""

    # The order the model is shown them in.
    classes: tuple[type[WorkspaceTool], ...] = (ReadFile, Search, ListDir, SubmitLabel)

    def __init__(self, ws: Workspace, read_max_lines: int, search_max_hits: int,
                 list_max_entries: int):
        self.ledger = EvidenceLedger()
        self.tools: dict[str, WorkspaceTool] = {
            ReadFile.name: ReadFile(ws, self.ledger, read_max_lines),
            Search.name: Search(ws, self.ledger, search_max_hits),
            ListDir.name: ListDir(ws, self.ledger, list_max_entries),
            SubmitLabel.name: SubmitLabel(ws, self.ledger),
        }

    def get(self, name: str) -> WorkspaceTool | None:
        return self.tools.get(name)

    @classmethod
    def names(cls) -> list[str]:
        return [c.name for c in cls.classes]

    @classmethod
    def schemas(cls, submit_only: bool = False) -> list[dict]:
        """What the model is shown this turn. A submit-only turn offers submit_label alone."""
        return [SubmitLabel.schema()] if submit_only else [c.schema() for c in cls.classes]
