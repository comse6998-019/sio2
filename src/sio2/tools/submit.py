"""submit_label: the model's proposed classification, checked before the runtime settles a row."""
from __future__ import annotations

from typing import ClassVar

from sio2.tools.base import Observation, ToolRefused, WorkspaceTool


class SubmitLabel(WorkspaceTool):
    """Submit your final classification of this alert. Ends the investigation of this alert."""
    name = "submit_label"
    properties = {"label": {"type": "integer", "enum": [0, 1],
                            "description": "1 = potential vulnerability, 0 = not a vulnerability"},
                  "rationale": {"type": "string",
                                "description": "Two to four sentences citing the line numbers you read"},
                  "evidence": {"type": "array", "minItems": 1, "items": {
                      "type": "object",
                      "properties": {"path": {"type": "string"},
                                     "start_line": {"type": "integer", "minimum": 1},
                                     "end_line": {"type": "integer", "minimum": 1}},
                      "required": ["path", "start_line", "end_line"]}}}
    required = ("label", "rationale", "evidence")

    max_rationale_chars: ClassVar[int] = 1500
    max_evidence: ClassVar[int] = 5

    def run(self, label: int, rationale: str, evidence: list) -> Observation:
        """Accept or refuse. Accepting writes nothing: the runtime, not the model, settles the row."""
        if type(label) is not int or label not in (0, 1):
            raise ToolRefused("label must be 1 (potential vulnerability) or 0 (not a vulnerability)")
        rationale = rationale.strip()
        if not rationale:
            raise ToolRefused("rationale must not be empty")
        if len(rationale) > self.max_rationale_chars:
            raise ToolRefused(f"rationale must be at most {self.max_rationale_chars} characters")
        if not evidence:
            raise ToolRefused("give at least one evidence range you read")
        if len(evidence) > self.max_evidence:
            raise ToolRefused(f"give at most {self.max_evidence} evidence ranges")
        clean = []
        for i, ev in enumerate(evidence):
            if not isinstance(ev, dict):
                raise ToolRefused(f"evidence[{i}] must be an object with path, start_line, end_line")
            p, s, e = ev.get("path"), ev.get("start_line"), ev.get("end_line")
            if not isinstance(p, str) or not isinstance(s, int) or not isinstance(e, int) \
                    or isinstance(s, bool) or isinstance(e, bool):
                raise ToolRefused(f"evidence[{i}] needs a string path and integer start_line, end_line")
            try:
                _, rel = self.resolve(p)
            except ToolRefused as exc:
                raise ToolRefused(f"evidence[{i}]: {exc}") from exc
            if s < 1 or e < s:
                raise ToolRefused(f"evidence[{i}]: need 1 <= start_line <= end_line")
            if not self.ledger.covers(rel, s, e):
                seen = ", ".join(f"{a}-{b}" for a, b in self.ledger.shown(rel)) or "none"
                raise ToolRefused(f"evidence[{i}] cites {rel} lines {s}-{e}, which no observation "
                                  f"showed you (ranges seen in {rel}: {seen}); cite lines you read")
            clean.append({"path": rel, "start_line": s, "end_line": e})
        return Observation("accepted", {"label": label, "rationale": rationale, "evidence": clean})
