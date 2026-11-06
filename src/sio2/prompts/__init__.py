"""What the model is told.

One Markdown file per prompt, so a change to what the model reads shows up in a
diff on its own, apart from any control flow:

    system.md          the classifier's standing instructions
    alert.md           one alert and the runtime's opening read: the task
    turn_note.md       the runtime's note after each turn's observations
    final_turns.md     the instruction on a submit-only turn
    nudge_no_tool.md   after a reply that called no tool
    nudge_length.md    after a reply cut off by the output allowance

Each file holds exactly the text sent, with no trailing newline added; only
system.md ends in one. The system prompt is used verbatim. The others are
`str.format` templates, so they hold no literal braces besides their placeholders.

Every file is read at import, so a missing one fails at once, not mid-run.
"""
from __future__ import annotations

from functools import cache
from pathlib import Path

_here = Path(__file__).resolve().parent


@cache
def load(name: str) -> str:
    path = _here / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"no prompt {name!r} in {_here}")
    return path.read_text(encoding="utf-8")


for _name in ("system", "alert", "turn_note", "final_turns", "nudge_no_tool", "nudge_length"):
    load(_name)


def system() -> str:
    return load("system")


def alert_message(alert, opening: str, turns: int) -> str:
    """The alert, the runtime's opening read, and the turn cap: the alert's first user message."""
    return load("alert").format(
        test_id=alert.test_id, test_name=alert.test_name,
        cwe=f"CWE-{alert.cwe}" if alert.cwe else "no CWE",
        severity=alert.severity, confidence=alert.confidence, issue_text=alert.issue_text,
        path=alert.path, line=alert.line, lines=", ".join(str(n) for n in alert.line_range),
        opening=opening, turns=turns)


def turn_note(used: int, cap: int, submit_only: int) -> str:
    """Appended to the last observation of a turn, after a blank line."""
    return "\n\n" + load("turn_note").format(used=used, cap=cap,
                                               first_submit_only=cap - submit_only + 1)


def final_turns(left: int) -> str:
    return load("final_turns").format(left=left)


def nudge(cut_off: bool) -> str:
    """After a reply with no tool call: cut off at the output allowance, or simply none."""
    return load("nudge_length") if cut_off else load("nudge_no_tool")
