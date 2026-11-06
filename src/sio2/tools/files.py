"""The model's investigation tools: read, search and list, inside one alert's workspace."""
from __future__ import annotations

import re
from typing import ClassVar

from sio2.tools.base import Observation, ToolRefused, WorkspaceTool


class ReadFile(WorkspaceTool):
    """Read numbered lines of a text file in the repository. At most 120 lines per call."""
    name = "read_file"
    properties = {"path": {"type": "string", "description": "Repository-relative path"},
                  "start_line": {"type": "integer", "minimum": 1},
                  "end_line": {"type": "integer", "minimum": 1}}
    required = ("path",)

    max_body_chars: ClassVar[int] = 11_000   # under the dispatcher's 12,000-character observation cap

    def __init__(self, ws, ledger, max_lines: int):
        super().__init__(ws, ledger)
        self.max_lines = max_lines

    def run(self, path: str, start_line: int = 1, end_line: int | None = None) -> Observation:
        rel, lines = self.text_lines(path)
        n = len(lines)
        if n == 0:
            return Observation(f"{rel}: empty file", {"path": rel, "lines": 0})
        if start_line < 1:
            raise ToolRefused("start_line must be >= 1")
        if start_line > n:
            raise ToolRefused(f"start_line {start_line} is past the end of {rel} ({n} lines)")
        if end_line is None:
            end_line = start_line + self.max_lines - 1
        if end_line < start_line:
            raise ToolRefused("end_line must be >= start_line")
        end_line = min(end_line, n)
        clipped = end_line - start_line + 1 > self.max_lines
        if clipped:
            end_line = start_line + self.max_lines - 1
        rows, size = [], 0
        for i in range(start_line, end_line + 1):
            row = f"{i:>5}  {self.clip(lines[i - 1])}"
            if rows and size + len(row) + 1 > self.max_body_chars:
                end_line, clipped = i - 1, True   # stop here, so the ledger records only lines shown
                break
            rows.append(row)
            size += len(row) + 1
        body = "\n".join(rows)
        note = f" (clipped at line {end_line}; read on from there)" if clipped else ""
        self.ledger.note(rel, start_line, end_line)
        return Observation(f"{rel} lines {start_line}-{end_line} of {n}{note}:\n{body}",
                           {"path": rel, "start_line": start_line, "end_line": end_line, "file_lines": n})


class Search(WorkspaceTool):
    """Find lines matching a pattern across repository files. Returns path:line: text, at most 30 hits."""
    name = "search"
    properties = {"pattern": {"type": "string", "description": "Literal text, or a Python regex if regex is true"},
                  "path": {"type": "string", "description": "File or directory to search in, default . (the repository)"},
                  "glob": {"type": "string", "description": "Inside a directory, which files to search; default **/*.py"},
                  "regex": {"type": "boolean"}}
    required = ("pattern",)

    max_pattern_chars: ClassVar[int] = 200

    def __init__(self, ws, ledger, max_hits: int):
        super().__init__(ws, ledger)
        self.max_hits = max_hits

    def run(self, pattern: str, path: str = ".", glob: str = "**/*.py", regex: bool = False) -> Observation:
        if not pattern or len(pattern) > self.max_pattern_chars:
            raise ToolRefused(f"pattern must be 1 to {self.max_pattern_chars} characters")
        # Refuse before walking: a glob with '..' would traverse above the workspace.
        if ".." in glob.split("/") or glob.startswith("/"):
            raise ToolRefused("glob must be relative, without '..'")
        try:
            rx = re.compile(pattern if regex else re.escape(pattern))
        except re.error as exc:
            raise ToolRefused(f"invalid regex: {exc}") from exc
        base, base_rel = self.resolve(path)
        if not base.exists():
            raise ToolRefused(f"{path!r} does not exist")
        candidates = [base] if base.is_file() else sorted(base.glob(glob))
        hits: list[str] = []
        files = 0
        truncated = False
        for full in candidates:
            if not full.is_file() or full.is_symlink():
                continue
            rel = full.relative_to(self.ws.root).as_posix()
            try:
                self.resolve(rel)          # the one path check, same as every tool
            except ToolRefused:
                continue
            if full.stat().st_size > self.max_file_bytes:
                continue
            files += 1
            try:
                text = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    hits.append(f"{rel}:{i}: {self.clip(line.strip())}")
                    self.ledger.note(rel, i, i)
                    if len(hits) >= self.max_hits:
                        truncated = True
                        break
            if truncated:
                break
        where = base_rel if base.is_file() else f"{base_rel}/{glob}"
        head = f"{len(hits)} match(es) for {pattern!r} in {where} ({files} files searched)"
        if truncated:
            head += f"; stopped at {self.max_hits}, narrow the glob or pattern"
        return Observation(head + (":\n" + "\n".join(hits) if hits else ""),
                           {"hits": len(hits), "truncated": truncated})


class ListDir(WorkspaceTool):
    """List the entries of a repository directory."""
    name = "list_dir"
    properties = {"path": {"type": "string", "description": "Repository-relative directory, default ."}}

    def __init__(self, ws, ledger, max_entries: int):
        super().__init__(ws, ledger)
        self.max_entries = max_entries

    def run(self, path: str = ".") -> Observation:
        full, rel = self.resolve(path)
        if not full.is_dir():
            raise ToolRefused(f"{path!r} is not a directory")
        entries = []
        for child in sorted(full.iterdir()):
            crel = child.relative_to(self.ws.root).as_posix()
            if self.ws.is_withheld(crel):
                continue
            entries.append(crel + ("/" if child.is_dir() and not child.is_symlink() else ""))
        shown = entries[:self.max_entries]
        more = len(entries) - len(shown)
        tail = f"\n... {more} more" if more else ""
        return Observation(f"{rel}/ ({len(entries)} entries):\n" + "\n".join(shown) + tail,
                           {"entries": len(entries)})
