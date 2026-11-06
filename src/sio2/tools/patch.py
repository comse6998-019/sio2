"""Exact source replacements for disposable repair candidates."""
from __future__ import annotations

from collections import Counter
import difflib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from sio2.tools.base import Observation, Tool, ToolRefused
from sio2.workspace import PathRefused, Workspace


class PatchRefused(Exception):
    """The proposed patch violates a source boundary or replacement rule."""


@dataclass(frozen=True)
class PatchResult:
    before: dict[str, str]
    after: dict[str, str]
    diff: str


PATCH_PARAMETERS: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["edits"],
    "properties": {
        "edits": {
            "type": "array",
            "minItems": 1,
            "maxItems": 20,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "old_text", "new_text"],
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "old_text": {"type": "string", "minLength": 1},
                    "new_text": {"type": "string"},
                },
            },
        },
    },
}

class ProposePatch(Tool):
    """Apply exact replacements in the supplied Python source file."""

    name = "propose_patch"
    properties = PATCH_PARAMETERS["properties"]
    required = ("edits",)

    def __init__(self, ws: Workspace, allowed_paths: set[str]):
        self.ws = ws
        self.allowed_paths = allowed_paths
        self.applied: PatchResult | None = None

    def run(self, edits: list[dict]) -> Observation:
        try:
            self.applied = apply_patch(self.ws, edits, self.allowed_paths)
        except PatchRefused as exc:
            raise ToolRefused(str(exc)) from exc
        return Observation("Patch applied to the disposable candidate.",
                           {"changed_paths": list(self.applied.after)})


def _resolve_patch_target(ws: Workspace, path: str, allowed_paths: set[str]) -> tuple[Path, str]:
    """Resolve and validate the source path for a patch.

    Args:
        ws: The workspace containing the source files.
        path: The relative path to the source file.
        allowed_paths: A set of allowed relative paths for patching.

    Returns:
        A tuple of the full path and the relative path.

    Raises:
        PatchRefused: If the path is not valid for patching.
    """
    raw = PurePosixPath(path.replace("\\", "/"))
    if any(p.startswith(".") for p in raw.parts) or any(
        p.lower() in {"tests", "test", "integ_tests"} for p in raw.parts
    ) or raw.name.lower().startswith("test_") or raw.name.lower().endswith("_test.py"):
        raise PatchRefused("hidden files and tests are not patch targets")
    try:
        full, rel = ws.resolve(path)
    except PathRefused as exc:
        raise PatchRefused(str(exc)) from exc
    if any((ws.root / Path(*raw.parts[:i])).is_symlink() for i in range(1, len(raw.parts) + 1)):
        raise PatchRefused("symlinks are not patch targets")
    if rel not in allowed_paths or full.suffix != ".py" or not full.is_file():
        raise PatchRefused("patch path must be a permitted Python source file")
    if full.stat().st_size > 2_000_000:
        raise PatchRefused("patch source exceeds the size limit")
    return full, rel


def apply_patch(ws: Workspace, edits: list[dict], allowed_paths: set[str]) -> PatchResult:
    """Validate every edit before disk writes. Restore originals if a write fails."""
    import jsonschema

    try:
        jsonschema.validate({"edits": edits}, PATCH_PARAMETERS)
    except jsonschema.ValidationError as exc:
        raise PatchRefused(exc.message) from exc
    before, paths, spans = {}, {}, {}
    for edit in edits:
        full, rel = _resolve_patch_target(ws, edit["path"], allowed_paths)
        if rel not in before:
            try:
                before[rel] = full.read_bytes().decode("utf-8")
            except UnicodeError as exc:
                raise PatchRefused("patch source must be UTF-8 text") from exc
            paths[rel] = full
        original = before[rel]
        old, new = edit["old_text"], edit["new_text"]
        if old == new or original.count(old) != 1:
            raise PatchRefused("old_text must match exactly once and new_text must differ")
        start = original.index(old)
        end = start + len(old)
        for left, right, _ in spans.get(rel, []):
            if start < right and left < end:
                raise PatchRefused("replacement ranges overlap")
        spans.setdefault(rel, []).append((start, end, new))
    after = {}
    for rel, original in before.items():
        result = original
        for start, end, new in sorted(spans[rel], reverse=True):
            result = result[:start] + new + result[end:]
        if len(result.encode("utf-8")) > 2_000_000:
            raise PatchRefused("patch result exceeds the size limit")
        # Do not let a repair hide a finding through a new suppression comment.
        suppressions = re.compile(r"#[^\n]*(?:nosec|noqa|bandit\s*:)", re.IGNORECASE)
        old_lines = Counter(line for line in original.splitlines() if suppressions.search(line))
        new_lines = Counter(line for line in result.splitlines() if suppressions.search(line))
        if old_lines != new_lines:
            raise PatchRefused("scanner suppression lines must remain unchanged")
        after[rel] = result
    staged, replaced = [], []
    try:
        for rel, full in paths.items():
            fd, name = tempfile.mkstemp(prefix=".sio2-patch-", dir=full.parent)
            staged.append(Path(name))
            with os.fdopen(fd, "wb") as stream:
                stream.write(after[rel].encode("utf-8"))
            os.chmod(name, full.stat().st_mode & 0o777)
        for (rel, full), temporary in zip(paths.items(), staged):
            temporary.replace(full)
            replaced.append(rel)
    except OSError as exc:
        for rel in replaced:
            paths[rel].write_bytes(before[rel].encode("utf-8"))
        raise PatchRefused(f"patch write failed: {exc}") from exc
    finally:
        for temporary in staged:
            temporary.unlink(missing_ok=True)
    diff = "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
                   for rel in before for line in difflib.unified_diff(
                       before[rel].splitlines(keepends=True), after[rel].splitlines(keepends=True),
                       fromfile=f"a/{rel}", tofile=f"b/{rel}",
                   ))
    return PatchResult(before, after, diff)
