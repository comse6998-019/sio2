"""The agent's view of the target: a disposable copy with some files withheld.

    with Workspace(input_root, target=Target.OWASP) as ws:
        ws.focus("testcode/BenchmarkTest00011.py")   # per alert, OWASP only
        path = ws.resolve("helpers/utils.py")       # every tool goes through here

What the model can reach is the copy and nothing else. Three things are
withheld, for the reasons in REPORT.md (A7):

* `.git/` on every target. It is never copied, so there is nothing to restore;
  the checkout given as --input is never written to.
* On OWASP, the answer key `expectedresults*.csv` and the `results/` folder of
  other scanners' outputs. Moved to a stash outside the copy when the
  workspace opens, moved back when it closes.
* On OWASP, every `BenchmarkTest*` file except the case under investigation,
  because each case has a safe twin. `focus()` moves them out per alert and
  restores the previous alert's set first.

Moving files out is the mechanism; `resolve()` also refuses withheld paths by
pattern, so a file that somehow came back is still refused (defence in depth).
"""
from __future__ import annotations

import fnmatch
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import ClassVar

from sio2.config import Target


class PathRefused(Exception):
    """A tool path failed the workspace check. The message is shown to the model."""


def _matches(rel: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(rel, p) for p in patterns)


class Workspace:
    # Withheld on every target.
    always_withheld: ClassVar[tuple[str, ...]] = (".git", ".git/*")
    # Withheld for the whole OWASP run.
    owasp_run_withheld: ClassVar[tuple[str, ...]] = ("expectedresults*.csv", "results", "results/*")
    # Withheld on OWASP except for the case under investigation.
    owasp_case_globs: ClassVar[tuple[str, ...]] = ("testcode/BenchmarkTest*.py",
                                                   "templates/web/*/BenchmarkTest*.html")

    def __init__(self, source: Path, target: Target, keep: bool = False):
        self.source = Path(source).resolve()
        self.target = target
        self.keep = keep
        self.root: Path | None = None
        self.stash: Path | None = None
        self.case: str | None = None          # stem of the OWASP case in focus
        self._case_moved: list[str] = []      # rel paths currently stashed by focus()
        self._run_moved: list[str] = []       # rel paths stashed for the whole run

    # lifetime ---------------------------------------------------------------

    def __enter__(self) -> "Workspace":
        if not self.source.is_dir():
            raise FileNotFoundError(f"--input is not a directory: {self.source}")
        base = Path(tempfile.mkdtemp(prefix="sio2-ws-"))
        dest = base / "repo"
        # .git is never copied: it can hold commits made after the pinned one.
        shutil.copytree(self.source, dest, symlinks=True,
                        ignore=shutil.ignore_patterns(".git"))
        self.root = dest.resolve()
        self.stash = (base / "withheld").resolve()   # outside the copy, so no tool path reaches it
        self.stash.mkdir()
        if self.target == Target.OWASP:
            for rel in self._glob(self.owasp_run_withheld):
                self._move_out(rel)
                self._run_moved.append(rel)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.root is None:
            return
        self.unfocus()
        for rel in reversed(self._run_moved):
            self._move_back(rel)
        self._run_moved.clear()
        base = self.root.parent
        if not self.keep:
            shutil.rmtree(base, ignore_errors=True)
        self.root = None

    # withholding ------------------------------------------------------------

    def focus(self, alert_path: str) -> list[str]:
        """Withhold every OWASP case except the one `alert_path` belongs to."""
        self.unfocus()
        if self.target != Target.OWASP:
            return []
        self.case = PurePosixPath(alert_path).stem
        for rel in self._glob(self.owasp_case_globs):
            if PurePosixPath(rel).stem != self.case:
                self._move_out(rel)
                self._case_moved.append(rel)
        return list(self._case_moved)

    def unfocus(self) -> None:
        for rel in reversed(self._case_moved):
            self._move_back(rel)
        self._case_moved.clear()
        self.case = None

    def withheld(self) -> list[str]:
        """Repository-relative paths currently out of the agent's view."""
        return sorted(self._run_moved + self._case_moved)

    def is_withheld(self, rel: str) -> bool:
        if _matches(rel, self.always_withheld):
            return True
        if self.target == Target.OWASP:
            if _matches(rel, self.owasp_run_withheld):
                return True
            if _matches(rel, self.owasp_case_globs) and PurePosixPath(rel).stem != self.case:
                return True
        return False

    def _glob(self, patterns) -> list[str]:
        out = set()
        for p in patterns:
            for hit in self.root.glob(p):
                out.add(hit.relative_to(self.root).as_posix())
        # Parents before children, so moving a folder does not orphan a later move.
        return sorted(out, key=lambda r: (r.count("/"), r))

    def _move_out(self, rel: str) -> None:
        src = self.root / rel
        if not src.exists() and not src.is_symlink():
            return  # already gone with a folder moved earlier
        dst = self.stash / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))

    def _move_back(self, rel: str) -> None:
        src = self.stash / rel
        if not src.exists() and not src.is_symlink():
            return
        dst = self.root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))

    # the one path check -----------------------------------------------------

    def resolve(self, path: str) -> tuple[Path, str]:
        """Return (absolute path, repo-relative POSIX path) inside the copy, or raise PathRefused.

        Every model-callable tool calls this before touching disk.
        """
        if self.root is None:
            raise PathRefused("workspace is not open")
        if not isinstance(path, str) or not path.strip():
            raise PathRefused("path must be a non-empty string")
        raw = path.strip().replace("\\", "/")
        if raw.startswith("/") or (len(raw) > 1 and raw[1] == ":"):
            raise PathRefused(f"{path!r} is absolute; give a path relative to the repository root")
        parts = PurePosixPath(raw).parts
        if ".." in parts:
            raise PathRefused(f"{path!r} contains '..'")
        # Resolve both sides fully: this follows symlinks, so a link that points
        # outside the copy is caught by the containment test below.
        candidate = (self.root / raw).resolve()
        if not candidate.is_relative_to(self.root):
            raise PathRefused(f"{path!r} resolves outside the workspace")
        rel = candidate.relative_to(self.root).as_posix()
        rel = "." if rel == "" else rel
        if rel != "." and self.is_withheld(rel):
            raise PathRefused(f"{path!r} is withheld from the agent")
        return candidate, rel
