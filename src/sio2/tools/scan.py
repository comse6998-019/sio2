"""Discovery: the Bandit wrapper, and `BanditScan`, the runtime tool around it.

Turns a [scan] block into a Bandit command line, runs it from the root of the
target checkout, and parses the JSON it writes. `BanditScan` is a runtime tool:
the dispatcher runs it once at the start of the run, and the model cannot call
it, because it is not in the model's `Toolbox`.

    [scan] key                 Bandit flag
    paths (globs, expanded)    positional arguments, with -r
    exclude                    -x a,b   (omitted when empty)
    min_severity = "MEDIUM"    --severity-level medium
    (any confidence)           no --confidence-level flag
    bandit_version             `bandit --version` must report it
    (output)                   -q -f json -o <file>
"""
from __future__ import annotations

import glob
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

from sio2.config import Scan
from sio2.tools.base import Observation, Tool, ToolRefused


class Severity(IntEnum):
    """Bandit's severities, ordered, so a floor is a comparison."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class ScanError(Exception):
    pass


@dataclass(frozen=True)
class Alert:
    alert_id: str
    test_id: str
    test_name: str
    path: str          # repository-relative POSIX, no leading ./
    line: int
    line_range: tuple[int, ...]
    severity: str
    confidence: str
    issue_text: str
    cwe: int | None
    code: str


def bandit_executable() -> str:
    """The bandit next to this interpreter (the pinned one), else the one on PATH."""
    local = Path(sys.executable).parent / "bandit"
    if local.exists():
        return str(local)
    found = shutil.which("bandit")
    if not found:
        raise ScanError("bandit is not installed")
    return found


def bandit_version(exe: str) -> str:
    out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60)
    m = re.search(r"bandit\s+(\d+\.\d+\.\d+)", out.stdout + out.stderr)
    if not m:
        raise ScanError(f"could not read the Bandit version from: {out.stdout!r}")
    return m.group(1)


def expand_paths(root: Path, patterns) -> list[str]:
    """Glob-expand each `paths` entry relative to the checkout root, as a shell would."""
    out: list[str] = []
    for pattern in patterns:
        if glob.has_magic(pattern):
            hits = sorted(glob.glob(pattern, root_dir=root))
            if not hits:
                raise ScanError(f"scan path {pattern!r} matches nothing under {root}")
            out.extend(hits)
        else:
            if not (root / pattern).exists():
                raise ScanError(f"scan path {pattern!r} does not exist under {root}")
            out.append(pattern)
    return out


def build_command(exe: str, scan: Scan, targets: list[str], out_file: Path) -> list[str]:
    cmd = [exe, "-q", "-r", "--severity-level", scan.min_severity.lower()]
    if scan.exclude:
        cmd += ["-x", ",".join(scan.exclude)]
    cmd += ["-f", "json", "-o", str(out_file), *targets]
    return cmd


def normalise_path(p: str) -> str:
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "-", text).strip("-")


def parse_results(data: dict, target: str, min_severity: str) -> list[Alert]:
    floor = Severity[min_severity]
    alerts: list[Alert] = []
    for r in data.get("results", []):
        if r["issue_severity"] not in Severity.__members__ or Severity[r["issue_severity"]] < floor:
            continue  # defensive: --severity-level already filters
        path = normalise_path(r["filename"])
        alerts.append(Alert(
            alert_id="",
            test_id=r["test_id"],
            test_name=r.get("test_name", ""),
            path=path,
            line=int(r["line_number"]),
            line_range=tuple(int(x) for x in r.get("line_range") or [r["line_number"]]),
            severity=r["issue_severity"],
            confidence=r["issue_confidence"],
            issue_text=r.get("issue_text", ""),
            cwe=(r.get("issue_cwe") or {}).get("id"),
            code=r.get("code", ""),
        ))
    # Report order: path (plain string comparison), line (integer), test_id.
    alerts.sort(key=lambda a: (a.path, a.line, a.test_id))
    out, seen = [], {}
    for a in alerts:
        base = f"{target}-{_slug(a.path)}-{a.line}-{a.test_id}"
        n = seen.get(base, 0)
        seen[base] = n + 1
        aid = base if n == 0 else f"{base}-{n + 1}"   # rows are never merged
        out.append(Alert(**{**a.__dict__, "alert_id": aid}))
    return out


def run_bandit(root: Path, scan: Scan, target: str, timeout: int = 900) -> dict:
    """Run Bandit over the scan scope. Returns the parsed alerts and the facts the trace records."""
    exe = bandit_executable()
    version = bandit_version(exe)
    if version != scan.bandit_version:
        raise ScanError(f"bandit --version reports {version}, config requires {scan.bandit_version}")
    targets = expand_paths(root, scan.paths)
    with tempfile.TemporaryDirectory(prefix="bandit-out-") as tmp:
        out_file = Path(tmp) / "bandit.json"
        cmd = build_command(exe, scan, targets, out_file)
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=timeout)
        # Exit 1 means "results found", not failure.
        if proc.returncode not in (0, 1) or not out_file.exists():
            raise ScanError(f"bandit exited {proc.returncode}: {proc.stderr.strip()[:500]}")
        try:
            data = json.loads(out_file.read_text())
        except json.JSONDecodeError as exc:
            raise ScanError(f"bandit output is not JSON: {exc}") from exc
    alerts = parse_results(data, target, scan.min_severity)
    return {
        "alerts": alerts,
        "version": version,
        "argv": [Path(cmd[0]).name, *cmd[1:cmd.index("-o") + 1], "<tmp>/bandit.json", *targets]
        if len(targets) <= 20 else [Path(cmd[0]).name, "...", f"{len(targets)} paths"],
        "returncode": proc.returncode,
        "bandit_errors": data.get("errors", []),
    }


class BanditScan(Tool):
    """Run Bandit 1.9.4 over the configured scope and parse its alerts."""
    name = "bandit"
    properties = {"paths": {"type": "array", "items": {"type": "string"}},
                  "exclude": {"type": "array", "items": {"type": "string"}},
                  "min_severity": {"enum": ["MEDIUM"]}}
    required = ("paths", "exclude", "min_severity")

    def __init__(self, root: Path, bandit_version: str, target: str):
        self.root = root
        self.bandit_version = bandit_version
        self.target = target
        self.found: dict | None = None   # the full result, for the runtime; the trace gets a summary

    def run(self, paths: list[str], exclude: list[str], min_severity: str) -> Observation:
        scan = Scan(tuple(paths), tuple(exclude), min_severity, self.bandit_version)
        try:
            self.found = run_bandit(self.root, scan, self.target)
        except ScanError as exc:
            raise ToolRefused(str(exc)) from exc
        f = self.found
        return Observation(f"{len(f['alerts'])} alerts", {
            "alerts": len(f["alerts"]), "bandit_version": f["version"], "argv": f["argv"],
            "returncode": f["returncode"], "bandit_errors": len(f["bandit_errors"])})
