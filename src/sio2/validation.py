"""Runtime-only syntax, scanner, and sandboxed test checks."""
from __future__ import annotations

import difflib
import os
import re
import selectors
import signal
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

from sio2.tools.patch import PatchResult
from sio2.tools.scan import Alert, ScanError, run_bandit


def run_bounded(argv: list[str], *, timeout_s: float, output_limit: int, stdin=None) -> dict:
    """Collect bounded output and stop the process group at either limit."""
    try:
        proc = subprocess.Popen(argv, stdin=stdin if stdin is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    except OSError as exc:
        return {"status": "unavailable", "returncode": None, "output": str(exc)[:output_limit]}
    output = bytearray()
    status = None
    deadline = time.monotonic() + timeout_s
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    available = output_limit - len(output)
                    output.extend(data[:available])
                    if len(data) > available:
                        status = "output_limit"
                        break
                if status:
                    break
            if status is None:
                try:
                    proc.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    status = "timeout"
    finally:
        # Also stop children that close stdout but outlive their parent.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        proc.stdout.close()
    text = output.decode("utf-8", errors="replace")
    text = text.encode("utf-8")[:output_limit].decode("utf-8", errors="ignore")
    return {"status": status or ("passed" if proc.returncode == 0 else "failed"),
            "returncode": proc.returncode, "output": text}


def run_tests(root: Path, cfg) -> dict:
    """Run trusted test arguments inside a resource-limited, offline container."""
    if not cfg.test_image or not cfg.test_command:
        return {"status": "not_configured", "returncode": None, "output": "No container test command configured."}
    name = f"sio2-test-{uuid.uuid4().hex}"
    argv = ["docker", "run", "--rm", "--interactive", "--pull=never", "--name", name,
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=1g", "--cpus=1",
            "--user=65534:65534", "--tmpfs", "/work:rw,size=512m,mode=1777",
            "--tmpfs", "/tmp:rw,size=256m,mode=1777",
            "--workdir", "/work", "--entrypoint", "/bin/sh", cfg.test_image,
            "-c", 'tar -xf - -C /work && exec "$@"', "sio2-tests", *cfg.test_command]
    with tempfile.TemporaryFile() as source:
        with tarfile.open(fileobj=source, mode="w", dereference=False) as archive:
            for path in sorted(root.iterdir()):
                archive.add(path, arcname=path.name)
        source.seek(0)
        try:
            result = run_bounded(argv, timeout_s=cfg.test_timeout_s,
                                 output_limit=cfg.output_limit, stdin=source)
        finally:
            # Killing the Docker client does not necessarily stop its container.
            run_bounded(["docker", "rm", "--force", name], timeout_s=10, output_limit=1024)
    if result["status"] == "failed":
        code, output = result["returncode"], result["output"]
        if code == 5:
            result["status"] = "no_tests"
        elif code in (125, 126, 127) or any(text in output for text in (
            "ModuleNotFoundError", "ImportError", "No module named", "Cannot connect to the Docker daemon",
        )):
            result["status"] = "infrastructure_error"
    result["command"] = list(cfg.test_command)
    result["image"] = cfg.test_image
    return result


def _code(alert: Alert) -> str:
    return "\n".join(re.sub(r"^\d+\s+", "", line).strip() for line in alert.code.splitlines())


def _mapped_range(alert: Alert, patch: PatchResult) -> tuple[int, int]:
    if alert.path not in patch.before:
        return alert.line, alert.line
    old = patch.before[alert.path].splitlines()
    new = patch.after[alert.path].splitlines()
    for tag, i, j, a, b in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if i <= alert.line - 1 < j:
            if tag == "equal":
                line = a + (alert.line - 1 - i) + 1
                return line, line
            # Match any finding of the same rule inside a replacement block.
            # A deleted block maps to an empty interval.
            return a + 1, b
    return alert.line, alert.line


def compare_findings(baseline: list[Alert], candidate: list[Alert], target_id: str,
                     patch: PatchResult) -> dict:
    """Match findings one-to-one by rule, path, and source location or context."""
    remaining = list(baseline)
    matched, new = set(), []
    for finding in candidate:
        matches = []
        for old in remaining:
            if (old.test_id, old.path, old.severity, old.confidence) != (
                finding.test_id, finding.path, finding.severity, finding.confidence
            ):
                continue
            start, end = _mapped_range(old, patch)
            if start <= finding.line <= end or (_code(old) and _code(old) == _code(finding)):
                matches.append(old)
        if not matches:
            new.append(finding.alert_id)
            continue
        # Prefer source context when multiple old findings share a changed block.
        chosen = min(matches, key=lambda old: (0 if _code(old) == _code(finding) else 1,
                                               abs(_mapped_range(old, patch)[0] - finding.line)))
        # An ambiguous match cannot prove that the target disappeared.
        if any(old.alert_id == target_id for old in matches):
            matched.add(target_id)
        remaining.remove(chosen)
        matched.add(chosen.alert_id)
    removed = target_id not in matched and any(a.alert_id == target_id for a in baseline)
    return {"status": "passed" if removed and not new else "failed",
            "target_removed": removed, "new_findings": new}


def check_syntax(root: Path, patch: PatchResult) -> dict:
    """Compile changed source without execution."""
    try:
        for rel in patch.after:
            compile((root / rel).read_bytes(), rel, "exec", dont_inherit=True)
    except (SyntaxError, ValueError, OSError) as exc:
        return {"status": "failed", "error": str(exc)}
    return {"status": "passed"}


def check_bandit(root: Path, cfg, baseline: list[Alert], target: Alert, patch: PatchResult) -> dict:
    """Scan the candidate and compare findings under the original scan policy."""
    try:
        scan = run_bandit(root, cfg.scan, cfg.target)
        if scan["bandit_errors"]:
            return {"status": "error", "errors": scan["bandit_errors"]}
        result = compare_findings(baseline, scan["alerts"], target.alert_id, patch)
        result["alert_count"] = len(scan["alerts"])
        return result
    except (ScanError, OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        return {"status": "error", "error": str(exc)}


def validate_candidate(root: Path, cfg, baseline: list[Alert], target: Alert,
                       patch: PatchResult, baseline_tests: dict) -> dict:
    """Convenience checks for callers outside the graph. This function owns no retry loop."""
    result = {"status": "rejected", "syntax": check_syntax(root, patch),
              "bandit": {"status": "not_run"}, "tests": {"status": "not_run"}}
    if result["syntax"]["status"] != "passed":
        return result
    result["bandit"] = check_bandit(root, cfg, baseline, target, patch)
    if result["bandit"]["status"] != "passed":
        return result
    result["tests"] = run_tests(root, cfg.repair)
    if result["tests"]["status"] == "passed" and baseline_tests["status"] == "passed":
        result["status"] = "accepted"
    elif result["tests"]["status"] != "failed":
        result["status"] = "unvalidated"
    return result
