"""Runtime checks for independent repair candidates."""
import os
from types import SimpleNamespace
import sys

import pytest

from sio2.config import Scan
from sio2.tools.patch import PatchResult
from sio2.tools.scan import Alert, ScanError
from sio2.validation import compare_findings, run_bounded, run_tests, validate_candidate


def alert(aid="target", line=2, test_id="B307", code="2 eval(value)\n"):
    return Alert(aid, test_id, "eval", "radicale/app.py", line, (line,),
                 "MEDIUM", "HIGH", "unsafe", 95, code)


def patch(before="x = 1\neval(value)\n", after="x = 1\nvalue = int(value)\n"):
    return PatchResult({"radicale/app.py": before}, {"radicale/app.py": after}, "diff")


def test_line_shift_does_not_create_a_new_finding():
    original = "eval(value)\nprint(value)\n"
    candidate = "# context\neval(value)\nprint(value)\n"
    result = compare_findings([alert(line=1)], [alert("shifted", line=2)], "target",
                              patch(original, candidate))
    assert result == {"status": "failed", "target_removed": False, "new_findings": []}


def test_ambiguous_same_rule_match_cannot_prove_target_removal():
    change = patch("eval(first)\neval(second)\n", "eval(third)\n")
    baseline = [alert("other", 1, code="1 eval(first)\n"),
                alert("target", 2, code="2 eval(second)\n")]
    result = compare_findings(baseline, [alert("candidate", 1, code="1 eval(third)\n")],
                              "target", change)
    assert result["target_removed"] is False


def test_removal_and_new_findings_are_independent():
    baseline = [alert(), alert("other", 1, "B101", "1 assert x\n")]
    result = compare_findings(baseline, [baseline[1]], "target", patch())
    assert result == {"status": "passed", "target_removed": True, "new_findings": []}
    result = compare_findings(baseline, [alert("new", 2, "B602")], "target", patch())
    assert result["status"] == "failed"
    assert result["target_removed"] is True
    assert result["new_findings"] == ["new"]


def test_same_rule_in_changed_range_still_counts_as_target():
    result = compare_findings([alert()], [alert("candidate", code="2 eval(other)\n")],
                              "target", patch(after="x = 1\neval(other)\n"))
    assert result["target_removed"] is False


def test_duplicate_findings_cannot_hide_an_additional_finding():
    result = compare_findings([alert()], [alert("one"), alert("two")], "target", patch())
    assert result["status"] == "failed"
    assert len(result["new_findings"]) == 1


def test_syntax_failure_does_not_run_scan_or_tests(tmp_path):
    (tmp_path / "radicale").mkdir()
    (tmp_path / "radicale/app.py").write_text("def invalid(\n")
    cfg = SimpleNamespace()
    result = validate_candidate(tmp_path, cfg, [alert()], alert(), patch(), {"status": "passed"})
    assert result["syntax"]["status"] == "failed"
    assert result["status"] == "rejected"
    assert result["bandit"]["status"] == "not_run"
    assert result["tests"]["status"] == "not_run"


def test_scanner_errors_block_acceptance(tmp_path, monkeypatch):
    (tmp_path / "radicale").mkdir()
    (tmp_path / "radicale/app.py").write_text("x = 1\n")
    from sio2 import validation
    monkeypatch.setattr(validation, "run_bandit", lambda *args: {
        "alerts": [], "bandit_errors": [{"reason": "syntax error"}]})
    result = validate_candidate(tmp_path, SimpleNamespace(scan=None, target="radicale"),
                                [alert()], alert(), patch(), {"status": "passed"})
    assert result["status"] == "rejected"
    assert result["bandit"]["status"] == "error"


def test_scan_exception_is_a_recorded_error(tmp_path, monkeypatch):
    (tmp_path / "radicale").mkdir()
    (tmp_path / "radicale/app.py").write_text("x = 1\n")
    from sio2 import validation

    def fail(*args):
        raise ScanError("scanner unavailable")

    monkeypatch.setattr(validation, "run_bandit", fail)
    result = validate_candidate(tmp_path, SimpleNamespace(scan=None, target="radicale"),
                                [alert()], alert(), patch(), {"status": "passed"})
    assert result["status"] == "rejected"
    assert "scanner unavailable" in result["bandit"]["error"]


def test_real_bandit_validates_a_safe_replacement(tmp_path):
    (tmp_path / "radicale").mkdir()
    (tmp_path / "radicale/app.py").write_text("value = int('1')\n")
    cfg = SimpleNamespace(scan=Scan(("radicale",), ("radicale/tests",), "MEDIUM", "1.9.4"),
                          target="radicale", repair=SimpleNamespace(test_image="", test_command=()))
    result = validate_candidate(tmp_path, cfg, [alert()], alert(), patch(), {"status": "passed"})
    assert result["bandit"]["status"] == "passed"
    assert result["tests"]["status"] == "not_configured"
    assert result["status"] == "unvalidated"


@pytest.mark.parametrize("code,expected", [
    ("print('ok')", "passed"), ("raise SystemExit(1)", "failed"),
    ("import time; time.sleep(10)", "timeout"),
    ("print('x' * 100000)", "output_limit"),
])
def test_process_limits(code, expected):
    result = run_bounded([sys.executable, "-c", code], timeout_s=0.3, output_limit=1024)
    assert result["status"] == expected
    assert len(result["output"].encode()) <= 1024


def test_invalid_utf8_output_stays_inside_byte_limit():
    result = run_bounded([sys.executable, "-c", "import os; os.write(1, bytes([255]) * 100)"],
                         timeout_s=1, output_limit=8)
    assert len(result["output"].encode("utf-8")) <= 8
    assert result["status"] == "output_limit"


@pytest.mark.skipif(not os.environ.get("SIO2_TEST_IMAGE"), reason="Set SIO2_TEST_IMAGE for the Docker integration test.")
def test_real_container_runs_in_disposable_offline_workspace(tmp_path):
    source = tmp_path / "value.txt"
    source.write_text("original")
    code = (
        "import os, pathlib; "
        "assert os.getuid() == 65534; "
        "assert pathlib.Path.cwd() == pathlib.Path('/work'); "
        "assert pathlib.Path('value.txt').read_text() == 'original'; "
        "pathlib.Path('value.txt').write_text('candidate'); "
        "assert not pathlib.Path('/source').exists()"
    )
    cfg = SimpleNamespace(test_image=os.environ["SIO2_TEST_IMAGE"], test_command=("python", "-c", code),
                          test_timeout_s=30, output_limit=1024)
    result = run_tests(tmp_path, cfg)
    assert result["status"] == "passed", result
    assert source.read_text() == "original"


def test_missing_process_is_an_infrastructure_error():
    result = run_bounded(["/nonexistent/sio2-command"], timeout_s=1, output_limit=1024)
    assert result["status"] == "unavailable"


def test_docker_boundary_uses_restricted_runtime_and_fixed_command(tmp_path, monkeypatch):
    from sio2 import validation
    import tarfile
    commands = []
    (tmp_path / "test_app.py").write_text("assert True\n")

    def runner(command, **kwargs):
        commands.append(command)
        if command[:2] == ["docker", "run"]:
            with tarfile.open(fileobj=kwargs["stdin"], mode="r:") as archive:
                assert archive.extractfile("test_app.py").read() == b"assert True\n"
            kwargs["stdin"].seek(0)
        return {"status": "passed", "returncode": 0, "output": "3 passed"}

    monkeypatch.setattr(validation, "run_bounded", runner)
    cfg = SimpleNamespace(test_image="sio2-tests:local", test_command=("python", "-m", "pytest", "-q"),
                          test_timeout_s=20, output_limit=1024)
    result = run_tests(tmp_path, cfg)
    assert result["status"] == "passed"
    command = commands[0]
    assert command[:2] == ["docker", "run"]
    for flag in ("--read-only", "--network=none", "--cap-drop=ALL", "--pull=never"):
        assert flag in command
    assert "--security-opt=no-new-privileges" in command
    assert "--interactive" in command
    assert "--mount" not in command
    assert any("tar -xf - -C /work" in arg for arg in command)
    assert command[-4:] == ["python", "-m", "pytest", "-q"]
    assert commands[-1][:3] == ["docker", "rm", "--force"]


@pytest.mark.parametrize("returncode,output,status", [
    (5, "no tests ran", "no_tests"),
    (2, "ModuleNotFoundError: No module named 'requests'", "infrastructure_error"),
    (127, "python: not found", "infrastructure_error"),
])
def test_unusable_test_environment_is_not_a_test_failure(tmp_path, monkeypatch, returncode, output, status):
    from sio2 import validation
    monkeypatch.setattr(validation, "run_bounded", lambda *a, **kw: {
        "status": "failed", "returncode": returncode, "output": output})
    cfg = SimpleNamespace(test_image="tests:local", test_command=("python", "-m", "pytest"),
                          test_timeout_s=20, output_limit=1024)
    assert run_tests(tmp_path, cfg)["status"] == status
