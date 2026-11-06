"""One LangGraph workflow for classification, patch tools, and validation."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from sio2.check import check_run
from sio2.cli import run
from sio2.config import ConfigError, load_config
from sio2.graph import Agent
from sio2.llm import Reply, ScriptedChat
from sio2.repair import RepairWorkflow
from sio2.trace import TerminalStatus, Trace, read_events
from sio2.workspace import Workspace


CONFIG = '''[scan]
paths = ["radicale"]
exclude = ["radicale/tests"]
min_severity = "MEDIUM"
bandit_version = "1.9.4"

[model]
provider = "ollama"
name = "test-model"

[budget]
max_tokens = 100000
output_allowance = 256
max_steps = 200

[repair]
max_attempts = 2
max_tokens = 20000
output_allowance = 2048
test_image = "sio2-tests:local"
test_command = ["python", "-m", "pytest", "-q"]
'''
SOURCE = "def parse(value):\n    return eval(value)\n"


@pytest.fixture
def repair_case(tmp_path):
    root = tmp_path / "input"
    (root / "radicale").mkdir(parents=True)
    (root / "radicale/app.py").write_text(SOURCE)
    config = tmp_path / "config.toml"
    config.write_text(CONFIG)
    return root, config, tmp_path / "out"


def proposal(old="eval(value)", new="int(value)", path="radicale/app.py"):
    return Reply("", [{"name": "propose_patch", "arguments": {"edits": [
        {"path": path, "old_text": old, "new_text": new}]}}],
        {"input": 100, "output": 50}, "stop")


def workflow_model(*patches, labels=None):
    pending = list(patches)

    def chat(messages, tools):
        if tools[0]["function"]["name"] == "propose_patch":
            item = pending.pop(0)
            return item(messages) if callable(item) else item
        user = messages[1]["content"]
        path = user.split("file: ")[1].split("\n")[0]
        start, end = map(int, user.split(f"{path} lines ")[1].split(" ")[0].split("-"))
        label = (labels or {}).get(path, 1)
        return Reply("", [{"name": "submit_label", "arguments": {
            "label": label, "rationale": "Expression evidence.",
            "evidence": [{"path": path, "start_line": start, "end_line": end}]}}],
            {"input": 100, "output": 10}, "stop")

    return ScriptedChat(chat)


def passing_tests(*args):
    return {"status": "passed", "returncode": 0, "output": "1 passed"}


@pytest.fixture
def clean_tests(monkeypatch):
    monkeypatch.setattr("sio2.validation.run_tests", passing_tests)


def repair_messages(model):
    return [messages for messages in model.calls if messages[0]["content"].startswith("You propose")]


def reports(output):
    return (json.loads((output / "report.json").read_text()),
            json.loads((output / "repair-report.json").read_text()))


def test_repair_nodes_execute_inside_the_existing_graph(repair_case, clean_tests):
    root, config, output = repair_case
    cfg = load_config(config)
    model = workflow_model(proposal())
    output.mkdir()
    with Trace(output / "trace.jsonl", "unified-test") as trace, Workspace(root, cfg.target) as ws:
        with RepairWorkflow(cfg, ws, trace, model, output, {"input": str(root), "commit": "0" * 40}) as repairs:
            graph = Agent(cfg, ws, trace, model, repairs=repairs).build()
            nodes, state = [], {}
            for mode, update in graph.stream({}, stream_mode=["updates", "values"]):
                if mode == "updates":
                    nodes.extend(update)
                else:
                    state = update
            repairs.finalize(state, TerminalStatus.COMPLETED, "")
            trace.terminal(TerminalStatus.COMPLETED)
    expected = ["settle", "repair_baseline", "repair_prepare", "repair_gate", "propose_patch",
                "apply_patch", "validate_syntax", "rerun_bandit", "run_tests", "repair_review", "repair_settle"]
    assert [node for node in nodes if node in expected] == expected
    assert nodes.index("repair_settle") < len(nodes) - 1
    assert nodes[-1] == "next_alert"
    assert next(iter(state["repair_rows"].values()))["status"] == "accepted"
    assert state["usage"] == {"input": 200, "output": 60}
    assert state["repair_usage"] == {"input": 100, "output": 50}


def test_one_trace_and_report_cover_the_whole_workflow(repair_case, clean_tests):
    root, config, output = repair_case
    assert run(str(root), output, config, quiet=True, llm=workflow_model(proposal()), repair=True) == 0
    report, repair = reports(output)
    row = repair["alerts"][0]
    assert row["status"] == "accepted"
    assert report["repairs"] == repair
    assert report["budget"]["used_tokens"] == 260
    assert repair["budget"]["used_tokens"] == 150
    assert "+    return int(value)" in (output / row["patch"]).read_text()
    assert (root / "radicale/app.py").read_text() == SOURCE
    assert not (output / "repair-trace.jsonl").exists()
    assert check_run(output) == []
    events = read_events(output / "trace.jsonl")
    assert [event["role"] for event in events if event["kind"] == "model_call"] == ["classifier", "repair"]
    request = next(event for event in events if event.get("tool") == "propose_patch")
    assert request["kind"] == "tool_request"
    assert request["requested_by"] == "model"
    assert events[-1]["kind"] == "terminal"


def test_failed_validation_routes_to_a_fresh_candidate(repair_case, clean_tests):
    root, config, output = repair_case
    model = workflow_model(proposal(new="eval(str(value))"), proposal())
    assert run(str(root), output, config, quiet=True, llm=model, repair=True) == 0
    row = reports(output)[1]["alerts"][0]
    assert row["status"] == "accepted"
    assert len(row["attempts"]) == 2
    assert row["attempts"][0]["validation"]["bandit"]["status"] == "failed"
    second = repair_messages(model)[1][1]["content"]
    assert "eval(str(value))" not in second
    assert "Previous validation" in second
    assert check_run(output) == []


@pytest.mark.parametrize("bad", [proposal(new="("), Reply("no patch", [], {"input": 10, "output": 5}, "stop")])
def test_syntax_and_missing_tools_follow_bounded_retry_edges(repair_case, clean_tests, bad):
    root, config, output = repair_case
    model = workflow_model(bad, bad)
    assert run(str(root), output, config, quiet=True, llm=model, repair=True) == 0
    row = reports(output)[1]["alerts"][0]
    assert row["status"] == "rejected"
    assert len(row["attempts"]) == 2
    assert not any(event.get("tool") == "candidate_tests" for event in read_events(output / "trace.jsonl"))
    assert check_run(output) == []


def test_patch_tool_uses_dispatcher_schema_checks(repair_case, clean_tests):
    root, config, output = repair_case
    bad = proposal()
    bad.tool_calls[0]["arguments"]["unexpected"] = True
    assert run(str(root), output, config, quiet=True, llm=workflow_model(bad, bad), repair=True) == 0
    row = reports(output)[1]["alerts"][0]
    assert row["status"] == "rejected"
    events = read_events(output / "trace.jsonl")
    results = [event for event in events if event.get("tool") == "propose_patch" and event["kind"] == "tool_result"]
    assert len(results) == 2 and all(not event["ok"] for event in results)
    assert check_run(output) == []


def test_bad_baseline_preserves_all_classifications(repair_case, monkeypatch):
    root, config, output = repair_case
    (root / "radicale/other.py").write_text(SOURCE)
    monkeypatch.setattr("sio2.validation.run_tests", lambda *args: {
        "status": "infrastructure_error", "returncode": 2, "output": "missing dependency"})
    model = workflow_model()
    assert run(str(root), output, config, quiet=True, llm=model, repair=True) == 2
    report, repair = reports(output)
    assert [row["status"] for row in report["alerts"]] == ["classified", "classified"]
    assert [row["status"] for row in repair["alerts"]] == ["blocked", "blocked"]
    assert not repair_messages(model)
    assert repair["status"] == "blocked"
    assert check_run(output) == []


def test_baseline_runs_once_for_multiple_alerts(repair_case, clean_tests):
    root, config, output = repair_case
    (root / "radicale/other.py").write_text(SOURCE)
    model = workflow_model(proposal(), proposal(path="radicale/other.py"))
    assert run(str(root), output, config, quiet=True, llm=model, repair=True) == 0
    report, repair = reports(output)
    assert [row["status"] for row in repair["alerts"]] == ["accepted", "accepted"]
    events = read_events(output / "trace.jsonl")
    baseline = [event for event in events if event["kind"] == "tool_request" and event["tool"] == "baseline_tests"]
    assert len(baseline) == 1
    assert report["budget"]["used_tokens"] == 520
    assert check_run(output) == []


def test_missing_tests_leave_scanner_validated_candidate_unaccepted(repair_case):
    root, config, output = repair_case
    config.write_text(CONFIG.replace('test_image = "sio2-tests:local"', 'test_image = ""'))
    assert run(str(root), output, config, quiet=True, llm=workflow_model(proposal()), repair=True) == 0
    row = reports(output)[1]["alerts"][0]
    assert row["status"] == "unvalidated"
    assert row.get("patch") is None
    assert check_run(output) == []


def test_repair_budget_is_a_sublimit_of_the_workflow(repair_case, clean_tests):
    root, config, output = repair_case
    config.write_text(CONFIG.replace("max_tokens = 20000", "max_tokens = 0"))
    model = workflow_model()
    assert run(str(root), output, config, quiet=True, llm=model, repair=True) == 0
    report, repair = reports(output)
    assert repair["status"] == "budget_exhausted"
    assert repair["budget"]["used_tokens"] == 0
    assert report["budget"]["used_tokens"] == 110
    assert not repair_messages(model)
    assert check_run(output) == []


def test_global_budget_also_limits_repair_calls(repair_case, clean_tests):
    root, config, output = repair_case
    config.write_text(CONFIG.replace("max_tokens = 100000", "max_tokens = 3000")
                      .replace("output_allowance = 2048", "output_allowance = 4096"))
    model = workflow_model()
    assert run(str(root), output, config, quiet=True, llm=model, repair=True) == 0
    report, repair = reports(output)
    assert report["alerts"][0]["status"] == "classified"
    assert repair["alerts"][0]["status"] == "budget_exhausted"
    assert read_events(output / "trace.jsonl")[-1]["status"] == "budget_exhausted"
    assert not repair_messages(model)
    assert check_run(output) == []


def test_step_limit_closes_candidate_workspace(repair_case, clean_tests):
    root, config, output = repair_case
    config.write_text(CONFIG.replace("max_steps = 200", "max_steps = 9"))
    assert run(str(root), output, config, quiet=True, llm=workflow_model(), repair=True) == 2
    events = read_events(output / "trace.jsonl")
    assert events[-1]["status"] == "max_steps"
    candidates = [Path(event["candidate"]) for event in events if event.get("candidate")]
    assert candidates and all(not path.exists() for path in candidates)
    assert reports(output)[1]["alerts"][0]["status"] == "max_steps"
    assert check_run(output) == []


def test_step_limit_between_proposal_and_apply_skips_the_tool(repair_case, clean_tests):
    root, config, output = repair_case
    config.write_text(CONFIG.replace("max_steps = 200", "max_steps = 10"))
    model = workflow_model(proposal())
    assert run(str(root), output, config, quiet=True, llm=model, repair=True) == 2
    events = read_events(output / "trace.jsonl")
    assert len(repair_messages(model)) == 1
    assert not any(event["kind"] == "tool_request" and event["tool"] == "propose_patch" for event in events)
    assert reports(output)[1]["alerts"][0]["status"] == "max_steps"
    assert check_run(output) == []


def test_repair_usage_can_exhaust_budget_before_the_next_classification(repair_case, clean_tests):
    root, config, output = repair_case
    (root / "radicale/other.py").write_text(SOURCE)
    config.write_text(CONFIG.replace("max_tokens = 100000", "max_tokens = 3000")
                      .replace("output_allowance = 2048", "output_allowance = 500"))
    fix = proposal()
    fix.usage = {"input": 1800, "output": 500}
    assert run(str(root), output, config, quiet=True, llm=workflow_model(fix), repair=True) == 0
    report, repair = reports(output)
    assert [row["status"] for row in report["alerts"]] == ["classified", "budget_exhausted"]
    assert report["budget"]["used_tokens"] == 2410
    assert repair["budget"]["used_tokens"] == 2300
    assert check_run(output) == []


def test_interrupt_during_validation_preserves_trace_and_cleans_candidate(repair_case, clean_tests, monkeypatch):
    root, config, output = repair_case

    def interrupt(*args):
        raise KeyboardInterrupt("test interrupt")

    monkeypatch.setattr("sio2.validation.check_syntax", interrupt)
    assert run(str(root), output, config, quiet=True, llm=workflow_model(proposal()), repair=True) == 2
    events = read_events(output / "trace.jsonl")
    assert events[-1]["status"] == "error"
    row = reports(output)[1]["alerts"][0]
    assert row["status"] == "interrupted"
    assert row["attempts"][0]["validation"]["status"] == "interrupted"
    candidates = [Path(event["candidate"]) for event in events if event.get("candidate")]
    assert candidates and all(not path.exists() for path in candidates)
    assert check_run(output) == []


def test_crlf_source_remains_exact_in_patch_proposals(repair_case):
    root, config, output = repair_case
    original = SOURCE.replace("\n", "\r\n").encode()
    (root / "radicale/app.py").write_bytes(original)
    config.write_text(CONFIG.replace('test_image = "sio2-tests:local"', 'test_image = ""'))

    def patch(messages):
        source = json.loads(messages[1]["content"])["original_source"]
        return proposal(old=source, new=source.replace("eval(value)", "int(value)"))

    assert run(str(root), output, config, quiet=True, llm=workflow_model(patch), repair=True) == 0
    assert reports(output)[1]["alerts"][0]["status"] == "unvalidated"
    assert (root / "radicale/app.py").read_bytes() == original


@pytest.mark.parametrize("test_status", ["not_configured", "failed"])
def test_owasp_restores_runtime_cases_and_redacts_retry_feedback(tmp_path, monkeypatch, test_status):
    root, config, output = tmp_path / "owasp", tmp_path / "config.toml", tmp_path / "out"
    (root / "testcode").mkdir(parents=True)
    (root / "testcode/BenchmarkTest00001.py").write_text("value = eval('1')\n")
    (root / "testcode/BenchmarkTest00002.py").write_text("secret_twin = eval('2')\n")
    (root / "expectedresults.csv").write_text("secret_answer_key")
    config.write_text((Path(__file__).parents[1] / "configs/owasp-full.toml").read_text())
    if test_status == "failed":
        calls = []

        def tests(*args):
            calls.append(True)
            return passing_tests() if len(calls) == 1 else {
                "status": "failed", "returncode": 1, "output": "secret_twin traceback source"}

        monkeypatch.setattr("sio2.validation.run_tests", tests)
    fix = proposal("eval('1')", "int('1')", "testcode/BenchmarkTest00001.py")
    model = workflow_model(fix, fix, labels={"testcode/BenchmarkTest00002.py": 0})
    assert run(str(root), output, config, quiet=True, llm=model, repair=True) == 0
    repair = reports(output)[1]
    validation = repair["alerts"][0]["attempts"][0]["validation"]
    assert validation["bandit"]["status"] == "passed"
    assert validation["bandit"]["alert_count"] == 1
    assert validation["status"] == ("rejected" if test_status == "failed" else "unvalidated")
    assert "secret_twin" not in json.dumps(repair_messages(model))
    assert "secret_answer_key" not in json.dumps(model.calls)
    assert (root / "expectedresults.csv").exists()
    assert check_run(output) == []


@pytest.mark.parametrize("setting", [
    "max_attempts = 0", "max_attempts = true", 'test_command = "pytest"',
    "test_timeout_s = 0", "max_tokens = -1", "output_limit = 0", "unknown_option = 1",
])
def test_invalid_repair_configuration_is_refused(tmp_path, setting):
    path = tmp_path / "config.toml"
    path.write_text(CONFIG.split("[repair]")[0] + "[repair]\n" + setting + "\n")
    with pytest.raises(ConfigError):
        load_config(path)


def test_false_positive_skips_repair_nodes_even_when_enabled(repair_case):
    root, config, output = repair_case
    model = workflow_model(labels={"radicale/app.py": 0})
    assert run(str(root), output, config, quiet=True, llm=model, repair=True) == 0
    assert reports(output)[1]["alerts"] == []
    assert not any(event.get("node") == "repair_baseline" for event in read_events(output / "trace.jsonl"))
    assert check_run(output) == []


def test_old_standalone_command_points_to_the_single_workflow():
    result = subprocess.run([sys.executable, "-m", "sio2.repair", "--help"], capture_output=True, text=True)
    assert result.returncode != 0
    assert "--repair" in result.stderr


def test_classification_only_keeps_the_existing_workflow(repair_case):
    root, config, output = repair_case
    assert run(str(root), output, config, quiet=True, llm=workflow_model()) == 0
    assert check_run(output) == []
    assert not (output / "repair-report.json").exists()
    assert "repairs" not in json.loads((output / "report.json").read_text())


@pytest.mark.skipif(not os.environ.get("SIO2_TEST_IMAGE"), reason="Set SIO2_TEST_IMAGE for Docker workflow tests.")
@pytest.mark.parametrize("value,expected", [("1", "accepted"), ("1.5", "rejected")])
def test_real_bandit_and_container_tests_in_one_workflow(repair_case, value, expected):
    root, config, output = repair_case
    command = ["python", "-c", f"from radicale.app import parse; assert parse({value!r}) == {value}"]
    text = CONFIG.replace("max_attempts = 2", "max_attempts = 1")
    text = text.replace('test_image = "sio2-tests:local"', f'test_image = "{os.environ["SIO2_TEST_IMAGE"]}"')
    text = text.replace('["python", "-m", "pytest", "-q"]', json.dumps(command))
    config.write_text(text)
    assert run(str(root), output, config, quiet=True, llm=workflow_model(proposal()), repair=True) == 0
    repair = reports(output)[1]
    assert repair["baseline"]["tests"]["status"] == "passed"
    assert repair["alerts"][0]["status"] == expected
    assert (root / "radicale/app.py").read_text() == SOURCE
    assert check_run(output) == []
