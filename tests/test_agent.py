"""Mechanism tests. No model needed: a scripted model stands in for Ollama.

The fake target is a tiny tree laid out like Radicale (so the staff [scan]
block applies unchanged) with three Bandit alerts in it.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from sio2.check import check_run
from sio2.cli import run
from sio2.config import load_config
from sio2.dispatch import Dispatcher
from sio2.llm import Reply, ScriptedChat
from sio2.tools import Toolbox
from sio2.tools.scan import build_command, normalise_path, parse_results
from sio2.trace import Trace, read_events
from sio2.workspace import PathRefused, Workspace

repo_root = Path(__file__).resolve().parent.parent

vulnerable_source = textwrap.dedent('''\
    import pickle
    import subprocess


    def load(blob):
        return pickle.loads(blob)


    def run(cmd):
        return subprocess.call(cmd, shell=True)


    def fetch(url):
        import requests
        return requests.get(url)
    ''')


@pytest.fixture
def fake_radicale(tmp_path) -> Path:
    root = tmp_path / "radicale-checkout"
    (root / "radicale" / "tests").mkdir(parents=True)
    (root / "radicale" / "app.py").write_text(vulnerable_source)
    (root / "radicale" / "tests" / "test_x.py").write_text("import pickle\npickle.loads(b'')\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root


def write_config(tmp_path, **budget) -> Path:
    b = {"max_tokens": 100000, "output_allowance": 256, "max_steps": 200, **budget}
    text = (repo_root / "configs" / "full.toml").read_text()
    for k, v in b.items():
        lines = [f"{k} = {v}" if line.startswith(f"{k} =") else line for line in text.splitlines()]
        text = "\n".join(lines) + "\n"
    p = tmp_path / "cfg.toml"
    p.write_text(text)
    return p


def call(name, **args):
    return {"name": name, "arguments": args}


def reply(*calls, inp=100, out=10, content=""):
    return Reply(content=content, tool_calls=list(calls), usage={"input": inp, "output": out},
                 done_reason="stop")


def honest_model(messages, tools):
    """Submits label 1, citing the opening read the runtime gave it."""
    user = messages[1]["content"]
    path = user.split("file: ")[1].split("\n")[0]
    rng = user.split(f"{path} lines ")[1].split(" ")[0]
    s, e = (int(x) for x in rng.split("-"))
    return reply(call("submit_label", label=1, rationale=f"Line evidence {s}-{e}.",
                      evidence=[{"path": path, "start_line": s, "end_line": e}]))


# --- workspace and path check ------------------------------------------------

def test_resolve_refuses_escapes(fake_radicale, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("x")
    os.symlink(outside, fake_radicale / "radicale" / "link.txt")
    with Workspace(fake_radicale, "radicale") as ws:
        assert ws.resolve("radicale/app.py")[1] == "radicale/app.py"
        for bad in ("../secret.txt", "/etc/passwd", "radicale/../../x", "radicale/link.txt", ".git/config"):
            with pytest.raises(PathRefused):
                ws.resolve(bad)
        assert not (ws.root / ".git").exists()
        root = ws.root
    assert not root.exists()                       # disposable
    assert (fake_radicale / ".git").is_dir()       # the input is untouched


def test_owasp_withholding_and_restore(tmp_path):
    root = tmp_path / "owasp"
    (root / "testcode").mkdir(parents=True)
    (root / "templates/web/x").mkdir(parents=True)
    (root / "results").mkdir()
    (root / "helpers").mkdir()
    for n in ("00001", "00002", "00003"):
        (root / f"testcode/BenchmarkTest{n}.py").write_text(f"# {n}\n")
        (root / f"templates/web/x/BenchmarkTest{n}.html").write_text(n)
    (root / "expectedresults-0.1.csv").write_text("key")
    (root / "results/Bandit.sarif").write_text("{}")
    (root / "helpers/util.py").write_text("x = 1\n")
    with Workspace(root, "owasp", keep=True) as ws:
        assert not (ws.root / "expectedresults-0.1.csv").exists()
        with pytest.raises(PathRefused):
            ws.resolve("expectedresults-0.1.csv")
        ws.focus("testcode/BenchmarkTest00002.py")
        assert sorted(p.name for p in (ws.root / "testcode").iterdir()) == ["BenchmarkTest00002.py"]
        assert ws.resolve("helpers/util.py")
        assert ws.resolve("templates/web/x/BenchmarkTest00002.html")
        with pytest.raises(PathRefused):
            ws.resolve("testcode/BenchmarkTest00001.py")
        ws.focus("testcode/BenchmarkTest00003.py")   # switch case: previous set restored first
        assert sorted(p.name for p in (ws.root / "testcode").iterdir()) == ["BenchmarkTest00003.py"]
        kept = ws.root
    # On exit everything is put back, so a kept tree is complete.
    assert len(list((kept / "testcode").iterdir())) == 3
    assert (kept / "expectedresults-0.1.csv").exists() and (kept / "results/Bandit.sarif").exists()
    shutil.rmtree(kept.parent)


# --- dispatcher ---------------------------------------------------------------

def test_dispatcher_refuses_without_crashing(fake_radicale, tmp_path):
    trace = Trace(tmp_path / "t.jsonl", "t")
    d = Dispatcher(trace)
    with Workspace(fake_radicale, "radicale") as ws:
        toolbox = Toolbox(ws, 50, 10, 50)
        assert not d.run("a", "rm_rf", {}, toolbox).ok
        assert not d.run("a", "read_file", {"path": 3}, toolbox).ok
        assert not d.run("a", "read_file", {"path": "x", "bogus": 1}, toolbox).ok
        assert not d.run("a", "read_file", "not a dict", toolbox).ok
        assert not d.run("a", "read_file", {"path": "../../etc/passwd"}, toolbox).ok
        assert not d.run("a", "search", {"pattern": "(", "regex": True}, toolbox).ok
        assert not d.run("a", "submit_label", {"label": 1, "rationale": "r",
                                                "evidence": [{"path": "radicale/app.py", "start_line": 1,
                                                              "end_line": 3}]}, toolbox).ok  # never read
        ok = d.run("a", "read_file", {"path": "radicale/app.py", "start_line": 1, "end_line": 6}, toolbox)
        assert ok.ok and "pickle.loads" in ok.text
        assert d.run("a", "submit_label", {"label": 0, "rationale": "r",
                                            "evidence": [{"path": "radicale/app.py", "start_line": 2,
                                                          "end_line": 5}]}, toolbox).ok
    trace.close()
    ev = read_events(tmp_path / "t.jsonl")
    for i, e in enumerate(ev):
        if e["kind"] == "tool_request":
            assert ev[i + 1]["kind"] == "tool_result"
    assert all("error" in e for e in ev if e["kind"] == "tool_result" and not e["ok"])


# --- scan ----------------------------------------------------------------------

def test_bandit_command_and_parsing():
    cfg = load_config(repo_root / "configs" / "full.toml")
    cmd = build_command("bandit", cfg.scan, ["radicale"], Path("/o.json"))
    assert cmd == ["bandit", "-q", "-r", "--severity-level", "medium", "-x", "radicale/tests",
                   "-f", "json", "-o", "/o.json", "radicale"]
    assert normalise_path("./testcode/a.py") == "testcode/a.py"
    data = {"results": [
        {"filename": "./b.py", "line_number": 3, "test_id": "B301", "issue_severity": "MEDIUM",
         "issue_confidence": "HIGH"},
        {"filename": "./a.py", "line_number": 10, "test_id": "B602", "issue_severity": "HIGH",
         "issue_confidence": "HIGH"},
        {"filename": "./a.py", "line_number": 9, "test_id": "B301", "issue_severity": "LOW",
         "issue_confidence": "HIGH"},
        {"filename": "./a.py", "line_number": 10, "test_id": "B602", "issue_severity": "HIGH",
         "issue_confidence": "LOW"}]}
    alerts = parse_results(data, "t", "MEDIUM")
    assert [(a.path, a.line) for a in alerts] == [("a.py", 10), ("a.py", 10), ("b.py", 3)]
    assert len({a.alert_id for a in alerts}) == 3          # duplicates kept, ids unique


# --- whole runs ------------------------------------------------------------------

def test_full_run_classifies_everything(fake_radicale, tmp_path):
    out = tmp_path / "out"
    run(str(fake_radicale), out, write_config(tmp_path), quiet=True, llm=ScriptedChat(honest_model))
    assert check_run(out) == []
    rep = json.loads((out / "report.json").read_text())
    assert rep["scan"]["alert_count"] == 3                      # tests/ excluded, LOW filtered
    assert {r["status"] for r in rep["alerts"]} == {"classified"}
    assert rep["budget"]["used_tokens"] == 3 * 110
    assert read_events(out / "trace.jsonl")[-1]["status"] == "completed"


def test_budget_cutoff(fake_radicale, tmp_path):
    out = tmp_path / "out"
    # Enough for the first call only: the gate refuses the second before it is made.
    run(str(fake_radicale), out, write_config(tmp_path, max_tokens=3200, output_allowance=256),
        quiet=True, llm=ScriptedChat(lambda m, t: reply(*honest_model(m, t).tool_calls, inp=2000)))
    assert check_run(out) == []
    rep = json.loads((out / "report.json").read_text())
    assert [r["status"] for r in rep["alerts"]] == ["classified", "budget_exhausted", "budget_exhausted"]
    assert rep["budget"]["exhausted"] and rep["budget"]["used_tokens"] <= 3200
    ev = read_events(out / "trace.jsonl")
    assert ev[-1]["status"] == "budget_exhausted"
    cut = [e for e in ev if e["kind"] == "routing" and e["decision"] == "cutoff"]
    assert cut and cut[0]["by"] == "runtime"


def test_zero_budget_makes_no_model_call(fake_radicale, tmp_path):
    out = tmp_path / "out"
    model = ScriptedChat(honest_model)
    run(str(fake_radicale), out, write_config(tmp_path, max_tokens=0), quiet=True, llm=model)
    assert model.calls == [] and check_run(out) == []


def test_max_steps(fake_radicale, tmp_path):
    out = tmp_path / "out"
    model = ScriptedChat(lambda m, t: reply(call("read_file", path="radicale/app.py",
                                                 start_line=len(m), end_line=len(m) + 1)))
    run(str(fake_radicale), out, write_config(tmp_path, max_steps=12), quiet=True, llm=model)
    assert check_run(out) == []
    ev = read_events(out / "trace.jsonl")
    assert ev[-1]["status"] == "max_steps"
    assert {r["status"] for r in json.loads((out / "report.json").read_text())["alerts"]} == {"error"}


def test_no_progress(fake_radicale, tmp_path):
    out = tmp_path / "out"
    model = ScriptedChat(lambda m, t: reply(call("read_file", path="../../etc/passwd")))
    run(str(fake_radicale), out, write_config(tmp_path), quiet=True, llm=model)
    assert check_run(out) == []
    assert read_events(out / "trace.jsonl")[-1]["status"] == "no_progress"
    assert len(model.calls) == 3                     # no_progress_limit in configs/full.toml


def test_crash_still_writes_report_and_terminal(fake_radicale, tmp_path):
    out = tmp_path / "out"
    n = {"calls": 0}

    def flaky(m, t):
        n["calls"] += 1
        if n["calls"] == 2:
            raise RuntimeError("simulated crash in the provider client")
        return honest_model(m, t)

    run(str(fake_radicale), out, write_config(tmp_path), quiet=True, llm=ScriptedChat(flaky))
    assert check_run(out) == []
    rep = json.loads((out / "report.json").read_text())
    assert [r["status"] for r in rep["alerts"]] == ["classified", "error", "error"]
    assert read_events(out / "trace.jsonl")[-1]["status"] == "error"


def test_model_without_tool_call_is_nudged_then_settled(fake_radicale, tmp_path):
    out = tmp_path / "out"
    script = iter([reply(content="I think it is fine.")])

    def model(m, t):
        return next(script, None) or honest_model(m, t)

    run(str(fake_radicale), out, write_config(tmp_path), quiet=True, llm=ScriptedChat(model))
    assert check_run(out) == []
    ev = read_events(out / "trace.jsonl")
    assert any(e["kind"] == "routing" and e["decision"] == "nudge" and e["by"] == "runtime" for e in ev)


def _tree_digest(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and ".git" not in p.parts}


def test_input_checkout_is_untouched_by_a_run(fake_radicale, tmp_path):
    before = _tree_digest(fake_radicale)
    run(str(fake_radicale), tmp_path / "out", write_config(tmp_path), quiet=True,
        llm=ScriptedChat(honest_model))
    assert _tree_digest(fake_radicale) == before


def test_evidence_must_lie_inside_lines_shown(fake_radicale, tmp_path):
    trace = Trace(tmp_path / "t.jsonl", "t")
    d = Dispatcher(trace)
    with Workspace(fake_radicale, "radicale") as ws:
        toolbox = Toolbox(ws, 50, 10, 50)
        d.run("a", "read_file", {"path": "radicale/app.py", "start_line": 1, "end_line": 4}, toolbox)
        d.run("a", "read_file", {"path": "radicale/app.py", "start_line": 5, "end_line": 8}, toolbox)
        d.run("a", "read_file", {"path": "radicale/app.py", "start_line": 12, "end_line": 15}, toolbox)
        sub = lambda s, e: d.run("a", "submit_label", {"label": 1, "rationale": "r", "evidence": [
            {"path": "radicale/app.py", "start_line": s, "end_line": e}]}, toolbox).ok
        assert sub(2, 7)            # spans two adjacent reads: covered
        assert not sub(6, 13)       # crosses the unread gap 9-11
        assert not sub(14, 16)      # runs past the last line read
    trace.close()


def test_interrupt_inside_a_tool_keeps_invariants(fake_radicale, tmp_path, monkeypatch):
    import sio2.tools.scan as scan

    def interrupted(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(scan, "run_bandit", interrupted)
    out = tmp_path / "out"
    run(str(fake_radicale), out, write_config(tmp_path), quiet=True, llm=ScriptedChat(honest_model))
    assert check_run(out) == []
    ev = read_events(out / "trace.jsonl")
    assert [e["kind"] for e in ev[1:3]] == ["tool_request", "tool_result"] and ev[-1]["status"] == "error"


@pytest.mark.parametrize("node,budget", [("cutoff", {"max_tokens": 0}), ("halt", {"max_steps": 12})])
@pytest.mark.parametrize("when", ["before_rows", "after_rows"])
def test_failure_while_settling_in_bulk_settles_each_row_once(fake_radicale, tmp_path, monkeypatch,
                                                              node, budget, when):
    """A failure inside cutoff/halt, before or after its rows reach the trace, still settles each row once."""
    import sio2.graph as graph
    real = getattr(graph.Agent, node)

    def failing(self, s):
        if when == "before_rows":
            raise OSError("simulated failure before settling")
        real(self, s)               # rows are written to the trace...
        raise OSError("simulated failure after settling")   # ...but never committed to state
    monkeypatch.setattr(graph.Agent, node, failing)
    out = tmp_path / "out"
    model = ScriptedChat(lambda m, t: reply(call("read_file", path="radicale/app.py",
                                                 start_line=len(m), end_line=len(m) + 1)))
    run(str(fake_radicale), out, write_config(tmp_path, **budget), quiet=True, llm=model)
    assert check_run(out) == []
    rep = json.loads((out / "report.json").read_text())
    want = {"before_rows": "error", "after_rows": "budget_exhausted" if node == "cutoff" else "error"}[when]
    assert {r["status"] for r in rep["alerts"]} == {want}
    assert read_events(out / "trace.jsonl")[-1]["status"] == "error"


def test_last_turns_offer_only_submit_and_refuse_other_tools(fake_radicale, tmp_path):
    out = tmp_path / "out"
    offered = []

    def investigator(m, t):
        offered.append([x["function"]["name"] for x in t])
        return reply(call("read_file", path="radicale/app.py", start_line=len(m), end_line=len(m)))
    run(str(fake_radicale), out, write_config(tmp_path), quiet=True, llm=ScriptedChat(investigator))
    assert check_run(out) == []
    assert offered[:8] == [["read_file", "search", "list_dir", "submit_label"]] * 6 + [["submit_label"]] * 2
    ev = read_events(out / "trace.jsonl")
    assert any(e["kind"] == "tool_result" and not e["ok"] and "not available on this turn" in e["error"]
               for e in ev)
    rows = json.loads((out / "report.json").read_text())["alerts"]
    assert rows[0]["status"] == "error" and "8 model turns" in rows[0]["rationale"]


def test_sigterm_still_writes_report_and_terminal(fake_radicale, tmp_path):
    import signal as sig
    out = tmp_path / "out"
    n = {"calls": 0}

    def killed(m, t):
        n["calls"] += 1
        if n["calls"] == 2:
            os.kill(os.getpid(), sig.SIGTERM)
        return honest_model(m, t)
    run(str(fake_radicale), out, write_config(tmp_path), quiet=True, llm=ScriptedChat(killed))
    assert check_run(out) == []
    ev = read_events(out / "trace.jsonl")
    assert ev[-1]["status"] == "error" and "signal" in ev[-1]["reason"]


def test_submit_cannot_cite_a_read_from_the_same_reply(fake_radicale, tmp_path):
    """The model chose its evidence before it saw that read's output, so the citation is refused."""
    out = tmp_path / "out"
    first = {"done": False}

    def blind_then_honest(m, t):
        if not first["done"]:
            first["done"] = True
            return reply(call("read_file", path="radicale/app.py", start_line=13, end_line=15),
                         call("submit_label", label=1, rationale="r",
                              evidence=[{"path": "radicale/app.py", "start_line": 13, "end_line": 15}]))
        return honest_model(m, t)
    # context_lines = 0: the opening read shows only the flagged line, not 13-15
    run(str(fake_radicale), out, write_config(tmp_path, context_lines=0), quiet=True,
        llm=ScriptedChat(blind_then_honest))
    assert check_run(out) == []
    ev = read_events(out / "trace.jsonl")
    first_submit = next(e for e in ev if e["kind"] == "tool_result" and e["tool"] == "submit_label")
    assert not first_submit["ok"] and "no observation showed you" in first_submit["error"]


def test_float_arguments_are_refused(fake_radicale, tmp_path):
    trace = Trace(tmp_path / "t.jsonl", "t")
    d = Dispatcher(trace)
    with Workspace(fake_radicale, "radicale") as ws:
        toolbox = Toolbox(ws, 50, 10, 50)
        assert d.run("a", "read_file", {"path": "radicale/app.py", "start_line": 1, "end_line": 6}, toolbox).ok
        assert not d.run("a", "read_file", {"path": "radicale/app.py", "start_line": 1.0}, toolbox).ok
        assert not d.run("a", "submit_label", {"label": 1.0, "rationale": "r", "evidence": [
            {"path": "radicale/app.py", "start_line": 1, "end_line": 2}]}, toolbox).ok
    trace.close()


def test_crash_right_after_discovery_still_reports_every_alert(fake_radicale, tmp_path, monkeypatch):
    import sio2.graph as graph
    real = graph.Agent.discover

    def discover_then_crash(self, s):
        real(self, s)
        raise RuntimeError("crash before LangGraph commits discover's update")
    monkeypatch.setattr(graph.Agent, "discover", discover_then_crash)
    out = tmp_path / "out"
    run(str(fake_radicale), out, write_config(tmp_path), quiet=True, llm=ScriptedChat(honest_model))
    assert check_run(out) == []
    rep = json.loads((out / "report.json").read_text())
    assert rep["scan"]["alert_count"] == 3 and {r["status"] for r in rep["alerts"]} == {"error"}
