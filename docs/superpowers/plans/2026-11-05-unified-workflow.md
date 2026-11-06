# Unified Repair Workflow Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. Track the tasks below.

**Goal:** Execute classification, repair, and validation inside one LangGraph workflow.

**Architecture:** Register explicit repair nodes on the existing StateGraph. Repair follows each vulnerable classification before the next alert. Reuse the dispatcher, source checks, Docker runner, and one trace.

**Tech Stack:** Python 3.12, LangGraph, Bandit 1.9.4, Docker, pytest.

**Spec:** The user correction: repair must belong to one workflow, not a separate controller.

## Global Constraints

- Preserve classification-only behavior when repair is disabled.
- Keep classification rows write-once and separate from repair outcomes.
- Count all model calls in the main trace and token total.
- Apply the repair token limit within the workflow budget.
- Keep independent candidates and protect the original input.
- Preserve OWASP withholding and runtime-only test access.
- Close candidate workspaces after retries, errors, and interrupts.
- Remove the separate repair controller and standalone repair command.

## Approaches

A second graph or a Python loop would preserve separate orchestration. The user rejects that separation.

Use explicit nodes in the existing graph instead. The graph controls proposal, patch application, syntax checks, Bandit, tests, review, and retries.

## Review Focus

- Actual graph updates must contain repair and validation nodes.
- Failed validation must route through graph edges to a fresh candidate.
- Repair calls must affect the global budget and trace invariants.
- Baseline failure must block repair without losing later classifications.
- Step limits and interrupts must preserve artifacts and release candidates.

### Task 1: Specify the unified workflow

**Files:** Rewrite `tests/test_repair.py` for the single workflow.

**Interface:** `Agent(..., repairs=RepairWorkflow(...)).build()` returns the only compiled graph. CLI `run(..., repair=True)` drives it once.

- [x] Test real graph node execution and paired dispatcher events.
- [x] Test acceptance, retries, syntax refusal, scan refusal, and test failure.
- [x] Test global and repair budgets, baseline reuse, and step limits.
- [x] Retain Docker, CRLF, source-isolation, and OWASP coverage.
- [x] Run tests and confirm failures against the separate controller.

### Task 2: Integrate repair nodes

**Files:** Change `src/sio2/repair.py`, `graph.py`, `dispatch.py`, `tools/patch.py`, and `validation.py`.

**Interface:** `RepairWorkflow.install(graph)` registers nodes and edges. Its lifetime owns active candidates, not graph execution. Validation checks return structured results.

- [x] Add a dispatcher-backed patch tool and split reusable validation checks.
- [x] Add repair state and register explicit nodes on the existing StateGraph.
- [x] Route vulnerable labels into repair and finished repairs into the next alert.
- [x] Enforce global steps and tokens plus the repair token limit.
- [x] Run targeted tests and confirm successful graph execution.

### Task 3: Use one CLI lifetime and trace

**Files:** Change `src/sio2/cli.py` and `README.md`.

**Interface:** One graph stream produces `report.json`, `trace.jsonl`, repair outcomes, and patch artifacts.

- [x] Remove post-graph repair execution and the separate repair trace.
- [x] Create model clients and candidate cleanup inside the existing run lifetime.
- [x] Save repair outcomes in the main report and detailed validation artifacts.
- [x] Document the unified flow and token-accounting change.
- [x] Run the full suite, real Docker tests, compilation, and CLI help checks.

## Execution Record

- Work proceeds in place. The directory has no Git metadata.
- No subagent tool is available. Native execution and a final self-review apply.
- This plan supersedes the separate-controller architecture in the earlier repair plan.
- Baseline: 85 tests passed with the local Docker image before this change.
- Task 1: New tests failed because the separate controller lacked RepairWorkflow.
- Tasks 2 and 3: Complete. Actual graph updates contain every repair node.
- Budget test correction: The classifier needs 2145 estimated tokens. A 3000-token workflow limit tests repair cutoff after classification.
- Final review: Self-review. The review found step-limit gaps between proposal and patch application, plus incomplete attempt statuses after interrupts.
- Regression tests failed before the fixes. Step guards now protect each repair node, and interrupted attempts preserve final status in artifacts.
- The old standalone module command now exits with guidance to use `sio2 --repair`.
- Final verification: 94 tests passed with `SIO2_TEST_IMAGE=python:3.12-slim uv run python -m pytest -q`.
- Python compilation and CLI help checks passed. No test containers remain.
- Model tests use scripted replies. Bandit and the three Docker integration tests use real processes.
