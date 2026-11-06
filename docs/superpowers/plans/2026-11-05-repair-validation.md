# Repair Validation Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. Track each task below.

**Goal:** Produce independent, reviewable security patches with Bandit and test validation.

**Architecture:** Add an opt-in repair phase after classification. Preserve the original report and trace. Use independent disposable candidates and a separate repair budget, report, and event log.

**Tech Stack:** Python 3.12, existing model clients, Bandit 1.9.4, Docker, pytest.

**Spec:** The repair proposal in this conversation, accepted through the request to apply it.

## Global Constraints

- Never change the input checkout or classification results.
- Allow exact replacements only in the alert's Python source file.
- Refuse test files, hidden files, symlinks, and added scanner suppressions.
- Restore all OWASP cases before runtime validation. Keep answer keys withheld.
- Use identical scan configuration for baseline and candidate scans.
- Accept patches only after clean baseline tests and successful candidate tests.
- Run configured test commands only inside a restricted Docker container.
- Keep each retry independent. Return the previous validation result to the model.
- Keep classification token accounting unchanged. Record repair usage separately.

## Review Focus

- Line changes must not count unchanged findings as new findings. Task 2 tests this.
- Scanner errors must block acceptance. Task 2 tests this.
- Missing tests or dependencies must never produce accepted patches. Tasks 2 and 3 test this.
- Invalid replacements must leave every file unchanged. Task 1 tests this.
- Budget limits and malformed model replies must stop with saved results. Task 3 tests this.

### Task 1: Constrained patches

**Files:** Create `src/sio2/tools/patch.py` and `tests/test_patch.py`.

**Interfaces:** `apply_patch(ws, edits, allowed_paths) -> PatchResult`. Each edit contains `path`, `old_text`, and `new_text`. The result contains original text, candidate text, and a unified diff.

- [x] Write tests for exact replacement, atomic refusal, overlap, path escape, symlink, tests, and suppressions.
- [x] Run `uv run python -m pytest tests/test_patch.py -q`. Confirm missing module failures.
- [x] Implement validation before writes and rollback after write errors.
- [x] Run the patch tests and full suite. Confirm all tests pass.

### Task 2: Runtime validation

**Files:** Create `src/sio2/validation.py` and `tests/test_validation.py`.

**Interfaces:** `compare_findings(baseline, candidate, target_id, patch) -> dict`. `run_tests(root, repair_config) -> dict` returns status, exit code, output, and command. `validate_candidate(...) -> dict` combines syntax, scan, and tests.

- [x] Write tests for mapped findings, remaining target findings, new findings, syntax errors, and scan errors.
- [x] Add bounded-process tests for timeout, output overflow, command failure, and missing executables.
- [x] Run the tests and verify failure before implementation.
- [x] Implement conservative source mapping and the restricted Docker runner.
- [x] Run targeted tests and the full suite. Confirm all tests pass.

### Task 3: Repair controller and CLI

**Files:** Create `src/sio2/repair.py`, `tests/test_repair.py`, and a repair prompt. Change `src/sio2/config.py`, `src/sio2/cli.py`, and `README.md`.

**Interfaces:** `run_repairs(input_root, output, cfg, report, llm=None) -> dict`. Add validated optional repair configuration. Add `--repair` to the existing CLI and a standalone `python -m sio2.repair` entry point.

- [x] Write tests for disabled behavior, successful patch artifacts, independent retries, baseline failure, and bounded budgets.
- [x] Run the tests and verify failure before implementation.
- [x] Implement one patch proposal per attempt, separate repair accounting, and incremental artifact persistence.
- [x] Document container preparation, configuration, command use, and acceptance limits.
- [x] Run the full suite and command help checks. Confirm all tests pass.

## Execution Record

- Baseline: 26 tests passed after `uv sync --reinstall` repaired stale executable paths.
- Workspace: This directory has no Git metadata. Worktree and commit steps do not apply.
- Execution: Native implementation. No subagent tool is available.
- Task 1: complete. Initial suite: 41 passed.
- Task 2: complete. Initial suite: 58 passed.
- Task 3: complete. Initial suite: 74 passed.
- Final review: self-review, because no subagent tool is available.
- Fixed suppression-line changes, invalid diffs without final newlines, ambiguous finding matches, and UTF-8 output expansion. Regression tests failed before each fix.
- Fixed CRLF source normalization and OWASP test-output exposure through retry feedback. Regression tests failed before each fix.
- Ruling: Transfer source archives through standard input instead of bind mounts. Colima cannot mount this machine's system temporary directories.
- Cost: Test images need `tar` and `/bin/sh`. No host filesystem mount enters the container.
- Final suite: 85 tests passed with `SIO2_TEST_IMAGE=python:3.12-slim uv run python -m pytest -q`.
- Real Docker tests cover source isolation, accepted repairs, and test-regression rejection. Bandit runs without a test double.
- Model behavior uses scripted replies. No live model or full target-suite evaluation ran.
- CLI help checks and Python compilation passed.
