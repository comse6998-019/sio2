# sio2

Named for silicon dioxide (SiO₂), the main component of sand.

A bounded agent for HW1 (COMS E6998-019). It scans a pinned Python repository
with Bandit 1.9.4 at MEDIUM or higher severity. A model server then labels
every alert 1 (potential vulnerability) or 0 (not a vulnerability), with a
rationale and line evidence. Each run writes
`report.json` and `trace.jsonl`.

- Design report (A1–A7, C2, C3): [REPORT.md](REPORT.md)
- Who did what: [CONTRIBUTIONS.md](CONTRIBUTIONS.md)
- The runs the report cites: [runs/](runs/), each with the config it used

## 1. Setup from a fresh clone

You need macOS or Linux, `git`, [uv](https://docs.astral.sh/uv/), and access to a model server.

Use an OpenAI-compatible chat-completions server with tool-call support and token-usage counters. The server can run on your host or a remote machine.

```bash
git clone <this repository> sio2 && cd sio2

# Python 3.12 and every dependency, pinned by uv.lock (Bandit 1.9.4 included)
uv python install 3.12
uv sync
uv run bandit --version          # must print: bandit 1.9.4
```

### Configure the model server

Start your chosen server separately. Select a model that supports tool calls and record the exact model ID that the server exposes.

Copy a target configuration before changing its model settings:

```bash
cp configs/full.toml configs/local-radicale.toml
```

Replace the copy's entire `[model]` block with:

```toml
[model]
provider = "openai-compatible"
name = "YOUR_MODEL_ID"
host = "http://localhost:8080"
api_key_var = "LOCAL_MODEL_KEY"
temperature = 0.0
```

Replace `YOUR_MODEL_ID` and the host URL with your server's values. sio2 appends `/v1/chat/completions`, so omit `/v1` from `model.host`.

The committed run configurations retain their original model settings for reproducibility. Replace their `[model]` block before using another server.

Changing the endpoint environment variable alone does not select the provider or model.

Clone the three targets at their pinned commits into `targets/`, which git
ignores:

```bash
mkdir -p targets
git clone https://github.com/OWASP-Benchmark/BenchmarkPython targets/owasp-benchmark-python
git -C targets/owasp-benchmark-python checkout f1291485808b66e20ddb6b01b10dc71b3df8c8ba
git clone https://github.com/Kozea/Radicale targets/radicale
git -C targets/radicale checkout eff8027f3dc4910be1659ee71f4b4a454ade5a8c
git clone https://github.com/sgl-project/sglang targets/sglang
git -C targets/sglang checkout bbe9c7eeb520b0a67e92d133dfc137a3688dc7f2
```

**Model environment variables:**

- TOML `model.host` selects the endpoint for either client. For OpenAI-compatible endpoints, supply the base URL without `/v1`.
- `model.api_key_var` selects the environment variable that supplies the bearer token. It defaults to `LOCAL_MODEL_KEY`.
- To use another variable, set `api_key_var = "MY_PROVIDER_API_KEY"`. Store only the variable name in TOML, never the credential value.

For an unauthenticated local server, no key is necessary. Configure authentication according to the server's requirements.

## 2. Run command

The agent is `sio2`, installed into the project environment by `uv sync`:

```bash
uv run sio2 --input <target checkout root> --output <out dir> --config <config.toml>
```

For example:

```bash
uv run sio2 --input targets/radicale --output runs/radicale-full --config configs/local-radicale.toml
```

It writes `<out dir>/report.json` and `<out dir>/trace.jsonl`. The trace is
also echoed to stderr as the run goes; add `--quiet` to silence it.

Exit status:

| Status | Meaning |
|---|---|
| 0 | the run ended `completed` or `budget_exhausted` |
| 2 | the run ended `max_steps`, `no_progress` or `error`; the report and trace are still written |
| 1 | the config is invalid; nothing ran |

## 3. Configs

| File | Purpose |
|---|---|
| `configs/full.toml` | Full budget: 600,000 tokens, 1,024 output tokens per call, 600 steps. Enough for the largest target. |
| `configs/low.toml` | The same, but `max_tokens = 15000`, which runs out partway through Radicale. Later rows are `budget_exhausted`. |

Both configurations use the Radicale `[scan]` block and validate against `schemas/config.schema.json`, an unchanged copy of the staff schema.

For another target, use its scan block from the staff repository's `briefs/scan/*.toml`. The copies in `configs/owasp-*.toml` and `configs/sglang-*.toml` preserve those blocks.

Keep the budget and agent settings, and configure `[model]` for your server. `configs/demo-max-steps.toml` uses `max_steps = 40` to show the step failsafe.

To repeat the recorded runs, use `scripts/run_all.sh` with the original model environment. For a different server, copy the target configuration and replace its `[model]` block.

Keys we added beyond the required ones (all optional, with defaults):

| Key | Purpose |
|---|---|
| `model.host` | Model server base URL, without `/v1` for the OpenAI-compatible client |
| `model.temperature` | Sampling temperature, default 0 |
| `agent.max_turns_per_alert` | model calls per alert |
| `agent.submit_only_turns` | how many of those last turns offer only `submit_label` |
| `agent.no_progress_limit` | consecutive turns without a new observation |
| `agent.context_lines` | lines either side of the alert in the opening read |
| `agent.read_max_lines`, `agent.search_max_hits`, `agent.list_max_entries` | tool limits (120, 30, 150) |
| `agent.chars_per_token` | divisor of the pre-call budget estimate (3.0; never used for the charge) |
| `agent.keep_workspace` | keep the disposable copy after the run, for inspection |

## 4. Checking a run

```bash
# Schemas and all six trace invariants, plus label counts
uv run python -m sio2.check runs/radicale-full

# One alert's trajectory as a Mermaid sequence diagram
uv run python -m sio2.trajectory runs/radicale-low/trace.jsonl --list
uv run python -m sio2.trajectory runs/radicale-low/trace.jsonl <alert_id>

# OWASP precision and recall against the benchmark's own key (developer tool, never the agent)
uv run python scripts/evaluate_owasp.py runs/owasp-full/report.json targets/owasp-benchmark-python

# Mechanism tests with a scripted model: no model server needed
uv run pytest
```

## Code map

| Path (under `src/sio2/`) | What it is |
|---|---|
| `cli.py` | the entry point; one run is `with Trace(...)` around `with Workspace(...), model_client(...)` |
| `graph.py` | the LangGraph state machine: `Node` and `Route` enums, the state and its reducers, nodes and edges |
| `tools/` | the tools as classes: `base.py` (`Tool`, `WorkspaceTool`, `EvidenceLedger`), `files.py` (`ReadFile`, `Search`, `ListDir`), `submit.py` (`SubmitLabel`), `scan.py` (the Bandit wrapper and the runtime-only `BanditScan`); `Toolbox` binds the model's tools to one alert |
| `dispatch.py` | the dispatcher: validates and runs every request, writes every observation |
| `prompts/` | every prompt as a Markdown file, and the loader that fills them in |
| `trace.py` | `trace.jsonl` writer, and the `EventKind`, `TerminalStatus`, `AlertStatus` and `Decider` enums |
| `workspace.py` | the disposable copy, withholding, and the one path check |
| `config.py`, `llm.py` | the config (with the `Target` enum) and model-provider clients |
| `check.py`, `trajectory.py` | the run checker and the sequence-diagram renderer |
| `repair.py`, `validation.py` | repair nodes on the same LangGraph workflow, source-aware scan comparison, and container tests |
| `tools/patch.py` | constrained exact replacements and unified patch export |

## Container deployment and runtime scan inputs

The sio2 image contains the agent and its tools, not the application under review. Supply target source at runtime.

The same image can scan different checkouts under the supported scan profiles. Do not build a new sio2 image for each repository.

### From repository selection to scan results

The intended user flow is:

```text
Select repository, revision, scan scope, and budget
    → prepare an exact source snapshot
    → supply source, configuration, and model access
    → execute one sio2 workflow
    → collect reports, traces, and proposed patches
```

With repair enabled, the workflow scans, classifies, proposes patches, and validates candidates in the same LangGraph graph.

sio2 currently accepts a local directory through `--input`, not a repository URL. A production ingestion layer must download repositories before sio2 starts.

That layer should resolve branches or tags to commit SHAs, record the resolved revision, and reject unsupported repository locations. Keep ingestion outside the agent.

For OWASP Python, use the checkout command in the setup section. The pinned commit is `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`.

### Separate immutable inputs from writable work

| Container path | Purpose | Access |
|---|---|---|
| `/inputs/target` | Original repository snapshot | Read-only |
| `/inputs/config.toml` | Scan configuration | Read-only |
| `/sandbox/runs` | Reports, traces, and proposed patches | Writable |
| `/tmp` | Disposable analysis and repair workspaces | Writable |

sio2 copies source into disposable workspaces. It never applies proposed repairs to the original checkout.

Keep the target, model credentials, and previous run output out of the agent image. `.dockerignore` limits the build context to agent inputs.

### Build and run with Docker

Build the target-independent image from the repository root:

```bash
docker build -f Dockerfile.openshell -t sio2-openshell:local .
```

The image includes Python 3.12, locked sio2 dependencies, Bandit 1.9.4, and the system tools for OpenShell integration. It uses a non-root account.

Configure a model endpoint that the container can reach. `localhost` inside the container does not refer to the host model server.

Prepare a local OWASP configuration:

```bash
cp configs/owasp-full.toml configs/local-owasp.toml
```

Replace its `[model]` block as described in the setup section. Use `provider = "openai-compatible"` and your server's model ID.

For a host server under Colima, use `host.lima.internal`. For Docker Desktop, use `host.docker.internal`.

The example assumes Colima and port `8080`. Set `host = "http://host.lima.internal:8080"` in the configuration's `[model]` block.
The server must accept connections from the container or its VM.

```bash
mkdir -p runs/owasp-container

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,mode=1777 \
  --env LOCAL_MODEL_KEY \
  --mount "type=bind,src=$PWD/targets/owasp-benchmark-python,dst=/inputs/target,readonly" \
  --mount "type=bind,src=$PWD/configs/local-owasp.toml,dst=/inputs/config.toml,readonly" \
  --mount "type=bind,src=$PWD/runs/owasp-container,dst=/sandbox/runs" \
  sio2-openshell:local \
  sio2 \
    --input /inputs/target \
    --output /sandbox/runs \
    --config /inputs/config.toml
```

The user override lets the process write reports with the host user's identity. Use a fresh output directory for each run.

The mounted configuration supplies both the endpoint URL and model ID through its `[model]` block.

If authentication is necessary, set `LOCAL_MODEL_KEY` in the host environment before the command. Never place credentials in the image or scan configuration.

### Does the target application need to run?

Not for the Bandit scan. Bandit reads Python source without execution, so the OWASP web server does not need to start.

Behavioral validation needs the dependencies for the target code that the tests exercise. Keep those dependencies separate from sio2's environment.

OWASP's full requirements pin Bandit 1.8.6, while sio2 needs 1.9.4. Installing those requirements into sio2's environment would create a conflict.

Target services or a separate target environment are necessary only when the selected behavioral tests need them.

### Current limits

- Repository URL ingestion is not implemented. Supply a prepared checkout.
- The OWASP profile scans `testcode/BenchmarkTest000*.py`, not the entire repository. Full-repository scans need changes to the current scope restrictions.
- Behavioral tests currently use a separate Docker container. The sio2 application image contains neither Docker nor a Docker daemon.

Add `--repair` to the command for patch proposals and scanner validation. Without test configuration, successful candidates remain `unvalidated`, not `accepted`.

Full behavioral validation inside an OpenShell sandbox needs a sandbox-aware test backend. Do not expose the host Docker socket to the agent as a workaround.

The image packages software. OpenShell policy must separately control source access, workspace writes, and model-provider access.

## Optional repair and validation

The default command classifies alerts only. Add `--repair` to include patch and validation nodes in the same LangGraph workflow:

```bash
uv run sio2 --input targets/radicale --output runs/radicale-repair --config configs/local-radicale.toml --repair
```

The graph repairs each alert with label `1` before the next classification. It keeps labels and repair outcomes separate:

```text
scan → next_alert → classify → settle label
          ▲                       │
          │       label 0 ────────┘
          │                       │ label 1
          │                 repair_baseline
          │                       ↓
          │               repair_prepare ←──────────┐
          │                       ↓                  │
          │                  repair_gate             │
          │                       ↓                  │
          │                 propose_patch            │
          │                       ↓                  │
          │                  apply_patch             │
          │                       ↓                  │
          │                validate_syntax           │
          │                       ↓                  │
          │                 rerun_bandit             │
          │                       ↓                  │
          │                   run_tests              │
          │                       ↓                  │
          │                 repair_review ── retry ──┘
          │                       ↓
          └──────────────── repair_settle
```

Failed checks route directly to `repair_review`. The graph bounds retries and routes exhausted workflow limits to the existing halt nodes.

`propose_patch` requests pass through the same dispatcher as classification tools. Syntax checks, Bandit, and tests use runtime-only tools in their own nodes.

One `trace.jsonl` records both phases and ends with one terminal event. There is no separate repair controller or repair command.

Use a fresh output directory for each run.

### Test environment

Install Docker and prepare a local image with the target's dependencies and test tools. The image also needs `/bin/sh` and `tar`.

sio2 never pulls an image or installs dependencies during validation.

For example, build this image for a small target whose tests need only pytest:

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir pytest
```

```bash
docker build -t sio2-tests:local -f Dockerfile.tests .
```

Save the example as `Dockerfile.tests` first. For Radicale or SGLang, add their pinned runtime and test dependencies to the image.

Append this block to the target's existing TOML configuration:

```toml
[repair]
max_attempts = 2
max_tokens = 20000
output_allowance = 4096
test_image = "sio2-tests:local"
test_command = ["python", "-m", "pytest", "-q"]
test_timeout_s = 120
output_limit = 16000
```

Choose a test command that exercises the target's behavior. A successful command with no meaningful checks cannot establish repair correctness.

Tests run as an unprivileged container user with no network, no added capabilities, and a read-only root filesystem. CPU, memory, process, time, and output limits apply.

sio2 transfers a source archive through standard input, without a host filesystem mount. Tests receive a disposable copy under `/work` and temporary space under `/tmp`.

sio2 passes no host credentials into the container. Keep credentials out of the target tree and test image as well.

### Acceptance and artifacts

Each attempt starts from the same original snapshot. The model can propose exact replacements only in the alert's Python source file.

sio2 refuses test changes, hidden files, symlink paths, and changes to scanner suppression lines. It restores other OWASP cases before runtime checks, but keeps the answer key withheld.

Test output can contain other OWASP cases. sio2 retains that output in validation artifacts, but excludes it from model feedback for OWASP repairs.

An accepted patch needs all of these results:

1. Changed Python source compiles without execution.
2. Bandit completes without scan errors under the original pinned scan policy.
3. The target finding disappears, with no new findings at the configured severity threshold.
4. Baseline tests and candidate tests pass.

The comparison maps source locations across line changes instead of comparing line-based alert identifiers alone. Bandit success does not prove that a vulnerability is absent.

If tests lack configuration, sio2 saves scanner-validated candidates with status `unvalidated`, not `accepted`. A failed or unavailable baseline test environment blocks repair attempts.

The main `budget.max_tokens` covers all classification and repair calls. `repair.max_tokens` sets a repair limit within that total.

The main report and terminal trace counters include both kinds of model call. The repair report also records the repair subset.

`max_attempts` limits each alert to one through five repair model calls. The workflow step limit applies to both phases.

| Artifact | Content |
|---|---|
| `report.json` | Classification rows, total workflow token usage, and repair outcomes under `repairs` |
| `trace.jsonl` | All graph routes, model calls, tools, validation results, and one terminal event |
| `repair-report.json` | Detailed repair outcomes, also present in the main report |
| `patches/<alert_id>.diff` | Accepted patches for human review |
| `validation/<alert_id>/<attempt>/` | Proposal, candidate diff, and validation result for each attempt |
| `validation/bandit-baseline.json` | Baseline findings and scanner metadata |

sio2 does not apply accepted patches to the input checkout. Independent patches can overlap, so review their combination and rerun validation before use.

The workflow returns `2` for blocked repair, runtime errors, or step-limit failures. A completed run can contain rejected or unvalidated candidates.

A repair-only token limit can stop repairs while classification continues. Exhaustion of the main token budget stops further model calls.

Inspect `report.json` or `repair-report.json` before use.

The normal test suite needs no Docker daemon. To include real-container tests with a local Python image, use:

```bash
SIO2_TEST_IMAGE=python:3.12-slim uv run python -m pytest -q
```

## Timing

Runtime depends on the model, server hardware, target size, and configured limits.

The recorded full runs took 19 minutes for OWASP, 29 minutes for Radicale, and 74 minutes for SGLang. Those historical timings exclude repair.

Each recorded run's `exit.txt` contains its wall time.
