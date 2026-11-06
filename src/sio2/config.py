"""Reading and checking the run configuration.

The config is a TOML file named by --config. Once parsed it must validate
against config.schema.json (copied unchanged into schemas/). The required keys
are [scan], [model] and [budget]; our own settings live under [agent] and in
optional keys of [model], all with defaults, so a config that carries only the
required keys still runs.
"""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

import jsonschema


class Target(StrEnum):
    """The three targets. The value is the prefix of every alert_id."""

    RADICALE = "radicale"
    SGLANG = "sglang"
    OWASP = "owasp"

    @classmethod
    def from_scan_paths(cls, paths: list[str]) -> "Target":
        """Name a staff [scan] block. The schema already forces it to be one of the three."""
        first = paths[0]
        if first == "radicale":
            return cls.RADICALE
        if first.startswith("python/sglang/"):
            return cls.SGLANG
        if first.startswith("testcode/BenchmarkTest"):
            return cls.OWASP
        raise ConfigError(f"[scan] paths {paths} match no staff block")


def schema_path(name: str) -> Path:
    """One of the staff JSON Schemas, copied unchanged into schemas/ at the repository root."""
    return Path(__file__).resolve().parent.parent.parent / "schemas" / name


class ConfigError(Exception):
    """The config file is missing, is not TOML, or fails the schema."""


@dataclass(frozen=True)
class Scan:
    paths: tuple[str, ...]
    exclude: tuple[str, ...]
    min_severity: str
    bandit_version: str


@dataclass(frozen=True)
class Model:
    provider: str
    name: str
    host: str             # server base URL, optionally overridden by LOCAL_MODEL_URL
    temperature: float
    seed: int
    num_ctx: int          # context window we ask Ollama for
    think: bool           # qwen3's reasoning mode; off by default
    timeout_s: float
    api_key_var: str = "LOCAL_MODEL_KEY"  # environment variable name, never the secret


@dataclass(frozen=True)
class Budget:
    max_tokens: int
    output_allowance: int
    max_steps: int


@dataclass(frozen=True)
class Agent:
    max_turns_per_alert: int     # model calls per alert before the row is settled as error
    submit_only_turns: int       # the last N of those offer only submit_label
    no_progress_limit: int       # consecutive turns with no new observation
    context_lines: int           # lines either side of the alert in the opening read
    read_max_lines: int          # read_file limit per call
    search_max_hits: int
    list_max_entries: int
    chars_per_token: float       # only for the pre-call budget estimate, never for the charge
    keep_workspace: bool


@dataclass(frozen=True)
class Repair:
    max_attempts: int = 2
    max_tokens: int = 20000
    output_allowance: int = 4096
    test_image: str = ""
    test_command: tuple[str, ...] = ()
    test_timeout_s: float = 120
    output_limit: int = 16000


REPAIR_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "max_attempts": {"type": "integer", "minimum": 1, "maximum": 5},
        "max_tokens": {"type": "integer", "minimum": 0},
        "output_allowance": {"type": "integer", "minimum": 1},
        "test_image": {"type": "string", "pattern": "^(?!-)[^\\s]*$"},
        "test_command": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "test_timeout_s": {"type": "number", "exclusiveMinimum": 0, "maximum": 3600},
        "output_limit": {"type": "integer", "minimum": 1, "maximum": 1000000},
    },
}


def repair_config(raw: dict) -> Repair:
    """Check optional repair settings without changes to the staff schema."""
    try:
        jsonschema.validate(raw, REPAIR_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise ConfigError(f"invalid [repair] configuration: {exc.message}") from exc
    values = dict(raw)
    if "test_command" in values:
        values["test_command"] = tuple(values["test_command"])
    return Repair(**values)


@dataclass(frozen=True)
class Config:
    path: Path
    raw: dict
    target: Target
    scan: Scan
    model: Model
    budget: Budget
    agent: Agent
    repair: Repair = field(default_factory=Repair)


def load_schema(name: str) -> dict:
    return json.loads(schema_path(name).read_text())


def load_config(path: Path) -> Config:
    path = Path(path)
    try:
        raw = tomllib.loads(path.read_text())
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc

    try:
        jsonschema.validate(raw, load_schema("config.schema.json"))
    except jsonschema.ValidationError as exc:
        raise ConfigError(f"{path} fails config.schema.json: {exc.message}") from exc

    s, m, b, a = raw["scan"], raw["model"], raw["budget"], raw.get("agent", {})
    api_key_var = m.get("api_key_var", "LOCAL_MODEL_KEY")
    if not isinstance(api_key_var, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", api_key_var):
        raise ConfigError("model.api_key_var must name an environment variable, not contain an API key")
    if m["provider"] not in ("ollama", "openai-compatible"):
        raise ConfigError(f"model.provider {m['provider']!r} is not supported; use \"ollama\" or \"openai-compatible\"")

    return Config(
        path=path,
        raw=raw,
        target=Target.from_scan_paths(s["paths"]),
        repair=repair_config(raw.get("repair", {})),
        scan=Scan(tuple(s["paths"]), tuple(s["exclude"]), s["min_severity"], s["bandit_version"]),
        model=Model(
            provider=m["provider"],
            name=m["name"],
            host=m.get("host", "http://localhost:11434"),
            temperature=float(m.get("temperature", 0.0)),
            seed=int(m.get("seed", 0)),
            num_ctx=int(m.get("num_ctx", 16384)),
            think=bool(m.get("think", False)),
            timeout_s=float(m.get("timeout_s", 600)),
            api_key_var=api_key_var,
        ),
        budget=Budget(b["max_tokens"], b["output_allowance"], b["max_steps"]),
        agent=Agent(
            max_turns_per_alert=int(a.get("max_turns_per_alert", 8)),
            submit_only_turns=int(a.get("submit_only_turns", 2)),
            no_progress_limit=int(a.get("no_progress_limit", 3)),
            context_lines=int(a.get("context_lines", 20)),
            read_max_lines=int(a.get("read_max_lines", 120)),
            search_max_hits=int(a.get("search_max_hits", 30)),
            list_max_entries=int(a.get("list_max_entries", 150)),
            chars_per_token=float(a.get("chars_per_token", 3.0)),
            keep_workspace=bool(a.get("keep_workspace", False)),
        ),
    )
