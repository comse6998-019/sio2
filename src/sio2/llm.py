"""The provider seam. The only module that talks to a model.

`chat()` sends one request to Ollama's /api/chat and returns the reply together
with the usage Ollama reported for that request:

    input       = prompt_eval_count          (every prompt token Ollama counted)
    output      = eval_count                 (every generated token, thinking included)
    cache_read  = prompt_eval_cached_count   (when reported; recorded, never charged)

Nothing here estimates tokens. If Ollama omits a counter we raise, because a
charge we made up is worse than a failed call.

The output allowance is sent on every request as `options.num_predict`, which
is Ollama's cap on generated tokens.

    with OllamaChat(cfg.model, cfg.budget.output_allowance) as model:
        reply = model.chat(messages, tools)

`OpenAIChat` is the same seam for an OpenAI-compatible server (llama-server,
llama-swap), chosen by `provider = "openai-compatible"`: usage comes from
`usage.prompt_tokens` and `usage.completion_tokens`, the allowance is sent as
`max_tokens`, and the same no-estimate rule holds.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

import httpx

from sio2.config import Model


class ModelError(Exception):
    pass


@dataclass
class Reply:
    content: str
    tool_calls: list[dict]          # [{"name": str, "arguments": dict|str}]
    usage: dict                     # provider-reported counters
    done_reason: str
    thinking: str = ""
    raw: dict = field(default_factory=dict)


def _auth_headers(model: Model) -> dict[str, str]:
    """Read the bearer token from the configured environment variable."""
    return {"Authorization": f"Bearer {os.environ.get(model.api_key_var, 'none')}"}


class OllamaChat:
    def __init__(self, model: Model, output_allowance: int):
        self.model = model
        self.output_allowance = output_allowance
        self.host = model.host.rstrip("/")
        if not self.host.startswith("http"):
            self.host = "http://" + self.host
        self._client = httpx.Client(timeout=model.timeout_s)

    def __enter__(self) -> "OllamaChat":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._client.close()

    def chat(self, messages: list[dict], tools: list[dict]) -> Reply:
        body = {
            "model": self.model.name,
            "messages": messages,
            "tools": tools,
            "stream": False,
            "think": self.model.think,
            "options": {
                "num_predict": self.output_allowance,
                "temperature": self.model.temperature,
                "seed": self.model.seed,
                "num_ctx": self.model.num_ctx,
            },
        }
        try:
            resp = self._client.post(f"{self.host}/api/chat", json=body, headers=_auth_headers(self.model))
        except httpx.HTTPError as exc:
            raise ModelError(f"Ollama request failed: {exc}") from exc
        if resp.status_code != 200:
            raise ModelError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        if "prompt_eval_count" not in data or "eval_count" not in data:
            raise ModelError("Ollama reply has no usage counters")
        usage = {"input": int(data["prompt_eval_count"]), "output": int(data["eval_count"])}
        if "prompt_eval_cached_count" in data:
            usage["cache_read"] = int(data["prompt_eval_cached_count"])
        msg = data.get("message") or {}
        calls = [{"name": (c.get("function") or {}).get("name", ""),
                  "arguments": (c.get("function") or {}).get("arguments", {})}
                 for c in msg.get("tool_calls") or []]
        return Reply(content=msg.get("content") or "", tool_calls=calls, usage=usage,
                     done_reason=data.get("done_reason", ""),
                     thinking=msg.get("thinking") or "", raw=msg)


def _wire_messages(messages: list[dict]) -> list[dict]:
    """Ollama's history shape to OpenAI's. An assistant tool call gains an id and type "function", and its
    arguments become a JSON string; a tool result is matched, in order, to the calls of the assistant
    message before it and names the call by tool_call_id. The ids are positional; the input is not changed."""
    out, open_ids = [], []
    for n, m in enumerate(messages):
        if m.get("role") == "assistant" and m.get("tool_calls"):
            calls = []
            for k, c in enumerate(m["tool_calls"]):
                fn = c.get("function") or {}
                args = fn.get("arguments", {})
                calls.append({"id": f"call_{n}_{k}", "type": "function",
                              "function": {"name": fn.get("name", ""),
                                           "arguments": args if isinstance(args, str) else json.dumps(args)}})
            open_ids = [c["id"] for c in calls]
            out.append({"role": "assistant", "content": m.get("content") or "", "tool_calls": calls})
        elif m.get("role") == "tool":
            out.append({"role": "tool", "tool_call_id": open_ids.pop(0) if open_ids else "",
                        "content": m.get("content", "")})
        else:
            out.append(m)
    return out


class OpenAIChat:
    """An OpenAI-compatible server: POST {host}/v1/chat/completions. Usage comes from usage.prompt_tokens and
    usage.completion_tokens. The output allowance is sent as max_tokens. The TOML model.host selects the endpoint.
    The agent's history is in Ollama's shape and is rewritten to OpenAI's on the way out (_wire_messages)."""

    def __init__(self, model: Model, output_allowance: int):
        self.model, self.output_allowance = model, output_allowance
        self.host = model.host.rstrip("/")
        self._client = None

    def __enter__(self) -> "OpenAIChat":
        self._client = httpx.Client(timeout=httpx.Timeout(600.0))
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._client.close()

    def chat(self, messages: list[dict], tools: list[dict]) -> Reply:
        body = {"model": self.model.name, "messages": _wire_messages(messages), "tools": tools,
                "max_tokens": self.output_allowance,
                "temperature": self.model.temperature, "stream": False}
        headers = _auth_headers(self.model)
        try:
            resp = self._client.post(f"{self.host}/v1/chat/completions", json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise ModelError(f"model request failed: {exc}") from exc
        if resp.status_code != 200:
            raise ModelError(f"model server returned HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        u = data.get("usage") or {}
        if "prompt_tokens" not in u or "completion_tokens" not in u:
            raise ModelError("reply has no usage counters")
        usage = {"input": int(u["prompt_tokens"]), "output": int(u["completion_tokens"])}
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        calls = []
        for c in msg.get("tool_calls") or []:
            fn = c.get("function") or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    pass
            calls.append({"name": fn.get("name", ""), "arguments": args})
        return Reply(content=msg.get("content") or "", tool_calls=calls, usage=usage,
                     done_reason=choice.get("finish_reason", ""), raw=msg)


class ScriptedChat:
    """A stand-in model for tests: replays a list of Replies, or calls a function."""

    def __init__(self, script):
        self.script = script
        self.calls: list[list[dict]] = []

    def chat(self, messages, tools) -> Reply:
        self.calls.append(messages)
        if callable(self.script):
            return self.script(messages, tools)
        if not self.script:
            raise ModelError("script exhausted")
        return self.script.pop(0)
