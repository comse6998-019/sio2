import httpx
from sio2.llm import OpenAIChat
from sio2.config import Model

def test_openai_chat_parses_tool_call_and_usage(monkeypatch):
    body = {"choices": [{"message": {"content": "", "tool_calls": [{"function": {"name": "read_file", "arguments": "{\"path\": \"a.py\"}"}}]},
                         "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 9}}
    def fake_post(self, url, json=None, headers=None):
        assert url.endswith("/v1/chat/completions") and json["max_tokens"] == 256 and json["tools"]
        return httpx.Response(200, json=body, request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx.Client, "post", fake_post)
    m = Model(provider="openai-compatible", name="qwen3.8-27b", host="http://localhost:8080", temperature=0.0, seed=0, num_ctx=16384, think=False, timeout_s=600.0)
    with OpenAIChat(m, 256) as model:
        r = model.chat([{"role": "user", "content": "hi"}], [{"type": "function", "function": {"name": "read_file", "parameters": {"type": "object"}}}])
    assert r.tool_calls == [{"name": "read_file", "arguments": {"path": "a.py"}}]
    assert r.usage == {"input": 120, "output": 9} and r.done_reason == "tool_calls"


def test_openai_compatible_config_selects_openai_chat(tmp_path):
    from pathlib import Path
    from sio2.cli import model_client
    from sio2.config import load_config
    from sio2.llm import OllamaChat
    low = Path(__file__).resolve().parent.parent / "configs" / "owasp-low.toml"
    with model_client(load_config(low)) as model:
        assert isinstance(model, OllamaChat)
    p = tmp_path / "cfg.toml"
    p.write_text(low.read_text().replace('provider = "ollama"', 'provider = "openai-compatible"'))
    cfg = load_config(p)
    assert cfg.model.provider == "openai-compatible" and isinstance(model_client(cfg), OpenAIChat)


def test_openai_chat_sends_agent_history_in_openai_shape(monkeypatch):
    # The agent keeps Ollama's shape: tool calls without id or type, arguments as a dict, results
    # named by tool_name. llama-server answers that second turn with HTTP 500 "Missing tool call type".
    sent = {}
    def fake_post(self, url, json=None, headers=None):
        sent.update(json)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                                         "usage": {"prompt_tokens": 1, "completion_tokens": 1}},
                              request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx.Client, "post", fake_post)
    history = [{"role": "user", "content": "hi"},
               {"role": "assistant", "content": "", "tool_calls": [
                   {"function": {"name": "search", "arguments": {"pattern": "x"}}},
                   {"function": {"name": "list_dir", "arguments": {"path": "helpers"}}}]},
               {"role": "tool", "tool_name": "search", "content": "1 hit"},
               {"role": "tool", "tool_name": "list_dir", "content": "6 entries"}]
    m = Model(provider="openai-compatible", name="qwen3.8-27b", host="http://localhost:8080", temperature=0.0, seed=0, num_ctx=16384, think=False, timeout_s=600.0)
    with OpenAIChat(m, 256) as model:
        model.chat(history, [])
    user, a, t1, t2 = sent["messages"]
    assert user == history[0]
    assert [c["type"] for c in a["tool_calls"]] == ["function", "function"]
    assert a["tool_calls"][0]["function"] == {"name": "search", "arguments": "{\"pattern\": \"x\"}"}
    ids = [c["id"] for c in a["tool_calls"]]
    assert len(set(ids)) == 2 and [t1["tool_call_id"], t2["tool_call_id"]] == ids
    assert (t1["role"], t1["content"], t2["content"]) == ("tool", "1 hit", "6 entries")
    assert history[1]["tool_calls"][0] == {"function": {"name": "search", "arguments": {"pattern": "x"}}}
