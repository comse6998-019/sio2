"""TOML endpoint selection and configured credential variable names."""
from pathlib import Path
import re

import httpx
import pytest

from sio2.cli import model_client
from sio2.config import ConfigError, load_config


CONFIG = Path(__file__).resolve().parents[1] / "configs/owasp-low.toml"


def model_config(tmp_path, provider, extra=""):
    text = CONFIG.read_text().replace('provider = "ollama"', f'provider = "{provider}"')
    text = re.sub(r'^api_key_var = .*\n', '', text, flags=re.MULTILINE)
    text = text.replace('[model]\n', '[model]\n' + extra)
    path = tmp_path / "config.toml"
    path.write_text(text)
    return load_config(path)


@pytest.mark.parametrize("override,host", [
    (None, "http://configured.example:8080"),
    ("http://override.example:8080/", "http://override.example:8080"),
])
@pytest.mark.parametrize("provider,path", [
    ("ollama", "/api/chat"),
    ("openai-compatible", "/v1/chat/completions"),
])
def test_endpoint_uses_optional_environment_override(tmp_path, monkeypatch, provider, path, override, host):
    if override is None:
        monkeypatch.delenv("LOCAL_MODEL_URL", raising=False)
    else:
        monkeypatch.setenv("LOCAL_MODEL_URL", override)
    monkeypatch.setenv("OLLAMA_HOST", "http://legacy.example:11434")
    requests = []

    def post(self, url, **kwargs):
        requests.append(url)
        return httpx.Response(200, json={
            "prompt_eval_count": 1, "eval_count": 1, "message": {"content": "ok"},
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        }, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.Client, "post", post)
    model_config(tmp_path, provider)
    config_path = tmp_path / "config.toml"
    config_path.write_text(re.sub(
        r'^host = .*$', 'host = "http://configured.example:8080/"',
        config_path.read_text(), flags=re.MULTILINE,
    ))
    cfg = load_config(config_path)
    with model_client(cfg) as client:
        client.chat([{"role": "user", "content": "test"}], [])
    assert requests == [host + path]


@pytest.mark.parametrize("provider", ["ollama", "openai-compatible"])
def test_api_key_comes_from_the_configured_environment_variable(tmp_path, monkeypatch, provider):
    monkeypatch.setenv("COURSE_API_KEY", "configured-test-token")
    monkeypatch.setenv("LOCAL_MODEL_KEY", "wrong-test-token")
    requests = []

    def post(self, url, **kwargs):
        requests.append(kwargs.get("headers", {}).get("Authorization"))
        return httpx.Response(200, json={
            "prompt_eval_count": 1, "eval_count": 1, "message": {"content": "ok"},
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        }, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.Client, "post", post)
    cfg = model_config(tmp_path, provider, 'api_key_var = "COURSE_API_KEY"\n')
    with model_client(cfg) as client:
        client.chat([{"role": "user", "content": "test"}], [])
    assert requests == ["Bearer configured-test-token"]
    assert "configured-test-token" not in repr(cfg.raw)


@pytest.mark.parametrize("provider", ["ollama", "openai-compatible"])
@pytest.mark.parametrize("extra,expected", [
    ("", "Bearer default-test-token"),
    ('api_key_var = "UNSET_COURSE_API_KEY"\n', "Bearer none"),
])
def test_default_key_and_missing_custom_key_do_not_mix(tmp_path, monkeypatch, provider, extra, expected):
    monkeypatch.setenv("LOCAL_MODEL_KEY", "default-test-token")
    monkeypatch.delenv("UNSET_COURSE_API_KEY", raising=False)
    requests = []

    def post(self, url, **kwargs):
        requests.append(kwargs.get("headers", {}).get("Authorization"))
        return httpx.Response(200, json={
            "prompt_eval_count": 1, "eval_count": 1, "message": {"content": "ok"},
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        }, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.Client, "post", post)
    cfg = model_config(tmp_path, provider, extra)
    with model_client(cfg) as client:
        client.chat([{"role": "user", "content": "test"}], [])
    assert requests == [expected]


@pytest.mark.parametrize("value", ['42', '""', '"not a variable"', '"SECRET=value"'])
def test_api_key_var_rejects_invalid_variable_names(tmp_path, value):
    with pytest.raises(ConfigError, match="api_key_var"):
        model_config(tmp_path, "openai-compatible", f"api_key_var = {value}\n")
