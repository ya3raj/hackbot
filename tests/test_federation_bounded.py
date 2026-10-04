"""No-network tests for the bounded federation paths."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from hackbot.config import AIConfig
from hackbot.core.bounded import CancellationToken, OperationCancelled
from hackbot.core.engine import AIEngine
from hackbot.core.osint import OSINTEngine


class _Stream(list):
    def close(self) -> None:
        self.closed = True


class _Client:
    def __init__(self) -> None:
        chunk = SimpleNamespace(
            model="gpt-test-snapshot",
            id="req_test",
            usage=SimpleNamespace(prompt_tokens=2, completion_tokens=1, total_tokens=3),
            choices=[SimpleNamespace(
                finish_reason="stop",
                delta=SimpleNamespace(content="answer"),
            )],
        )
        self.stream = _Stream([chunk])
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=MagicMock(return_value=self.stream))
        )
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_bounded_ai_is_one_call_no_tools_no_retry_or_fallback() -> None:
    with patch("hackbot.core.engine.OpenAI"):
        engine = AIEngine(AIConfig(
            provider="openai", model="gpt-test", api_key="secret",
            base_url="https://api.example.invalid/v1",
        ))
    client = _Client()
    with patch.object(engine, "_new_bounded_client", return_value=client):
        result = engine.bounded_one_shot(
            "hello", enabled=True, system="short", max_input_chars=64,
            max_output_tokens=16, timeout_seconds=5,
        )
    call = client.chat.completions.create.call_args
    assert call is not None
    assert call.kwargs["model"] == "gpt-test"
    assert call.kwargs["max_tokens"] == 16
    assert call.kwargs["stream"] is True
    assert "tools" not in call.kwargs
    assert "tool_choice" not in call.kwargs
    assert result.content == "answer"
    assert result.provider_origin == "https://api.example.invalid"
    assert result.response_model == "gpt-test-snapshot"
    assert client.closed


def test_bounded_ai_pre_cancel_does_not_create_provider_client() -> None:
    with patch("hackbot.core.engine.OpenAI"):
        engine = AIEngine(AIConfig(api_key="secret"))
    token = CancellationToken()
    token.cancel()
    with patch.object(engine, "_new_bounded_client") as factory:
        with pytest.raises(OperationCancelled):
            engine.bounded_one_shot(
                "hello", enabled=True, timeout_seconds=5, cancellation=token,
            )
    factory.assert_not_called()


@pytest.mark.parametrize("target", ["https://example.com", "127.0.0.1", "one-label", "a..b"])
def test_full_osint_rejects_non_bare_fqdn(target: str) -> None:
    with pytest.raises(ValueError):
        OSINTEngine.strict_domain(target)


def test_bounded_get_rejects_cross_origin_redirect() -> None:
    response = MagicMock()
    response.status_code = 302
    response.headers = {"Location": "https://other.example/path"}
    session = MagicMock()
    session.get.return_value = response
    from hackbot.core.bounded import Deadline

    with pytest.raises(RuntimeError, match="cross-origin"):
        OSINTEngine._bounded_get(
            session, "https://example.com/", Deadline(5), CancellationToken(), 4096,
        )
    session.get.assert_called_once()
    assert session.get.call_args.kwargs["allow_redirects"] is False
    assert session.get.call_args.kwargs["verify"] is True


def test_public_resolution_rejects_private_or_mixed_answers() -> None:
    private = (None, None, None, None, ("127.0.0.1", 443))
    public = (None, None, None, None, ("93.184.216.34", 443))
    with patch("hackbot.core.osint.socket.getaddrinfo", return_value=[public, private]):
        with pytest.raises(RuntimeError, match="not exclusively public"):
            OSINTEngine._require_public_resolution("example.com")


def test_rdap_cross_origin_redirect_is_skipped_not_followed() -> None:
    from hackbot.core.bounded import Deadline

    with patch.object(
        OSINTEngine, "_bounded_get",
        side_effect=RuntimeError("cross-origin redirect blocked"),
    ):
        result = OSINTEngine._bounded_whois(
            MagicMock(), "example.com", Deadline(5), CancellationToken(), 8, 4096,
        )
    assert result is None


def test_capabilities_attest_provider_and_hard_guarantees() -> None:
    pytest.importorskip("flask")
    from hackbot.gui import app as app_module

    with patch("hackbot.core.engine.OpenAI"):
        engine = AIEngine(AIConfig(
            provider="openai", model="gpt-test", api_key="secret",
            base_url="https://api.example.invalid/v1",
        ))
    previous = app_module._state.get("engine")
    app_module._state["engine"] = engine
    try:
        response = app_module.app.test_client().get("/api/federation/v1/capabilities")
    finally:
        app_module._state["engine"] = previous
    assert response.status_code == 200
    data = response.get_json()
    ai = data["capabilities"]["ai-one-shot"]
    assert ai["tools"] is False
    assert ai["retry_or_fallback"] is False
    assert ai["cancel"] is True
    assert ai["provider"] == {
        "name": "openai", "model": "gpt-test",
        "origin": "https://api.example.invalid",
    }
    osint = data["capabilities"]["osint-full"]
    assert osint["tls_verify"] is True
    assert osint["cross_host_redirects"] is False
    assert osint["public_targets_only"] is True
