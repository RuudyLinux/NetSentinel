import json

import httpx
import pytest
from fastapi import HTTPException

from app.services.ai import client as ai_client_module
from app.services.ai.client import AiClientError, OpenRouterClient, get_ai_client


def _fake_response(payload: dict, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code,
        json={"choices": [{"message": {"content": json.dumps(payload)}}]},
        request=httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions"),
    )


def test_interpret_returns_a_valid_suggestion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *a, **k: _fake_response(
            {
                "interpretation": "Enables local logging.",
                "suggested_parameter": "logging.local.enabled",
                "suggested_value": True,
                "confidence": 0.82,
            }
        ),
    )
    result = OpenRouterClient("test-key", "test-model").interpret(
        construct_text="logging buffered 4096", block="logging"
    )
    assert result.suggested_parameter == "logging.local.enabled"
    assert result.suggested_value is True
    assert result.confidence == 0.82
    assert result.model == "test-model"


def test_out_of_vocabulary_parameter_is_dropped_not_trusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *a, **k: _fake_response(
            {
                "interpretation": "Something.",
                "suggested_parameter": "made.up.parameter",
                "suggested_value": True,
                "confidence": 0.9,
            }
        ),
    )
    result = OpenRouterClient("test-key", "test-model").interpret(construct_text="x", block=None)
    assert result.suggested_parameter is None


@pytest.mark.parametrize(("given", "expected"), [(1.5, 1.0), (-0.3, 0.0), ("nope", 0.0)])
def test_confidence_is_clamped_to_zero_one(
    monkeypatch: pytest.MonkeyPatch, given: object, expected: float
) -> None:
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *a, **k: _fake_response(
            {
                "interpretation": "x",
                "suggested_parameter": None,
                "suggested_value": None,
                "confidence": given,
            }
        ),
    )
    result = OpenRouterClient("test-key", "test-model").interpret(construct_text="x", block=None)
    assert result.confidence == expected


def test_http_failure_becomes_ai_client_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_error(*a: object, **k: object) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", raise_error)
    with pytest.raises(AiClientError):
        OpenRouterClient("test-key", "test-model").interpret(construct_text="x", block=None)


def test_unparseable_response_becomes_ai_client_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *a, **k: httpx.Response(
            200,
            json={"choices": [{"message": {"content": "not json"}}]},
            request=httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions"),
        ),
    )
    with pytest.raises(AiClientError):
        OpenRouterClient("test-key", "test-model").interpret(construct_text="x", block=None)


def test_get_ai_client_raises_503_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ai_client_module.settings, "openrouter_api_key", None)
    with pytest.raises(HTTPException) as exc_info:
        get_ai_client()
    assert exc_info.value.status_code == 503


def test_get_ai_client_returns_a_real_client_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai_client_module.settings, "openrouter_api_key", "test-key")
    assert isinstance(get_ai_client(), OpenRouterClient)
