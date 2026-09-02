import json
from dataclasses import dataclass
from typing import Protocol

import httpx
from fastapi import HTTPException, status

from app.config import settings
from app.domain.controls import CONTROL_KEYS

_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_TIMEOUT_SECONDS = 20.0

_SYSTEM_PROMPT = (
    "You are assisting a network security compliance tool. A configuration line "
    "could not be parsed by the deterministic parser. Suggest which known control "
    "parameter it most likely sets, and its normalized value. Only ever choose a "
    "parameter from this exact list, or null if none apply: "
    + ", ".join(sorted(CONTROL_KEYS))
    + '. Respond with strict JSON only, no prose: {"interpretation": string, '
    '"suggested_parameter": string|null, "suggested_value": boolean|number|string|null, '
    '"confidence": number between 0 and 1}.'
)


class AiClientError(RuntimeError):
    """Raised when the AI provider call fails or returns something unusable."""


@dataclass(frozen=True)
class Interpretation:
    interpretation: str
    suggested_parameter: str | None
    suggested_value: object
    confidence: float
    model: str


class AiClient(Protocol):
    """The only interface through which an AI provider may be reached.

    Advisory only, by construction: nothing in this codebase ever takes a value
    straight from here and applies it — every caller persists it as a *suggestion*
    a human must approve (see models/ai.py).
    """

    def interpret(self, *, construct_text: str, block: str | None) -> Interpretation: ...


class OpenRouterClient:
    def __init__(self, api_key: str, model: str) -> None:
        self._api_key = api_key
        self._model = model

    def interpret(self, *, construct_text: str, block: str | None) -> Interpretation:
        user_prompt = f"Block: {block or 'unknown'}\nConfiguration line: {construct_text}"
        try:
            response = httpx.post(
                _OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    "response_format": {"type": "json_object"},
                },
                timeout=_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise AiClientError(f"OpenRouter request failed: {exc}") from exc

        try:
            content = response.json()["choices"][0]["message"]["content"]
            parsed = json.loads(content)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise AiClientError(f"OpenRouter returned an unparseable response: {exc}") from exc

        parameter = parsed.get("suggested_parameter")
        if parameter is not None and parameter not in CONTROL_KEYS:
            # Never trust an out-of-vocabulary suggestion — treat it as "no match".
            parameter = None

        confidence = parsed.get("confidence")
        if not isinstance(confidence, (int, float)):
            confidence = 0.0
        confidence = max(0.0, min(1.0, float(confidence)))

        return Interpretation(
            interpretation=str(parsed.get("interpretation", "")),
            suggested_parameter=parameter,
            suggested_value=parsed.get("suggested_value"),
            confidence=confidence,
            model=self._model,
        )


def get_ai_client() -> AiClient:
    if not settings.openrouter_api_key:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "No AI provider is configured on this deployment.",
        )
    return OpenRouterClient(settings.openrouter_api_key, settings.openrouter_model)
