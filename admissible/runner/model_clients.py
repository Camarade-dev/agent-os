"""Model client implementations behind the baseline_runner ModelClient protocol.

Provides fixed-response clients for tests and mock CLI paths, plus an optional
env-configured HTTP client for live frontier-direct baselines. Nothing here
sends gold annotations, scoring output, or rules-only evaluator output to the
model — callers build prompts via build_frontier_direct_prompt only.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

API_URL_ENV = "ADMISSIBLE_MODEL_API_URL"
API_KEY_ENV = "ADMISSIBLE_MODEL_API_KEY"
MODEL_NAME_ENV = "ADMISSIBLE_MODEL_NAME"
TIMEOUT_ENV = "ADMISSIBLE_MODEL_TIMEOUT_SECONDS"

REQUIRED_ENV_VARS: tuple[str, ...] = (API_URL_ENV, API_KEY_ENV, MODEL_NAME_ENV)

DEFAULT_TIMEOUT_SECONDS = 30.0


class FixedResponseModelClient:
    """Returns a fixed response for every prompt. No network access."""

    def __init__(self, response: str | dict):
        if isinstance(response, dict):
            self._response_text = json.dumps(response)
        else:
            self._response_text = response
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self._response_text


def _parse_timeout_seconds(raw: str | None) -> float:
    if raw is None or not str(raw).strip():
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = float(str(raw).strip())
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    if value <= 0:
        return DEFAULT_TIMEOUT_SECONDS
    return value


def _extract_text_from_response(parsed: Any) -> str | None:
    if not isinstance(parsed, dict):
        return None
    text = parsed.get("text")
    if isinstance(text, str):
        return text
    output = parsed.get("output")
    if isinstance(output, str):
        return output
    choices = parsed.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    return content
    return None


class EnvConfiguredHttpModelClient:
    """Minimal stdlib HTTP client for a generic model completion endpoint."""

    def __init__(
        self,
        *,
        api_url: str,
        api_key: str,
        model_name: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self._api_url = api_url
        self._api_key = api_key
        self._model_name = model_name
        self._timeout_seconds = timeout_seconds

    def complete(self, prompt: str) -> str:
        payload = json.dumps({"model": self._model_name, "prompt": prompt}).encode("utf-8")
        request = urllib.request.Request(
            self._api_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"model API request failed with HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError("model API request failed: network error") from exc

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"model API response is not valid JSON: {exc}") from exc

        text = _extract_text_from_response(parsed)
        if text is None:
            raise ValueError(
                "model API response has unsupported shape; "
                "expected text, output, or choices[0].message.content"
            )
        return text


HF_TOKEN_ENV = "ADMISSIBLE_HF_TOKEN"
HF_MODEL_ENV = "ADMISSIBLE_HF_MODEL"
HF_BASE_URL_ENV = "ADMISSIBLE_HF_BASE_URL"
HF_TIMEOUT_ENV = "ADMISSIBLE_HF_TIMEOUT_SECONDS"

HF_REQUIRED_ENV_VARS: tuple[str, ...] = (HF_TOKEN_ENV, HF_MODEL_ENV)
DEFAULT_HF_BASE_URL = "https://router.huggingface.co/v1"
DEFAULT_HF_TIMEOUT_SECONDS = 60.0


def _parse_hf_timeout_seconds(raw: str | None) -> float:
    if raw is None or not str(raw).strip():
        return DEFAULT_HF_TIMEOUT_SECONDS
    try:
        value = float(str(raw).strip())
    except ValueError:
        return DEFAULT_HF_TIMEOUT_SECONDS
    if value <= 0:
        return DEFAULT_HF_TIMEOUT_SECONDS
    return value


class HuggingFaceChatCompletionsModelClient:
    """OpenAI-compatible chat completions client for Hugging Face Inference Providers."""

    def __init__(
        self,
        *,
        token: str,
        model: str,
        base_url: str = DEFAULT_HF_BASE_URL,
        timeout_seconds: float = DEFAULT_HF_TIMEOUT_SECONDS,
    ):
        self._token = token
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds

    def complete(self, prompt: str) -> str:
        url = f"{self._base_url}/chat/completions"
        payload = json.dumps({
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "max_tokens": 1000,
        }).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Hugging Face API request failed with HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError("Hugging Face API request failed: network error") from exc

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Hugging Face API response is not valid JSON: {exc}") from exc

        text = _extract_text_from_response(parsed)
        if text is None:
            raise ValueError(
                "Hugging Face API response has unsupported shape; "
                "expected text, output, or choices[0].message.content"
            )
        return text


def build_huggingface_model_client_from_env() -> HuggingFaceChatCompletionsModelClient:
    """Build a HuggingFaceChatCompletionsModelClient from environment variables.

    Raises ValueError naming any missing required variables. Never includes
    secrets in error messages.
    """
    missing = [name for name in HF_REQUIRED_ENV_VARS if not os.environ.get(name, "").strip()]
    if missing:
        raise ValueError(
            "missing required environment variable(s): " + ", ".join(missing)
        )

    base_url = os.environ.get(HF_BASE_URL_ENV, DEFAULT_HF_BASE_URL).strip() or DEFAULT_HF_BASE_URL

    return HuggingFaceChatCompletionsModelClient(
        token=os.environ[HF_TOKEN_ENV].strip(),
        model=os.environ[HF_MODEL_ENV].strip(),
        base_url=base_url,
        timeout_seconds=_parse_hf_timeout_seconds(os.environ.get(HF_TIMEOUT_ENV)),
    )


def build_model_client_from_env() -> EnvConfiguredHttpModelClient:
    """Build an EnvConfiguredHttpModelClient from process environment variables.

    Raises ValueError naming any missing required variables. Never includes
    secrets in error messages.
    """
    missing = [name for name in REQUIRED_ENV_VARS if not os.environ.get(name, "").strip()]
    if missing:
        raise ValueError(
            "missing required environment variable(s): " + ", ".join(missing)
        )

    return EnvConfiguredHttpModelClient(
        api_url=os.environ[API_URL_ENV].strip(),
        api_key=os.environ[API_KEY_ENV].strip(),
        model_name=os.environ[MODEL_NAME_ENV].strip(),
        timeout_seconds=_parse_timeout_seconds(os.environ.get(TIMEOUT_ENV)),
    )
