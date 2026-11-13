"""Universal modular LLM client module using the Factory Pattern.

Supports:
1. Local LLM engines on Host B via Ollama (accessed over a reverse SSH tunnel,
   default `http://host.docker.internal:11434/v1`).
2. Local Qwen models (`qwen2.5`, `qwen2.5-coder`, `qwen3`, etc.) executed locally
   via the same Ollama/OpenAI-compatible endpoint on Host B.
3. Cloud inference via Google Gemini (`google-genai` SDK).

Returns a standardized `LLMResponse` containing the text response,
`prompt_tokens`, `completion_tokens`, and `inference_latency_ms` measured
with high-precision `time.perf_counter()`.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

from network_adapter import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LLMResponse:
    """Standardized response payload returned by all LLM client implementations."""

    text: str
    prompt_tokens: int
    completion_tokens: int
    inference_latency_ms: float
    provider: str = "ollama"
    model: str = "llama3.1:8b"
    request_bytes: int = 0
    response_bytes: int = 0

    @property
    def total_tokens(self) -> int:
        """Return total tokens consumed (prompt + completion)."""
        return self.prompt_tokens + self.completion_tokens

    @property
    def signaling_bytes(self) -> int:
        """Return total HTTP/API request + response payload size in bytes."""
        return self.request_bytes + self.response_bytes

    def to_dict(self) -> dict[str, Any]:
        """Serialize the LLM response to a standardized dictionary."""
        return {
            "text": self.text,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "inference_latency_ms": round(self.inference_latency_ms, 4),
            "Inference Latency": round(self.inference_latency_ms, 4),
            "provider": self.provider,
            "model": self.model,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
        }


class BaseLLMClient(ABC):
    """Abstract base class for all LLM providers."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
    ) -> LLMResponse:
        """Send a prompt to the underlying LLM and return a standardized `LLMResponse`.

        Args:
            prompt: User prompt containing raw logs or structured JSON telemetry.
            system_instruction: Optional system-level role prompt.

        Returns:
            Standardized `LLMResponse` with token counts and inference latency (ms).
        """


def _estimate_tokens(text: str) -> int:
    """Fallback token estimator (~4 characters per token) if backend omits token metadata."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def _strip_reasoning_tags(text: str) -> str:
    """Remove optional `<think>...</think>` blocks emitted by reasoning models (e.g., Qwen3/QwQ)."""
    if "<think>" in text:
        cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        if cleaned:
            return cleaned
    return text.strip()


class OllamaLLMClient(BaseLLMClient):
    """LLM client for local models running via Ollama on Host B over a reverse SSH tunnel."""

    PROVIDER_NAME: str = "ollama"
    DEFAULT_MODEL: str = "llama3.1:8b"

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float | None = None,
        temperature: float | None = None,
    ) -> None:
        """Initialize the local Ollama-compatible LLM client.

        Args:
            base_url: Base URL for Ollama OpenAI-compatible API
                (default `http://host.docker.internal:11434/v1`).
            model: Model identifier installed on Host B (e.g., `llama3.1:8b`).
            api_key: Optional API key header (default `ollama`).
            timeout_seconds: Request timeout in seconds.
            temperature: Sampling temperature (default `0.0` for deterministic IDS output).
        """
        self.base_url: str = (
            base_url or os.getenv("LLM_BASE_URL", "http://host.docker.internal:11434/v1")
        ).rstrip("/")
        self.model: str = model or os.getenv("LLM_MODEL", self.DEFAULT_MODEL)
        self.api_key: str = api_key or os.getenv("LLM_API_KEY", self.PROVIDER_NAME)
        self.timeout_seconds: float = float(
            timeout_seconds
            if timeout_seconds is not None
            else os.getenv("LLM_TIMEOUT_SECONDS", "60.0")
        )
        self.temperature: float = float(
            temperature if temperature is not None else os.getenv("LLM_TEMPERATURE", "0.0")
        )
        self.mock_mode: bool = os.getenv("LLM_MOCK_MODE", "false").strip().lower() in {
            "1",
            "true",
            "yes",
        }

    def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
    ) -> LLMResponse:
        """Execute chat completion against the local endpoint and measure latency in ms."""
        messages: list[dict[str, str]] = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "stream": False,
        }
        serialized_request = json.dumps(payload).encode("utf-8")
        request_bytes = len(serialized_request)

        if self.mock_mode:
            return self._generate_mock_response(
                prompt=prompt,
                system_instruction=system_instruction,
                request_bytes=request_bytes,
            )

        endpoint = (
            f"{self.base_url}/chat/completions"
            if self.base_url.endswith("/v1")
            else f"{self.base_url}/v1/chat/completions"
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        start_ns = time.perf_counter()
        try:
            if httpx is not None:
                with httpx.Client(timeout=self.timeout_seconds) as client:
                    response = client.post(endpoint, content=serialized_request, headers=headers)
                    response.raise_for_status()
                    raw_response_bytes = response.content
                    data = response.json()
            else:
                req = urllib.request.Request(
                    endpoint,
                    data=serialized_request,
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    raw_response_bytes = resp.read()
                    data = json.loads(raw_response_bytes.decode("utf-8"))
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_ns) * 1000.0
            logger.error(
                "%s request failed at %s after %.2f ms: %s",
                self.PROVIDER_NAME,
                endpoint,
                elapsed_ms,
                exc,
            )
            raise RuntimeError(
                f"Failed communicating with {self.PROVIDER_NAME} at {endpoint}: {exc}"
            ) from exc

        elapsed_ms = (time.perf_counter() - start_ns) * 1000.0
        response_bytes = len(raw_response_bytes)

        choices = data.get("choices", [])
        raw_text_content = ""
        if choices and isinstance(choices[0], dict):
            msg = choices[0].get("message", {})
            raw_text_content = str(msg.get("content", "")).strip()

        text_content = _strip_reasoning_tags(raw_text_content)

        usage = data.get("usage", {}) or {}
        prompt_tokens = int(
            usage.get("prompt_tokens")
            or data.get("prompt_eval_count")
            or _estimate_tokens((system_instruction or "") + prompt)
        )
        completion_tokens = int(
            usage.get("completion_tokens")
            or data.get("eval_count")
            or _estimate_tokens(raw_text_content)
        )

        return LLMResponse(
            text=text_content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            inference_latency_ms=round(elapsed_ms, 4),
            provider=self.PROVIDER_NAME,
            model=self.model,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
        )

    def _generate_mock_response(
        self,
        prompt: str,
        system_instruction: str | None,
        request_bytes: int,
    ) -> LLMResponse:
        """Deterministic offline emulator when `LLM_MOCK_MODE=true` is explicitly set."""
        start_ns = time.perf_counter()
        full_input = f"{system_instruction or ''}\n{prompt}"

        # Extract candidate attacker IP (defaulting to traffic-gen 10.200.0.20)
        ip_matches = re.findall(r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", prompt)
        attacker_ip = "10.200.0.20"
        for ip in ip_matches:
            if ip not in {"10.200.0.1", "10.200.0.10", "127.0.0.1"}:
                attacker_ip = ip
                break

        if "block_ip" in full_input or "JSON" in full_input or "target_ip" in full_input:
            reply_text = json.dumps(
                {
                    "action": "block_ip",
                    "target_ip": attacker_ip,
                    "reason": "High-rate anomalous SYN/reconnaissance flow detected",
                }
            )
        else:
            reply_text = (
                f'ovs-ofctl add-flow br0 "priority=500,dl_type=0x0800,nw_src={attacker_ip},actions=drop"'
            )

        elapsed_ms = (time.perf_counter() - start_ns) * 1000.0
        prompt_tokens = _estimate_tokens(full_input)
        completion_tokens = _estimate_tokens(reply_text)
        response_bytes = len(reply_text.encode("utf-8"))

        return LLMResponse(
            text=reply_text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            inference_latency_ms=round(elapsed_ms, 4),
            provider=f"{self.PROVIDER_NAME}-mock",
            model=self.model,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
        )


class QwenLLMClient(OllamaLLMClient):
    """LLM client for local Qwen models executed on Host B via the local Ollama endpoint."""

    PROVIDER_NAME: str = "qwen"
    DEFAULT_MODEL: str = "qwen2.5:7b"

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float | None = None,
        temperature: float | None = None,
    ) -> None:
        """Initialize the local Qwen LLM client.

        Uses the same local execution pipeline and reverse SSH tunnel (`LLM_BASE_URL`)
        as `OllamaLLMClient`, while resolving Qwen-specific model defaults
        (`QWEN_MODEL` or `LLM_MODEL`, defaulting to `qwen2.5:7b`).
        """
        env_qwen_model = os.getenv("QWEN_MODEL", "").strip()
        env_llm_model = os.getenv("LLM_MODEL", "").strip()

        resolved_model = model or env_qwen_model
        if not resolved_model:
            if env_llm_model and "qwen" in env_llm_model.lower():
                resolved_model = env_llm_model
            else:
                resolved_model = self.DEFAULT_MODEL

        super().__init__(
            base_url=base_url,
            model=resolved_model,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
            temperature=temperature,
        )


class GeminiLLMClient(BaseLLMClient):
    """LLM client for Google Gemini via the official `google-genai` SDK."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
    ) -> None:
        """Initialize the Google Gemini client.

        Args:
            api_key: Google Gemini API key (defaults to `GEMINI_API_KEY` env var).
            model: Gemini model name (defaults to `GEMINI_MODEL` or `gemini-2.5-flash`).
            temperature: Sampling temperature (default `0.0`).
        """
        self.api_key: str = api_key or os.getenv("GEMINI_API_KEY", "")
        self.model: str = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.temperature: float = float(
            temperature if temperature is not None else os.getenv("LLM_TEMPERATURE", "0.0")
        )
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY must be set when using the 'gemini' LLM provider.")

        from google import genai

        self._client = genai.Client(api_key=self.api_key)

    def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
    ) -> LLMResponse:
        """Generate content via Google Gemini and measure exact inference latency in ms."""
        from google.genai import types

        config = types.GenerateContentConfig(
            temperature=self.temperature,
            system_instruction=system_instruction,
        )
        request_bytes = len(((system_instruction or "") + prompt).encode("utf-8"))

        start_ns = time.perf_counter()
        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_ns) * 1000.0
            logger.error("Gemini API call failed after %.2f ms: %s", elapsed_ms, exc)
            raise RuntimeError(f"Gemini generation failed: {exc}") from exc

        elapsed_ms = (time.perf_counter() - start_ns) * 1000.0
        text_content = (response.text or "").strip()
        response_bytes = len(text_content.encode("utf-8"))

        usage = getattr(response, "usage_metadata", None)
        prompt_tokens = int(
            getattr(usage, "prompt_token_count", 0)
            or _estimate_tokens((system_instruction or "") + prompt)
        )
        completion_tokens = int(
            getattr(usage, "candidates_token_count", 0) or _estimate_tokens(text_content)
        )

        return LLMResponse(
            text=text_content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            inference_latency_ms=round(elapsed_ms, 4),
            provider="gemini",
            model=self.model,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
        )


class LLMClientFactory:
    """Factory class to instantiate the configured LLM provider client."""

    @staticmethod
    def create_client(provider: str | None = None, **kwargs: Any) -> BaseLLMClient:
        """Create and return an LLM client instance for the specified provider.

        Args:
            provider: `"ollama"`, `"qwen"`, or `"gemini"`. Defaults to `LLM_PROVIDER`
                in `.env` (or `"ollama"` if unset).
            **kwargs: Provider-specific overrides passed to the concrete constructor.

        Returns:
            An initialized `BaseLLMClient` implementation.

        Raises:
            ValueError: If an unsupported provider name is supplied.
        """
        selected = (provider or os.getenv("LLM_PROVIDER", "ollama")).strip().lower()
        configured_model = str(kwargs.get("model") or os.getenv("LLM_MODEL", "")).strip().lower()

        if selected.startswith("qwen") or (
            selected in {"ollama", "local", "openai"} and configured_model.startswith("qwen")
        ):
            return QwenLLMClient(**kwargs)
        if selected in {"ollama", "local", "openai"}:
            return OllamaLLMClient(**kwargs)
        if selected in {"gemini", "google", "google-genai"}:
            return GeminiLLMClient(**kwargs)
        raise ValueError(
            f"Unsupported LLM provider '{selected}'. "
            "Supported providers: 'ollama', 'qwen', 'gemini'."
        )
