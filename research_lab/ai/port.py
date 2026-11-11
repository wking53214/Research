"""AIRequest, AIResponse, the AIPort protocol and the error classes. No provider logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence

from ..canonical import CanonicalError, canonical_bytes, digest, normalize, sha256_hex
from ..clock import parse_utc

REQUEST_SCHEMA = "research_lab.ai_request/1"


class AIError(Exception):
    """Base class for AI port failures."""


class ProviderUnavailable(AIError):
    """The provider could not answer (network, outage, rate limit, replay miss)."""

    def __init__(self, reason: str, status: int | None = None) -> None:
        super().__init__(reason if status is None else f"{reason} (status {status})")
        self.reason = reason
        self.status = status


class ProviderTimeout(ProviderUnavailable):
    """The provider did not answer in time. A kind of unavailability, distinguishable by type."""


class ProviderRefused(AIError):
    """The provider, or the policy in front of it, declined the request. Not unavailability."""


class ResponseFormatError(AIError):
    """The response text does not have the expected shape. response_digest is the SHA-256 of
    the raw text so the preserved blob can be found."""

    def __init__(self, reason: str, response_digest: str | None = None) -> None:
        suffix = f" [response sha256 {response_digest}]" if response_digest else ""
        super().__init__(reason + suffix)
        self.reason = reason
        self.response_digest = response_digest


def _nonempty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class SourceInput:
    """One preserved source given to the provider: its entity id, the digest of its full
    content, and the exact excerpt text the provider saw."""

    source_id: str
    content_digest: str
    excerpt: str

    def __post_init__(self) -> None:
        _nonempty(self.source_id, "source_id")
        if not isinstance(self.content_digest, str) or len(self.content_digest) != 64:
            raise ValueError("content_digest must be a full SHA-256 hex digest")
        if not isinstance(self.excerpt, str):
            raise ValueError("excerpt must be a string")

    def to_dict(self) -> dict[str, Any]:
        return {"source_id": self.source_id, "content_digest": self.content_digest, "excerpt": self.excerpt}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SourceInput":
        return cls(data["source_id"], data["content_digest"], data["excerpt"])


@dataclass(frozen=True)
class AIRequest:
    purpose: str
    instructions: str
    inputs: tuple[SourceInput, ...]
    max_output_tokens: int
    settings: dict[str, Any] = field(default_factory=dict)
    request_digest: str = ""

    def __post_init__(self) -> None:
        _nonempty(self.purpose, "purpose")
        _nonempty(self.instructions, "instructions")
        if not isinstance(self.inputs, tuple) or not all(isinstance(item, SourceInput) for item in self.inputs):
            raise ValueError("inputs must be a tuple of SourceInput")
        if not isinstance(self.max_output_tokens, int) or isinstance(self.max_output_tokens, bool) or self.max_output_tokens < 1:
            raise ValueError("max_output_tokens must be a positive integer")
        try:
            object.__setattr__(self, "settings", normalize(dict(self.settings)))
        except CanonicalError as exc:
            raise ValueError(f"settings are not canonical JSON: {exc}") from exc
        computed = digest(self.content())
        if self.request_digest and self.request_digest != computed:
            raise ValueError("request_digest does not match the request content")
        object.__setattr__(self, "request_digest", computed)

    def content(self) -> dict[str, Any]:
        return {
            "schema": REQUEST_SCHEMA,
            "purpose": self.purpose,
            "instructions": self.instructions,
            "inputs": [item.to_dict() for item in self.inputs],
            "max_output_tokens": self.max_output_tokens,
            "settings": self.settings,
        }

    def to_dict(self) -> dict[str, Any]:
        out = self.content()
        out["request_digest"] = self.request_digest
        return out

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.content())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AIRequest":
        return cls(
            purpose=data["purpose"],
            instructions=data["instructions"],
            inputs=tuple(SourceInput.from_dict(item) for item in data["inputs"]),
            max_output_tokens=data["max_output_tokens"],
            settings=dict(data.get("settings", {})),
            request_digest=data.get("request_digest", ""),
        )


@dataclass(frozen=True)
class AIResponse:
    text: str
    provider_id: str
    provider_kind: str
    adapter_version: str
    model_requested: str
    model_reported: str
    request_digest: str
    response_digest: str
    finish_reason: str
    usage: dict[str, Any]
    latency_seconds: int
    is_live: bool
    origin: str

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise ValueError("text must be a string")
        if sha256_hex(self.text.encode("utf-8")) != self.response_digest:
            raise ValueError("response_digest does not match text")
        for name in ("provider_id", "provider_kind", "adapter_version", "model_requested", "model_reported", "finish_reason", "origin"):
            _nonempty(getattr(self, name), name)
        if not isinstance(self.request_digest, str) or len(self.request_digest) != 64:
            raise ValueError("request_digest must be a full SHA-256 hex digest")
        if not isinstance(self.latency_seconds, int) or isinstance(self.latency_seconds, bool) or self.latency_seconds < 0:
            raise ValueError("latency_seconds must be a non-negative integer")
        if not isinstance(self.is_live, bool):
            raise ValueError("is_live must be a bool")
        try:
            object.__setattr__(self, "usage", normalize(dict(self.usage)))
        except CanonicalError as exc:
            raise ValueError(f"usage is not canonical JSON: {exc}") from exc

    def to_dict(self, include_text: bool = True) -> dict[str, Any]:
        out = {
            "provider_id": self.provider_id,
            "provider_kind": self.provider_kind,
            "adapter_version": self.adapter_version,
            "model_requested": self.model_requested,
            "model_reported": self.model_reported,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "finish_reason": self.finish_reason,
            "usage": self.usage,
            "latency_seconds": self.latency_seconds,
            "is_live": self.is_live,
            "origin": self.origin,
        }
        if include_text:
            out["text"] = self.text
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], text: str | None = None) -> "AIResponse":
        return cls(
            text=data["text"] if text is None else text,
            provider_id=data["provider_id"],
            provider_kind=data["provider_kind"],
            adapter_version=data["adapter_version"],
            model_requested=data["model_requested"],
            model_reported=data["model_reported"],
            request_digest=data["request_digest"],
            response_digest=data["response_digest"],
            finish_reason=data["finish_reason"],
            usage=dict(data.get("usage", {})),
            latency_seconds=data["latency_seconds"],
            is_live=data["is_live"],
            origin=data["origin"],
        )


def latency_between(start: str, end: str) -> int:
    """Whole seconds between two injected-clock timestamps, never negative."""
    return max(0, int((parse_utc(end) - parse_utc(start)).total_seconds()))


class AIPort(Protocol):
    """What every AI implementation must provide. is_live says whether complete() reaches an
    external service; is_model says whether the output is (or replays) a model's output rather
    than deterministic code; origin is a short tag recorded in every ai_call provenance block
    (for example "synthetic_test_data", "deterministic_baseline", or the live provider name)."""

    provider_id: str
    provider_kind: str
    adapter_version: str
    is_live: bool
    is_model: bool
    origin: str

    def complete(self, request: AIRequest) -> AIResponse: ...


def build_response(port: AIPort, request: AIRequest, text: str, model_requested: str, model_reported: str, finish_reason: str, usage: Mapping[str, Any], started_at: str, finished_at: str) -> AIResponse:
    """Helper for implementations: fills the provenance fields from the port and the request."""
    return AIResponse(
        text=text,
        provider_id=port.provider_id,
        provider_kind=port.provider_kind,
        adapter_version=port.adapter_version,
        model_requested=model_requested,
        model_reported=model_reported,
        request_digest=request.request_digest,
        response_digest=sha256_hex(text.encode("utf-8")),
        finish_reason=finish_reason,
        usage=dict(usage),
        latency_seconds=latency_between(started_at, finished_at),
        is_live=port.is_live,
        origin=port.origin,
    )


def excerpt_inputs(items: Sequence[tuple[str, str, str]]) -> tuple[SourceInput, ...]:
    return tuple(SourceInput(source_id, content_digest, excerpt) for source_id, content_digest, excerpt in items)
