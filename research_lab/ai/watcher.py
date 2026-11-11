"""WatcherAIPort: the AIPort that sends a request through WATCHER_MCU's generic port.

The lab does not import WATCHER_MCU. The adapter is given `call`, a callable that takes the
wire request (a plain mapping) and returns the wire response (a plain mapping); in a
deployment that is `watcher.port.complete`, obtained with load_watcher_call(), which imports
it only when asked. WATCHER_MCU owns the credentials, the vendor SDK and the network call;
none of them is named or held here.

Wire request built from an AIRequest: instructions, inputs (one string per SourceInput: a
source_id line, a content_sha256 line, then the excerpt), model, max_output_tokens,
request_digest, and effort when one was configured. The purpose and the settings of the
AIRequest are covered by its digest and are not sent.

The wire response is checked strictly before anything is believed: exactly the expected
keys, their types, provider_id and provider_kind "watcher_mcu", is_live true,
model_requested equal to the model sent, request_digest equal to the lab's own digest, and
response_digest recomputed from the text. A violation is a ResponseFormatError that carries
the raw text (when there is one) so the caller can preserve it. Latency comes from the
lab's injected clock, never from the other side.

A failure of the call is mapped by the string attribute `code` of the exception:
refused -> ProviderRefused; too_large and format -> ProviderRefused with the reason
(retrying the same request cannot help); unavailable -> ProviderUnavailable; any other
code, or an exception with no code -> ProviderUnavailable naming the exception type (its
message is not copied, because the failure text is written into the event log).
"""

from __future__ import annotations

import importlib
from typing import Any, Callable, Mapping

from ..canonical import sha256_hex
from ..clock import Clock
from .policy import WATCHER_MCU_KIND
from .port import AIRequest, AIResponse, ProviderRefused, ProviderUnavailable, ResponseFormatError, build_response

WireCall = Callable[[dict[str, Any]], Mapping[str, Any]]
RESPONSE_KEYS = frozenset(
    {"text", "provider_id", "provider_kind", "adapter_version", "model_requested", "model_reported",
     "finish_reason", "usage", "request_digest", "response_digest", "is_live"}
)
USAGE_KEYS = frozenset({"input_tokens", "output_tokens"})
UNREPORTED_MODEL = "unreported"


def load_watcher_call() -> WireCall:
    """Return watcher.port.complete, importing WATCHER_MCU only now. Raises ProviderUnavailable
    with a plain reason when WATCHER_MCU, or its generic port, is not installed."""
    try:
        module = importlib.import_module("watcher.port")
    except ImportError as exc:
        raise ProviderUnavailable(f"WATCHER_MCU with its generic port (watcher.port) is not installed: {type(exc).__name__}: {exc}") from exc
    call = getattr(module, "complete", None)
    if not callable(call):
        raise ProviderUnavailable("the installed watcher.port has no complete(); it is not the generic port")
    return call


def wire_request(request: AIRequest, model: str, effort: str | None = None) -> dict[str, Any]:
    """The mapping sent to WATCHER_MCU for an AIRequest. Built fresh; the request is not changed."""
    out: dict[str, Any] = {
        "instructions": request.instructions,
        "inputs": [f"source_id: {item.source_id}\ncontent_sha256: {item.content_digest}\n{item.excerpt}" for item in request.inputs],
        "model": model,
        "max_output_tokens": request.max_output_tokens,
        "request_digest": request.request_digest,
    }
    if effort is not None:
        out["effort"] = effort
    return out


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def check_wire_response(data: Any, request_digest: str, model: str) -> None:
    """Raise ResponseFormatError unless data is exactly a valid wire response to this request."""
    text = data.get("text") if isinstance(data, Mapping) else None
    raw = text if isinstance(text, str) else None
    try:
        actual = sha256_hex(raw.encode("utf-8")) if raw is not None else None
    except UnicodeEncodeError:
        raw, actual = None, None

    def bad(reason: str) -> ResponseFormatError:
        return ResponseFormatError(f"watcher_mcu wire response: {reason}", actual, raw_text=raw)

    if not isinstance(data, Mapping):
        raise bad(f"not a mapping ({type(data).__name__})")
    keys = set(data)
    if keys != RESPONSE_KEYS:
        missing, extra = sorted(RESPONSE_KEYS - keys), sorted(repr(key) for key in keys - RESPONSE_KEYS)
        raise bad(f"wrong keys (missing {missing}, unexpected {extra})")
    if actual is None:
        raise bad("text must be a string that encodes as UTF-8")
    if data["provider_id"] != WATCHER_MCU_KIND or data["provider_kind"] != WATCHER_MCU_KIND:
        raise bad(f"provider_id and provider_kind must be {WATCHER_MCU_KIND!r}")
    if data["is_live"] is not True:
        raise bad("is_live must be true")
    for name in ("adapter_version", "finish_reason"):
        if not isinstance(data[name], str) or not data[name].strip():
            raise bad(f"{name} must be a non-empty string")
    if data["model_requested"] != model:
        raise bad("model_requested is not the model that was sent")
    reported = data["model_reported"]
    if reported is not None and (not isinstance(reported, str) or not reported.strip()):
        raise bad("model_reported must be a non-empty string or null")
    usage = data["usage"]
    if usage is not None and not (isinstance(usage, Mapping) and set(usage) == USAGE_KEYS and all(_count(v) for v in usage.values())):
        raise bad("usage must be null or exactly input_tokens and output_tokens as non-negative integers")
    if data["request_digest"] != request_digest:
        raise bad("request_digest is not the digest of the request that was sent")
    if data["response_digest"] != actual:
        raise bad("response_digest does not match the text")


class WatcherAIPort:
    provider_kind = WATCHER_MCU_KIND
    adapter_version = "1"
    is_live = True
    is_model = True
    origin = "watcher_mcu"

    def __init__(self, call: WireCall, *, clock: Clock, model: str, effort: str | None = None, provider_id: str = "watcher_mcu") -> None:
        if not callable(call):
            raise ValueError("call must be a callable taking the wire request")
        for name, value in (("model", model), ("provider_id", provider_id)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if effort is not None and (not isinstance(effort, str) or not effort.strip()):
            raise ValueError("effort must be a non-empty string or None")
        self.provider_id = provider_id
        self.model = model
        self.effort = effort
        self._call = call
        self._clock = clock
        self.calls: list[str] = []

    def complete(self, request: AIRequest) -> AIResponse:
        started = self._clock.now()
        self.calls.append(request.request_digest)
        try:
            data = self._call(wire_request(request, self.model, self.effort))
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code == "refused":
                raise ProviderRefused(f"watcher_mcu: the model declined: {exc}") from exc
            if code == "too_large":
                raise ProviderRefused(f"watcher_mcu rejected the request as too large: {exc}") from exc
            if code == "format":
                raise ProviderRefused(f"watcher_mcu rejected the request as malformed: {exc}") from exc
            if code == "unavailable":
                raise ProviderUnavailable(f"watcher_mcu unavailable: {exc}") from exc
            said = f" with unknown code {code!r}" if isinstance(code, str) else ""
            raise ProviderUnavailable(f"watcher_mcu call failed: {type(exc).__name__}{said}") from exc
        check_wire_response(data, request.request_digest, self.model)
        usage = dict(data["usage"] or {})
        usage["watcher_adapter_version"] = data["adapter_version"]  # which WATCHER_MCU answered; AIResponse has no other slot
        return build_response(
            self,
            request,
            text=data["text"],
            model_requested=self.model,
            model_reported=data["model_reported"] or UNREPORTED_MODEL,
            finish_reason=data["finish_reason"],
            usage=usage,
            started_at=started,
            finished_at=self._clock.now(),
        )
