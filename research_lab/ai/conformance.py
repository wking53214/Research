"""Conformance suite for AIPort implementations.

A future WATCHER_MCU adapter runs run_conformance(port, request) against itself (with a
request its recording or live backend can answer) and must pass every check. The checks are
deliberately about provenance and behaviour, never about the quality of the text.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..canonical import sha256_hex
from .port import AIError, AIPort, AIRequest, ProviderRefused, ProviderTimeout, ProviderUnavailable, ResponseFormatError


@dataclass(frozen=True)
class ConformanceResult:
    name: str
    ok: bool
    detail: str


def _result(name: str, ok: bool, detail: str = "") -> ConformanceResult:
    return ConformanceResult(name, ok, detail)


def run_conformance(port: AIPort, request: AIRequest, unknown_request: AIRequest | None = None) -> list[ConformanceResult]:
    results: list[ConformanceResult] = []

    # 1. port attributes
    problems = []
    for name in ("provider_id", "provider_kind", "adapter_version", "origin"):
        value = getattr(port, name, None)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{name} missing or empty")
    for name in ("is_live", "is_model"):
        if not isinstance(getattr(port, name, None), bool):
            problems.append(f"{name} must be a bool")
    if getattr(port, "is_live", None) is False and getattr(port, "origin", "") == "live":
        problems.append("a port that is not live may not claim origin 'live'")
    results.append(_result("port_attributes", not problems, "; ".join(problems)))

    # 2. deterministic request digest
    rebuilt = AIRequest.from_dict(request.to_dict())
    changed = AIRequest(request.purpose, request.instructions + " ", request.inputs, request.max_output_tokens, request.settings)
    ok = rebuilt.request_digest == request.request_digest and changed.request_digest != request.request_digest
    results.append(_result("request_digest_deterministic", ok, "" if ok else "digest not stable or not sensitive to content"))

    # 3. error classes are distinguishable
    ok = (
        not issubclass(ProviderRefused, ProviderUnavailable)
        and not issubclass(ProviderUnavailable, ProviderRefused)
        and issubclass(ProviderTimeout, ProviderUnavailable)
        and issubclass(ResponseFormatError, AIError)
        and not issubclass(ResponseFormatError, (ProviderUnavailable, ProviderRefused))
    )
    results.append(_result("error_classes_distinguishable", ok))

    # 4. the request is not mutated and the response carries provenance
    before = request.to_dict()
    try:
        response = port.complete(request)
    except AIError as exc:
        results.append(_result("request_not_mutated", request.to_dict() == before))
        results.append(_result("response_provenance", False, f"complete() raised {type(exc).__name__}: {exc}"))
        return results
    results.append(_result("request_not_mutated", request.to_dict() == before))
    problems = []
    for name in ("provider_id", "provider_kind", "adapter_version", "is_live", "origin"):
        if getattr(response, name) != getattr(port, name):
            problems.append(f"response.{name} differs from port.{name}")
    if response.request_digest != request.request_digest:
        problems.append("response does not echo the request digest")
    if response.response_digest != sha256_hex(response.text.encode("utf-8")):
        problems.append("response digest does not match text")
    if not isinstance(response.latency_seconds, int) or response.latency_seconds < 0:
        problems.append("latency must be a non-negative integer")
    if not isinstance(response.usage, dict):
        problems.append("usage must be a dict")
    for name in ("model_requested", "model_reported", "finish_reason"):
        if not isinstance(getattr(response, name), str) or not getattr(response, name):
            problems.append(f"{name} missing")
    results.append(_result("response_provenance", not problems, "; ".join(problems)))

    # 5. repeatability of provenance for the same request (text may differ for a live model)
    second = port.complete(request)
    ok = second.request_digest == response.request_digest and second.provider_id == response.provider_id
    results.append(_result("same_request_same_provenance", ok))

    # 6. an unknown request is answered or refused through the defined errors only
    if unknown_request is not None:
        try:
            port.complete(unknown_request)
            results.append(_result("unknown_request_handled", True, "answered"))
        except (ProviderUnavailable, ProviderRefused) as exc:
            results.append(_result("unknown_request_handled", True, f"{type(exc).__name__}"))
        except Exception as exc:  # noqa: BLE001
            results.append(_result("unknown_request_handled", False, f"raised {type(exc).__name__}, not a defined AI error"))
    return results


def assert_conformant(port: AIPort, request: AIRequest, unknown_request: AIRequest | None = None) -> list[ConformanceResult]:
    results = run_conformance(port, request, unknown_request)
    failed = [r for r in results if not r.ok]
    if failed:
        raise AssertionError("conformance failed: " + "; ".join(f"{r.name}: {r.detail}" for r in failed))
    return results
