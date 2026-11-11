"""ReplayAIPort: serves recorded responses keyed by request digest.

Every recording this repository ships or generates is SYNTHETIC TEST DATA. The file header
says so, the port refuses a recording that is not labelled so, and every response carries
origin "synthetic_test_data". Nothing served by this port is a model's output.
"""

from __future__ import annotations

import json
import os
from typing import Any, Mapping, Sequence

from ..clock import Clock
from .port import AIRequest, AIResponse, ProviderRefused, ProviderTimeout, ProviderUnavailable, build_response

RECORDING_SCHEMA = "research_lab.ai_replay/1"
SYNTHETIC_ORIGIN = "synthetic_test_data"
WARNING = "SYNTHETIC TEST DATA: hand-written for tests and demos; not the output of any model"


def write_recording(path: str, entries: Sequence[Mapping[str, Any]], note: str) -> None:
    """Write a synthetic recording. Each entry has request_digest and either text (plus
    optional model_reported, finish_reason, usage) or error {type, reason}."""
    header = {"recording_schema": RECORDING_SCHEMA, "origin": SYNTHETIC_ORIGIN, "warning": WARNING, "note": note}
    lines = [json.dumps(header, sort_keys=True)]
    for entry in entries:
        if "request_digest" not in entry or not (("text" in entry) ^ ("error" in entry)):
            raise ValueError("each entry needs request_digest and exactly one of text or error")
        lines.append(json.dumps(dict(entry), sort_keys=True))
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    os.replace(tmp, path)


class ReplayAIPort:
    provider_kind = "replay"
    adapter_version = "1"
    is_live = False
    is_model = True  # it stands in for a model, so its output is treated as a model's proposal
    origin = SYNTHETIC_ORIGIN

    def __init__(self, path: str, clock: Clock, provider_id: str = "replay") -> None:
        self.provider_id = provider_id
        self._clock = clock
        self.calls: list[str] = []
        self._entries: dict[str, dict[str, Any]] = {}
        with open(path, encoding="utf-8") as handle:
            lines = [line for line in handle.read().split("\n") if line.strip()]
        if not lines:
            raise ValueError("empty recording")
        header = json.loads(lines[0])
        if header.get("recording_schema") != RECORDING_SCHEMA or header.get("origin") != SYNTHETIC_ORIGIN:
            raise ValueError("refusing a recording that is not labelled synthetic test data")
        self.note = str(header.get("note", ""))
        for line in lines[1:]:
            entry = json.loads(line)
            self._entries[entry["request_digest"]] = entry

    def __len__(self) -> int:
        return len(self._entries)

    def complete(self, request: AIRequest) -> AIResponse:
        started = self._clock.now()
        self.calls.append(request.request_digest)
        entry = self._entries.get(request.request_digest)
        if entry is None:
            raise ProviderUnavailable(f"replay miss: no recorded response for request digest {request.request_digest}")
        error = entry.get("error")
        if error is not None:
            kind, reason = error.get("type"), error.get("reason", "recorded failure")
            if kind == "refused":
                raise ProviderRefused(reason)
            if kind == "timeout":
                raise ProviderTimeout(reason)
            raise ProviderUnavailable(reason, error.get("status"))
        return build_response(
            self,
            request,
            text=entry["text"],
            model_requested=str(request.settings.get("model", "unspecified")),
            model_reported=str(entry.get("model_reported", "synthetic")),
            finish_reason=str(entry.get("finish_reason", "stop")),
            usage=entry.get("usage", {}),
            started_at=started,
            finished_at=self._clock.now(),
        )
