"""Strict parsing of provider output. The only accepted shape is

    {"questions": [{"text": "..."}], "hypotheses": [{"text": "...", "cites": [{"source_id": "...", "quote": "..."}]}]}

Unknown keys, wrong types, empty strings, oversize payloads, too many items and duplicate
cites are refused with ResponseFormatError carrying the raw text's SHA-256.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..canonical import canonical_json, sha256_hex
from .port import ResponseFormatError

MAX_TEXT_BYTES = 256 * 1024
MAX_ITEMS = 50
MAX_FIELD_CHARS = 2000
MAX_CITES = 20


@dataclass(frozen=True)
class Cite:
    source_id: str
    quote: str

    def to_dict(self) -> dict[str, str]:
        return {"source_id": self.source_id, "quote": self.quote}


@dataclass(frozen=True)
class HypothesisProposal:
    text: str
    cites: tuple[Cite, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "cites": [cite.to_dict() for cite in self.cites]}


@dataclass(frozen=True)
class Proposals:
    questions: tuple[str, ...]
    hypotheses: tuple[HypothesisProposal, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"questions": [{"text": q} for q in self.questions], "hypotheses": [h.to_dict() for h in self.hypotheses]}


def render_proposals(proposals: Proposals) -> str:
    """The canonical JSON text of a Proposals value (what a conforming provider returns)."""
    return canonical_json(proposals.to_dict())


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} is not allowed")


def _string(value: Any, where: str, digest: str, limit: int = MAX_FIELD_CHARS) -> str:
    if not isinstance(value, str):
        raise ResponseFormatError(f"{where} must be a string", digest)
    stripped = value.strip()
    if not stripped:
        raise ResponseFormatError(f"{where} must not be empty", digest)
    if len(stripped) > limit:
        raise ResponseFormatError(f"{where} exceeds {limit} characters", digest)
    return stripped


def _object(value: Any, where: str, keys: set[str], digest: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResponseFormatError(f"{where} must be an object", digest)
    if set(value) != keys:
        raise ResponseFormatError(f"{where} must have exactly the keys {sorted(keys)}, got {sorted(value)}", digest)
    return value


def _list(value: Any, where: str, digest: str, limit: int = MAX_ITEMS) -> list[Any]:
    if not isinstance(value, list):
        raise ResponseFormatError(f"{where} must be a list", digest)
    if len(value) > limit:
        raise ResponseFormatError(f"{where} has {len(value)} items; the cap is {limit}", digest)
    return value


def parse_proposals(text: str, max_bytes: int = MAX_TEXT_BYTES) -> Proposals:
    if not isinstance(text, str):
        raise ResponseFormatError("response text must be a string")
    raw = text.encode("utf-8")
    digest = sha256_hex(raw)
    if len(raw) > max_bytes:
        raise ResponseFormatError(f"response of {len(raw)} bytes exceeds the cap of {max_bytes}", digest)
    try:
        data = json.loads(text, parse_constant=_reject_constant)
    except ValueError as exc:
        raise ResponseFormatError(f"response is not JSON: {exc}", digest) from exc
    top = _object(data, "response", {"questions", "hypotheses"}, digest)
    questions = []
    for index, item in enumerate(_list(top["questions"], "questions", digest)):
        where = f"questions[{index}]"
        questions.append(_string(_object(item, where, {"text"}, digest)["text"], f"{where}.text", digest))
    hypotheses = []
    for index, item in enumerate(_list(top["hypotheses"], "hypotheses", digest)):
        where = f"hypotheses[{index}]"
        obj = _object(item, where, {"text", "cites"}, digest)
        text_value = _string(obj["text"], f"{where}.text", digest)
        cites: list[Cite] = []
        seen: set[tuple[str, str]] = set()
        for cindex, cite in enumerate(_list(obj["cites"], f"{where}.cites", digest, MAX_CITES)):
            cwhere = f"{where}.cites[{cindex}]"
            cobj = _object(cite, cwhere, {"source_id", "quote"}, digest)
            key = (_string(cobj["source_id"], f"{cwhere}.source_id", digest, 200), _string(cobj["quote"], f"{cwhere}.quote", digest))
            if key in seen:
                raise ResponseFormatError(f"{cwhere} duplicates an earlier cite", digest)
            seen.add(key)
            cites.append(Cite(*key))
        hypotheses.append(HypothesisProposal(text_value, tuple(cites)))
    return Proposals(tuple(questions), tuple(hypotheses))
