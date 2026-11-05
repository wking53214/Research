"""Canonical JSON: exactly one byte sequence per value, so digests are stable.

Rules enforced here (each one is tested in tests/test_canonical.py):

* keys are sorted, separators are compact, output is ASCII (non-ASCII is escaped);
* strings and keys are normalized to Unicode NFC before serialization;
* floats must be finite: NaN, Infinity and -Infinity are refused;
* only None, bool, int, float, str, list, tuple and dict (str keys) are accepted;
* two keys that become equal after NFC normalization are refused as duplicates.

Floats are written with Python's shortest round-trip repr (1.0 stays "1.0", 1 stays "1").
That is deterministic for one Python implementation; cross-language byte equality is not
claimed by this module.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from typing import Any


class CanonicalError(ValueError):
    """The value cannot be represented as canonical JSON."""


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def normalize(value: Any, path: str = "$") -> Any:
    """Return a plain JSON-ready copy of value, or raise CanonicalError."""
    if value is None or value is True or value is False:
        return value
    if isinstance(value, str):
        return _nfc(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalError(f"{path}: non-finite float {value!r} is not allowed")
        return value
    if isinstance(value, (list, tuple)):
        return [normalize(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: key {key!r} is not a string")
            nkey = _nfc(key)
            if nkey in out:
                raise CanonicalError(f"{path}: duplicate key {nkey!r} after NFC normalization")
            out[nkey] = normalize(item, f"{path}.{nkey}")
        return out
    raise CanonicalError(f"{path}: type {type(value).__name__} is not canonical JSON")


def canonical_json(value: Any) -> str:
    """Serialize value to its single canonical JSON text."""
    return json.dumps(
        normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    """Full SHA-256 hex digest of the canonical JSON of value. Never truncated here."""
    return sha256_hex(canonical_bytes(value))
