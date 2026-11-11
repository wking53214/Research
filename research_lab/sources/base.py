"""The source port contract. No adapter logic here."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from ..canonical import CanonicalError, normalize, sha256_hex
from ..clock import parse_utc


class SourceError(Exception):
    """Base class for source failures."""


class SourceUnavailable(SourceError):
    """The source could not be fetched (network, HTTP error, rate limit, missing file)."""

    def __init__(self, reason: str, status: int | None = None) -> None:
        super().__init__(reason if status is None else f"{reason} (HTTP {status})")
        self.reason = reason
        self.status = status


class SourceRefused(SourceError):
    """Policy refused the request (host, scheme, redirect, path outside roots, file type)."""


class SourceFormatError(SourceError):
    """The response did not have the expected shape. response_digest is the SHA-256 of the
    raw response so the exact bytes can be found again."""

    def __init__(self, reason: str, response_digest: str | None = None) -> None:
        suffix = f" [response sha256 {response_digest}]" if response_digest else ""
        super().__init__(reason + suffix)
        self.reason = reason
        self.response_digest = response_digest


class SourceTooLarge(SourceError):
    """The content exceeds the configured cap."""


@dataclass(frozen=True)
class SourceDocument:
    """What an adapter returns. content_digest is the SHA-256 of content; response_digest is
    the SHA-256 of the raw response the content was decoded from (equal to content_digest for
    a local file). pinned carries the immutable coordinates when the adapter has them (for
    GitHub: repository, path, ref as requested, commit_sha, blob_sha)."""

    locator: str
    content: bytes
    media_type: str
    retrieved_at: str
    adapter_id: str
    adapter_version: str
    retrieval: dict[str, Any]
    response_digest: str
    content_digest: str
    pinned: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.locator, str) or not self.locator:
            raise ValueError("locator must be a non-empty string")
        if not isinstance(self.content, bytes):
            raise ValueError("content must be bytes")
        if sha256_hex(self.content) != self.content_digest:
            raise ValueError("content_digest does not match content")
        if len(self.response_digest) != 64:
            raise ValueError("response_digest must be a full SHA-256 hex digest")
        parse_utc(self.retrieved_at)
        for name in ("adapter_id", "adapter_version", "media_type"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValueError(f"{name} must be a non-empty string")
        try:
            object.__setattr__(self, "retrieval", normalize(dict(self.retrieval)))
            if self.pinned is not None:
                object.__setattr__(self, "pinned", normalize(dict(self.pinned)))
        except CanonicalError as exc:
            raise ValueError(f"retrieval metadata is not canonical JSON: {exc}") from exc

    @property
    def size(self) -> int:
        return len(self.content)

    def record_body(self) -> dict[str, Any]:
        """The body of the source record: everything except the content itself."""
        body: dict[str, Any] = {
            "locator": self.locator,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "media_type": self.media_type,
            "size": self.size,
            "retrieved_at": self.retrieved_at,
            "retrieval": self.retrieval,
            "response_digest": self.response_digest,
            "content_digest": self.content_digest,
        }
        if self.pinned is not None:
            body["pinned"] = self.pinned
        return body


class SourcePort(Protocol):
    adapter_id: str
    adapter_version: str

    def fetch(self, locator: str) -> SourceDocument: ...
