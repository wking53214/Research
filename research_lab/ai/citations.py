"""Citation verification: does the quoted text appear verbatim in the preserved source?

A VERIFIED cite proves only that the source's stored bytes contain those words (after
whitespace normalisation), at the recorded span. It does not prove the claim the cite
supports, that the quote is in context, or that the source is reliable. An UNVERIFIED cite
is flagged with its reason and kept; it is never silently dropped.

Minimum quote size: a fabricating provider could cite any short common substring ("a",
"the") and obtain VERIFIED, because almost any text contains it. A quote must therefore be
long enough to identify a passage before it can be VERIFIED: at least MIN_QUOTE_CHARS
characters and MIN_QUOTE_TOKENS whitespace-separated words, both counted after whitespace
normalisation. Callers may override both; the defaults are deliberately conservative.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

from ..records import Kind
from ..sources.blobs import BlobCorrupt, BlobMissing
from .outputs import Cite

if TYPE_CHECKING:  # pragma: no cover
    from ..lab import Lab

VERIFIED = "VERIFIED"
UNVERIFIED = "UNVERIFIED"
MIN_QUOTE_CHARS = 20
MIN_QUOTE_TOKENS = 4
_WS = re.compile(r"\s+")


def normalize_ws(text: str) -> str:
    return _WS.sub(" ", text).strip()


@dataclass(frozen=True)
class CitationCheck:
    """span is (start, end) character offsets of the match in the whitespace-normalised
    source text, present only when VERIFIED, so an auditor can find the passage."""

    source_id: str
    quote: str
    status: str
    reason: str
    span: tuple[int, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "quote": self.quote,
            "status": self.status,
            "reason": self.reason,
            "span": list(self.span) if self.span is not None else None,
        }


def too_short(normalised_quote: str, min_chars: int = MIN_QUOTE_CHARS, min_tokens: int = MIN_QUOTE_TOKENS) -> bool:
    return len(normalised_quote) < min_chars or len(normalised_quote.split(" ")) < min_tokens if normalised_quote else True


def verify_citations(
    lab: "Lab",
    cites: Sequence[Cite],
    min_chars: int = MIN_QUOTE_CHARS,
    min_tokens: int = MIN_QUOTE_TOKENS,
) -> list[CitationCheck]:
    out: list[CitationCheck] = []
    cache: dict[str, tuple[str | None, str]] = {}
    for cite in cites:
        if cite.source_id not in cache:
            cache[cite.source_id] = _load(lab, cite.source_id)
        text, problem = cache[cite.source_id]
        quote = normalize_ws(cite.quote)
        if text is None:
            out.append(CitationCheck(cite.source_id, cite.quote, UNVERIFIED, problem))
        elif too_short(quote, min_chars, min_tokens):
            out.append(
                CitationCheck(
                    cite.source_id, cite.quote, UNVERIFIED,
                    f"quote too short to identify a passage (minimum {min_chars} characters and {min_tokens} words)",
                )
            )
        else:
            start = text.find(quote)
            if start < 0:
                out.append(CitationCheck(cite.source_id, cite.quote, UNVERIFIED, "quote not found in source"))
            else:
                out.append(
                    CitationCheck(
                        cite.source_id, cite.quote, VERIFIED,
                        "quote found verbatim (whitespace normalised) at the recorded span",
                        (start, start + len(quote)),
                    )
                )
    return out


def _load(lab: "Lab", source_id: str) -> tuple[str | None, str]:
    node = lab.graph.nodes.get(source_id)
    if node is None or node.kind is not Kind.SOURCE:
        return None, "unknown source: no source entity with this id in this tenant"
    digest = node.latest.body.get("blob_digest")
    if not isinstance(digest, str):
        return None, "source has no blob digest"
    if lab.blobs is None:
        return None, "no blob store configured"
    try:
        content = lab.blobs.read(digest)
    except BlobCorrupt:
        return None, "blob corrupt: stored source no longer hashes to its digest"
    except BlobMissing:
        return None, "blob missing: stored source not found"
    return normalize_ws(content.decode("utf-8", errors="replace")), ""
