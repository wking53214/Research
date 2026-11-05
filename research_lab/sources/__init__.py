"""Source adapters: instruments that fetch external content for the lab to preserve.

A source is never evidence by itself and never verified knowledge. What an adapter returns
is a SourceDocument: bytes plus where they came from, when, through which adapter, with full
SHA-256 digests, and for GitHub the pinned commit and blob so the citation is immutable.

Core contract: base.py. Adapters: local.py (LocalFileSource), github.py (GitHubSource).
Reproducibility cache: blobs.py (BlobStore). No AI code lives here; the AI port is a later
round and a separate package.
"""

from .base import (
    SourceDocument,
    SourceError,
    SourceFormatError,
    SourcePort,
    SourceRefused,
    SourceTooLarge,
    SourceUnavailable,
)
from .blobs import BlobCorrupt, BlobError, BlobMissing, BlobStore, BlobTooLarge
from .github import FixtureTransport, GitHubSource, urllib_transport
from .local import LocalFileSource

__all__ = [
    "BlobCorrupt",
    "BlobError",
    "BlobMissing",
    "BlobStore",
    "BlobTooLarge",
    "FixtureTransport",
    "GitHubSource",
    "LocalFileSource",
    "SourceDocument",
    "SourceError",
    "SourceFormatError",
    "SourcePort",
    "SourceRefused",
    "SourceTooLarge",
    "SourceUnavailable",
    "urllib_transport",
]
