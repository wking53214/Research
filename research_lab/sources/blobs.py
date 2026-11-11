"""BlobStore: a content-addressed, write-once reproducibility cache for fetched inputs.

This is NOT an evidence authority. The native evidence owners (TIE, HERALD, CCC in the
STACK family) keep that role; the lab references their ids and keeps these bytes only so a
run can be repeated against exactly the input it saw. One directory per tenant; a blob is
named by the SHA-256 of its bytes, written atomically, verified on every read, never
overwritten and never deleted by this module.
"""

from __future__ import annotations

import os
import re
import tempfile

from ..canonical import sha256_hex
from .base import SourceError

DEFAULT_MAX_BYTES = 64 * 1024 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class BlobError(SourceError):
    """Base class for blob store failures."""


class BlobMissing(BlobError):
    """No blob with that digest."""


class BlobCorrupt(BlobError):
    """The stored bytes no longer hash to their name."""


class BlobTooLarge(BlobError):
    """The content exceeds the configured cap."""


class BlobStore:
    def __init__(self, root: str, tenant: str, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        if not isinstance(root, str) or not os.path.isabs(root):
            raise BlobError("blob root must be an absolute path")
        if not isinstance(tenant, str) or not _TENANT.match(tenant):
            raise BlobError(f"tenant {tenant!r} is not a safe directory name")
        self.root = os.path.realpath(root)
        self.tenant = tenant
        self.directory = os.path.join(self.root, tenant)
        self._max_bytes = int(max_bytes)
        os.makedirs(self.directory, exist_ok=True)

    def _path(self, digest: str) -> str:
        if not isinstance(digest, str) or not _DIGEST.match(digest):
            raise BlobError(f"not a SHA-256 hex digest: {digest!r}")
        return os.path.join(self.directory, digest[:2], digest)

    def exists(self, digest: str) -> bool:
        return os.path.isfile(self._path(digest))

    def write(self, content: bytes) -> str:
        """Store content under its digest and return the digest. Writing bytes that are
        already stored is a no-op after confirming the stored copy still matches."""
        if not isinstance(content, bytes):
            raise BlobError("content must be bytes")
        if len(content) > self._max_bytes:
            raise BlobTooLarge(f"{len(content)} bytes exceeds the cap of {self._max_bytes}")
        digest = sha256_hex(content)
        path = self._path(digest)
        if os.path.exists(path):
            if self.read(digest) != content:  # read() raises BlobCorrupt on a mismatch
                raise BlobCorrupt(f"stored blob {digest} differs from the content offered")
            return digest
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o444)
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return digest

    def read(self, digest: str) -> bytes:
        path = self._path(digest)
        try:
            with open(path, "rb") as handle:
                content = handle.read(self._max_bytes + 1)
        except FileNotFoundError as exc:
            raise BlobMissing(f"no blob {digest} for tenant {self.tenant}") from exc
        if len(content) > self._max_bytes or sha256_hex(content) != digest:
            raise BlobCorrupt(f"blob {digest} for tenant {self.tenant} does not hash to its name")
        return content

    def verify(self, digest: str) -> bool:
        try:
            self.read(digest)
        except (BlobMissing, BlobCorrupt):
            return False
        return True

    def status(self, digest: str) -> str:
        """'ok', 'missing' or 'corrupt'."""
        try:
            self.read(digest)
        except BlobMissing:
            return "missing"
        except BlobCorrupt:
            return "corrupt"
        return "ok"
