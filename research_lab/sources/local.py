"""LocalFileSource: reads a regular file inside explicitly configured roots, nothing else."""

from __future__ import annotations

import mimetypes
import os
import stat
from typing import Sequence

from ..canonical import sha256_hex
from ..clock import Clock
from .base import SourceDocument, SourceRefused, SourceTooLarge, SourceUnavailable

DEFAULT_MAX_BYTES = 16 * 1024 * 1024


class LocalFileSource:
    """Allowed roots must be given; there is no default. Every path is resolved with
    realpath (symlinks followed) and must land inside a root; the final open uses
    O_NOFOLLOW and fstat so that only a regular file is read. Directories, FIFOs, devices
    and sockets are refused without being opened."""

    adapter_id = "local_file"
    adapter_version = "1"

    def __init__(self, allowed_roots: Sequence[str], clock: Clock, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        if not allowed_roots:
            raise SourceRefused("LocalFileSource needs at least one allowed root; there is no default")
        roots = []
        for root in allowed_roots:
            if not isinstance(root, str) or not os.path.isabs(root):
                raise SourceRefused(f"allowed root must be an absolute path: {root!r}")
            real = os.path.realpath(root)
            if not os.path.isdir(real):
                raise SourceRefused(f"allowed root is not a directory: {root!r}")
            roots.append(real)
        self._roots = tuple(roots)
        self._clock = clock
        self._max_bytes = int(max_bytes)

    @property
    def allowed_roots(self) -> tuple[str, ...]:
        return self._roots

    @staticmethod
    def locator_for(path: str) -> str:
        return "file://" + os.path.realpath(path)

    def _confine(self, locator: str) -> tuple[str, str]:
        path = locator[len("file://") :] if locator.startswith("file://") else locator
        if not path or not os.path.isabs(path):
            raise SourceRefused(f"an absolute path is required: {locator!r}")
        real = os.path.realpath(path)
        for root in self._roots:
            if real == root or real.startswith(root + os.sep):
                return real, root
        raise SourceRefused(f"path resolves outside the allowed roots: {path!r}")

    def fetch(self, locator: str) -> SourceDocument:
        real, root = self._confine(locator)
        try:
            # O_NONBLOCK: opening a FIFO read-only would otherwise block until a writer appears;
            # with it the open returns at once and fstat refuses the non-regular file.
            fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_NOCTTY", 0))
        except FileNotFoundError as exc:
            raise SourceUnavailable(f"file not found: {real}") from exc
        except IsADirectoryError as exc:
            raise SourceRefused(f"not a regular file (directory): {real}") from exc
        except OSError as exc:
            # ELOOP means the last component is a symlink that realpath could not settle.
            raise SourceRefused(f"cannot open {real}: {exc.strerror}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise SourceRefused(f"not a regular file: {real}")
            if info.st_size > self._max_bytes:
                raise SourceTooLarge(f"{real} is {info.st_size} bytes; cap is {self._max_bytes}")
            chunks = []
            remaining = self._max_bytes + 1
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 1 << 20))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(fd)
        content = b"".join(chunks)
        if len(content) > self._max_bytes:
            raise SourceTooLarge(f"{real} exceeds the cap of {self._max_bytes} bytes")
        digest = sha256_hex(content)
        media_type = mimetypes.guess_type(real)[0] or "application/octet-stream"
        return SourceDocument(
            locator="file://" + real,
            content=content,
            media_type=media_type,
            retrieved_at=self._clock.now(),
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            retrieval={"path": real, "root": root, "size": len(content), "mtime": int(info.st_mtime)},
            response_digest=digest,
            content_digest=digest,
        )
