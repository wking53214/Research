import os
import stat

import pytest

from research_lab.canonical import sha256_hex
from research_lab.clock import StepClock
from research_lab.sources import LocalFileSource, SourceRefused, SourceTooLarge, SourceUnavailable


@pytest.fixture
def root(tmp_path):
    base = tmp_path / "root"
    base.mkdir()
    (base / "data.txt").write_bytes(b"hello\n")
    (base / "sub").mkdir()
    (base / "sub" / "inner.md").write_bytes(b"# inner\n")
    return base


def source(root, **kw):
    return LocalFileSource([str(root)], StepClock(), **kw)


def test_roots_must_be_explicit_absolute_directories(tmp_path):
    with pytest.raises(SourceRefused, match="no default"):
        LocalFileSource([], StepClock())
    with pytest.raises(SourceRefused, match="absolute"):
        LocalFileSource(["relative/dir"], StepClock())
    with pytest.raises(SourceRefused, match="not a directory"):
        LocalFileSource([str(tmp_path / "missing")], StepClock())


def test_reads_a_regular_file_inside_the_root(root):
    doc = source(root).fetch(str(root / "data.txt"))
    assert doc.content == b"hello\n" and doc.content_digest == sha256_hex(b"hello\n") == doc.response_digest
    assert doc.locator == "file://" + os.path.realpath(str(root / "data.txt"))
    assert doc.media_type == "text/plain" and doc.adapter_id == "local_file"
    assert doc.retrieval["size"] == 6 and doc.retrieval["root"] == os.path.realpath(str(root))
    assert doc.pinned is None
    assert source(root).fetch(doc.locator).content_digest == doc.content_digest  # file:// locator works too
    inner = source(root).fetch(str(root / "sub" / "inner.md"))
    assert inner.media_type == "text/markdown"


def test_path_traversal_is_refused(root, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"secret")
    with pytest.raises(SourceRefused, match="outside the allowed roots"):
        source(root).fetch(str(root / ".." / "secret.txt"))
    with pytest.raises(SourceRefused, match="outside the allowed roots"):
        source(root).fetch(str(root / "sub" / ".." / ".." / "secret.txt"))
    with pytest.raises(SourceRefused, match="outside the allowed roots"):
        source(root).fetch("/etc/hostname")
    with pytest.raises(SourceRefused, match="absolute path"):
        source(root).fetch("data.txt")


def test_symlink_escape_is_refused_and_symlink_inside_root_is_resolved(root, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"secret")
    os.symlink(str(outside), str(root / "escape.txt"))
    with pytest.raises(SourceRefused, match="outside the allowed roots"):
        source(root).fetch(str(root / "escape.txt"))
    os.symlink(str(tmp_path), str(root / "escape-dir"))
    with pytest.raises(SourceRefused, match="outside the allowed roots"):
        source(root).fetch(str(root / "escape-dir" / "secret.txt"))
    os.symlink(str(root / "data.txt"), str(root / "alias.txt"))
    doc = source(root).fetch(str(root / "alias.txt"))
    assert doc.content == b"hello\n" and doc.locator.endswith("/root/data.txt")


def test_root_that_is_a_symlink_is_resolved_before_confinement(root, tmp_path):
    link = tmp_path / "rootlink"
    os.symlink(str(root), str(link))
    src = LocalFileSource([str(link)], StepClock())
    assert src.allowed_roots == (os.path.realpath(str(root)),)
    assert src.fetch(str(link / "data.txt")).content == b"hello\n"


def test_non_regular_files_are_refused_without_being_opened(root):
    with pytest.raises(SourceRefused, match="not a regular file"):
        source(root).fetch(str(root / "sub"))
    fifo = root / "pipe"
    os.mkfifo(str(fifo))
    with pytest.raises(SourceRefused, match="not a regular file|cannot open"):
        source(root).fetch(str(fifo))  # opening a FIFO for reading would block; O_NOFOLLOW plus fstat refuses it
    dev = LocalFileSource(["/dev"], StepClock())
    with pytest.raises(SourceRefused, match="not a regular file"):
        dev.fetch("/dev/null")


def test_size_cap(root):
    (root / "big.bin").write_bytes(b"x" * 100)
    with pytest.raises(SourceTooLarge):
        source(root, max_bytes=99).fetch(str(root / "big.bin"))
    assert source(root, max_bytes=100).fetch(str(root / "big.bin")).size == 100


def test_missing_file_is_unavailable(root):
    with pytest.raises(SourceUnavailable, match="not found"):
        source(root).fetch(str(root / "nope.txt"))
