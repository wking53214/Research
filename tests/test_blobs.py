import os

import pytest

from research_lab.canonical import sha256_hex
from research_lab.sources import BlobCorrupt, BlobError, BlobMissing, BlobStore, BlobTooLarge


@pytest.fixture
def store(tmp_path):
    return BlobStore(str(tmp_path / "blobs"), "acme")


def test_write_read_roundtrip_is_content_addressed(store):
    digest = store.write(b"hello")
    assert digest == sha256_hex(b"hello") and store.exists(digest)
    assert store.read(digest) == b"hello" and store.verify(digest) and store.status(digest) == "ok"
    assert store.write(b"hello") == digest  # write-once, idempotent
    assert not os.access(store._path(digest), os.W_OK) or os.getuid() == 0  # read-only unless root


def test_atomic_write_leaves_no_temp_files(store, tmp_path):
    store.write(b"x" * 1000)
    leftovers = [name for _, _, files in os.walk(str(tmp_path / "blobs")) for name in files if name.startswith(".tmp-")]
    assert leftovers == []


def test_modified_blob_is_detected_and_refused(store):
    digest = store.write(b"original")
    path = store._path(digest)
    os.chmod(path, 0o644)
    with open(path, "ab") as handle:
        handle.write(b" tampered")
    assert store.status(digest) == "corrupt" and not store.verify(digest)
    with pytest.raises(BlobCorrupt):
        store.read(digest)
    with pytest.raises(BlobCorrupt):  # write-once: a mismatching existing blob is never overwritten
        store.write(b"original")


def test_missing_blob(store):
    digest = sha256_hex(b"never written")
    assert not store.exists(digest) and store.status(digest) == "missing" and not store.verify(digest)
    with pytest.raises(BlobMissing):
        store.read(digest)


def test_bad_digests_and_names_are_refused(store, tmp_path):
    for bad in ("../../etc/passwd", "abc", "A" * 64, "", None):
        with pytest.raises(BlobError, match="not a SHA-256"):
            store.read(bad)  # type: ignore[arg-type]
    with pytest.raises(BlobError, match="not a safe directory name"):
        BlobStore(str(tmp_path / "blobs"), "../other")
    with pytest.raises(BlobError, match="not a safe directory name"):
        BlobStore(str(tmp_path / "blobs"), "a/b")
    with pytest.raises(BlobError, match="absolute"):
        BlobStore("relative", "acme")
    with pytest.raises(BlobError, match="bytes"):
        store.write("text")  # type: ignore[arg-type]


def test_size_cap(tmp_path):
    small = BlobStore(str(tmp_path / "blobs"), "acme", max_bytes=10)
    with pytest.raises(BlobTooLarge):
        small.write(b"x" * 11)
    assert small.write(b"x" * 10)


def test_tenant_isolation(tmp_path):
    a = BlobStore(str(tmp_path / "blobs"), "tenant-a")
    b = BlobStore(str(tmp_path / "blobs"), "tenant-b")
    digest = a.write(b"a's input")
    assert a.exists(digest) and not b.exists(digest)
    with pytest.raises(BlobMissing, match="tenant tenant-b"):
        b.read(digest)
    assert b.status(digest) == "missing"
    assert a.directory != b.directory and a.directory.startswith(a.root)
