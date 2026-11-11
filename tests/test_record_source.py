"""Lab.record_source, verify_sources, shared_sources and the CLI source commands."""

import json
import os

import pytest
from conftest import ISSUERS, LEGACY_MODE, ROOT, TENANT

from research_lab.cli import main
from research_lab.clock import StepClock
from research_lab.graph import EdgeType, Graph
from research_lab.lab import Lab
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind, RecordError
from research_lab.sources import FixtureTransport, GitHubSource, LocalFileSource, SourceRefused

FIXTURES = os.path.join(ROOT, "tests", "fixtures", "github")
EXTERNAL = Actor("github.com", ActorKind.EXTERNAL)
SYSTEM = Actor("local-filesystem", ActorKind.SYSTEM)


@pytest.fixture
def slab(db_path, principal, tmp_path):
    created = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), blob_root=str(tmp_path / "blobs"), governance_mode=LEGACY_MODE)
    yield created
    created.close()


@pytest.fixture
def root(tmp_path):
    base = tmp_path / "inputs"
    base.mkdir()
    (base / "a.txt").write_bytes(b"alpha\n")
    return base


def local(root):
    return LocalFileSource([str(root)], StepClock())


def test_record_source_preserves_document_and_blob(slab, root):
    doc = local(root).fetch(str(root / "a.txt"))
    done = slab.record_source(doc, SYSTEM)
    assert done.created and not done.changed and done.previous_id is None
    body = done.record.body
    assert done.record.kind is Kind.SOURCE and done.record.disposition == "OPEN" and done.record.evidence_label is None
    assert body["locator"] == doc.locator and body["adapter_id"] == "local_file" and body["adapter_version"] == "1"
    assert body["content_digest"] == doc.content_digest == body["blob_digest"] and body["media_type"] == "text/plain"
    assert body["retrieval"]["size"] == 6 and body["size"] == 6 and "pinned" not in body
    assert slab.blobs.read(body["blob_digest"]) == b"alpha\n"
    assert slab.verify_sources().ok and slab.verify_sources().checked == 1
    assert Graph.rebuild(slab.store.events()) == slab.graph


def test_github_source_record_carries_pins(slab):
    doc = GitHubSource(FixtureTransport(FIXTURES), StepClock()).fetch_file("wking53214", "WATCHER_MCU", "README.md", ref="main")
    done = slab.record_source(doc, EXTERNAL)
    pinned = done.record.body["pinned"]
    assert pinned["commit_sha"] == "4ab218d0c4c31e78bc0b9359f6c09fa32c87babd" and pinned["blob_sha"] == "1862cdec13f22793e20c82f95ef43ddb86d40385"
    assert done.record.body["response_digest"] != done.record.body["content_digest"]
    assert slab.graph.source_by_locator(doc.locator).entity_id == done.record.entity_id


def test_source_actor_must_be_external_or_system(slab, root, human, ai):
    doc = local(root).fetch(str(root / "a.txt"))
    for actor in (human, ai):
        with pytest.raises(RecordError, match="EXTERNAL or SYSTEM"):
            slab.record_source(doc, actor)
    assert slab.graph.sources() == []


def test_lab_without_blob_store_refuses_sources(lab, root):
    with pytest.raises(SourceRefused, match="no blob store"):
        lab.record_source(local(root).fetch(str(root / "a.txt")), SYSTEM)


def test_blob_store_tenant_must_match(db_path, principal, tmp_path):
    from research_lab.sources import BlobStore
    from research_lab.store import EventStore

    store = EventStore.create(db_path, TENANT, principal, ISSUERS, governance_mode=LEGACY_MODE)
    with pytest.raises(SourceRefused, match="belongs to tenant 'other'"):
        Lab(store, StepClock(), blobs=BlobStore(str(tmp_path / "blobs"), "other"))
    store.close()


def test_refetch_with_identical_content_is_idempotent(slab, root):
    first = slab.record_source(local(root).fetch(str(root / "a.txt")), SYSTEM)
    count = slab.store.count()
    again = slab.record_source(local(root).fetch(str(root / "a.txt")), SYSTEM)
    assert not again.created and again.record == first.record and slab.store.count() == count
    assert len(slab.graph.sources()) == 1


def test_changed_content_supersedes_and_is_flagged(slab, root):
    first = slab.record_source(local(root).fetch(str(root / "a.txt")), SYSTEM)
    (root / "a.txt").write_bytes(b"alpha changed\n")
    second = slab.record_source(local(root).fetch(str(root / "a.txt")), SYSTEM)
    assert second.created and second.changed and second.previous_id == first.record.entity_id
    assert second.record.body["change"] == {
        "type": "source_changed",
        "previous": first.record.entity_id,
        "previous_content_digest": first.record.body["content_digest"],
    }
    assert slab.graph.node(first.record.entity_id).status == "SUPERSEDED"
    assert slab.graph.edges_from(second.record.entity_id, EdgeType.SUPERSEDES)[0].to_id == first.record.entity_id
    assert slab.graph.source_by_locator(first.record.body["locator"]).entity_id == second.record.entity_id
    assert len(slab.graph.sources()) == 2 and slab.verify_sources().checked == 2 and slab.verify_sources().ok
    third = slab.record_source(local(root).fetch(str(root / "a.txt")), SYSTEM)
    assert not third.created and third.record.entity_id == second.record.entity_id


def test_verify_sources_detects_tampered_and_missing_blobs(slab, root):
    done = slab.record_source(local(root).fetch(str(root / "a.txt")), SYSTEM)
    (root / "b.txt").write_bytes(b"beta\n")
    other = slab.record_source(local(root).fetch(str(root / "b.txt")), SYSTEM)
    assert slab.verify_sources().ok
    path = slab.blobs._path(done.record.body["blob_digest"])
    os.chmod(path, 0o644)
    with open(path, "wb") as handle:
        handle.write(b"evidence modified after preservation\n")
    os.unlink(slab.blobs._path(other.record.body["blob_digest"]))
    check = slab.verify_sources()
    assert not check.ok and check.checked == 2
    assert any(done.record.entity_id in p and "corrupt" in p for p in check.problems)
    assert any(other.record.entity_id in p and "missing" in p for p in check.problems)
    assert slab.verify().ok  # the log itself is intact; the cached input is not


def test_reopen_without_blob_store_reports_unchecked(db_path, principal, slab, root):
    slab.record_source(local(root).fetch(str(root / "a.txt")), SYSTEM)
    slab.close()
    plain = Lab.open(db_path, TENANT, principal, StepClock())
    check = plain.verify_sources()
    assert not check.ok and "no blob store" in check.problems[0]
    plain.close()


def test_shared_sources_and_sources_cited_by(slab, root, human, ai):
    (root / "b.txt").write_bytes(b"beta\n")
    s1 = slab.record_source(local(root).fetch(str(root / "a.txt")), SYSTEM).record
    s2 = slab.record_source(local(root).fetch(str(root / "b.txt")), SYSTEM).record
    h = slab.add(Kind.HYPOTHESIS, {"text": "H"}, ai, edges=[(EdgeType.CITES, s1.entity_id)])
    e1 = slab.add(Kind.EVIDENCE, {"text": "e1"}, human, edges=[(EdgeType.SUPPORTS, h.entity_id), (EdgeType.CITES, s1.entity_id), (EdgeType.CITES, s2.entity_id)], evidence_label=EvidenceLabel.INSPECTED)
    e2 = slab.add(Kind.EVIDENCE, {"text": "e2"}, human, edges=[(EdgeType.SUPPORTS, h.entity_id), (EdgeType.CITES, s1.entity_id)], evidence_label=EvidenceLabel.INSPECTED)
    e3 = slab.add(Kind.EVIDENCE, {"text": "e3"}, human, edges=[(EdgeType.SUPPORTS, h.entity_id)], evidence_label=EvidenceLabel.INSPECTED)
    assert [n.entity_id for n in slab.graph.sources_cited_by(e1.entity_id)] == [s1.entity_id, s2.entity_id]
    assert [n.entity_id for n in slab.graph.shared_sources(e1.entity_id, e2.entity_id)] == [s1.entity_id]
    assert [n.entity_id for n in slab.graph.shared_sources(e1.entity_id, h.entity_id)] == [s1.entity_id]
    assert slab.graph.shared_sources(e1.entity_id, e3.entity_id) == []
    assert slab.graph.shared_sources(e2.entity_id, e2.entity_id)[0].entity_id == s1.entity_id
    assert Graph.rebuild(slab.store.events()) == slab.graph and slab.verify().ok


# CLI


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, (json.loads(captured.out) if captured.out.strip() else None), captured.err


def test_cli_add_source_file_and_github_and_verify(capsys, tmp_path, root):
    db = str(tmp_path / "cli.sqlite")
    common = ["--db", db, "--tenant", "acme", "--principal", "alice", "--at", "2026-04-01T12:00:00Z"]
    assert run(capsys, "init", *common, "--issuer", "gov-1", "--unauthenticated-governance")[0] == 0
    code, data, err = run(capsys, "add", "source", *common, "--actor", "fs", "--actor-kind", "SYSTEM", "--kind", "file", "--path", str(root / "a.txt"), "--allow-root", str(root))
    assert code == 0, err
    assert data["created"] and not data["changed"] and data["record"]["body"]["adapter_id"] == "local_file"
    assert os.path.isdir(db + ".blobs")  # default blob root beside the store
    code, data, _ = run(capsys, "add", "source", *common, "--actor", "fs", "--actor-kind", "SYSTEM", "--kind", "file", "--path", str(root / "a.txt"), "--allow-root", str(root))
    assert code == 0 and not data["created"]
    code, _, err = run(capsys, "add", "source", *common, "--actor", "fs", "--actor-kind", "SYSTEM", "--kind", "file", "--path", "/etc/hostname", "--allow-root", str(root))
    assert code == 1 and json.loads(err)["error"] == "SourceRefused"
    code, _, err = run(capsys, "add", "source", *common, "--actor", "fs", "--actor-kind", "SYSTEM", "--kind", "file", "--path", str(root / "a.txt"))
    assert code == 1 and "allow-root" in json.loads(err)["message"]
    code, _, err = run(capsys, "add", "source", *common, "--actor", "alice", "--actor-kind", "HUMAN", "--kind", "file", "--path", str(root / "a.txt"), "--allow-root", str(root))
    assert code == 1 and "EXTERNAL or SYSTEM" in json.loads(err)["message"]
    code, data, err = run(
        capsys, "add", "source", *common, "--actor", "github.com", "--actor-kind", "EXTERNAL", "--kind", "github",
        "--repo", "wking53214/WATCHER_MCU", "--path", "README.md", "--ref", "main", "--github-fixtures", FIXTURES,
    )
    assert code == 0, err
    assert data["offline_fixtures"] and data["record"]["body"]["pinned"]["commit_sha"] == "4ab218d0c4c31e78bc0b9359f6c09fa32c87babd"
    code, data, _ = run(capsys, "verify", *common)
    assert code == 0 and data["ok"] and data["sources"] == {"ok": True, "checked": 2, "problems": []}
    assert data["events_checked"] == 3 and data["policy_checked"]
    from research_lab.canonical import sha256_hex
    from research_lab.sources import BlobStore

    path = BlobStore(db + ".blobs", "acme")._path(sha256_hex(b"alpha\n"))  # the local file's blob
    os.chmod(path, 0o644)
    with open(path, "ab") as handle:
        handle.write(b"tampered")
    code, data, _ = run(capsys, "verify", *common)
    assert code == 1 and data["ok"] and not data["sources"]["ok"] and "corrupt" in data["sources"]["problems"][0]
    code, data, _ = run(capsys, "verify", *common, "--blob-root", str(tmp_path / "elsewhere"))
    assert code == 1 and "missing" in data["sources"]["problems"][0]  # a different blob root has no blobs


def test_cli_verify_without_blob_store_says_so(capsys, tmp_path):
    db = str(tmp_path / "cli.sqlite")
    common = ["--db", db, "--tenant", "acme", "--principal", "alice", "--at", "2026-04-01T12:00:00Z"]
    assert run(capsys, "init", *common)[0] == 0
    code, data, _ = run(capsys, "verify", *common)
    assert code == 0 and data["ok"] and data["sources"]["checked"] == 0 and "skipped" in data["sources"]
