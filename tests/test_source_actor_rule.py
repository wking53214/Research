"""A source record may only be written by an EXTERNAL or SYSTEM actor, on every path.

The rule used to be checked in Lab.record_source only. The general Lab.add accepted a
SOURCE record from a HUMAN actor and from an AI actor, and reopening the store and
verify() flagged neither (EXECUTED 2026-11-18). The rule now lives in the graph's
record check, which the write path and the replay path share, so each way a source
record can arrive is covered here:

* Lab.add, at write time
* Lab.supersede (the replacement record), at write time
* a raw RECORD event through the validated store, at write time
* a raw RECORD event written outside the validated path, refused on reopen
* the CLI
* Lab.record_source, which keeps its own earlier error
"""

import pytest
from conftest import ISSUERS, TENANT

from research_lab.cli import main
from research_lab.clock import StepClock
from research_lab.graph import EVENT_RECORD, Graph, PolicyViolation
from research_lab.lab import SOURCE_ACTOR_KINDS, Lab, verify_store
from research_lab.records import Actor, ActorKind, Kind, Record, RecordError
from research_lab.store import EventStore

AT = "2026-11-05T00:00:00Z"
MESSAGE = "a source is recorded by an EXTERNAL or SYSTEM actor"
SYSTEM = Actor("local-filesystem", ActorKind.SYSTEM)
EXTERNAL = Actor("github.com", ActorKind.EXTERNAL)
BODY = {"locator": "file:///x", "content_digest": "d" * 64}


@pytest.fixture
def raw(db_path, principal, lab):
    """A store on the same file with no validator, as an attacker with store access would have."""
    store = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)
    yield store
    store.close()


def forged_source(actor):
    return Record.create(Kind.SOURCE, TENANT, BODY, actor, AT, "OPEN")


def test_the_allowed_kinds_are_external_and_system_only():
    assert SOURCE_ACTOR_KINDS == frozenset({ActorKind.EXTERNAL, ActorKind.SYSTEM})


def test_lab_add_refuses_a_source_from_a_human_or_an_ai(lab, human, ai):
    count = lab.store.count()
    for actor in (human, ai):
        with pytest.raises(PolicyViolation, match=MESSAGE):
            lab.add(Kind.SOURCE, BODY, actor)
    assert lab.store.count() == count and lab.graph.sources() == []
    assert Graph.rebuild(lab.store.events()) == lab.graph


def test_lab_add_still_accepts_a_source_from_external_and_system(lab):
    for actor, locator in ((SYSTEM, "file:///a"), (EXTERNAL, "https://example.invalid/b")):
        record = lab.add(Kind.SOURCE, {**BODY, "locator": locator}, actor)
        assert record.kind is Kind.SOURCE and record.origin == actor
    assert len(lab.graph.sources()) == 2 and lab.verify().ok


def test_lab_supersede_refuses_a_replacement_source_from_a_human_or_an_ai(lab, human, ai):
    old = lab.add(Kind.SOURCE, BODY, SYSTEM)
    count = lab.store.count()
    for actor in (human, ai):
        with pytest.raises(PolicyViolation, match=MESSAGE):
            lab.supersede(old.entity_id, {**BODY, "content_digest": "e" * 64}, actor, "content changed")
    assert lab.store.count() == count and lab.graph.node(old.entity_id).status == "OPEN"


def test_a_raw_record_event_through_the_validated_store_is_refused_at_write_time(lab, human, ai):
    count = lab.store.count()
    for actor in (human, ai):
        with pytest.raises(PolicyViolation, match=MESSAGE):
            lab.store.append(EVENT_RECORD, {"record": forged_source(actor).to_dict(), "edges": []})
    assert lab.store.count() == count and lab.verify().ok


def test_a_source_written_outside_the_validated_path_is_refused_on_reopen(db_path, principal, lab, raw, human):
    raw.append(EVENT_RECORD, {"record": forged_source(human).to_dict(), "edges": []})
    assert raw.verify().ok, "the hash chain alone is intact; only the policy replay catches this"
    live = lab.verify()
    assert not live.ok and any(MESSAGE in p for p in live.problems)
    lab.close()
    with pytest.raises(PolicyViolation, match=MESSAGE):
        Lab.open(db_path, TENANT, principal, StepClock())
    bare = EventStore.open(db_path, TENANT, principal)
    result = verify_store(bare)
    bare.close()
    assert not result.ok and any("policy violation" in p for p in result.problems)


def test_a_source_by_an_ai_written_outside_the_validated_path_is_refused_on_reopen(db_path, principal, lab, raw, ai):
    raw.append(EVENT_RECORD, {"record": forged_source(ai).to_dict(), "edges": []})
    lab.close()
    with pytest.raises(PolicyViolation, match=MESSAGE):
        Lab.open(db_path, TENANT, principal, StepClock())


def test_record_source_keeps_its_own_earlier_error(tmp_path, db_path, principal, human):
    created = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), blob_root=str(tmp_path / "blobs"))
    try:
        (tmp_path / "a.txt").write_bytes(b"alpha\n")
        from research_lab.sources import LocalFileSource

        doc = LocalFileSource([str(tmp_path)], StepClock()).fetch(str(tmp_path / "a.txt"))
        with pytest.raises(RecordError, match="EXTERNAL or SYSTEM"):
            created.record_source(doc, human)
        assert created.graph.sources() == []
    finally:
        created.close()


def test_cli_add_source_refuses_a_human_actor(capsys, tmp_path, principal):
    db = str(tmp_path / "lab.sqlite")
    base = ["--db", db, "--tenant", TENANT, "--principal", principal.id]
    assert main(["init", *base, "--issuer", "gov-1", "--blob-root", str(tmp_path / "blobs")]) == 0
    data = tmp_path / "in"
    data.mkdir()
    (data / "a.txt").write_bytes(b"alpha\n")
    capsys.readouterr()
    code = main([
        "add", "source", *base, "--actor", "alice", "--actor-kind", "HUMAN",
        "--kind", "file", "--path", str(data / "a.txt"), "--allow-root", str(data),
    ])
    out = capsys.readouterr()
    assert code != 0 and "EXTERNAL or SYSTEM" in (out.out + out.err)
