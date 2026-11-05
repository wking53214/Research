import math

import pytest

from research_lab.canonical import digest
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind, Record, RecordError, Ref

AT = "2026-01-01T00:00:00Z"


def human() -> Actor:
    return Actor("alice", ActorKind.HUMAN)


def test_actor_validation_and_roundtrip():
    with pytest.raises(RecordError):
        Actor("", ActorKind.HUMAN)
    with pytest.raises(RecordError):
        Actor("x", "HUMAN")  # type: ignore[arg-type]
    with pytest.raises(RecordError):
        Actor("x", ActorKind.AI, provider="")
    ai = Actor("m", ActorKind.AI, provider="p", model_family="f")
    assert Actor.from_dict(ai.to_dict()) == ai
    assert Actor.from_dict(human().to_dict()) == human()
    with pytest.raises(RecordError):
        Actor.from_dict({"id": "x", "kind": "ROBOT"})


def test_ref_validation():
    with pytest.raises(RecordError):
        Ref("", 1)
    with pytest.raises(RecordError):
        Ref("a", 0)
    with pytest.raises(RecordError):
        Ref("a", True)  # bool is not a version


def test_create_version_one_has_derived_id_and_full_digests():
    record = Record.create(Kind.OBJECTIVE, "t", {"title": "x"}, human(), AT, "OPEN")
    assert record.version == 1
    assert record.entity_id == f"objective_{record.entity_digest[:16]}"
    assert len(record.entity_digest) == 64
    assert len(record.digest) == 64
    assert record.verify_digest()
    assert record.parents == ()


def test_roundtrip_through_dict_is_lossless():
    record = Record.create(
        Kind.EVIDENCE, "t", {"text": "e"}, human(), AT, "OPEN", provenance=[{"src": "x"}], evidence_label=EvidenceLabel.INSPECTED
    )
    again = Record.from_dict(record.to_dict())
    assert again == record
    assert again.verify_digest()


def test_tampered_body_fails_digest_check():
    record = Record.create(Kind.OBJECTIVE, "t", {"title": "x"}, human(), AT, "OPEN")
    data = record.to_dict()
    data["body"]["title"] = "y"
    assert not Record.from_dict(data).verify_digest()


def test_forged_derived_entity_id_fails_digest_check():
    # An attacker re-signs a record whose derived id no longer matches its entity_digest.
    record = Record.create(Kind.OBJECTIVE, "t", {"title": "x"}, human(), AT, "OPEN")
    data = record.to_dict()
    data["entity_id"] = "objective_0000000000000000"
    data["digest"] = digest({k: v for k, v in data.items() if k != "digest"})
    forged = Record.from_dict(data)
    assert forged.digest == digest(forged.content())  # content digest is self-consistent
    assert not forged.verify_digest()  # but the id prefix does not match entity_digest


def test_in_place_mutation_of_body_is_detectable():
    record = Record.create(Kind.OBJECTIVE, "t", {"title": "x"}, human(), AT, "OPEN")
    record.body["title"] = "mutated"
    assert not record.verify_digest()


def test_invalid_timestamp_is_refused():
    with pytest.raises(RecordError, match="created_at"):
        Record.create(Kind.OBJECTIVE, "t", {"title": "x"}, human(), "2026-01-01 00:00:00", "OPEN")


def test_evidence_and_finding_require_a_label_and_others_do_not():
    with pytest.raises(RecordError, match="evidence_label"):
        Record.create(Kind.EVIDENCE, "t", {"text": "e"}, human(), AT, "OPEN")
    with pytest.raises(RecordError, match="evidence_label"):
        Record.create(Kind.FINDING, "t", {"text": "f"}, human(), AT, "PROPOSED")
    Record.create(Kind.QUESTION, "t", {"text": "q"}, human(), AT, "OPEN")


def test_non_canonical_body_is_refused():
    with pytest.raises(RecordError, match="canonical"):
        Record.create(Kind.OBJECTIVE, "t", {"x": math.nan}, human(), AT, "OPEN")
    with pytest.raises(RecordError, match="mapping"):
        Record.create(Kind.OBJECTIVE, "t", ["not", "a", "mapping"], human(), AT, "OPEN")  # type: ignore[arg-type]


def test_next_version_links_to_parent_and_keeps_entity_digest():
    first = Record.create(Kind.QUESTION, "t", {"text": "q"}, human(), AT, "OPEN")
    second = first.next_version(human(), "2026-01-01T00:00:01Z", "CLOSED", provenance=[{"reason": "done"}])
    assert second.version == 2
    assert second.parents == (Ref(first.entity_id, 1),)
    assert second.entity_id == first.entity_id
    assert second.entity_digest == first.entity_digest
    assert second.body == first.body
    assert second.digest != first.digest
    assert second.verify_digest()


def test_caller_supplied_id_may_not_imitate_derived_form():
    with pytest.raises(RecordError, match="imitate"):
        Record.create(Kind.OBJECTIVE, "t", {"title": "x"}, human(), AT, "OPEN", entity_id="objective_abc")
    record = Record.create(Kind.OBJECTIVE, "t", {"title": "x"}, human(), AT, "OPEN", entity_id="OBJ-1")
    assert record.entity_id == "OBJ-1"
    assert record.verify_digest()


def test_different_content_gives_different_entity_id():
    one = Record.create(Kind.OBJECTIVE, "t", {"title": "x"}, human(), AT, "OPEN")
    two = Record.create(Kind.OBJECTIVE, "t", {"title": "y"}, human(), AT, "OPEN")
    same = Record.create(Kind.OBJECTIVE, "t", {"title": "x"}, human(), AT, "OPEN")
    assert one.entity_id != two.entity_id
    assert one.entity_id == same.entity_id


def test_from_dict_rejects_garbage():
    with pytest.raises(RecordError):
        Record.from_dict({"entity_id": "x"})
    with pytest.raises(RecordError):
        Record.from_dict({**Record.create(Kind.OBJECTIVE, "t", {"a": 1}, human(), AT, "OPEN").to_dict(), "digest": "short"})
