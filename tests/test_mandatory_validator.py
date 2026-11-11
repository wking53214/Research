"""The policy validator is mandatory in the store (finding E1).

EventStore.open and create attach the standard Graph-based validator themselves, so a bare
store in another process refuses an out-of-policy append exactly as a Lab does. The only way
to write unvalidated is the loudly named test-only opt-out unsafe_unvalidated=True.
"""

import inspect

import pytest
from conftest import ISSUERS, LEGACY_MODE, TENANT

from research_lab.clock import StepClock
from research_lab.graph import EVENT_RECORD, EVENT_TRANSITION, Graph, PolicyViolation
from research_lab.lab import Lab
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind, Record
from research_lab.store import EventStore

AT = "2026-11-05T00:00:00Z"


def forged_admitted(lab, ai):
    f = lab.add(Kind.FINDING, {"text": "x"}, ai, evidence_label=EvidenceLabel.INFERRED)
    forged = lab.graph.node(f.entity_id).latest.next_version(
        origin=ai, created_at=AT, disposition="ADMITTED",
        provenance=({"type": "governance_disposition", "issuer_id": "gov-1", "reason": "forged"},),
    )
    return f.entity_id, {"record": forged.to_dict(), "from": "PROPOSED", "to": "ADMITTED", "actor": ai.to_dict(), "reason": "forged", "governance": {"issuer_id": "gov-1"}}


def test_e1_bare_store_refuses_forged_admitted_at_write_time_and_lab_still_opens(db_path, principal, lab, ai):
    f, payload = forged_admitted(lab, ai)
    lab.close()
    bare = EventStore.open(db_path, TENANT, principal)
    assert isinstance(bare.validator, Graph) and bare.validator.applied_seq == -1  # caught up lazily
    count = bare.count()
    with pytest.raises(PolicyViolation, match="seq 2: TRANSITION: actor kind AI may not record a governance disposition"):
        bare.append(EVENT_TRANSITION, payload)
    assert bare.count() == count
    assert bare.validator.applied_seq == count - 1  # the catch-up happened inside the refused append
    bare.close()
    reopened = Lab.open(db_path, TENANT, principal, StepClock())
    assert reopened.graph.node(f).status == "PROPOSED"
    assert reopened.verify().ok
    reopened.close()


def test_bare_store_accepts_a_valid_append_after_catching_up(db_path, principal, lab, human):
    objective = lab.add(Kind.OBJECTIVE, {"title": "o"}, human)
    lab.close()
    bare = EventStore.open(db_path, TENANT, principal)
    question = Record.create(Kind.QUESTION, TENANT, {"text": "q"}, human, AT, "OPEN")
    event = bare.append(EVENT_RECORD, {"record": question.to_dict(), "edges": [{"edge": "DECOMPOSES", "to": objective.entity_id}]})
    assert event.seq == 2 and bare.validator.applied_seq == 2
    bare.close()
    reopened = Lab.open(db_path, TENANT, principal, StepClock())
    assert reopened.graph.children(objective.entity_id)[0].entity_id == question.entity_id
    assert reopened.verify().ok
    reopened.close()


def test_create_attaches_the_validator_too(db_path, principal, ai):
    store = EventStore.create(db_path, TENANT, principal, ISSUERS, governance_mode=LEGACY_MODE)
    assert isinstance(store.validator, Graph)
    with pytest.raises(PolicyViolation, match="unknown event type 'NOTE'"):
        store.append("NOTE", {"anything": 1})
    assert store.count() == 1
    store.close()
    Lab.open(db_path, TENANT, principal, StepClock()).close()


def test_unsafe_opt_out_is_explicit_and_only_way_to_write_unvalidated(db_path, principal, lab):
    lab.close()
    for method in (EventStore.open, EventStore.create):
        assert "unsafe_unvalidated" in inspect.signature(method).parameters
        assert inspect.signature(method).parameters["unsafe_unvalidated"].default is False
    unsafe = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)
    assert unsafe.validator is None
    unsafe.append("NOTE", {"corrupt": True})  # the replay backstop is what catches this
    unsafe.close()
    with pytest.raises(PolicyViolation, match="unknown event type 'NOTE'"):
        Lab.open(db_path, TENANT, principal, StepClock())


def test_explicit_validator_is_used_instead_of_the_default(db_path, principal, lab):
    lab.close()
    mine = Graph()
    store = EventStore.open(db_path, TENANT, principal, validator=mine)
    assert store.validator is mine
    store.close()
