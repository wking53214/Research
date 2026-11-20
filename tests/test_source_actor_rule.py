"""The source-actor rule lives in the store validator, so it holds on every way a source can enter.

A source is an input the lab preserved. Only an EXTERNAL or SYSTEM actor may originate one. The
rule is checked inside the append transaction (so nothing is written) and again on replay (so a
log written outside the validated path is refused when it is reopened). One test per entry path.
"""

import pytest
from conftest import TENANT

from research_lab.clock import StepClock
from research_lab.graph import EVENT_RECORD, PolicyViolation
from research_lab.lab import Lab
from research_lab.lifecycle import AuthorityError
from research_lab.records import Actor, ActorKind, Kind, Record
from research_lab.store import EventStore

SYSTEM = Actor("local-filesystem", ActorKind.SYSTEM)
BODY = {"locator": "file:///a.txt", "content_digest": "abc"}


def forged_source(actor):
    return Record.create(Kind.SOURCE, TENANT, BODY, actor, "2026-11-05T00:00:00Z", "OPEN")


@pytest.fixture
def raw(db_path, principal, lab):
    store = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)  # a writer outside the Lab
    yield store
    store.close()


def test_add_refuses_a_source_from_a_human_or_an_ai(lab, human, ai):
    count = lab.store.count()
    for actor in (human, ai):
        with pytest.raises(AuthorityError, match="EXTERNAL or SYSTEM"):
            lab.add(Kind.SOURCE, BODY, actor)
    assert lab.store.count() == count


def test_supersede_refuses_a_replacement_source_from_an_ai(lab, ai):
    first = lab.add(Kind.SOURCE, BODY, SYSTEM)
    count = lab.store.count()
    with pytest.raises(AuthorityError, match="EXTERNAL or SYSTEM"):
        lab.supersede(first.entity_id, {**BODY, "content_digest": "def"}, ai, "changed")
    assert lab.store.count() == count


def test_a_raw_append_through_the_lab_store_is_refused_at_write_time(lab, ai):
    count = lab.store.count()
    with pytest.raises(PolicyViolation, match="EXTERNAL or SYSTEM"):
        lab.store.append(EVENT_RECORD, {"record": forged_source(ai).to_dict(), "edges": []})
    assert lab.store.count() == count


def test_a_source_written_outside_the_validated_path_is_refused_on_reopen(db_path, principal, lab, raw, ai):
    raw.append(EVENT_RECORD, {"record": forged_source(ai).to_dict(), "edges": []})
    with pytest.raises(PolicyViolation, match="EXTERNAL or SYSTEM"):
        Lab.open(db_path, TENANT, principal, StepClock())


def test_external_and_system_sources_are_still_accepted(lab):
    for actor in (SYSTEM, Actor("github.com", ActorKind.EXTERNAL)):
        lab.add(Kind.SOURCE, {**BODY, "locator": f"file:///{actor.id}"}, actor)
