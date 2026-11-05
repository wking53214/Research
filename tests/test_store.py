import math
import sqlite3

import pytest
from conftest import ISSUERS, TENANT, tamper

from research_lab.store import (
    GENESIS,
    GENESIS_PREV_HASH,
    SCHEMA_VERSION,
    AccessRefused,
    AppendRefused,
    Event,
    EventStore,
    MemoryAnchor,
    Principal,
    StoreError,
    verify_events,
)


@pytest.fixture
def store(db_path, principal):
    # These tests exercise the chain layer below policy with bare "NOTE" events, so the store
    # is opened without the policy validator (the test-only opt-out).
    created = EventStore.create(db_path, TENANT, principal, ISSUERS, unsafe_unvalidated=True)
    yield created
    created.close()


def fill(store: EventStore, n: int = 4) -> None:
    for i in range(n):
        store.append("NOTE", {"i": i})


def test_genesis_carries_tenant_schema_issuers_and_principals(store, principal):
    genesis = store.events()[0]
    assert genesis.seq == 0
    assert genesis.event_type == GENESIS
    assert genesis.prev_hash == GENESIS_PREV_HASH
    assert genesis.payload == {
        "schema_version": SCHEMA_VERSION,
        "tenant": TENANT,
        "governance_issuers": ISSUERS,
        "principals": [principal.id],
    }
    assert store.governance_issuers == frozenset(ISSUERS)
    assert store.verify().ok


def test_append_chains_and_verifies(store):
    fill(store)
    events = store.events()
    assert [e.seq for e in events] == [0, 1, 2, 3, 4]
    for prev, cur in zip(events, events[1:]):
        assert cur.prev_hash == prev.hash
    result = store.verify()
    assert result.ok and result.events_checked == 5 and result.head_hash == store.head().hash


def test_no_update_or_delete_api_exists():
    names = [name for name in dir(EventStore) if not name.startswith("_")]
    forbidden = [name for name in names if any(word in name.lower() for word in ("update", "delete", "remove", "truncate", "rewrite"))]
    assert forbidden == []


def test_triggers_refuse_update_and_delete(store, db_path):
    fill(store)
    raw = sqlite3.connect(db_path, isolation_level=None)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        raw.execute("UPDATE events SET payload = '{}' WHERE seq = 1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        raw.execute("DELETE FROM events WHERE seq = 1")
    raw.close()
    assert store.verify().ok


def test_edited_payload_is_detected(store, db_path):
    fill(store)
    raw = tamper(db_path)
    raw.execute("UPDATE events SET payload = ? WHERE seq = 2", ('{"i":99}',))
    raw.close()
    result = store.verify()
    assert not result.ok
    assert any("seq 2: hash mismatch" in p for p in result.problems)


def test_deleted_event_is_detected_as_gap(store, db_path):
    fill(store)
    raw = tamper(db_path)
    raw.execute("DELETE FROM events WHERE seq = 2")
    raw.close()
    result = store.verify()
    assert not result.ok
    assert any("position 2: seq 3" in p for p in result.problems)
    assert any("seq 3: prev_hash" in p for p in result.problems)


def test_deleted_tail_event_is_detected_by_anchor(db_path, principal):
    anchor = MemoryAnchor()
    store = EventStore.create(db_path, TENANT, principal, ISSUERS, anchor=anchor, unsafe_unvalidated=True)
    fill(store)
    head = store.head().seq
    raw = tamper(db_path)
    raw.execute("DELETE FROM events WHERE seq = ?", (head,))
    raw.close()
    result = store.verify()
    assert not result.ok
    assert any(f"anchor for seq {head}" in p for p in result.problems)
    store.close()


def test_reordered_events_are_detected(store, db_path):
    fill(store)
    raw = tamper(db_path)
    raw.execute("UPDATE events SET seq = -1 WHERE seq = 2")
    raw.execute("UPDATE events SET seq = 2 WHERE seq = 3")
    raw.execute("UPDATE events SET seq = 3 WHERE seq = -1")
    raw.close()
    result = store.verify()
    assert not result.ok
    assert any("seq 2: hash mismatch" in p for p in result.problems)
    assert any("seq 2: prev_hash" in p for p in result.problems)


def test_wrong_tenant_on_an_event_is_detected(store, db_path):
    fill(store)
    raw = tamper(db_path)
    raw.execute("UPDATE events SET tenant = 'other' WHERE seq = 1")
    raw.close()
    result = store.verify()
    assert not result.ok
    assert any("seq 1: wrong tenant 'other'" in p for p in result.problems)


def test_edited_genesis_is_detected(store, db_path):
    raw = tamper(db_path)
    raw.execute(
        "UPDATE events SET payload = ? WHERE seq = 0",
        ('{"governance_issuers":["mallory"],"principals":["alice"],"schema_version":1,"tenant":"acme"}',),
    )
    raw.close()
    result = store.verify()
    assert not result.ok
    assert any("seq 0: hash mismatch" in p for p in result.problems)


def test_second_genesis_is_refused(store):
    with pytest.raises(AppendRefused, match="second GENESIS"):
        store.append(GENESIS, {"tenant": TENANT, "schema_version": 1, "governance_issuers": ["mallory"], "principals": ["x"]})
    assert store.count() == 1


def test_non_canonical_payload_is_refused(store):
    with pytest.raises(AppendRefused, match="canonical"):
        store.append("NOTE", {"x": math.nan})
    assert store.count() == 1


def test_create_over_existing_store_is_refused(store, db_path, principal):
    with pytest.raises(StoreError, match="already has events"):
        EventStore.create(db_path, TENANT, principal, ISSUERS)


def test_open_for_another_tenant_is_refused(store, db_path):
    with pytest.raises(AccessRefused, match="belongs to tenant 'acme'"):
        EventStore.open(db_path, "other", Principal("alice", frozenset({"other"})))


def test_open_by_unentitled_principal_is_refused(store, db_path):
    with pytest.raises(AccessRefused, match="not entitled"):
        EventStore.open(db_path, TENANT, Principal("mallory", frozenset({TENANT})))


def test_principal_that_does_not_claim_the_tenant_is_refused(store, db_path):
    with pytest.raises(AccessRefused, match="does not claim tenant"):
        EventStore.open(db_path, TENANT, Principal("alice", frozenset({"other"})))
    with pytest.raises(AccessRefused):
        EventStore.open(db_path, TENANT, "alice")  # type: ignore[arg-type]


def test_additional_entitled_principal_can_open(db_path, principal):
    store = EventStore.create(db_path, TENANT, principal, ISSUERS, principals=["alice", "carol"])
    store.close()
    other = EventStore.open(db_path, TENANT, Principal("carol", frozenset({TENANT})))
    assert other.genesis()["principals"] == ["alice", "carol"]
    other.close()
    with pytest.raises(AccessRefused):
        EventStore.create(str(db_path) + ".2", TENANT, principal, ISSUERS, principals=["carol"])


def test_open_missing_or_genesis_less_file_is_refused(tmp_path, principal):
    with pytest.raises(StoreError, match="no store"):
        EventStore.open(str(tmp_path / "missing.sqlite"), TENANT, principal)
    empty = str(tmp_path / "empty.sqlite")
    sqlite3.connect(empty).close()
    with pytest.raises(StoreError, match="no genesis"):
        EventStore.open(empty, TENANT, principal)


def test_bad_issuers_are_refused(db_path, principal):
    with pytest.raises(StoreError, match="governance_issuers"):
        EventStore.create(db_path, TENANT, principal, ["ok", ""])
    with pytest.raises(StoreError):
        EventStore.create(db_path, "", principal, ISSUERS)


def test_verify_events_with_nothing_fails():
    assert not verify_events([], TENANT).ok


def test_event_from_dict_rejects_garbage():
    with pytest.raises(StoreError):
        Event.from_dict({"seq": 1})


def test_anchor_receives_every_head(db_path, principal):
    anchor = MemoryAnchor()
    store = EventStore.create(db_path, TENANT, principal, ISSUERS, anchor=anchor, unsafe_unvalidated=True)
    fill(store, 2)
    assert [seq for seq, _ in anchor.anchored(TENANT)] == [0, 1, 2]
    assert anchor.anchored(TENANT)[-1][1] == store.head().hash
    assert store.verify().ok
    store.close()
