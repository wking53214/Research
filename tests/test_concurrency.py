"""Two writers on one store: stale views, two processes, threads.

The store is the single enforcement point. Under its write lock it catches the caller's
validator up to the real head, checks the candidate against the real state, and only then
inserts. A stale caller whose event is invalid on the real state gets
ConcurrentWriteConflict and nothing is written; a stale caller whose event is still valid is
accepted after catch-up. The Lab's graph never disagrees with the log.

The first two tests are the D1 and D2 scenarios from the independent verification's
attack2.py; the thread test is its D3.
"""

import json
import os
import subprocess
import sys
import threading

import pytest
from conftest import ISSUERS, LEGACY_MODE, ROOT, TENANT

from research_lab.clock import StepClock
from research_lab.graph import Graph, PolicyViolation
from research_lab.lab import Lab, verify_store
from research_lab.records import Actor, ActorKind, Kind
from research_lab.store import ConcurrentWriteConflict, EventStore, ThreadAffinityError


def open_lab(db_path, principal):
    return Lab.open(db_path, TENANT, principal, StepClock())


def assert_consistent(db_path, principal, *labs):
    for lab in labs:
        assert Graph.rebuild(lab.store.events()) == lab.graph
    fresh = open_lab(db_path, principal)
    result = fresh.verify()
    assert result.ok and result.policy_checked
    fresh.close()


def test_d1_stale_writer_repeating_a_close_is_refused_and_store_survives(db_path, lab, principal, human, reviewer):
    a = lab
    o = a.add(Kind.OBJECTIVE, {"text": "o"}, human)
    b = open_lab(db_path, principal)  # b sees o at OPEN
    a.transition(o.entity_id, "CLOSED", human, "A closes")
    assert b.graph.node(o.entity_id).status == "OPEN"  # stale view
    count = a.store.count()
    # B built version 2 from its stale view; on the real state version 2 already exists.
    with pytest.raises(ConcurrentWriteConflict, match="another writer appended 1 event.*version 2 does not follow 2"):
        b.transition(o.entity_id, "CLOSED", reviewer, "B closes")
    assert b.store.count() == count  # nothing written
    assert b.graph.node(o.entity_id).status == "CLOSED"  # b was caught up during the refused append
    assert_consistent(db_path, principal, a, b)
    b.close()


def test_d2_stale_writer_whose_event_is_legal_only_on_its_view_is_refused(db_path, lab, principal, human, reviewer):
    a = lab
    o = a.add(Kind.OBJECTIVE, {"text": "o"}, human)
    b = open_lab(db_path, principal)
    a.transition(o.entity_id, "SUPERSEDED", human, "terminal")
    with pytest.raises(ConcurrentWriteConflict, match="not valid on the real state.*version 2 does not follow 2"):
        b.transition(o.entity_id, "REJECTED", reviewer, "legal on B's stale view only")
    assert b.graph.node(o.entity_id).status == "SUPERSEDED"
    assert_consistent(db_path, principal, a, b)
    b.close()
    reopened = open_lab(db_path, principal)
    assert [r.disposition for r in reopened.graph.history(o.entity_id)] == ["OPEN", "SUPERSEDED"]
    reopened.close()


def test_stale_writer_with_a_still_valid_event_is_accepted_after_catch_up(db_path, lab, principal, human, reviewer):
    a = lab
    o = a.add(Kind.OBJECTIVE, {"text": "o"}, human)
    b = open_lab(db_path, principal)
    q = a.add(Kind.QUESTION, {"text": "q"}, human, edges=[("DECOMPOSES", o.entity_id)])  # b has not seen q
    assert not b.graph.has(q.entity_id)
    closed = b.transition(o.entity_id, "CLOSED", reviewer, "unrelated to q")  # valid on the real state
    assert closed.version == 2
    assert b.graph.has(q.entity_id)  # caught up under the write lock
    assert b.graph.applied_seq == b.store.head().seq
    assert a.graph.node(o.entity_id).status == "OPEN"  # a is now the stale one
    assert a.refresh() == 1
    assert a.graph.node(o.entity_id).status == "CLOSED"
    assert_consistent(db_path, principal, a, b)
    b.close()


def test_graph_equals_rebuild_after_every_failed_write(lab, human, reviewer, ai):
    o = lab.add(Kind.OBJECTIVE, {"text": "o"}, human)
    attempts = [
        lambda: lab.transition(o.entity_id, "REOPENED", human, "illegal from OPEN"),
        lambda: lab.transition("objective_ghost", "CLOSED", human, "unknown"),
        lambda: lab.add(Kind.HYPOTHESIS, {"text": "h"}, ai, edges=[("ANSWERS", o.entity_id)]),
        lambda: lab.store.append("NOTE", {}),
        lambda: lab.transition(o.entity_id, "CLOSED", human, ""),
    ]
    for attempt in attempts:
        count = lab.store.count()
        with pytest.raises(Exception):
            attempt()
        assert lab.store.count() == count
        assert Graph.rebuild(lab.store.events()) == lab.graph
        assert lab.verify().ok


def test_a_poisoned_log_written_outside_the_validated_path_refuses_every_writer(db_path, lab, principal, human):
    o = lab.add(Kind.OBJECTIVE, {"text": "o"}, human)
    bare = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)  # test-only opt-out
    bare.append("NOTE", {"poison": True})
    bare.close()
    with pytest.raises(PolicyViolation, match="unknown event type 'NOTE'"):
        lab.transition(o.entity_id, "CLOSED", human, "the Lab's catch-up hits the poison first")
    assert lab.store.count() == 3  # nothing more was written
    with pytest.raises(PolicyViolation):
        open_lab(db_path, principal)
    bare = EventStore.open(db_path, TENANT, principal)
    assert not verify_store(bare).ok
    bare.close()


WORKER = """
import sys
from research_lab.clock import StepClock
from research_lab.lab import Lab
from research_lab.records import Actor, ActorKind, Kind
from research_lab.store import Principal
db, name, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
lab = Lab.open(db, "acme", Principal("alice", frozenset({"acme"})), StepClock("2026-06-01T00:00:00Z"))
actor = Actor(name, ActorKind.HUMAN)
objective = lab.add(Kind.OBJECTIVE, {"text": "root"}, actor, entity_id="ROOT-" + name)
for i in range(n):
    q = lab.add(Kind.QUESTION, {"text": f"{name}-{i}"}, actor, edges=[("DECOMPOSES", objective.entity_id)])
    lab.transition(q.entity_id, "CLOSED", actor, "done")
print(lab.graph.applied_seq, lab.store.count(), lab.verify().ok)
lab.close()
"""


def test_two_processes_appending_to_one_store(db_path, principal, tmp_path):
    Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), governance_mode=LEGACY_MODE).close()
    env = dict(os.environ, PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""), PYTHONDONTWRITEBYTECODE="1")
    n = 25
    procs = [
        subprocess.Popen([sys.executable, "-c", WORKER, db_path, name, str(n)], env=env, cwd=str(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for name in ("p1", "p2")
    ]
    outputs = [proc.communicate() for proc in procs]
    for proc, (out, err) in zip(procs, outputs):
        assert proc.returncode == 0, err
        seq, count, ok = out.split()
        assert ok == "True" and int(seq) + 1 == int(count)  # each worker's graph equals the log it saw last
    reopened = open_lab(db_path, principal)
    expected = 1 + 2 * (1 + 2 * n)  # genesis + per process: one objective + n questions + n closes
    assert reopened.store.count() == expected
    result = reopened.verify()
    assert result.ok and result.policy_checked
    assert len(reopened.graph.children("ROOT-p1")) == n and len(reopened.graph.children("ROOT-p2")) == n
    seqs = [e.seq for e in reopened.store.events()]
    assert seqs == list(range(expected))
    reopened.close()


def test_threads_on_one_lab_fail_closed_without_touching_the_log(db_path, lab, principal, human):
    errors = []
    before = lab.store.count()

    def worker(i):
        try:
            lab.add(Kind.OBJECTIVE, {"text": f"t{i}"}, human)
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == ["ThreadAffinityError"] * 20
    assert lab.store.count() == before
    lab.add(Kind.OBJECTIVE, {"text": "from the owning thread"}, human)  # the owning thread still works
    assert_consistent(db_path, principal, lab)


def test_one_lab_per_thread_works(db_path, lab, principal):
    results = []

    def worker(name):
        try:
            mine = open_lab(db_path, principal)
            mine.add(Kind.OBJECTIVE, {"text": name}, Actor(name, ActorKind.HUMAN))
            results.append(mine.verify().ok)
            mine.close()
        except Exception as exc:  # noqa: BLE001
            results.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == [True] * 5
    assert lab.refresh() == 5
    assert_consistent(db_path, principal, lab)
