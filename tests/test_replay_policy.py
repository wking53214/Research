"""Policy enforcement at two layers.

Write time: a store with a validator attached (every Lab attaches its graph) refuses an
out-of-policy event inside the append transaction; nothing is written.

Replay (the backstop): an event written outside the validated path (here through a bare
EventStore opened without a validator, as an attacker with store access would) is refused
when the store is reopened, verified, exported or when a bundle is verified, with a
PolicyViolation naming the seq.

The first tests are the exact B1 attack from the independent verification, at both layers.
"""

import sqlite3

import pytest
from conftest import ISSUERS, LEGACY_MODE, TENANT, Chain

from research_lab.canonical import canonical_json
from research_lab.cli import main
from research_lab.clock import StepClock
from research_lab.export import export_bundle, verify_bundle
from research_lab.graph import (
    EVENT_EDGE,
    EVENT_RECORD,
    EVENT_TRANSITION,
    RUN_COMPLETED,
    RUN_STARTED,
    EdgeType,
    Graph,
    PolicyViolation,
)
from research_lab.lab import Lab, verify_store
from research_lab.orchestration import Runner, create_plan
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind, Record
from research_lab.store import GENESIS, EventStore, IntegrityError, event_hash

AT = "2026-11-05T00:00:00Z"


@pytest.fixture
def raw(db_path, principal, lab):
    """The test-only opt-out: a store on the same file with no validator, to simulate a log
    corrupted outside the validated path."""
    store = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)
    assert store.validator is None
    yield store
    store.close()


def transition_payload(lab, entity_id, to, actor, governance=None, from_status=None, provenance=None):
    node = lab.graph.node(entity_id)
    if provenance is None:
        provenance = (
            ({"type": "governance_disposition", "issuer_id": governance["issuer_id"], "reason": "forged"},)
            if governance
            else ({"type": "transition", "reason": "forged"},)
        )
    record = node.latest.next_version(origin=actor, created_at=AT, disposition=to, provenance=provenance)
    return {
        "record": record.to_dict(),
        "from": node.status if from_status is None else from_status,
        "to": to,
        "actor": actor.to_dict(),
        "reason": "forged",
        "governance": governance,
    }


def forge_transition(lab, raw, entity_id, to, actor, governance=None, from_status=None, provenance=None):
    """Write a TRANSITION outside the validated path (bare store), bypassing the Lab's validator."""
    return raw.append(EVENT_TRANSITION, transition_payload(lab, entity_id, to, actor, governance, from_status, provenance))


def reopen_refused(db_path, principal, match):
    with pytest.raises(PolicyViolation, match=match):
        Lab.open(db_path, TENANT, principal, StepClock())
    bare = EventStore.open(db_path, TENANT, principal)
    assert bare.verify().ok, "the hash chain alone is intact; only the policy replay catches this"
    result = verify_store(bare)
    bare.close()
    assert not result.ok and not result.policy_checked
    assert any("policy violation" in p for p in result.problems)
    return result


def refused_at_write(lab, event_type, payload, match):
    """The validated path refuses, writes nothing, and the graph still equals the log."""
    count = lab.store.count()
    with pytest.raises(PolicyViolation, match=match):
        lab.store.append(event_type, payload)
    assert lab.store.count() == count
    assert Graph.rebuild(lab.store.events()) == lab.graph
    assert lab.verify().ok


# B1 at both layers


def test_b1_raw_append_through_the_lab_store_is_refused_at_write_time(lab, ai):
    finding = lab.add(Kind.FINDING, {"text": "ai finding"}, ai, evidence_label=EvidenceLabel.INFERRED)
    payload = transition_payload(lab, finding.entity_id, "ADMITTED", ai, governance={"issuer_id": "gov-1"}, from_status="PROPOSED")
    refused_at_write(lab, EVENT_TRANSITION, payload, "actor kind AI may not record a governance disposition")
    assert lab.graph.node(finding.entity_id).status == "PROPOSED"


def test_b1_written_outside_the_validated_path_is_refused_on_reopen(db_path, principal, lab, raw, ai, capsys):
    finding = lab.add(Kind.FINDING, {"text": "ai finding"}, ai, evidence_label=EvidenceLabel.INFERRED)
    forge_transition(lab, raw, finding.entity_id, "ADMITTED", ai, governance={"issuer_id": "gov-1"}, from_status="PROPOSED")
    assert raw.verify().ok  # the chain alone is intact
    live = lab.verify()  # the Lab notices on its next verify
    assert not live.ok and any("seq 2: TRANSITION: actor kind AI" in p for p in live.problems)
    lab.close()
    reopen_refused(db_path, principal, "seq 2: TRANSITION: actor kind AI may not record a governance disposition")
    code = main(["verify", "--db", db_path, "--tenant", TENANT, "--principal", principal.id])
    out = capsys.readouterr().out
    assert code == 1 and "policy violation: seq 2" in out


# forged transitions, write time


def test_forged_transitions_are_refused_at_write_time(lab, chain, human, reviewer, gov, ai):
    f = chain.finding.entity_id
    q = chain.question.entity_id
    refused_at_write(lab, EVENT_TRANSITION, transition_payload(lab, f, "ACCEPTED", gov, governance={"issuer_id": "gov-1"}), "PROPOSED -> ACCEPTED")
    refused_at_write(lab, EVENT_TRANSITION, transition_payload(lab, q, "REOPENED", human, from_status="CLOSED"), "from CLOSED but the entity is OPEN")
    refused_at_write(lab, EVENT_TRANSITION, transition_payload(lab, f, "REVIEWED", ai), "authored this finding and may not review it")
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(f, stage, reviewer, "r")
    refused_at_write(lab, EVENT_TRANSITION, transition_payload(lab, f, "ACCEPTED", gov, governance={"issuer_id": "mallory"}), "not in the genesis governance issuer set")
    refused_at_write(lab, EVENT_TRANSITION, transition_payload(lab, f, "ACCEPTED", Actor("gov-1", ActorKind.AI), governance={"issuer_id": "gov-1"}), "actor kind AI")
    refused_at_write(lab, EVENT_TRANSITION, transition_payload(lab, f, "ACCEPTED", reviewer), "ACCEPTED is governance-only")
    assert lab.graph.node(f).status == "RECOMMENDED"
    lab.govern(f, "ACCEPTED", gov, "gov-1", "legitimate")  # the legitimate path still works
    assert lab.graph.node(f).status == "ACCEPTED"


# forged transitions, replay backstop


def test_forged_illegal_from_and_to_are_refused(db_path, principal, lab, raw, chain, gov):
    forge_transition(lab, raw, chain.finding.entity_id, "ACCEPTED", gov, governance={"issuer_id": "gov-1"})  # skips review
    lab.close()
    reopen_refused(db_path, principal, "PROPOSED -> ACCEPTED is not an allowed transition")


def test_forged_from_that_does_not_match_current_status_is_refused(db_path, principal, lab, raw, chain, human):
    forge_transition(lab, raw, chain.question.entity_id, "REOPENED", human, from_status="CLOSED")  # entity is OPEN
    lab.close()
    reopen_refused(db_path, principal, "from CLOSED but the entity is OPEN")


def test_forged_record_disposition_that_differs_from_to_is_refused(db_path, principal, lab, raw, chain, human):
    q = chain.question.entity_id
    node = lab.graph.node(q)
    record = node.latest.next_version(origin=human, created_at=AT, disposition="CLOSED", provenance=({"type": "transition", "reason": "x"},))
    raw.append(
        EVENT_TRANSITION,
        {"record": record.to_dict(), "from": "OPEN", "to": "DEFERRED", "actor": human.to_dict(), "reason": "x", "governance": None},
    )
    lab.close()
    reopen_refused(db_path, principal, "record disposition CLOSED is not the event's to DEFERRED")


def test_forged_governance_issuer_not_in_genesis_is_refused(db_path, principal, lab, raw, chain, reviewer, gov):
    f = chain.finding.entity_id
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(f, stage, reviewer, "r")
    forge_transition(lab, raw, f, "ACCEPTED", gov, governance={"issuer_id": "mallory"})
    lab.close()
    reopen_refused(db_path, principal, "issuer 'mallory' is not in the genesis governance issuer set")


def test_forged_governance_by_ai_kind_after_full_review_is_refused(db_path, principal, lab, raw, chain, reviewer):
    f = chain.finding.entity_id
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(f, stage, reviewer, "r")
    forge_transition(lab, raw, f, "ACCEPTED", Actor("gov-1", ActorKind.AI), governance={"issuer_id": "gov-1"})
    lab.close()
    reopen_refused(db_path, principal, "actor kind AI may not record a governance disposition")


def test_forged_self_acceptance_at_replay_is_refused(db_path, principal, lab, raw, chain, reviewer, gov):
    own = lab.add(Kind.FINDING, {"text": "by gov"}, gov, edges=[(EdgeType.DERIVES_FROM, chain.experiment.entity_id)], evidence_label=EvidenceLabel.EXECUTED)
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(own.entity_id, stage, reviewer, "r")
    forge_transition(lab, raw, own.entity_id, "ACCEPTED", gov, governance={"issuer_id": "gov-1"})
    lab.close()
    reopen_refused(db_path, principal, "authored this finding and may not accept it")


def test_forged_lab_transition_to_governance_stage_is_refused(db_path, principal, lab, raw, chain, reviewer):
    f = chain.finding.entity_id
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(f, stage, reviewer, "r")
    forge_transition(lab, raw, f, "ACCEPTED", reviewer, governance=None)  # no governance block at all
    lab.close()
    reopen_refused(db_path, principal, "ACCEPTED is governance-only")


def test_forged_self_review_at_replay_is_refused(db_path, principal, lab, raw, chain, ai):
    forge_transition(lab, raw, chain.finding.entity_id, "REVIEWED", ai)
    lab.close()
    reopen_refused(db_path, principal, "authored this finding and may not review it")


def test_governance_provenance_must_name_the_issuer(db_path, principal, lab, raw, chain, reviewer, gov):
    f = chain.finding.entity_id
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(f, stage, reviewer, "r")
    forge_transition(lab, raw, f, "ACCEPTED", gov, governance={"issuer_id": "gov-1"}, provenance=({"type": "transition", "reason": "x"},))
    lab.close()
    reopen_refused(db_path, principal, "governance provenance does not name the issuer")


# genesis


def test_second_genesis_inserted_with_a_valid_hash_is_refused(db_path, principal, lab, chain):
    head = lab.store.head()
    lab.close()
    payload = {"schema_version": 1, "tenant": TENANT, "governance_issuers": ["mallory"], "principals": ["alice", "mallory"]}
    seq = head.seq + 1
    digest = event_hash(seq, TENANT, GENESIS, payload, head.hash)
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.execute(
        "INSERT INTO events (seq, tenant, event_type, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
        (seq, TENANT, GENESIS, canonical_json(payload), head.hash, digest),
    )
    conn.close()
    # Two layers refuse it. The chain verifier sees a GENESIS after seq 0, so Lab.open fails
    # with IntegrityError before replay; the replay layer refuses it on its own as well.
    with pytest.raises(IntegrityError, match="seq 7: second genesis"):
        Lab.open(db_path, TENANT, principal, StepClock())
    bare = EventStore.open(db_path, TENANT, principal)
    with pytest.raises(PolicyViolation, match="seq 7: GENESIS: second genesis"):
        Graph.rebuild(bare.events())
    assert bare.governance_issuers == frozenset(ISSUERS)  # the store reads issuers from seq 0 only
    bare.close()


# records and edges


def test_bad_records_are_refused_at_write_time(lab, human, ai):
    tampered = Record.create(Kind.OBJECTIVE, TENANT, {"title": "honest"}, human, AT, "OPEN").to_dict()
    tampered["body"]["title"] = "edited after signing"
    refused_at_write(lab, EVENT_RECORD, {"record": tampered, "edges": []}, "digest does not match content")
    born_accepted = Record.create(Kind.FINDING, TENANT, {"text": "x"}, ai, AT, "ACCEPTED", evidence_label=EvidenceLabel.INFERRED)
    refused_at_write(lab, EVENT_RECORD, {"record": born_accepted.to_dict(), "edges": []}, "must start PROPOSED, not ACCEPTED")
    foreign = Record.create(Kind.OBJECTIVE, "other", {"title": "x"}, human, AT, "OPEN")
    refused_at_write(lab, EVENT_RECORD, {"record": foreign.to_dict(), "edges": []}, "record tenant 'other'")
    dangling = Record.create(Kind.QUESTION, TENANT, {"text": "q"}, human, AT, "OPEN")
    refused_at_write(lab, EVENT_RECORD, {"record": dangling.to_dict(), "edges": [{"edge": "DECOMPOSES", "to": "objective_ghost"}]}, "unknown entity 'objective_ghost'")


def test_record_with_mismatched_digest_is_refused_on_reopen(db_path, principal, lab, raw, human):
    data = Record.create(Kind.OBJECTIVE, TENANT, {"title": "honest"}, human, AT, "OPEN").to_dict()
    data["body"]["title"] = "edited after signing"
    raw.append(EVENT_RECORD, {"record": data, "edges": []})
    lab.close()
    reopen_refused(db_path, principal, "digest does not match content")


def test_record_that_skips_the_initial_status_is_refused_on_reopen(db_path, principal, lab, raw, ai):
    record = Record.create(Kind.FINDING, TENANT, {"text": "born accepted"}, ai, AT, "ACCEPTED", evidence_label=EvidenceLabel.INFERRED)
    raw.append(EVENT_RECORD, {"record": record.to_dict(), "edges": []})
    lab.close()
    reopen_refused(db_path, principal, "a new finding must start PROPOSED, not ACCEPTED")


def test_record_with_wrong_tenant_is_refused_on_reopen(db_path, principal, lab, raw, human):
    foreign = Record.create(Kind.OBJECTIVE, "other", {"title": "x"}, human, AT, "OPEN")
    raw.append(EVENT_RECORD, {"record": foreign.to_dict(), "edges": []})
    lab.close()
    reopen_refused(db_path, principal, "record tenant 'other'")


def test_bad_edges_are_refused_at_write_time(lab, chain, human):
    refused_at_write(
        lab, EVENT_EDGE,
        {"from": chain.hypothesis.entity_id, "edge": "SUPPORTS", "to": chain.hypothesis.entity_id, "actor": human.to_dict(), "created_at": AT},
        "cannot point at itself",
    )
    refused_at_write(
        lab, EVENT_EDGE,
        {"from": chain.objective.entity_id, "edge": "DECOMPOSES", "to": chain.question.entity_id, "actor": human.to_dict(), "created_at": AT},
        "objective DECOMPOSES question is not an allowed edge",
    )


def test_edge_violating_the_edge_table_is_refused_on_reopen(db_path, principal, lab, raw, chain, human):
    raw.append(
        EVENT_EDGE,
        {"from": chain.objective.entity_id, "edge": "DECOMPOSES", "to": chain.question.entity_id, "actor": human.to_dict(), "created_at": AT},
    )
    lab.close()
    reopen_refused(db_path, principal, "objective DECOMPOSES question is not an allowed edge")


def test_record_edges_to_unknown_entity_are_refused_on_reopen(db_path, principal, lab, raw, human):
    record = Record.create(Kind.QUESTION, TENANT, {"text": "q"}, human, AT, "OPEN")
    raw.append(EVENT_RECORD, {"record": record.to_dict(), "edges": [{"edge": "DECOMPOSES", "to": "objective_ghost"}]})
    lab.close()
    reopen_refused(db_path, principal, "unknown entity 'objective_ghost'")


# runs


def run_payload(plan_id, task_id, step, attempt, actor, **extra):
    return {"plan": plan_id, "task": task_id, "step": step, "idempotency_key": f"{plan_id}:{step}", "attempt": attempt, "actor": actor.to_dict(), "created_at": AT, **extra}


def test_bad_run_events_are_refused_at_write_time(lab, human):
    plan, tasks = create_plan(lab, human, "P", ["a"])
    refused_at_write(lab, RUN_STARTED, run_payload(plan.entity_id, "task_ghost", "a", 1, human), "unknown entity 'task_ghost'")
    refused_at_write(lab, RUN_COMPLETED, run_payload(plan.entity_id, tasks[0].entity_id, "a", 1, human, output=1), "that is PENDING, not STARTED")
    runner = Runner(lab, plan.entity_id, human)
    runner.register("a", lambda ctx: 1)
    runner.run()
    refused_at_write(lab, RUN_STARTED, run_payload(plan.entity_id, tasks[0].entity_id, "a", 2, human), "never re-run")


def test_run_events_must_reference_an_existing_plan_task(db_path, principal, lab, raw, human):
    plan, tasks = create_plan(lab, human, "P", ["a"])
    raw.append(RUN_STARTED, run_payload(plan.entity_id, "task_ghost", "a", 1, human))
    lab.close()
    reopen_refused(db_path, principal, "unknown entity 'task_ghost'")


def test_completed_step_cannot_be_restarted_on_replay(db_path, principal, lab, raw, human):
    plan, tasks = create_plan(lab, human, "P", ["a"])
    runner = Runner(lab, plan.entity_id, human)
    runner.register("a", lambda ctx: 1)
    runner.run()
    raw.append(RUN_STARTED, run_payload(plan.entity_id, tasks[0].entity_id, "a", 2, human))
    lab.close()
    reopen_refused(db_path, principal, "completed or running steps are never re-run")


def test_completed_without_started_is_refused(db_path, principal, lab, raw, human):
    plan, tasks = create_plan(lab, human, "P", ["a"])
    raw.append(RUN_COMPLETED, run_payload(plan.entity_id, tasks[0].entity_id, "a", 1, human, output=1))
    lab.close()
    reopen_refused(db_path, principal, "RUN_COMPLETED for task .* that is PENDING, not STARTED")


def test_forged_plan_close_with_unfinished_tasks_is_refused(db_path, principal, lab, raw, human):
    plan, tasks = create_plan(lab, human, "P", ["a"])
    refused_at_write(lab, EVENT_TRANSITION, transition_payload(lab, plan.entity_id, "CLOSED", human), "cannot be closed: a=PENDING/NONE")
    forge_transition(lab, raw, plan.entity_id, "CLOSED", human)
    lab.close()
    reopen_refused(db_path, principal, "cannot be closed: a=PENDING/NONE")


# other


def test_unknown_event_type_is_refused_at_both_layers(db_path, principal, lab, raw):
    refused_at_write(lab, "NOTE", {"anything": 1}, "unknown event type 'NOTE'")
    raw.append("NOTE", {"anything": 1})
    lab.close()
    reopen_refused(db_path, principal, "unknown event type 'NOTE'")


def test_lab_emit_writes_nothing_on_refusal_and_graph_stays_in_sync(lab):
    count = lab.store.count()
    with pytest.raises(PolicyViolation, match="unknown event type"):
        lab._emit("NOTE", {"anything": 1})
    assert lab.store.count() == count
    assert Graph.rebuild(lab.store.events()) == lab.graph


def test_verify_bundle_detects_a_policy_violation_from_the_file_alone(db_path, principal, lab, raw, chain, ai, tmp_path):
    good = str(tmp_path / "good.jsonl")
    export_bundle(lab.store, good)
    assert verify_bundle(good).policy_checked
    forge_transition(lab, raw, chain.finding.entity_id, "ADMITTED", ai, governance={"issuer_id": "gov-1"})
    bad = str(tmp_path / "bad.jsonl")
    with pytest.raises(Exception, match="refusing to export"):
        export_bundle(raw, bad)
    # Write the forged log as a bundle by hand, the way an attacker would.
    events = raw.events()
    header = {"bundle_schema": "research_lab.bundle/1", "store_schema_version": 1, "tenant": TENANT, "event_count": len(events), "head_hash": events[-1].hash, "governance_issuers": ISSUERS}
    with open(bad, "w", encoding="ascii") as handle:
        handle.write("\n".join([canonical_json(header)] + [canonical_json(e.to_dict()) for e in events]) + "\n")
    result = verify_bundle(bad)
    assert not result.ok and not result.policy_checked
    assert any("policy violation: seq" in p and "actor kind AI" in p for p in result.problems)


def test_legitimate_full_lifecycle_replays_and_verifies(db_path, principal, human, ai, reviewer, gov):
    lab = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), governance_mode=LEGACY_MODE)
    chain = Chain(lab, human, ai)
    lab.transition(chain.hypothesis.entity_id, "REJECTED", human, "weak")
    lab.transition(chain.hypothesis.entity_id, "REOPENED", human, "new data")
    lab.supersede(chain.question.entity_id, {"text": "Q2"}, human, "sharper", edges=[(EdgeType.DECOMPOSES, chain.objective.entity_id)])
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(chain.finding.entity_id, stage, reviewer, "r")
    lab.govern(chain.finding.entity_id, "ACCEPTED", gov, "gov-1", "accepted")
    lab.govern(chain.finding.entity_id, "ADMITTED", Actor("sys-1", ActorKind.SYSTEM), "gov-1", "admitted")
    lab.add(Kind.CAPABILITY_PROPOSAL, {"text": "C"}, human, edges=[(EdgeType.DERIVES_FROM, chain.finding.entity_id)])
    plan, tasks = create_plan(lab, human, "P", ["a", "b"], pursues=chain.objective.entity_id)
    runner = Runner(lab, plan.entity_id, human)
    runner.register("a", lambda ctx: 1 / 0)
    with pytest.raises(Exception):
        runner.run()
    runner.register("a", lambda ctx: {"ok": True})
    runner.register("b", lambda ctx: ctx.checkpoint("half") or {"ok": True})
    runner.run()
    runner.complete("done")
    result = lab.verify()
    assert result.ok and result.policy_checked
    events = lab.store.count()
    lab.close()
    reopened = Lab.open(db_path, TENANT, principal, StepClock())
    assert reopened.store.count() == events
    assert reopened.graph.node(chain.finding.entity_id).status == "ADMITTED"
    assert reopened.graph.node(plan.entity_id).status == "CLOSED"
    assert Graph.rebuild(reopened.store.events()) == reopened.graph
    assert reopened.verify().ok
    reopened.close()
