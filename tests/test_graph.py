import pytest
from conftest import ISSUERS, LEGACY_MODE, TENANT, Chain

from research_lab.clock import FixedClock, StepClock
from research_lab.graph import EdgeType, Graph, GraphError, edge_allowed
from research_lab.lab import Lab
from research_lab.records import EvidenceLabel, Kind
from research_lab.store import Event


def test_edge_table_positive_and_negative():
    assert edge_allowed(Kind.QUESTION, EdgeType.DECOMPOSES, Kind.OBJECTIVE)
    assert edge_allowed(Kind.HYPOTHESIS, EdgeType.ANSWERS, Kind.QUESTION)
    assert edge_allowed(Kind.EVIDENCE, EdgeType.SUPPORTS, Kind.HYPOTHESIS)
    assert edge_allowed(Kind.EVIDENCE, EdgeType.CONTRADICTS, Kind.HYPOTHESIS)
    assert edge_allowed(Kind.FINDING, EdgeType.DERIVES_FROM, Kind.EXPERIMENT)
    assert edge_allowed(Kind.CAPABILITY_PROPOSAL, EdgeType.DERIVES_FROM, Kind.FINDING)
    assert edge_allowed(Kind.FINDING, EdgeType.SUPERSEDES, Kind.FINDING)
    assert not edge_allowed(Kind.FINDING, EdgeType.SUPERSEDES, Kind.HYPOTHESIS)
    assert not edge_allowed(Kind.OBJECTIVE, EdgeType.DECOMPOSES, Kind.QUESTION)
    assert not edge_allowed(Kind.HYPOTHESIS, EdgeType.SUPPORTS, Kind.HYPOTHESIS)
    assert not edge_allowed(Kind.CAPABILITY_PROPOSAL, EdgeType.DERIVES_FROM, Kind.HYPOTHESIS)


def test_disallowed_edge_unknown_target_and_self_edge_are_refused(lab, human):
    objective = lab.add(Kind.OBJECTIVE, {"title": "O"}, human)
    with pytest.raises(GraphError, match="not an allowed edge"):
        lab.add(Kind.HYPOTHESIS, {"text": "H"}, human, edges=[(EdgeType.ANSWERS, objective.entity_id)])
    with pytest.raises(GraphError, match="unknown entity"):
        lab.add(Kind.QUESTION, {"text": "Q"}, human, edges=[(EdgeType.DECOMPOSES, "nope")])
    with pytest.raises(GraphError, match="unknown edge type"):
        lab.add(Kind.QUESTION, {"text": "Q"}, human, edges=[("LIKES", objective.entity_id)])
    question = lab.add(Kind.QUESTION, {"text": "Q"}, human, edges=[(EdgeType.DECOMPOSES, objective.entity_id)])
    with pytest.raises(GraphError, match="itself"):
        lab.link(question.entity_id, EdgeType.DECOMPOSES, question.entity_id, human)
    assert lab.verify().ok


def test_children_ancestors_and_history(lab, chain, human):
    graph = lab.graph
    assert [n.entity_id for n in graph.children(chain.objective.entity_id)] == [chain.question.entity_id]
    assert [n.entity_id for n in graph.children(chain.hypothesis.entity_id, EdgeType.SUPPORTS)] == [chain.evidence.entity_id]
    ancestors = [n.entity_id for n in graph.ancestors(chain.finding.entity_id)]
    assert ancestors[0] == chain.experiment.entity_id
    assert chain.objective.entity_id in ancestors and chain.hypothesis.entity_id in ancestors
    lab.transition(chain.question.entity_id, "DEFERRED", human, "later")
    history = graph.history(chain.question.entity_id)
    assert [r.disposition for r in history] == ["OPEN", "DEFERRED"]
    assert [r.version for r in history] == [1, 2]


def test_contradictions_of_hypothesis(lab, chain, human):
    against = lab.add(
        Kind.EVIDENCE, {"text": "no"}, human, edges=[(EdgeType.CONTRADICTS, chain.hypothesis.entity_id)], evidence_label=EvidenceLabel.EXECUTED
    )
    record = lab.add(Kind.CONTRADICTION, {"text": "conflict"}, human, edges=[(EdgeType.INVOLVES, chain.hypothesis.entity_id)])
    found = lab.graph.contradictions_of(chain.hypothesis.entity_id)
    assert [n.entity_id for n in found["contradicting_evidence"]] == [against.entity_id]
    assert [n.entity_id for n in found["contradiction_records"]] == [record.entity_id]
    with pytest.raises(GraphError, match="not a hypothesis"):
        lab.graph.contradictions_of(chain.objective.entity_id)


def test_open_threads_follow_status_and_exclude_findings(lab, chain, human):
    ids = {n.entity_id for n in lab.graph.open_threads()}
    assert chain.question.entity_id in ids and chain.finding.entity_id not in ids
    lab.transition(chain.question.entity_id, "CLOSED", human, "answered")
    assert chain.question.entity_id not in {n.entity_id for n in lab.graph.open_threads()}
    lab.transition(chain.question.entity_id, "REOPENED", human, "new doubt")
    assert chain.question.entity_id in {n.entity_id for n in lab.graph.open_threads()}


def test_traceability_reports_complete_and_partial_chains(lab, chain, human):
    partial = lab.graph.traceability(chain.objective.entity_id)
    assert partial == [
        {
            "objective": chain.objective.entity_id,
            "question": chain.question.entity_id,
            "hypothesis": chain.hypothesis.entity_id,
            "experiment": chain.experiment.entity_id,
            "finding": chain.finding.entity_id,
            "complete": False,
        }
    ]
    proposal = lab.add(Kind.CAPABILITY_PROPOSAL, {"text": "C"}, human, edges=[(EdgeType.DERIVES_FROM, chain.finding.entity_id)])
    branch = lab.add(Kind.QUESTION, {"text": "Q2"}, human, edges=[(EdgeType.DECOMPOSES, chain.objective.entity_id)])
    chains = lab.graph.traceability(chain.objective.entity_id)
    assert len(chains) == 2
    complete = [c for c in chains if c["complete"]]
    assert complete[0]["capability_proposal"] == proposal.entity_id
    assert [c for c in chains if not c["complete"]] == [{"objective": chain.objective.entity_id, "question": branch.entity_id, "complete": False}]
    with pytest.raises(GraphError, match="not an objective"):
        lab.graph.traceability(chain.question.entity_id)


def test_supersede_keeps_old_entity_queryable(lab, chain, human, ai):
    # Return type changed under the owner's ruling W2: supersede() now reports whether the old
    # entity was retired (Supersession); the behaviour for threads and pre-acceptance findings
    # is unchanged.
    done = lab.supersede(chain.hypothesis.entity_id, {"text": "H2"}, human, "refined", edges=[(EdgeType.ANSWERS, chain.question.entity_id)])
    new_h = done.replacement
    assert done.retired and done.old_status_before == "OPEN" and done.old_status_after == "SUPERSEDED"
    old = lab.graph.node(chain.hypothesis.entity_id)
    assert old.status == "SUPERSEDED"
    assert [r.disposition for r in old.versions] == ["OPEN", "SUPERSEDED"]
    assert lab.graph.edges_from(new_h.entity_id, EdgeType.SUPERSEDES)[0].to_id == chain.hypothesis.entity_id
    assert lab.graph.children(chain.hypothesis.entity_id, EdgeType.SUPPORTS)
    done_f = lab.supersede(chain.finding.entity_id, {"text": "F2"}, human, "redone", edges=[(EdgeType.DERIVES_FROM, chain.experiment.entity_id)])
    assert done_f.retired and lab.graph.node(chain.finding.entity_id).status == "WITHDRAWN"
    assert done_f.replacement.evidence_label is EvidenceLabel.INFERRED
    assert lab.verify().ok


def test_duplicate_entity_is_refused(db_path, principal, human):
    lab = Lab.create(db_path, TENANT, principal, ISSUERS, FixedClock("2026-01-01T00:00:00Z"), governance_mode=LEGACY_MODE)
    lab.add(Kind.OBJECTIVE, {"title": "same"}, human)
    with pytest.raises(GraphError, match="already exists"):
        lab.add(Kind.OBJECTIVE, {"title": "same"}, human)
    lab.close()


def test_graph_apply_refuses_out_of_order_events(lab):
    graph = Graph()
    events = lab.store.events()
    graph.apply(events[0])
    bogus = Event(5, TENANT, "NOTE", {}, events[0].hash, "x" * 64)
    with pytest.raises(GraphError, match="out of order"):
        graph.apply(bogus)


def test_rebuild_equals_live_graph_across_reopen(db_path, principal, human, ai, reviewer, gov):
    lab = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), governance_mode=LEGACY_MODE)
    chain = Chain(lab, human, ai)
    lab.transition(chain.hypothesis.entity_id, "REJECTED", human, "weak")
    lab.transition(chain.hypothesis.entity_id, "REOPENED", human, "new data")
    lab.transition(chain.finding.entity_id, "REVIEWED", reviewer, "looked")
    lab.transition(chain.finding.entity_id, "REPRODUCED", reviewer, "ran it")
    lab.transition(chain.finding.entity_id, "RECOMMENDED", reviewer, "good")
    lab.govern(chain.finding.entity_id, "ACCEPTED", gov, "gov-1", "board accepts")
    lab.link(chain.evidence.entity_id, EdgeType.CONTRADICTS, chain.hypothesis.entity_id, human)
    live = lab.graph
    rebuilt = Graph.rebuild(lab.store.events())
    assert rebuilt == live
    assert rebuilt.to_dict() == live.to_dict()
    lab.close()
    reopened = Lab.open(db_path, TENANT, principal, StepClock())
    assert reopened.graph == live
    assert reopened.graph.governance_issuers == frozenset(ISSUERS)
    reopened.close()
