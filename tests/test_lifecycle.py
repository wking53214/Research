import pytest
from conftest import ISSUERS, TENANT, tamper

from research_lab.clock import StepClock
from research_lab.graph import EdgeType, Graph
from research_lab.lab import Lab
from research_lab.lifecycle import (
    GOVERNANCE_ONLY_STAGES,
    LAB_SETTABLE_STAGES,
    AuthorityError,
    FindingStage,
    LifecycleError,
    SelfReviewError,
    ThreadStatus,
    TransitionError,
    allowed_targets,
    initial_status,
)
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind
from research_lab.store import AppendRefused, EventStore, IntegrityError


def test_vocabularies_are_split_as_specified():
    assert {s.value for s in ThreadStatus} == {"OPEN", "DEFERRED", "CLOSED", "SUPERSEDED", "REJECTED", "REOPENED"}
    assert {s.value for s in LAB_SETTABLE_STAGES} == {"PROPOSED", "REVIEWED", "REPRODUCED", "RECOMMENDED", "WITHDRAWN"}
    assert {s.value for s in GOVERNANCE_ONLY_STAGES} == {"ACCEPTED", "ADMITTED"}
    assert initial_status(Kind.FINDING) == "PROPOSED"
    assert initial_status(Kind.HYPOTHESIS) == "OPEN"
    assert allowed_targets(Kind.FINDING, "RECOMMENDED") == {"ACCEPTED", "REPRODUCED", "WITHDRAWN"}
    assert allowed_targets(Kind.QUESTION, "SUPERSEDED") == frozenset()


def test_initial_status_is_fixed_regardless_of_author(lab, chain, human, ai):
    assert chain.finding.disposition == "PROPOSED"
    assert chain.finding.origin.kind is ActorKind.AI
    assert chain.hypothesis.disposition == "OPEN"
    human_finding = lab.add(Kind.FINDING, {"text": "F"}, human, edges=[(EdgeType.DERIVES_FROM, chain.experiment.entity_id)], evidence_label=EvidenceLabel.EXECUTED)
    assert human_finding.disposition == "PROPOSED"


def test_thread_transitions_positive(lab, chain, human):
    q = chain.question.entity_id
    lab.transition(q, "DEFERRED", human, "later")
    lab.transition(q, "REOPENED", human, "now")
    lab.transition(q, "CLOSED", human, "done")
    lab.transition(q, "REOPENED", human, "again")
    lab.transition(q, "REJECTED", human, "wrong question")
    lab.transition(q, "SUPERSEDED", human, "replaced")
    assert [r.disposition for r in lab.graph.history(q)] == ["OPEN", "DEFERRED", "REOPENED", "CLOSED", "REOPENED", "REJECTED", "SUPERSEDED"]
    assert [r.version for r in lab.graph.history(q)] == list(range(1, 8))


def test_thread_transitions_negative(lab, chain, human):
    q = chain.question.entity_id
    with pytest.raises(TransitionError, match="OPEN -> REOPENED"):
        lab.transition(q, "REOPENED", human, "cannot reopen an open thread")
    with pytest.raises(TransitionError, match="not a thread status"):
        lab.transition(q, "REVIEWED", human, "finding vocabulary on a thread")
    with pytest.raises(TransitionError, match="not a thread status"):
        lab.transition(q, "ACCEPTED", human, "governance vocabulary on a thread")
    lab.transition(q, "SUPERSEDED", human, "end")
    with pytest.raises(TransitionError):
        lab.transition(q, "REOPENED", human, "terminal")
    with pytest.raises(LifecycleError, match="reason"):
        lab.transition(chain.objective.entity_id, "CLOSED", human, "")


def test_finding_review_chain_and_governance(lab, chain, reviewer, gov):
    f = chain.finding.entity_id
    lab.transition(f, "REVIEWED", reviewer, "read it")
    lab.transition(f, "REPRODUCED", reviewer, "ran it")
    lab.transition(f, "RECOMMENDED", reviewer, "recommend")
    accepted = lab.govern(f, "ACCEPTED", gov, "gov-1", "board accepts")
    assert accepted.disposition == "ACCEPTED"
    assert accepted.provenance[0]["type"] == "governance_disposition"
    assert accepted.provenance[0]["issuer_id"] == "gov-1"
    admitted = lab.govern(f, FindingStage.ADMITTED, gov, "gov-1", "admitted to catalogue")
    assert admitted.version == 6
    assert [r.disposition for r in lab.graph.history(f)] == ["PROPOSED", "REVIEWED", "REPRODUCED", "RECOMMENDED", "ACCEPTED", "ADMITTED"]
    assert lab.verify().ok


def test_ai_cannot_review_its_own_record(lab, chain, ai):
    with pytest.raises(SelfReviewError, match="authored"):
        lab.transition(chain.finding.entity_id, "REVIEWED", ai, "I checked my own work")
    assert lab.graph.node(chain.finding.entity_id).status == "PROPOSED"


def test_human_cannot_review_own_finding_either(lab, chain, human):
    own = lab.add(Kind.FINDING, {"text": "mine"}, human, edges=[(EdgeType.DERIVES_FROM, chain.experiment.entity_id)], evidence_label=EvidenceLabel.EXECUTED)
    with pytest.raises(SelfReviewError):
        lab.transition(own.entity_id, "REVIEWED", human, "self")


def test_author_may_withdraw_own_finding_but_withdrawn_is_terminal(lab, chain, ai):
    # Changed under the owner's ruling W3: WITHDRAWN -> PROPOSED in place no longer exists.
    # A retry is a new finding that supersedes the withdrawn one (tests/test_withdrawal.py).
    lab.transition(chain.finding.entity_id, "WITHDRAWN", ai, "retracted")
    with pytest.raises(TransitionError, match="WITHDRAWN -> PROPOSED is not an allowed transition"):
        lab.transition(chain.finding.entity_id, "PROPOSED", ai, "resubmitted")
    assert [r.disposition for r in lab.graph.history(chain.finding.entity_id)] == ["PROPOSED", "WITHDRAWN"]
    assert allowed_targets(Kind.FINDING, "WITHDRAWN") == frozenset()


def test_increment1_limitation_a_different_ai_may_review(lab, chain):
    # Documented limitation: review independence descriptors arrive in increment 3. Today only
    # the same-actor rule and the governance rules hold; a second AI id may move review stages.
    other_ai = Actor("model-2", ActorKind.AI)
    lab.transition(chain.finding.entity_id, "REVIEWED", other_ai, "cross review")
    assert lab.graph.node(chain.finding.entity_id).status == "REVIEWED"


@pytest.mark.parametrize("stage", ["ACCEPTED", "ADMITTED"])
def test_lab_transition_can_never_set_governance_stages(lab, chain, human, ai, reviewer, stage):
    f = chain.finding.entity_id
    lab.transition(f, "REVIEWED", reviewer, "r")
    lab.transition(f, "REPRODUCED", reviewer, "r")
    lab.transition(f, "RECOMMENDED", reviewer, "r")
    for actor in (ai, human, reviewer, Actor("gov-1", ActorKind.HUMAN)):
        with pytest.raises(AuthorityError, match="governance-only"):
            lab.transition(f, stage, actor, "trying")
    assert lab.graph.node(f).status == "RECOMMENDED"


def test_ai_cannot_record_governance_disposition_even_with_valid_issuer(lab, chain, reviewer):
    f = chain.finding.entity_id
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(f, stage, reviewer, "r")
    ai_issuer = Actor("gov-1", ActorKind.AI)
    with pytest.raises(AuthorityError, match="actor kind AI"):
        lab.govern(f, "ACCEPTED", ai_issuer, "gov-1", "ai says yes")
    external = Actor("gov-1", ActorKind.EXTERNAL)
    with pytest.raises(AuthorityError, match="actor kind EXTERNAL"):
        lab.govern(f, "ACCEPTED", external, "gov-1", "external says yes")
    assert lab.graph.node(f).status == "RECOMMENDED"


def test_governance_requires_genesis_issuer(lab, chain, reviewer, gov):
    f = chain.finding.entity_id
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(f, stage, reviewer, "r")
    with pytest.raises(AuthorityError, match="not in the genesis governance issuer set"):
        lab.govern(f, "ACCEPTED", gov, "mallory", "fake issuer")
    with pytest.raises(AuthorityError, match="not in the genesis governance issuer set"):
        lab.govern(f, "ACCEPTED", Actor("someone", ActorKind.SYSTEM), "someone", "self-declared issuer")
    assert lab.graph.node(f).status == "RECOMMENDED"


def test_governance_refuses_self_approval_wrong_kind_wrong_stage_and_table(lab, chain, reviewer, gov):
    own = lab.add(Kind.FINDING, {"text": "by gov"}, gov, edges=[(EdgeType.DERIVES_FROM, chain.experiment.entity_id)], evidence_label=EvidenceLabel.EXECUTED)
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(own.entity_id, stage, reviewer, "r")
    with pytest.raises(SelfReviewError):
        lab.govern(own.entity_id, "ACCEPTED", gov, "gov-1", "accepting my own finding")
    with pytest.raises(AuthorityError, match="apply to findings"):
        lab.govern(chain.hypothesis.entity_id, "ACCEPTED", gov, "gov-1", "hypothesis")
    # Message changed under ruling W1 (governance_required is now a transition, not a stage).
    with pytest.raises(AuthorityError, match="not a governance transition"):
        lab.govern(chain.finding.entity_id, "REVIEWED", gov, "gov-1", "review via governance")
    with pytest.raises(TransitionError, match="PROPOSED -> ACCEPTED"):
        lab.govern(chain.finding.entity_id, "ACCEPTED", gov, "gov-1", "skipping review")
    with pytest.raises(TransitionError, match="PROPOSED -> ADMITTED"):
        lab.govern(chain.finding.entity_id, "ADMITTED", gov, "gov-1", "skipping everything")


def test_ai_hypothesis_is_a_proposal_never_a_finding(lab, chain, ai):
    node = lab.graph.node(chain.hypothesis.entity_id)
    assert node.kind is Kind.HYPOTHESIS and node.author.kind is ActorKind.AI
    for stage in ("PROPOSED", "REVIEWED", "ACCEPTED"):
        with pytest.raises(TransitionError):
            lab.transition(chain.hypothesis.entity_id, stage, ai, "promote")
    assert lab.graph.node(chain.hypothesis.entity_id).kind is Kind.HYPOTHESIS


def test_rejected_hypothesis_later_supported_keeps_rejection_history(lab, chain, human):
    h = chain.hypothesis.entity_id
    against = lab.add(Kind.EVIDENCE, {"text": "fails"}, human, edges=[(EdgeType.CONTRADICTS, h)], evidence_label=EvidenceLabel.EXECUTED)
    lab.transition(h, "REJECTED", human, "contradicted by experiment")
    assert lab.graph.node(h).status == "REJECTED"
    support = lab.add(Kind.EVIDENCE, {"text": "new run supports"}, human, edges=[(EdgeType.SUPPORTS, h)], evidence_label=EvidenceLabel.EXECUTED)
    lab.transition(h, "REOPENED", human, "new supporting evidence")
    history = lab.graph.history(h)
    assert [r.disposition for r in history] == ["OPEN", "REJECTED", "REOPENED"]
    assert history[1].provenance == ({"type": "transition", "reason": "contradicted by experiment"},)
    assert all(r.verify_digest() for r in history)
    supporters = {n.entity_id for n in lab.graph.children(h, EdgeType.SUPPORTS)}
    assert supporters == {chain.evidence.entity_id, support.entity_id}
    assert [n.entity_id for n in lab.graph.contradictions_of(h)["contradicting_evidence"]] == [against.entity_id]
    assert Graph.rebuild(lab.store.events()) == lab.graph


def test_governance_issuers_cannot_change_after_genesis(db_path, principal, lab, chain, reviewer):
    with pytest.raises(AppendRefused, match="fixed at genesis"):
        lab.store.append("GENESIS", {"tenant": TENANT, "schema_version": 1, "governance_issuers": ["mallory"], "principals": ["alice"]})
    namespaces = dir(Lab) + dir(EventStore) + dir(Graph) + dir(lab) + dir(lab.store) + dir(lab.graph)
    exposed = sorted({name for name in namespaces if "issuer" in name.lower()})
    assert exposed == ["governance_issuers"]  # a read-only property on the store, a plain attribute on the graph
    assert isinstance(EventStore.__dict__["governance_issuers"], property)
    assert EventStore.__dict__["governance_issuers"].fset is None
    # In-process mutation of the live graph's attribute does not persist: a reopen reads genesis.
    lab.graph.governance_issuers = frozenset({"mallory"})
    lab.close()
    reopened = Lab.open(db_path, TENANT, principal, StepClock())
    assert reopened.graph.governance_issuers == frozenset(ISSUERS)
    reopened.close()


def test_tampered_genesis_issuers_are_refused_at_open(db_path, lab, chain, principal, reviewer):
    f = chain.finding.entity_id
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(f, stage, reviewer, "r")
    lab.close()
    raw = tamper(db_path)
    raw.execute(
        "UPDATE events SET payload = ? WHERE seq = 0",
        ('{"governance_issuers":["mallory"],"principals":["alice"],"schema_version":1,"tenant":"acme"}',),
    )
    raw.close()
    with pytest.raises(IntegrityError, match="seq 0: hash mismatch"):
        Lab.open(db_path, TENANT, principal, StepClock())
    unverified = Lab.open(db_path, TENANT, principal, StepClock(), verify=False)
    assert not unverified.verify().ok
    unverified.close()
