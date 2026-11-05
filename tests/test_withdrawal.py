"""Owner's ruling: withdrawing an accepted or admitted finding is a governance act (W1),
supersede never retires such a finding (W2), and WITHDRAWN is terminal (W3).

Enforced identically on the write path, at the store (validated append) and on replay.
"""

import pytest
from conftest import TENANT

from research_lab.clock import StepClock
from research_lab.graph import EVENT_TRANSITION, EdgeType, Graph, PolicyViolation
from research_lab.lab import Lab
from research_lab.lifecycle import AuthorityError, SelfReviewError, TransitionError, governance_required
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind
from research_lab.store import EventStore

AT = "2026-11-05T00:00:00Z"
SYSTEM = Actor("sys-1", ActorKind.SYSTEM)


def accepted_finding(lab, chain, reviewer, gov, admit=False):
    f = chain.finding.entity_id
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(f, stage, reviewer, "r")
    lab.govern(f, "ACCEPTED", gov, "gov-1", "accepted")
    if admit:
        lab.govern(f, "ADMITTED", gov, "gov-1", "admitted")
    return f


def forged_payload(lab, entity_id, actor, governance):
    node = lab.graph.node(entity_id)
    provenance = (
        ({"type": "governance_disposition", "issuer_id": governance["issuer_id"], "reason": "forged"},)
        if governance
        else ({"type": "transition", "reason": "forged"},)
    )
    record = node.latest.next_version(origin=actor, created_at=AT, disposition="WITHDRAWN", provenance=provenance)
    return {"record": record.to_dict(), "from": node.status, "to": "WITHDRAWN", "actor": actor.to_dict(), "reason": "forged", "governance": governance}


def unchanged(lab, entity_id, status, count):
    assert lab.graph.node(entity_id).status == status
    assert lab.store.count() == count
    assert Graph.rebuild(lab.store.events()) == lab.graph


def test_governance_required_table():
    assert governance_required(Kind.FINDING, "RECOMMENDED", "ACCEPTED")
    assert governance_required(Kind.FINDING, "ACCEPTED", "ADMITTED")
    assert governance_required(Kind.FINDING, "ACCEPTED", "WITHDRAWN")
    assert governance_required(Kind.FINDING, "ADMITTED", "WITHDRAWN")
    assert not governance_required(Kind.FINDING, "PROPOSED", "WITHDRAWN")
    assert not governance_required(Kind.FINDING, "RECOMMENDED", "WITHDRAWN")
    assert not governance_required(Kind.FINDING, "PROPOSED", "REVIEWED")
    assert not governance_required(Kind.HYPOTHESIS, "OPEN", "CLOSED")


# W1: lab and AI cannot withdraw ACCEPTED or ADMITTED


@pytest.mark.parametrize("admit", [False, True])
def test_lab_and_ai_cannot_withdraw_accepted_or_admitted_by_transition(lab, chain, human, reviewer, gov, ai, admit):
    f = accepted_finding(lab, chain, reviewer, gov, admit)
    status = "ADMITTED" if admit else "ACCEPTED"
    count = lab.store.count()
    for actor in (human, reviewer, ai, gov, SYSTEM):
        with pytest.raises(AuthorityError, match=f"{status} -> WITHDRAWN is governance-only"):
            lab.transition(f, "WITHDRAWN", actor, "trying the lab path")
        unchanged(lab, f, status, count)


def test_withdrawal_below_acceptance_stays_lab_settable(lab, chain, reviewer, ai):
    f = chain.finding.entity_id
    lab.transition(f, "REVIEWED", reviewer, "r")
    lab.transition(f, "WITHDRAWN", ai, "the author retracts")  # author may withdraw its own
    assert lab.graph.node(f).status == "WITHDRAWN"


# governance withdrawal


@pytest.mark.parametrize("admit", [False, True])
def test_governance_withdrawal_succeeds_for_non_author_human_or_system(lab, chain, reviewer, gov, admit):
    f = accepted_finding(lab, chain, reviewer, gov, admit)
    actor = SYSTEM if admit else gov
    record = lab.govern(f, "WITHDRAWN", actor, "gov-1", "withdrawn by the board")
    assert record.disposition == "WITHDRAWN" and record.provenance[0]["issuer_id"] == "gov-1"
    expected = ["PROPOSED", "REVIEWED", "REPRODUCED", "RECOMMENDED", "ACCEPTED"] + (["ADMITTED"] if admit else []) + ["WITHDRAWN"]
    assert [r.disposition for r in lab.graph.history(f)] == expected
    assert lab.verify().ok


def test_governance_withdrawal_refuses_ai_unknown_issuer_and_author(lab, chain, reviewer, gov):
    f = accepted_finding(lab, chain, reviewer, gov)
    count = lab.store.count()
    with pytest.raises(AuthorityError, match="actor kind AI"):
        lab.govern(f, "WITHDRAWN", Actor("gov-1", ActorKind.AI), "gov-1", "ai withdraws")
    with pytest.raises(AuthorityError, match="not in the genesis governance issuer set"):
        lab.govern(f, "WITHDRAWN", gov, "mallory", "fake issuer")
    with pytest.raises(SelfReviewError):
        lab.govern(f, "WITHDRAWN", Actor("model-1", ActorKind.SYSTEM), "gov-1", "the author, relabelled")
    with pytest.raises(AuthorityError, match="apply to findings"):
        lab.govern(chain.hypothesis.entity_id, "WITHDRAWN", gov, "gov-1", "not a finding")
    unchanged(lab, f, "ACCEPTED", count)
    second = lab.add(Kind.FINDING, {"text": "early"}, reviewer, edges=[(EdgeType.DERIVES_FROM, chain.experiment.entity_id)], evidence_label=EvidenceLabel.EXECUTED)
    with pytest.raises(AuthorityError, match="PROPOSED -> WITHDRAWN is not a governance transition"):
        lab.govern(second.entity_id, "WITHDRAWN", gov, "gov-1", "governance cannot withdraw a proposal")


# forged events, write time and replay


@pytest.mark.parametrize(
    "actor_fn, governance, match",
    [
        (lambda: Actor("bob", ActorKind.HUMAN), None, "governance-only"),
        (lambda: Actor("gov-1", ActorKind.AI), {"issuer_id": "gov-1"}, "actor kind AI"),
        (lambda: Actor("gov-1", ActorKind.HUMAN), {"issuer_id": "mallory"}, "not in the genesis governance issuer set"),
        (lambda: Actor("model-1", ActorKind.SYSTEM), {"issuer_id": "gov-1"}, "authored this finding"),
    ],
)
def test_forged_withdrawals_are_refused_at_write_time_and_on_replay(db_path, principal, lab, chain, reviewer, gov, actor_fn, governance, match):
    f = accepted_finding(lab, chain, reviewer, gov, admit=True)
    payload = forged_payload(lab, f, actor_fn(), governance)
    count = lab.store.count()
    with pytest.raises(PolicyViolation, match=match):
        lab.store.append(EVENT_TRANSITION, payload)  # the validated store
    unchanged(lab, f, "ADMITTED", count)
    bare = EventStore.open(db_path, TENANT, principal)  # a bare store has the validator too
    with pytest.raises(PolicyViolation, match=match):
        bare.append(EVENT_TRANSITION, payload)
    bare.close()
    unsafe = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)  # corrupt the log on purpose
    unsafe.append(EVENT_TRANSITION, payload)
    unsafe.close()
    lab.close()
    with pytest.raises(PolicyViolation, match=match):
        Lab.open(db_path, TENANT, principal, StepClock())


def test_legitimate_governance_withdrawal_replays(db_path, principal, lab, chain, reviewer, gov):
    f = accepted_finding(lab, chain, reviewer, gov)
    lab.govern(f, "WITHDRAWN", SYSTEM, "gov-1", "withdrawn")
    lab.close()
    reopened = Lab.open(db_path, TENANT, principal, StepClock())
    assert reopened.graph.node(f).status == "WITHDRAWN"
    assert reopened.verify().ok and reopened.verify().policy_checked
    reopened.close()


# W2: supersede never retires an accepted finding


@pytest.mark.parametrize("admit", [False, True])
def test_supersede_leaves_accepted_or_admitted_finding_as_it_is(lab, chain, reviewer, gov, human, admit):
    f = accepted_finding(lab, chain, reviewer, gov, admit)
    status = "ADMITTED" if admit else "ACCEPTED"
    count = lab.store.count()
    done = lab.supersede(f, {"text": "F2"}, human, "newer result", edges=[(EdgeType.DERIVES_FROM, chain.experiment.entity_id)])
    assert not done.retired
    assert done.old_status_before == status and done.old_status_after == status
    assert lab.graph.node(f).status == status
    assert lab.store.count() == count + 1  # the replacement only, no transition on the old one
    assert lab.graph.edges_from(done.replacement.entity_id, EdgeType.SUPERSEDES)[0].to_id == f
    assert Graph.rebuild(lab.store.events()) == lab.graph
    lab.govern(f, "WITHDRAWN", gov, "gov-1", "withdrawn after supersession")  # governance still can
    assert lab.graph.node(f).status == "WITHDRAWN"


def test_supersede_of_ai_authored_accepted_finding_by_ai_does_not_retire_it(lab, chain, reviewer, gov, ai):
    f = accepted_finding(lab, chain, reviewer, gov)
    done = lab.supersede(f, {"text": "F2 by the same AI"}, ai, "ai tries to retire", edges=[(EdgeType.DERIVES_FROM, chain.experiment.entity_id)])
    assert not done.retired and lab.graph.node(f).status == "ACCEPTED"


# W3: WITHDRAWN is terminal; retry is a new finding


def test_withdrawn_cannot_be_reproposed_in_place_but_a_superseding_finding_works(lab, chain, reviewer, ai, human):
    f = chain.finding.entity_id
    lab.transition(f, "REVIEWED", reviewer, "r")
    lab.transition(f, "WITHDRAWN", ai, "retracted")
    for target in ("PROPOSED", "REVIEWED", "REPRODUCED", "RECOMMENDED"):
        with pytest.raises(TransitionError, match=f"WITHDRAWN -> {target} is not an allowed transition"):
            lab.transition(f, target, ai, "retry in place")
    done = lab.supersede(f, {"text": "second attempt"}, ai, "retry as a new finding", edges=[(EdgeType.DERIVES_FROM, chain.experiment.entity_id)])
    assert not done.retired and done.old_status_after == "WITHDRAWN"
    retry = done.replacement
    assert retry.disposition == "PROPOSED" and retry.entity_id != f
    derived = lab.add(Kind.FINDING, {"text": "third, deriving"}, human, edges=[(EdgeType.DERIVES_FROM, f)], evidence_label=EvidenceLabel.INFERRED)
    assert lab.graph.edges_from(derived.entity_id, EdgeType.DERIVES_FROM)[0].to_id == f
    assert [r.disposition for r in lab.graph.history(f)] == ["PROPOSED", "REVIEWED", "WITHDRAWN"]
    assert [n.entity_id for n in lab.graph.children(f, EdgeType.SUPERSEDES)] == [retry.entity_id]
    assert lab.verify().ok


def test_governance_withdrawal_is_terminal_too(lab, chain, reviewer, gov):
    f = accepted_finding(lab, chain, reviewer, gov)
    lab.govern(f, "WITHDRAWN", gov, "gov-1", "withdrawn")
    with pytest.raises(TransitionError):
        lab.govern(f, "ACCEPTED", gov, "gov-1", "re-accept in place")
    with pytest.raises(TransitionError):
        lab.transition(f, "PROPOSED", reviewer, "re-propose in place")
