"""Challenge records (owner option A): the lab can flag that an accepted or admitted finding
looks wrong without changing it or acting as authority. A challenge is advice; only a
governance disposition resolves it, and upholding it does not withdraw the finding.
"""

import json

import pytest
from conftest import ISSUERS, LEGACY_MODE, TENANT, Chain

from research_lab.cli import main
from research_lab.clock import StepClock
from research_lab.graph import EVENT_EDGE, EVENT_RECORD, EVENT_TRANSITION, EdgeType, Graph, PolicyViolation, edge_allowed
from research_lab.lab import Lab
from research_lab.lifecycle import (
    AuthorityError,
    ChallengeStatus,
    SelfReviewError,
    TransitionError,
    allowed_targets,
    governance_required,
    initial_status,
)
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind, Record
from research_lab.store import EventStore

AT = "2026-11-05T00:00:00Z"
SYSTEM = Actor("sys-1", ActorKind.SYSTEM)
EVIDENCE = [{"type": "evidence_ref", "ref": "run-42 disagrees"}]


def accepted(lab, chain, reviewer, gov, admit=False):
    f = chain.finding.entity_id
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(f, stage, reviewer, "r")
    lab.govern(f, "ACCEPTED", gov, "gov-1", "accepted")
    if admit:
        lab.govern(f, "ADMITTED", gov, "gov-1", "admitted")
    return f


def snapshot(lab, entity_id):
    node = lab.graph.node(entity_id)
    return node.status, node.latest.version, node.latest.digest


# vocabulary


def test_challenge_vocabulary_is_small_and_terminal():
    assert {s.value for s in ChallengeStatus} == {"OPEN", "UPHELD", "DISMISSED", "WITHDRAWN"}
    assert initial_status(Kind.CHALLENGE) == "OPEN"
    assert allowed_targets(Kind.CHALLENGE, "OPEN") == {"UPHELD", "DISMISSED", "WITHDRAWN"}
    for terminal in ("UPHELD", "DISMISSED", "WITHDRAWN"):
        assert allowed_targets(Kind.CHALLENGE, terminal) == frozenset()
    assert governance_required(Kind.CHALLENGE, "OPEN", "UPHELD")
    assert governance_required(Kind.CHALLENGE, "OPEN", "DISMISSED")
    assert not governance_required(Kind.CHALLENGE, "OPEN", "WITHDRAWN")
    assert edge_allowed(Kind.CHALLENGE, EdgeType.CHALLENGES, Kind.FINDING)
    assert edge_allowed(Kind.CHALLENGE, EdgeType.CHALLENGES, Kind.HYPOTHESIS)
    assert not edge_allowed(Kind.CHALLENGE, EdgeType.CHALLENGES, Kind.CHALLENGE)
    assert not edge_allowed(Kind.EVIDENCE, EdgeType.CHALLENGES, Kind.FINDING)


# filing


@pytest.mark.parametrize("admit", [False, True])
def test_ai_files_a_challenge_and_the_finding_is_untouched(lab, chain, reviewer, gov, ai, admit):
    f = accepted(lab, chain, reviewer, gov, admit)
    before = snapshot(lab, f)
    challenge = lab.file_challenge(f, "the reproduction run disagrees", ai, EVIDENCE)
    assert challenge.kind is Kind.CHALLENGE and challenge.disposition == "OPEN"
    assert challenge.origin == ai and challenge.provenance == tuple(EVIDENCE)
    assert snapshot(lab, f) == before
    assert [c.entity_id for c in lab.graph.open_challenges(f)] == [challenge.entity_id]
    assert lab.graph.edges_from(challenge.entity_id, EdgeType.CHALLENGES)[0].to_id == f
    assert lab.verify().ok


def test_author_may_challenge_own_finding_and_hypotheses_can_be_challenged(lab, chain, ai, human):
    own = lab.file_challenge(chain.finding.entity_id, "I no longer believe my own finding", ai, EVIDENCE)
    assert own.origin == ai and lab.graph.node(chain.finding.entity_id).status == "PROPOSED"
    h = lab.file_challenge(chain.hypothesis.entity_id, "contradicted by run 7", human, EVIDENCE)
    assert lab.graph.open_challenges(chain.hypothesis.entity_id)[0].entity_id == h.entity_id
    assert lab.graph.node(chain.hypothesis.entity_id).status == "OPEN"


def test_empty_challenges_are_refused(lab, chain, human):
    f = chain.finding.entity_id
    count = lab.store.count()
    with pytest.raises(PolicyViolation, match="non-empty reason"):
        lab.file_challenge(f, "   ", human, EVIDENCE)
    with pytest.raises(PolicyViolation, match="at least one provenance reference"):
        lab.file_challenge(f, "no evidence", human, [])
    with pytest.raises(PolicyViolation, match="at least one provenance reference"):
        lab.file_challenge(f, "empty evidence item", human, [{}])
    with pytest.raises(PolicyViolation, match="non-empty reason"):
        lab.add(Kind.CHALLENGE, {"text": "reason under the wrong key"}, human, edges=[(EdgeType.CHALLENGES, f)], provenance=EVIDENCE)
    with pytest.raises(PolicyViolation, match="exactly one CHALLENGES edge"):
        lab.add(Kind.CHALLENGE, {"reason": "no target"}, human, provenance=EVIDENCE)
    assert lab.store.count() == count
    assert Graph.rebuild(lab.store.events()) == lab.graph


def test_challenge_against_wrong_target_is_refused(lab, chain, human):
    count = lab.store.count()
    for target in (chain.objective.entity_id, chain.question.entity_id, chain.evidence.entity_id, chain.experiment.entity_id):
        with pytest.raises(Exception, match="not an allowed edge"):
            lab.file_challenge(target, "wrong target", human, EVIDENCE)
    c = lab.file_challenge(chain.finding.entity_id, "first", human, EVIDENCE)
    with pytest.raises(Exception, match="not an allowed edge"):
        lab.file_challenge(c.entity_id, "a challenge of a challenge", human, EVIDENCE)
    with pytest.raises(Exception, match="unknown entity"):
        lab.file_challenge("finding_ghost", "nothing there", human, EVIDENCE)
    with pytest.raises(Exception, match="created only when the challenge is filed"):
        lab.link(c.entity_id, EdgeType.CHALLENGES, chain.hypothesis.entity_id, human)
    with pytest.raises(Exception, match="not an allowed edge"):
        lab.link(chain.evidence.entity_id, EdgeType.CHALLENGES, chain.finding.entity_id, human)
    assert lab.store.count() == count + 1


# resolution


def test_governance_resolves_upheld_and_dismissed_and_the_finding_stays_accepted(lab, chain, reviewer, gov, ai, human):
    f = accepted(lab, chain, reviewer, gov)
    first = lab.file_challenge(f, "first", ai, EVIDENCE)
    second = lab.file_challenge(f, "second", human, EVIDENCE)
    before = snapshot(lab, f)
    upheld = lab.govern(first.entity_id, "UPHELD", gov, "gov-1", "the challenge is right")
    dismissed = lab.govern(second.entity_id, ChallengeStatus.DISMISSED, SYSTEM, "gov-1", "not persuasive")
    assert upheld.disposition == "UPHELD" and upheld.provenance[0]["issuer_id"] == "gov-1"
    assert dismissed.disposition == "DISMISSED"
    assert snapshot(lab, f) == before  # upholding never withdraws the finding by itself
    assert lab.graph.node(f).status == "ACCEPTED"
    assert lab.graph.open_challenges(f) == []
    assert [c.status for c in lab.graph.challenges_of(f)] == ["UPHELD", "DISMISSED"]
    summary = lab.graph.challenge_summary(f)
    assert summary[0]["resolution"]["status"] == "UPHELD" and summary[0]["resolution"]["by"]["id"] == "gov-1"
    assert summary[1]["filer"]["id"] == "alice" and summary[1]["reason"] == "second"
    lab.govern(f, "WITHDRAWN", gov, "gov-1", "withdrawn after the upheld challenge")  # separate act
    assert lab.graph.node(f).status == "WITHDRAWN"
    assert lab.verify().ok


def test_resolution_refused_for_ai_unknown_issuer_filer_and_lab_path(lab, chain, reviewer, gov, ai, human):
    f = accepted(lab, chain, reviewer, gov)
    c = lab.file_challenge(f, "flagged", human, EVIDENCE)  # filed by a human whose id is alice
    count = lab.store.count()
    with pytest.raises(AuthorityError, match="actor kind AI"):
        lab.govern(c.entity_id, "UPHELD", Actor("gov-1", ActorKind.AI), "gov-1", "ai upholds")
    with pytest.raises(AuthorityError, match="not in the genesis governance issuer set"):
        lab.govern(c.entity_id, "UPHELD", gov, "mallory", "fake issuer")
    with pytest.raises(SelfReviewError, match="filed this challenge and may not resolve it"):
        lab.govern(c.entity_id, "DISMISSED", Actor("alice", ActorKind.SYSTEM), "gov-1", "the filer, relabelled")
    for actor in (human, reviewer, gov, ai, SYSTEM):
        with pytest.raises(AuthorityError, match="governance-only"):
            lab.transition(c.entity_id, "UPHELD", actor, "lab path")
        with pytest.raises(AuthorityError, match="governance-only"):
            lab.transition(c.entity_id, "DISMISSED", actor, "lab path")
    with pytest.raises(TransitionError):
        lab.transition(c.entity_id, "CLOSED", human, "thread vocabulary on a challenge")
    assert lab.store.count() == count and lab.graph.node(c.entity_id).status == "OPEN"
    assert Graph.rebuild(lab.store.events()) == lab.graph


def test_only_the_filer_may_withdraw_and_resolved_challenges_stay_queryable(lab, chain, reviewer, gov, ai, human):
    f = accepted(lab, chain, reviewer, gov)
    c = lab.file_challenge(f, "flagged", ai, EVIDENCE)
    with pytest.raises(AuthorityError, match="only the filer may withdraw"):
        lab.transition(c.entity_id, "WITHDRAWN", human, "someone else")
    with pytest.raises(AuthorityError, match="only the filer may withdraw"):
        lab.transition(c.entity_id, "WITHDRAWN", gov, "governance uses DISMISSED, not WITHDRAWN")
    lab.transition(c.entity_id, "WITHDRAWN", ai, "the filer retracts")
    assert lab.graph.node(c.entity_id).status == "WITHDRAWN"
    for target in ("OPEN", "UPHELD", "DISMISSED"):
        with pytest.raises(Exception):
            lab.transition(c.entity_id, target, ai, "terminal")
    with pytest.raises(TransitionError):
        lab.govern(c.entity_id, "UPHELD", gov, "gov-1", "terminal for governance too")
    assert [r.disposition for r in lab.graph.history(c.entity_id)] == ["OPEN", "WITHDRAWN"]
    assert lab.graph.challenge_summary(f)[0]["status"] == "WITHDRAWN"
    assert lab.graph.open_challenges(f) == []
    assert lab.graph.challenges_of(f)[0].entity_id == c.entity_id


def test_supersede_of_a_challenge_never_retires_it(lab, chain, human):
    c = lab.file_challenge(chain.finding.entity_id, "first", human, EVIDENCE)
    with pytest.raises(PolicyViolation, match="at least one provenance reference"):  # a replacement is a filing too
        lab.supersede(c.entity_id, {"reason": "sharper"}, human, "refile", edges=[(EdgeType.CHALLENGES, chain.finding.entity_id)])
    done = lab.supersede(
        c.entity_id, {"reason": "sharper"}, human, "refile", edges=[(EdgeType.CHALLENGES, chain.finding.entity_id)], provenance=EVIDENCE
    )
    assert not done.retired and lab.graph.node(c.entity_id).status == "OPEN"
    assert len(lab.graph.open_challenges(chain.finding.entity_id)) == 2


# governance view


def test_open_challenges_and_governance_view(lab, chain, reviewer, gov, ai, human):
    f = accepted(lab, chain, reviewer, gov)
    other = lab.add(Kind.FINDING, {"text": "other"}, human, edges=[(EdgeType.DERIVES_FROM, chain.experiment.entity_id)], evidence_label=EvidenceLabel.EXECUTED)
    assert lab.graph.findings_with_open_challenges() == []
    a = lab.file_challenge(f, "a", ai, EVIDENCE)
    b = lab.file_challenge(f, "b", human, EVIDENCE)
    h = lab.file_challenge(chain.hypothesis.entity_id, "h", human, EVIDENCE)
    assert [n.entity_id for n in lab.graph.findings_with_open_challenges()] == [f]
    assert {n.entity_id for n in lab.graph.entities_with_open_challenges()} == {f, chain.hypothesis.entity_id}
    assert [c.entity_id for c in lab.graph.open_challenges(f)] == [a.entity_id, b.entity_id]
    assert lab.graph.open_challenges(other.entity_id) == []
    lab.govern(a.entity_id, "DISMISSED", gov, "gov-1", "no")
    assert [c.entity_id for c in lab.graph.open_challenges(f)] == [b.entity_id]
    lab.transition(b.entity_id, "WITHDRAWN", human, "retract")
    lab.govern(h.entity_id, "UPHELD", gov, "gov-1", "yes")
    assert lab.graph.findings_with_open_challenges() == [] and lab.graph.entities_with_open_challenges() == []
    assert len(lab.graph.challenges_of(f)) == 2  # nothing is deleted
    assert lab.graph.node(chain.hypothesis.entity_id).status == "OPEN"  # upheld challenge did not touch it


# forged events


def resolution_payload(lab, challenge_id, to, actor, governance):
    node = lab.graph.node(challenge_id)
    provenance = (
        ({"type": "governance_disposition", "issuer_id": governance["issuer_id"], "reason": "forged"},)
        if governance
        else ({"type": "transition", "reason": "forged"},)
    )
    record = node.latest.next_version(origin=actor, created_at=AT, disposition=to, provenance=provenance)
    return {"record": record.to_dict(), "from": node.status, "to": to, "actor": actor.to_dict(), "reason": "forged", "governance": governance}


def refused_everywhere(db_path, principal, lab, event_type, payload, match):
    count = lab.store.count()
    with pytest.raises(PolicyViolation, match=match):
        lab.store.append(event_type, payload)  # the Lab's validated store
    bare = EventStore.open(db_path, TENANT, principal)  # a bare store: validator attached by default
    with pytest.raises(PolicyViolation, match=match):
        bare.append(event_type, payload)
    bare.close()
    assert lab.store.count() == count and Graph.rebuild(lab.store.events()) == lab.graph
    unsafe = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)  # corrupt on purpose
    unsafe.append(event_type, payload)
    unsafe.close()
    lab.close()
    with pytest.raises(PolicyViolation, match=match):
        Lab.open(db_path, TENANT, principal, StepClock())


@pytest.mark.parametrize(
    "actor_fn, to, governance, match",
    [
        (lambda: Actor("gov-1", ActorKind.AI), "UPHELD", {"issuer_id": "gov-1"}, "actor kind AI"),
        (lambda: Actor("alice", ActorKind.SYSTEM), "UPHELD", {"issuer_id": "gov-1"}, "filed this challenge and may not resolve it"),
        (lambda: Actor("gov-1", ActorKind.HUMAN), "DISMISSED", {"issuer_id": "mallory"}, "not in the genesis governance issuer set"),
        (lambda: Actor("bob", ActorKind.HUMAN), "UPHELD", None, "OPEN -> UPHELD is governance-only"),
        (lambda: Actor("bob", ActorKind.HUMAN), "WITHDRAWN", None, "only the filer may withdraw"),
    ],
)
def test_forged_resolutions_refused_at_write_time_and_on_replay(db_path, principal, lab, chain, reviewer, gov, human, actor_fn, to, governance, match):
    f = accepted(lab, chain, reviewer, gov)
    c = lab.file_challenge(f, "flagged", human, EVIDENCE)  # filer id alice
    refused_everywhere(db_path, principal, lab, EVENT_TRANSITION, resolution_payload(lab, c.entity_id, to, actor_fn(), governance), match)


def test_forged_challenges_edges_and_empty_filings_refused_everywhere(db_path, principal, lab, chain, human):
    f = chain.finding.entity_id
    stray = {"from": chain.evidence.entity_id, "edge": "CHALLENGES", "to": f, "actor": human.to_dict(), "created_at": AT}
    count = lab.store.count()
    for store in (lab.store, EventStore.open(db_path, TENANT, principal)):
        with pytest.raises(PolicyViolation, match="created only when the challenge is filed"):
            store.append(EVENT_EDGE, stray)
    assert lab.store.count() == count
    empty = Record.create(Kind.CHALLENGE, TENANT, {"reason": "no evidence"}, human, AT, "OPEN")
    refused_everywhere(
        db_path, principal, lab, EVENT_RECORD,
        {"record": empty.to_dict(), "edges": [{"edge": "CHALLENGES", "to": f}]},
        "at least one provenance reference",
    )


def test_full_challenge_lifecycle_replays_and_verifies(db_path, principal, human, ai, reviewer, gov):
    lab = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), governance_mode=LEGACY_MODE)
    chain = Chain(lab, human, ai)
    f = accepted(lab, chain, reviewer, gov, admit=True)
    a = lab.file_challenge(f, "a", ai, EVIDENCE)
    b = lab.file_challenge(f, "b", human, EVIDENCE)
    c = lab.file_challenge(chain.hypothesis.entity_id, "c", ai, EVIDENCE)
    lab.govern(a.entity_id, "UPHELD", gov, "gov-1", "yes")
    lab.govern(b.entity_id, "DISMISSED", SYSTEM, "gov-1", "no")
    lab.transition(c.entity_id, "WITHDRAWN", ai, "retract")
    lab.govern(f, "WITHDRAWN", gov, "gov-1", "withdrawn after the upheld challenge")
    assert lab.verify().ok and lab.verify().policy_checked
    lab.close()
    again = Lab.open(db_path, TENANT, principal, StepClock())
    assert [n.status for n in again.graph.challenges_of(f)] == ["UPHELD", "DISMISSED"]
    assert again.graph.node(f).status == "WITHDRAWN"
    assert again.graph.node(c.entity_id).status == "WITHDRAWN"
    assert again.graph.entities_with_open_challenges() == []
    assert Graph.rebuild(again.store.events()) == again.graph
    assert again.verify().ok
    again.close()


# CLI


def test_cli_add_challenge_and_show(capsys, tmp_path):
    db = str(tmp_path / "cli.sqlite")
    common = ["--db", db, "--tenant", "acme", "--principal", "alice", "--at", "2026-04-01T12:00:00Z"]
    actor = ["--actor", "alice", "--actor-kind", "HUMAN"]

    def run(*argv):
        code = main(list(argv))
        captured = capsys.readouterr()
        return code, (json.loads(captured.out) if captured.out.strip() else None), captured.err

    assert run("init", *common, "--issuer", "gov-1", "--unauthenticated-governance")[0] == 0
    objective = run("add", "objective", *common, *actor, "--title", "O")[1]["record"]["entity_id"]
    question = run("add", "question", *common, *actor, "--text", "Q", "--decomposes", objective)[1]["record"]["entity_id"]
    hypothesis = run("add", "hypothesis", *common, "--actor", "model-1", "--actor-kind", "AI", "--text", "H", "--answers", question)[1]["record"]["entity_id"]
    code, data, _ = run("add", "challenge", *common, *actor, "--text", "contradicted by run 7", "--target", hypothesis, "--evidence", "run-7", "--evidence", "run-8")
    assert code == 0 and data["record"]["kind"] == "challenge" and data["record"]["disposition"] == "OPEN"
    assert data["record"]["provenance"] == [{"type": "evidence_ref", "ref": "run-7"}, {"type": "evidence_ref", "ref": "run-8"}]
    challenge = data["record"]["entity_id"]
    code, _, err = run("add", "challenge", *common, *actor, "--text", "no evidence", "--target", hypothesis)
    assert code == 1 and "at least one --evidence" in json.loads(err)["message"]
    code, _, err = run("add", "challenge", *common, *actor, "--text", "wrong target", "--target", objective, "--evidence", "x")
    assert code == 1 and "not an allowed edge" in json.loads(err)["message"]
    code, data, _ = run("show", *common, "--entity", hypothesis)
    assert code == 0 and data["status"] == "OPEN" and data["open_challenges"] == [challenge]
    assert data["challenges"][0]["reason"] == "contradicted by run 7" and data["challenges"][0]["resolution"] is None
    code, data, _ = run("transition", *common, *actor, "--entity", challenge, "--to", "WITHDRAWN", "--reason", "retract")
    assert code == 0 and data["record"]["disposition"] == "WITHDRAWN"
    code, data, _ = run("show", *common, "--entity", hypothesis)
    assert data["open_challenges"] == [] and data["challenges"][0]["status"] == "WITHDRAWN"
    assert run("verify", *common)[0] == 0
