"""run_investigation: provenance, fabricated citations, independence, failure isolation,
interruption and resume, idempotent provider calls. Offline and deterministic. Every replay
recording built here is synthetic test data."""

import pytest
from conftest import ISSUERS, LEGACY_MODE, TENANT

from research_lab import investigation as investigation_module
from research_lab.ai import (
    STACK_PROFILE,
    STANDALONE_DEV_PROFILE,
    Cite,
    ExtractiveBaselinePort,
    HypothesisProposal,
    Proposals,
    ProviderRefused,
    ReplayAIPort,
    render_proposals,
    write_recording,
)
from research_lab.clock import StepClock
from research_lab.export import export_bundle, verify_bundle
from research_lab.graph import EdgeType, Graph, TaskState
from research_lab.investigation import NOT_INDEPENDENT, InvestigationError, build_request, run_investigation
from research_lab.lab import Lab
from research_lab.lifecycle import IncompleteInvestigation, SelfReviewError, TransitionError
from research_lab.orchestration import Runner
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind
from research_lab.sources import LocalFileSource

RUNNER = Actor("investigation-runner", ActorKind.SYSTEM)
SYSTEM = Actor("local-filesystem", ActorKind.SYSTEM)
TEXT_A = "The Watcher narrates the run record for a person. Every sentence cites a measurement or is dropped. The Watcher never grades a change.\n"
TEXT_B = "The circuit has five members. Warden runs the circuit and issues grants. The Watcher is not a seat of the circuit.\n"
SETTINGS = {"topic_terms": ["watcher", "narrates", "circuit"]}
QUOTE_A = "The Watcher narrates the run record for a person."
QUOTE_B = "The Watcher is not a seat of the circuit."


class Crash(BaseException):
    """A killed process, not an Exception."""


class CrashOnce:
    """Wraps a port: the first complete() crashes before calling through."""

    def __init__(self, inner):
        self.inner = inner
        self.crashed = False

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def complete(self, request):
        if not self.crashed:
            self.crashed = True
            raise Crash()
        return self.inner.complete(request)


@pytest.fixture
def world(db_path, principal, tmp_path, human):
    root = tmp_path / "src"
    root.mkdir()
    (root / "a.txt").write_text(TEXT_A, encoding="utf-8")
    (root / "b.txt").write_text(TEXT_B, encoding="utf-8")
    local = LocalFileSource([str(root)], StepClock())
    docs = [(local.fetch(str(root / "a.txt")), SYSTEM), (local.fetch(str(root / "b.txt")), SYSTEM)]
    lab = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), blob_root=str(tmp_path / "blobs"), governance_mode=LEGACY_MODE)
    objective = lab.add(Kind.OBJECTIVE, {"title": "Which component is the AI interaction boundary?"}, human)
    ids = [lab.record_source(doc, actor).record.entity_id for doc, actor in docs]
    req = build_request(lab, ids, settings=SETTINGS)
    yield {"lab": lab, "objective": objective.entity_id, "docs": docs, "sources": ids, "request": req, "tmp": tmp_path, "db": db_path, "principal": principal}
    lab.close()


def synthetic(world, hypotheses=None, questions=("Is the Watcher the boundary?",), error=None, name="rec.jsonl"):
    a, b = world["sources"]
    if hypotheses is None:
        hypotheses = (
            HypothesisProposal("The Watcher is the designated AI interaction boundary", (Cite(a, QUOTE_A),)),
            HypothesisProposal("The Watcher grades every change", (Cite(a, "The Watcher grades every change."), Cite("source_fabricated", "made up"))),
        )
    path = str(world["tmp"] / name)
    if error:
        entry = {"request_digest": world["request"].request_digest, "error": error}
    else:
        entry = {"request_digest": world["request"].request_digest, "text": render_proposals(Proposals(tuple(questions), tuple(hypotheses))), "model_reported": "synthetic-model"}
    write_recording(path, [entry], "synthetic test data built by tests/test_investigation.py")
    return ReplayAIPort(path, StepClock(), provider_id="replay-synthetic")


def run(world, ports, policy=STANDALONE_DEV_PROFILE, plan_id=None):
    return run_investigation(world["lab"], world["objective"], world["docs"], ports, policy, RUNNER, plan_id=plan_id, settings=SETTINGS)


def test_happy_path_records_proposals_with_provenance(world):
    lab = world["lab"]
    baseline = ExtractiveBaselinePort(StepClock())
    replay = synthetic(world)
    summary = run(world, [baseline, replay])
    assert summary.complete and summary.failed == [] and summary.pending == []
    assert set(summary.calls) == {"extractive-baseline", "replay-synthetic"}
    assert summary.calls["replay-synthetic"]["origin"] == "synthetic_test_data" and summary.calls["extractive-baseline"]["origin"] == "deterministic_baseline"
    assert summary.sources == world["sources"] and lab.graph.node(summary.framing_question_id).kind is Kind.QUESTION
    assert len(summary.hypotheses) == 5 and len(summary.questions) == 3  # baseline 3 + 2, questions 2 + 1
    for hid in summary.hypotheses:
        node = lab.graph.node(hid)
        block = node.latest.provenance[0]
        assert block["type"] == "ai_call" and block["policy_profile"] == "standalone-dev" and block["is_live"] is False
        assert lab.blobs.exists(block["request_digest"]) and lab.blobs.exists(block["response_digest"])
        assert node.status == "OPEN" and node.latest.evidence_label is None
        assert lab.graph.edges_from(hid, EdgeType.ANSWERS)[0].to_id == summary.framing_question_id
    replay_h = [h for h in summary.hypotheses if lab.graph.node(h).author.id == "port:replay-synthetic"]
    baseline_h = [h for h in summary.hypotheses if lab.graph.node(h).author.id == "port:extractive-baseline"]
    assert lab.graph.node(replay_h[0]).author.kind is ActorKind.AI and lab.graph.node(baseline_h[0]).author.kind is ActorKind.SYSTEM
    assert lab.graph.node(replay_h[0]).author.provider == "replay" and lab.graph.node(replay_h[0]).author.model_family == "synthetic-model"
    assert lab.graph.node(world["objective"]).status == "OPEN" and lab.graph.node(summary.plan_id).status == "CLOSED"
    assert summary.calls["extractive-baseline"]["request_digest"] == world["request"].request_digest
    assert lab.verify().ok and lab.verify_sources().ok and Graph.rebuild(lab.store.events()) == lab.graph
    assert baseline.calls == [world["request"].request_digest] and replay.calls == [world["request"].request_digest]


def test_stack_profile_refuses_before_any_call(world):
    lab = world["lab"]
    baseline, replay = ExtractiveBaselinePort(StepClock()), synthetic(world)
    count = lab.store.count()
    with pytest.raises(ProviderRefused, match="policy profile 'stack' does not allow provider kind 'deterministic_baseline'"):
        run(world, [baseline, replay], policy=STACK_PROFILE)
    with pytest.raises(ProviderRefused, match="does not allow provider kind 'replay'"):
        run(world, [replay], policy=STACK_PROFILE)
    assert baseline.calls == [] and replay.calls == [] and lab.store.count() == count
    assert not [n for n in lab.graph.nodes.values() if n.kind is Kind.PLAN]


def test_fabricated_citations_are_flagged_and_kept_as_proposals(world):
    lab = world["lab"]
    summary = run(world, [synthetic(world)])
    assert summary.complete and summary.unverified_citations == 2
    fabricated = [h for h in summary.hypotheses if lab.graph.node(h).latest.body["text"] == "The Watcher grades every change"][0]
    body = lab.graph.node(fabricated).latest.body
    assert body["citation_summary"] == {"verified": 0, "unverified": 2}
    reasons = {c["source_id"]: (c["status"], c["reason"]) for c in body["citations"]}
    assert reasons[world["sources"][0]] == ("UNVERIFIED", "quote not found in source")
    assert reasons["source_fabricated"][0] == "UNVERIFIED" and reasons["source_fabricated"][1].startswith("unknown source")
    assert [e.to_id for e in lab.graph.edges_from(fabricated, EdgeType.CITES)] == [world["sources"][0]]  # no edge to a non-entity
    assert lab.graph.node(fabricated).status == "OPEN" and lab.graph.node(fabricated).kind is Kind.HYPOTHESIS
    assert not [n for n in lab.graph.nodes.values() if n.kind is Kind.EVIDENCE]  # nothing became evidence
    good = [h for h in summary.hypotheses if h != fabricated][0]
    assert lab.graph.node(good).latest.body["citation_summary"] == {"verified": 1, "unverified": 0}


def test_shared_source_pairs_are_marked_not_independent(world):
    lab = world["lab"]
    a, b = world["sources"]
    replay = synthetic(world, hypotheses=(HypothesisProposal("shares A", (Cite(a, QUOTE_A),)), HypothesisProposal("only B", (Cite(b, QUOTE_B),))))
    summary = run(world, [ExtractiveBaselinePort(StepClock(), max_hypotheses=1), replay])
    assert summary.complete
    baseline_h = summary.calls["extractive-baseline"]["hypotheses"][0]
    assert [e.to_id for e in lab.graph.edges_from(baseline_h, EdgeType.CITES)] == [a]
    shares, only_b = summary.calls["replay-synthetic"]["hypotheses"]
    assert summary.not_independent_pairs == [{"hypotheses": [baseline_h, shares], "providers": ["extractive-baseline", "replay-synthetic"], "shared_sources": [a]}]
    reviews = [n for n in lab.graph.nodes.values() if n.kind is Kind.REVIEW]
    verdicts = {tuple(n.latest.body["pair"]): n.latest.body["verdict"] for n in reviews}
    assert verdicts[(baseline_h, shares)] == NOT_INDEPENDENT and verdicts[(baseline_h, only_b)] == "INDEPENDENT_SOURCES"
    assert lab.graph.shared_sources(baseline_h, shares)[0].entity_id == a and lab.graph.shared_sources(baseline_h, only_b) == []


def test_contradictory_proposals_are_both_preserved(world, human):
    lab = world["lab"]
    a, _ = world["sources"]
    replay = synthetic(world, hypotheses=(HypothesisProposal("The Watcher does grade changes", (Cite(a, QUOTE_A),)),))
    summary = run(world, [ExtractiveBaselinePort(StepClock(), max_hypotheses=3), replay])
    baseline_h = [h for h in summary.calls["extractive-baseline"]["hypotheses"] if lab.graph.node(h).latest.body["text"] == "The Watcher never grades a change."][0]
    replay_h = summary.calls["replay-synthetic"]["hypotheses"][0]
    record = lab.record_contradiction(baseline_h, replay_h, "one says never grades, the other says grades", human, [{"type": "source", "ref": a}])
    assert lab.graph.node(baseline_h).status == "OPEN" and lab.graph.node(replay_h).status == "OPEN"
    assert lab.contradictions_of(replay_h)[0].entity_id == record.entity_id
    assert lab.graph.contradictions_of(baseline_h)["contradiction_records"][0].entity_id == record.entity_id
    assert lab.verify().ok


def test_provider_unavailable_fails_only_its_task_then_retry_succeeds(world):
    lab = world["lab"]
    baseline = ExtractiveBaselinePort(StepClock())
    down = synthetic(world, error={"type": "unavailable", "reason": "provider outage", "status": 503})
    summary = run(world, [baseline, down])
    assert not summary.complete
    assert summary.calls["extractive-baseline"]["state"] == "COMPLETED" and summary.calls["replay-synthetic"]["state"] == "FAILED"
    assert "ProviderUnavailable: provider outage (status 503)" in summary.calls["replay-synthetic"]["error"]
    assert summary.failed == [f"call:replay-synthetic: {summary.calls['replay-synthetic']['error']}"]
    assert lab.graph.node(summary.plan_id).status == "OPEN"
    with pytest.raises(IncompleteInvestigation, match="call:replay-synthetic=FAILED"):
        Runner(lab, summary.plan_id, RUNNER).complete("too early")
    with pytest.raises(IncompleteInvestigation):
        lab.transition(summary.plan_id, "CLOSED", RUNNER, "bypass")
    assert lab.graph.run_states(summary.plan_id)[[t.entity_id for t in lab.graph.plan_tasks(summary.plan_id) if t.latest.body["step"] == "analyse"][0]].output["providers_skipped"] == ["replay-synthetic"]
    back = synthetic(world)  # the provider returns
    again = run(world, [baseline, back], plan_id=summary.plan_id)
    assert again.complete and again.calls["replay-synthetic"]["attempts"] == 2 and again.calls["extractive-baseline"]["attempts"] == 1
    assert baseline.calls == [world["request"].request_digest] and back.calls == [world["request"].request_digest]
    assert lab.verify().ok


def test_changed_response_format_fails_with_raw_digest_preserved(world):
    lab = world["lab"]
    path = str(world["tmp"] / "bad.jsonl")
    bad_text = '{"answers": ["the format changed"]}'
    write_recording(path, [{"request_digest": world["request"].request_digest, "text": bad_text}], "synthetic bad format")
    bad = ReplayAIPort(path, StepClock(), provider_id="replay-bad")
    summary = run(world, [ExtractiveBaselinePort(StepClock()), bad])
    from research_lab.canonical import sha256_hex

    digest = sha256_hex(bad_text.encode("utf-8"))
    assert summary.calls["replay-bad"]["state"] == "FAILED" and digest in summary.calls["replay-bad"]["error"]
    assert "ResponseFormatError" in summary.calls["replay-bad"]["error"] and "exactly the keys" in summary.calls["replay-bad"]["error"]
    assert lab.blobs.read(digest) == bad_text.encode("utf-8")  # the raw response is preserved
    assert summary.calls["extractive-baseline"]["state"] == "COMPLETED" and len(summary.hypotheses) == 3
    assert not summary.complete


def test_replay_miss_fails_only_that_task(world):
    empty = synthetic(world, name="empty.jsonl")
    empty._entries.clear()
    summary = run(world, [ExtractiveBaselinePort(StepClock()), empty])
    assert "replay miss" in summary.calls["replay-synthetic"]["error"] and summary.calls["extractive-baseline"]["state"] == "COMPLETED"


def test_interruption_after_first_provider_then_resume_with_zero_extra_calls(world):
    lab = world["lab"]
    baseline = ExtractiveBaselinePort(StepClock())
    replay = synthetic(world)
    crashing = CrashOnce(replay)
    with pytest.raises(Crash):
        run(world, [baseline, crashing])
    plan_id = [n for n in lab.graph.nodes.values() if n.kind is Kind.PLAN][0].entity_id
    states = {run_.step: run_.state for run_ in lab.graph.run_states(plan_id).values()}
    assert states == {"record_sources": TaskState.COMPLETED, "call:extractive-baseline": TaskState.COMPLETED, "call:replay-synthetic": TaskState.STARTED, "analyse": TaskState.PENDING}
    assert baseline.calls == [world["request"].request_digest] and replay.calls == []
    with pytest.raises(IncompleteInvestigation):
        Runner(lab, plan_id, RUNNER).complete("partial")
    lab.close()
    reopened = Lab.open(world["db"], TENANT, world["principal"], StepClock("2026-02-01T00:00:00Z"), blob_root=str(world["tmp"] / "blobs"))
    world["lab"] = reopened
    summary = run(world, [baseline, crashing], plan_id=plan_id)
    assert summary.complete and summary.interrupted == []
    assert baseline.calls == [world["request"].request_digest]  # provider 1 was not called again
    assert replay.calls == [world["request"].request_digest]
    assert summary.calls["call:replay-synthetic".removeprefix("call:")]["attempts"] == 2
    assert reopened.verify().ok and Graph.rebuild(reopened.store.events()) == reopened.graph
    reopened.close()


def test_crash_after_the_provider_answered_reuses_the_preserved_response(world, monkeypatch):
    lab = world["lab"]
    replay = synthetic(world)
    real_parse = investigation_module.parse_proposals
    state = {"crashed": False}

    def parse_then_crash(text):
        if not state["crashed"]:
            state["crashed"] = True
            raise Crash()
        return real_parse(text)

    monkeypatch.setattr(investigation_module, "parse_proposals", parse_then_crash)
    with pytest.raises(Crash):
        run(world, [replay])
    assert replay.calls == [world["request"].request_digest]
    plan_id = [n for n in lab.graph.nodes.values() if n.kind is Kind.PLAN][0].entity_id
    summary = run(world, [replay], plan_id=plan_id)
    assert summary.complete and summary.calls["replay-synthetic"]["reused_recorded_response"] is True
    assert replay.calls == [world["request"].request_digest]  # idempotent by request digest: no second call


def test_ai_authored_proposals_stay_under_the_existing_rules(world, gov):
    lab = world["lab"]
    summary = run(world, [synthetic(world)])
    hyp = summary.calls["replay-synthetic"]["hypotheses"][0]
    author = lab.graph.node(hyp).author
    assert author.kind is ActorKind.AI
    with pytest.raises(TransitionError):
        lab.transition(hyp, "ACCEPTED", author, "promote")  # a hypothesis has no acceptance stage
    finding = lab.add(Kind.FINDING, {"text": "from the AI proposal"}, author, evidence_label=EvidenceLabel.INFERRED)
    with pytest.raises(Exception, match="EXECUTED"):
        lab.add(Kind.FINDING, {"text": "claimed as executed"}, author, evidence_label=EvidenceLabel.EXECUTED)
    with pytest.raises(SelfReviewError):
        lab.transition(finding.entity_id, "REVIEWED", author, "self review")
    with pytest.raises(Exception, match="governance-only"):
        lab.transition(finding.entity_id, "ACCEPTED", author, "self accept")


def test_runner_refuses_bad_inputs(world, human):
    lab = world["lab"]
    with pytest.raises(InvestigationError, match="SYSTEM actor"):
        run_investigation(lab, world["objective"], world["docs"], [], STANDALONE_DEV_PROFILE, human)
    with pytest.raises(InvestigationError, match="not an objective"):
        run_investigation(lab, world["sources"][0], world["docs"], [], STANDALONE_DEV_PROFILE, RUNNER)
    a = ExtractiveBaselinePort(StepClock())
    with pytest.raises(InvestigationError, match="duplicate provider id"):
        run_investigation(lab, world["objective"], world["docs"], [a, a], STANDALONE_DEV_PROFILE, RUNNER)


def test_export_after_investigation_verifies_from_file(world, tmp_path):
    lab = world["lab"]
    summary = run(world, [ExtractiveBaselinePort(StepClock()), synthetic(world)])
    out = str(tmp_path / "bundle.jsonl")
    export_bundle(lab.store, out)
    result = verify_bundle(out)
    assert summary.complete and result.ok and result.policy_checked
