"""AI port contract, policy, strict parser, replay and baseline ports, citations. Offline."""

import json
import os

import pytest
from conftest import ISSUERS, LEGACY_MODE, TENANT

from research_lab.ai import (
    STACK_PROFILE,
    STANDALONE_DEV_PROFILE,
    AIRequest,
    AIResponse,
    Cite,
    ExtractiveBaselinePort,
    HypothesisProposal,
    Proposals,
    ProviderPolicy,
    ProviderRefused,
    ProviderTimeout,
    ProviderUnavailable,
    ReplayAIPort,
    ResponseFormatError,
    SourceInput,
    assert_conformant,
    check_port_allowed,
    parse_proposals,
    render_proposals,
    run_conformance,
    verify_citations,
    write_recording,
)
from research_lab.canonical import sha256_hex
from research_lab.clock import StepClock
from research_lab.graph import EVENT_RECORD, EdgeType, PolicyViolation
from research_lab.lab import Lab
from research_lab.lifecycle import AuthorityError
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind, Record
from research_lab.sources import LocalFileSource

DIGEST = "0" * 64
SYSTEM = Actor("local-filesystem", ActorKind.SYSTEM)


def request(excerpt="The Watcher narrates the run record for a person. Every sentence cites a measurement.", **settings):
    return AIRequest("propose", "Propose hypotheses about the watcher", (SourceInput("source_a", DIGEST, excerpt),), 200, dict(settings))


@pytest.fixture
def slab(db_path, principal, tmp_path):
    created = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), blob_root=str(tmp_path / "blobs"), governance_mode=LEGACY_MODE)
    yield created
    created.close()


def record_text_source(slab, tmp_path, name, text):
    root = tmp_path / "src"
    root.mkdir(exist_ok=True)
    (root / name).write_text(text, encoding="utf-8")
    doc = LocalFileSource([str(root)], StepClock()).fetch(str(root / name))
    return slab.record_source(doc, SYSTEM).record.entity_id


# request and response


def test_request_digest_is_deterministic_and_content_sensitive():
    a, b = request(), request()
    assert a.request_digest == b.request_digest and len(a.request_digest) == 64
    assert AIRequest.from_dict(a.to_dict()).request_digest == a.request_digest
    assert request(model="x").request_digest != a.request_digest
    assert request(excerpt="other").request_digest != a.request_digest
    with pytest.raises(ValueError, match="request_digest does not match"):
        AIRequest("p", "i", a.inputs, 10, {}, request_digest="1" * 64)
    with pytest.raises(ValueError):
        AIRequest("", "i", a.inputs, 10)
    with pytest.raises(ValueError):
        AIRequest("p", "i", a.inputs, 0)
    with pytest.raises(ValueError):
        SourceInput("s", "short", "x")


def test_response_digest_must_match_text():
    with pytest.raises(ValueError, match="response_digest"):
        AIResponse("hello", "p", "k", "1", "m", "m", DIGEST, "1" * 64, "stop", {}, 0, False, "synthetic_test_data")
    ok = AIResponse("hello", "p", "k", "1", "m", "m", DIGEST, sha256_hex(b"hello"), "stop", {}, 0, False, "synthetic_test_data")
    assert ok.to_dict(include_text=False).get("text") is None and AIResponse.from_dict(ok.to_dict()) == ok


# policy


def test_policy_profiles_and_refusal(tmp_path):
    baseline = ExtractiveBaselinePort(StepClock())
    write_recording(str(tmp_path / "r.jsonl"), [], "empty")
    replay = ReplayAIPort(str(tmp_path / "r.jsonl"), StepClock())
    for port in (baseline, replay):
        check_port_allowed(port, STANDALONE_DEV_PROFILE)
        with pytest.raises(ProviderRefused, match="policy profile 'stack' does not allow"):
            check_port_allowed(port, STACK_PROFILE)
    assert STACK_PROFILE.allowed_kinds == frozenset({"watcher_mcu"})
    assert not any(STACK_PROFILE.allows(kind) for kind in ("replay", "deterministic_baseline"))
    with pytest.raises(ValueError):
        ProviderPolicy("", frozenset())
    assert baseline.calls == [] and replay.calls == []  # refusals never called the ports


# conformance


def test_conformance_baseline_and_replay(tmp_path):
    req = request(topic_terms=["watcher"])
    baseline = ExtractiveBaselinePort(StepClock())
    results = assert_conformant(baseline, req, unknown_request=request(excerpt="nothing here"))
    assert {r.name for r in results} >= {"port_attributes", "request_digest_deterministic", "error_classes_distinguishable", "request_not_mutated", "response_provenance", "same_request_same_provenance", "unknown_request_handled"}
    path = str(tmp_path / "rec.jsonl")
    write_recording(path, [{"request_digest": req.request_digest, "text": render_proposals(Proposals(("q?",), ())), "model_reported": "synthetic-model"}], "conformance")
    replay = ReplayAIPort(path, StepClock())
    results = assert_conformant(replay, req, unknown_request=request(excerpt="unknown"))
    assert any(r.name == "unknown_request_handled" and r.detail == "ProviderUnavailable" for r in results)


def test_conformance_reports_a_broken_port():
    class Broken:
        provider_id, provider_kind, adapter_version, is_live, is_model, origin = "b", "k", "1", False, True, "live"

        def complete(self, req):
            return AIResponse("x", "other", "k", "1", "m", "m", req.request_digest, sha256_hex(b"x"), "stop", {}, 0, False, "live")

    results = run_conformance(Broken(), request())
    failed = {r.name for r in results if not r.ok}
    assert "port_attributes" in failed and "response_provenance" in failed
    with pytest.raises(AssertionError, match="conformance failed"):
        assert_conformant(Broken(), request())


# strict parser


def good():
    return render_proposals(Proposals(("Why?",), (HypothesisProposal("H", (Cite("source_a", "quote one"), Cite("source_b", "quote two"))),)))


@pytest.mark.parametrize(
    "text, match",
    [
        ("not json", "not JSON"),
        ('{"questions": [], "hypotheses": [], "extra": 1}', "exactly the keys"),
        ('{"questions": []}', "exactly the keys"),
        ("[]", "must be an object"),
        ('{"questions": {}, "hypotheses": []}', "questions must be a list"),
        ('{"questions": ["Why?"], "hypotheses": []}', "questions\\[0\\] must be an object"),
        ('{"questions": [{"text": ""}], "hypotheses": []}', "must not be empty"),
        ('{"questions": [{"text": "   "}], "hypotheses": []}', "must not be empty"),
        ('{"questions": [{"text": 5}], "hypotheses": []}', "must be a string"),
        ('{"questions": [{"text": "q", "score": 1}], "hypotheses": []}', "exactly the keys"),
        ('{"questions": [], "hypotheses": [{"text": "h"}]}', "exactly the keys"),
        ('{"questions": [], "hypotheses": [{"text": "h", "cites": {}}]}', "cites must be a list"),
        ('{"questions": [], "hypotheses": [{"text": "h", "cites": [{"source_id": "s"}]}]}', "exactly the keys"),
        ('{"questions": [], "hypotheses": [{"text": "h", "cites": [{"source_id": "s", "quote": ""}]}]}', "must not be empty"),
        ('{"questions": [], "hypotheses": [{"text": "h", "cites": [{"source_id": "s", "quote": "q"}, {"source_id": "s", "quote": "q"}]}]}', "duplicates"),
        ('{"questions": [], "hypotheses": [{"text": "' + "x" * 2001 + '", "cites": []}]}', "exceeds 2000"),
        ('{"questions": [{"text": "q"}' + ', {"text": "q"}' * 50 + '], "hypotheses": []}', "the cap is 50"),
        ('{"questions": [], "hypotheses": [{"text": "h", "cites": [' + ", ".join(f'{{"source_id": "s{i}", "quote": "q"}}' for i in range(21)) + "]}]}", "the cap is 20"),
        ('{"questions": [{"text": NaN}], "hypotheses": []}', "not JSON"),
    ],
)
def test_parser_rejects_every_malformed_shape(text, match):
    with pytest.raises(ResponseFormatError, match=match) as info:
        parse_proposals(text)
    assert info.value.response_digest == sha256_hex(text.encode("utf-8"))


def test_parser_accepts_the_schema_and_strips_whitespace():
    proposals = parse_proposals(good())
    assert proposals.questions == ("Why?",) and proposals.hypotheses[0].cites[1] == Cite("source_b", "quote two")
    assert parse_proposals('{"questions": [{"text": "  q  "}], "hypotheses": []}').questions == ("q",)
    with pytest.raises(ResponseFormatError, match="exceeds the cap"):
        parse_proposals(good(), max_bytes=10)


# replay port


def test_replay_port_serves_recorded_errors_and_misses(tmp_path):
    req = request()
    path = str(tmp_path / "rec.jsonl")
    write_recording(
        path,
        [
            {"request_digest": req.request_digest, "text": good(), "finish_reason": "stop", "usage": {"tokens": 3}},
            {"request_digest": request(excerpt="refused").request_digest, "error": {"type": "refused", "reason": "policy says no"}},
            {"request_digest": request(excerpt="timeout").request_digest, "error": {"type": "timeout", "reason": "slow"}},
            {"request_digest": request(excerpt="down").request_digest, "error": {"type": "unavailable", "reason": "outage", "status": 503}},
        ],
        "test",
    )
    port = ReplayAIPort(path, StepClock(), provider_id="replay-a")
    assert len(port) == 4 and port.provider_kind == "replay" and not port.is_live and port.is_model and port.origin == "synthetic_test_data"
    response = port.complete(req)
    assert response.text == good() and response.usage == {"tokens": 3} and response.origin == "synthetic_test_data" and response.latency_seconds == 1
    with pytest.raises(ProviderRefused, match="policy says no"):
        port.complete(request(excerpt="refused"))
    with pytest.raises(ProviderTimeout, match="slow"):
        port.complete(request(excerpt="timeout"))
    with pytest.raises(ProviderUnavailable, match="outage \\(status 503\\)") as info:
        port.complete(request(excerpt="down"))
    assert info.value.status == 503 and not isinstance(info.value, ProviderTimeout)
    with pytest.raises(ProviderUnavailable, match="replay miss"):
        port.complete(request(excerpt="never recorded"))
    assert len(port.calls) == 5


def test_replay_port_refuses_unlabelled_recordings(tmp_path):
    path = str(tmp_path / "bad.jsonl")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps({"recording_schema": "research_lab.ai_replay/1", "origin": "real model output"}) + "\n")
    with pytest.raises(ValueError, match="not labelled synthetic test data"):
        ReplayAIPort(path, StepClock())
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("")
    with pytest.raises(ValueError, match="empty"):
        ReplayAIPort(path, StepClock())
    with pytest.raises(ValueError, match="exactly one of text or error"):
        write_recording(path, [{"request_digest": DIGEST}], "x")
    write_recording(path, [], "labelled")
    with open(path, encoding="utf-8") as handle:
        header = json.loads(handle.readline())
    assert header["origin"] == "synthetic_test_data" and "SYNTHETIC TEST DATA" in header["warning"]


# baseline port


def test_baseline_is_deterministic_and_quotes_verbatim():
    port = ExtractiveBaselinePort(StepClock(), max_questions=1, max_hypotheses=2)
    req = request(topic_terms=["watcher", "measurement"])
    one, two = port.complete(req), port.complete(req)
    assert one.text == two.text and one.response_digest == two.response_digest
    assert one.provider_kind == "deterministic_baseline" and not one.is_live and not port.is_model and one.origin == "deterministic_baseline"
    proposals = parse_proposals(one.text)
    assert len(proposals.hypotheses) == 2 and len(proposals.questions) == 1
    for hyp in proposals.hypotheses:
        assert hyp.cites[0].source_id == "source_a" and hyp.cites[0].quote in req.inputs[0].excerpt and hyp.text == hyp.cites[0].quote
    assert proposals.hypotheses[0].text == "The Watcher narrates the run record for a person."
    assert proposals.questions[0].startswith("What evidence supports or contradicts: ")
    nothing = port.complete(request(excerpt="Unrelated text about cooking rice slowly in a pot.", topic_terms=["watcher"]))
    assert parse_proposals(nothing.text).hypotheses == ()
    assert port.calls == [req.request_digest, req.request_digest, request(excerpt="Unrelated text about cooking rice slowly in a pot.", topic_terms=["watcher"]).request_digest]


# citations


def test_verify_citations_verbatim_whitespace_unknown_and_tampered(slab, tmp_path):
    sid = record_text_source(slab, tmp_path, "a.txt", "The Watcher narrates\n   the run record   for a person.\nIt never grades.\n")
    checks = verify_citations(
        slab,
        [
            Cite(sid, "The Watcher narrates the run record for a person."),
            Cite(sid, "narrates   the run\nrecord"),
            Cite(sid, "The Watcher grades every change."),
            Cite("source_fabricated", "anything"),
            Cite(slab.graph.node(sid).entity_id.replace("source_", "hypothesis_"), "x"),
        ],
    )
    assert [c.status for c in checks] == ["VERIFIED", "VERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED"]
    assert checks[2].reason == "quote not found in source" and checks[3].reason.startswith("unknown source")
    path = slab.blobs._path(slab.graph.node(sid).latest.body["blob_digest"])
    os.chmod(path, 0o644)
    with open(path, "ab") as handle:
        handle.write(b"tampered")
    tampered = verify_citations(slab, [Cite(sid, "The Watcher narrates the run record for a person.")])
    assert tampered[0].status == "UNVERIFIED" and tampered[0].reason.startswith("blob corrupt")
    os.unlink(path)
    assert verify_citations(slab, [Cite(sid, "x")])[0].reason.startswith("blob missing")


# AI origin rules


def test_ai_origin_records_never_carry_executed_label(slab, ai, human, principal, db_path):
    with pytest.raises(AuthorityError, match="EXECUTED"):
        slab.add(Kind.EVIDENCE, {"text": "ran"}, ai, evidence_label=EvidenceLabel.EXECUTED)
    inferred = slab.add(Kind.EVIDENCE, {"text": "guessed"}, ai, evidence_label=EvidenceLabel.INFERRED)
    assert inferred.evidence_label is EvidenceLabel.INFERRED
    forged = Record.create(Kind.EVIDENCE, TENANT, {"text": "ran"}, ai, "2026-11-05T00:00:00Z", "OPEN", evidence_label=EvidenceLabel.EXECUTED)
    count = slab.store.count()
    with pytest.raises(PolicyViolation, match="EXECUTED"):
        slab.store.append(EVENT_RECORD, {"record": forged.to_dict(), "edges": []})
    assert slab.store.count() == count


def test_ai_cannot_inherit_executed_label_through_supersede(slab, human, ai, reviewer, gov):
    finding = slab.add(Kind.FINDING, {"text": "human ran it"}, human, evidence_label=EvidenceLabel.EXECUTED)
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        slab.transition(finding.entity_id, stage, reviewer, "r")
    slab.govern(finding.entity_id, "ACCEPTED", gov, "gov-1", "accepted")
    count = slab.store.count()
    with pytest.raises(AuthorityError, match="EXECUTED"):
        slab.supersede(finding.entity_id, {"text": "ai replacement"}, ai, "ai tries to inherit EXECUTED")
    assert slab.store.count() == count and slab.graph.node(finding.entity_id).status == "ACCEPTED"
    done = slab.supersede(finding.entity_id, {"text": "ai replacement"}, ai, "explicit label", evidence_label=EvidenceLabel.INFERRED)
    assert not done.retired and done.replacement.evidence_label is EvidenceLabel.INFERRED
    assert slab.graph.node(finding.entity_id).status == "ACCEPTED"


def test_record_contradiction_preserves_both_sides(slab, human, ai):
    h1 = slab.add(Kind.HYPOTHESIS, {"text": "A"}, ai)
    h2 = slab.add(Kind.HYPOTHESIS, {"text": "not A"}, human)
    record = slab.record_contradiction(h1.entity_id, h2.entity_id, "they cannot both hold", human, [{"type": "note", "ref": "run-7"}])
    assert record.kind is Kind.CONTRADICTION and record.body["between"] == [h1.entity_id, h2.entity_id]
    assert slab.graph.node(h1.entity_id).status == "OPEN" and slab.graph.node(h2.entity_id).status == "OPEN"
    assert [c.entity_id for c in slab.contradictions_of(h1.entity_id)] == [record.entity_id]
    assert [c.entity_id for c in slab.contradictions_of(h2.entity_id)] == [record.entity_id]
    assert {e.to_id for e in slab.graph.edges_from(record.entity_id, EdgeType.INVOLVES)} == {h1.entity_id, h2.entity_id}
    with pytest.raises(Exception, match="two different"):
        slab.record_contradiction(h1.entity_id, h1.entity_id, "self", human)
    assert slab.verify().ok
