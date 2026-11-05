"""Minimum quote size for VERIFIED citations (verifier's attack7) and the recorded span."""

import json

import pytest
from conftest import ISSUERS, TENANT

from research_lab.ai import (
    MIN_QUOTE_CHARS,
    MIN_QUOTE_TOKENS,
    STANDALONE_DEV_PROFILE,
    Cite,
    HypothesisProposal,
    Proposals,
    ReplayAIPort,
    normalize_ws,
    render_proposals,
    verify_citations,
    write_recording,
)
from research_lab.cli import main
from research_lab.clock import StepClock
from research_lab.investigation import build_request, run_investigation
from research_lab.lab import Lab
from research_lab.records import Actor, ActorKind, Kind
from research_lab.sources import LocalFileSource

SYSTEM = Actor("sys", ActorKind.SYSTEM)
RUNNER = Actor("investigation-runner", ActorKind.SYSTEM)
TEXT_A = "The Watcher narrates run records. It has no authority over any verdict."
TEXT_B = "Completely different file about gardening and tomatoes."
TOO_SHORT = "quote too short to identify a passage (minimum 20 characters and 4 words)"


@pytest.fixture
def world(db_path, principal, tmp_path):
    root = tmp_path / "docs"
    root.mkdir()
    (root / "a.txt").write_text(TEXT_A, encoding="utf-8")
    (root / "b.txt").write_text(TEXT_B, encoding="utf-8")
    lab = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), blob_root=str(tmp_path / "blobs"))
    src = LocalFileSource([str(root)], StepClock())
    docs = [(src.fetch(str(root / "a.txt")), SYSTEM), (src.fetch(str(root / "b.txt")), SYSTEM)]
    a = lab.record_source(docs[0][0], SYSTEM).record.entity_id
    b = lab.record_source(docs[1][0], SYSTEM).record.entity_id
    yield lab, a, b, tmp_path, db_path, principal, docs
    lab.close()


def one(lab, source_id, quote, **kw):
    return verify_citations(lab, [Cite(source_id, quote)], **kw)[0]


def test_constants():
    assert MIN_QUOTE_CHARS == 20 and MIN_QUOTE_TOKENS == 4


def test_attack7_cases_q3_to_q6_are_unverified(world):
    lab, a, _, *_ = world
    for quote in ("a", "the", "", "   "):
        check = one(lab, a, quote)
        assert check.status == "UNVERIFIED" and check.reason == TOO_SHORT and check.span is None, quote


def test_attack7_other_cases_keep_their_verdicts(world):
    lab, a, _, *_ = world
    assert one(lab, a, "gardening and tomatoes are not here").reason == "quote not found in source"
    assert one(lab, a, "THE WATCHER NARRATES RUN RECORDS.").reason == "quote not found in source"
    assert one(lab, a, "The Watcher narrates run records. any verdict.").reason == "quote not found in source"
    assert one(lab, "source_nope", "The Watcher narrates run records.").reason.startswith("unknown source")
    assert one(lab, "objective_abc", "The Watcher narrates run records.").reason.startswith("unknown source")


def test_boundaries_characters_and_tokens(world):
    lab, a, _, *_ = world
    # 19 versus 20 characters, both with 4 words and both verbatim in TEXT_A
    nineteen = "narrates run record"  # 19 characters, 3 words: too short on both counts
    assert len(nineteen) == 19 and one(lab, a, nineteen).reason == TOO_SHORT
    twenty_three_words = "has no authority ove"  # 20 characters, 4 words (last cut), verbatim
    assert len(twenty_three_words) == 20 and len(twenty_three_words.split()) == 4
    assert one(lab, a, twenty_three_words).status == "VERIFIED"
    # 20 characters but only 3 words
    three_words = "Watcher narrates run"
    assert len(three_words) == 20 and len(three_words.split()) == 3 and one(lab, a, three_words).reason == TOO_SHORT
    # 4 words but fewer than 20 characters
    four_short = "It has no authority"  # 19 characters
    assert len(four_short) == 19 and len(four_short.split()) == 4 and one(lab, a, four_short).reason == TOO_SHORT
    # length is counted after normalisation: padding whitespace does not help
    padded = "   It   has   no   authority   "
    assert len(padded) > 20 and one(lab, a, padded).reason == TOO_SHORT
    # overrides make the minimum explicit and testable
    assert one(lab, a, "a", min_chars=1, min_tokens=1).status == "VERIFIED"
    assert one(lab, a, "It has no authority", min_chars=19).status == "VERIFIED"


def test_legitimate_long_quote_is_verified_with_the_right_span(world):
    lab, a, _, *_ = world
    quote = "narrates run records.\n   It has no authority"
    check = one(lab, a, quote)
    assert check.status == "VERIFIED" and check.span is not None
    start, end = check.span
    assert normalize_ws(TEXT_A)[start:end] == normalize_ws(quote) == "narrates run records. It has no authority"
    assert start == TEXT_A.index("narrates") and check.to_dict()["span"] == [start, end]
    assert check.reason.endswith("at the recorded span")


def test_span_reaches_the_investigation_body_and_cli_show(world, human, capsys):
    lab, a, b, tmp_path, db_path, principal, docs = world
    objective = lab.add(Kind.OBJECTIVE, {"title": "spans"}, human)
    request = build_request(lab, [a, b], settings={"topic_terms": ["watcher"]})
    proposals = Proposals(
        (),
        (
            HypothesisProposal("long quote", (Cite(a, "The Watcher narrates run records."),)),
            HypothesisProposal("short quote", (Cite(a, "a"),)),
        ),
    )
    path = str(tmp_path / "rec.jsonl")
    write_recording(path, [{"request_digest": request.request_digest, "text": render_proposals(proposals)}], "synthetic")
    port = ReplayAIPort(path, StepClock())
    # The sources are already recorded; re-recording them is idempotent and yields the same ids.
    summary = run_investigation(lab, objective.entity_id, docs, [port], STANDALONE_DEV_PROFILE, RUNNER, settings={"topic_terms": ["watcher"]})
    assert summary.complete and summary.unverified_citations == 1
    long_h, short_h = summary.hypotheses
    long_cite = lab.graph.node(long_h).latest.body["citations"][0]
    assert long_cite["status"] == "VERIFIED" and long_cite["span"] == [0, len("The Watcher narrates run records.")]
    short_cite = lab.graph.node(short_h).latest.body["citations"][0]
    assert short_cite["status"] == "UNVERIFIED" and short_cite["reason"] == TOO_SHORT and short_cite["span"] is None
    lab.close()
    code = main(["show", "--db", db_path, "--tenant", TENANT, "--principal", principal.id, "--entity", long_h])
    shown = json.loads(capsys.readouterr().out)
    assert code == 0 and shown["citations"][0]["span"] == [0, 33] and shown["ai_calls"][0]["type"] == "ai_call"
