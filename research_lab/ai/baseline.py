"""ExtractiveBaselinePort: a deterministic, non-model provider.

It proposes questions and hypotheses by keyword-overlap sentence extraction from the
excerpts it is given and returns exact quotes with their source ids in the strict JSON
schema. It is small, deterministic and testable, and it is explicitly NOT an AI model: it
exists to show that the port works with an internally operated implementation. Its output
is as weak as the heuristic; do not read anything more into it.
"""

from __future__ import annotations

import re

from ..clock import Clock
from .citations import MIN_QUOTE_CHARS, MIN_QUOTE_TOKENS
from .outputs import Cite, HypothesisProposal, Proposals, render_proposals
from .port import AIRequest, AIResponse, build_response

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n\s*\n")
_TOKEN = re.compile(r"[a-z][a-z0-9_-]{3,}")
STOPWORDS = frozenset(
    "that this with from into which what when where whose their there these those have been were will would could should"
    " about than then them they your into over under only also more most such very each every both some many much".split()
)
# A proposed quote must be verifiable, so a candidate sentence must meet the citation
# minimum (MIN_QUOTE_CHARS characters and MIN_QUOTE_TOKENS words) and a sanity ceiling.
MIN_SENTENCE_CHARS = max(24, MIN_QUOTE_CHARS)
MIN_SENTENCE_TOKENS = MIN_QUOTE_TOKENS
MAX_SENTENCE_CHARS = 300


def tokens(text: str) -> set[str]:
    return {token for token in _TOKEN.findall(text.lower()) if token not in STOPWORDS}


def sentences(text: str) -> list[str]:
    out = []
    for raw in _SENTENCE_SPLIT.split(text):
        candidate = " ".join(raw.split())
        if (
            MIN_SENTENCE_CHARS <= len(candidate) <= MAX_SENTENCE_CHARS
            and len(candidate.split(" ")) >= MIN_SENTENCE_TOKENS
            and _TOKEN.search(candidate.lower())
        ):
            out.append(candidate)
    return out


class ExtractiveBaselinePort:
    provider_id = "extractive-baseline"
    provider_kind = "deterministic_baseline"
    adapter_version = "1"
    is_live = False
    is_model = False
    origin = "deterministic_baseline"

    def __init__(self, clock: Clock, max_questions: int = 2, max_hypotheses: int = 3) -> None:
        self._clock = clock
        self._max_questions = max_questions
        self._max_hypotheses = max_hypotheses
        self.calls: list[str] = []

    @staticmethod
    def topic_terms(request: AIRequest) -> set[str]:
        configured = request.settings.get("topic_terms")
        if isinstance(configured, list) and configured:
            return {str(term).lower() for term in configured}
        return tokens(request.purpose + " " + request.instructions)

    def rank(self, request: AIRequest) -> list[tuple[int, int, str, str]]:
        """(score, position, source_id, sentence) for every candidate sentence, best first;
        ties keep source order then sentence order."""
        terms = self.topic_terms(request)
        ranked = []
        position = 0
        for item in request.inputs:
            for sentence in sentences(item.excerpt):
                ranked.append((len(tokens(sentence) & terms), position, item.source_id, sentence))
                position += 1
        ranked.sort(key=lambda row: (-row[0], row[1]))
        return ranked

    def propose(self, request: AIRequest) -> Proposals:
        ranked = [row for row in self.rank(request) if row[0] > 0]
        hypotheses = tuple(
            HypothesisProposal(sentence, (Cite(source_id, sentence),)) for _, _, source_id, sentence in ranked[: self._max_hypotheses]
        )
        questions = tuple(f"What evidence supports or contradicts: {sentence}" for _, _, _, sentence in ranked[: self._max_questions])
        return Proposals(questions, hypotheses)

    def complete(self, request: AIRequest) -> AIResponse:
        started = self._clock.now()
        self.calls.append(request.request_digest)
        proposals = self.propose(request)
        text = render_proposals(proposals)
        usage = {
            "input_chars": sum(len(item.excerpt) for item in request.inputs),
            "output_chars": len(text),
            "candidates": len(self.rank(request)),
        }
        return build_response(
            self,
            request,
            text=text,
            model_requested="none (deterministic baseline)",
            model_reported=f"{self.provider_id}/{self.adapter_version}",
            finish_reason="stop",
            usage=usage,
            started_at=started,
            finished_at=self._clock.now(),
        )
