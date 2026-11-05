"""Shared fixtures. Everything is deterministic: injected StepClock, temp files, no network."""

from __future__ import annotations

import os
import sqlite3
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from research_lab.clock import StepClock  # noqa: E402
from research_lab.graph import EdgeType  # noqa: E402
from research_lab.lab import Lab  # noqa: E402
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind  # noqa: E402
from research_lab.store import Principal  # noqa: E402

TENANT = "acme"
ISSUERS = ["gov-1"]


@pytest.fixture
def principal() -> Principal:
    return Principal("alice", frozenset({TENANT}))


@pytest.fixture
def human() -> Actor:
    return Actor("alice", ActorKind.HUMAN)


@pytest.fixture
def reviewer() -> Actor:
    return Actor("bob", ActorKind.HUMAN)


@pytest.fixture
def ai() -> Actor:
    return Actor("model-1", ActorKind.AI, provider="vendor", model_family="family")


@pytest.fixture
def gov() -> Actor:
    return Actor("gov-1", ActorKind.HUMAN)


@pytest.fixture
def clock() -> StepClock:
    return StepClock()


@pytest.fixture
def db_path(tmp_path) -> str:
    return str(tmp_path / "lab.sqlite")


@pytest.fixture
def lab(db_path, principal, clock):
    created = Lab.create(db_path, TENANT, principal, ISSUERS, clock)
    yield created
    created.close()


def tamper(db_path: str) -> sqlite3.Connection:
    """An attacker with file access: drop the append-only triggers and return a raw connection."""
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.execute("DROP TRIGGER IF EXISTS events_no_update")
    conn.execute("DROP TRIGGER IF EXISTS events_no_delete")
    return conn


class Chain:
    """objective <- question <- hypothesis <- experiment <- finding, plus one supporting evidence."""

    def __init__(self, lab: Lab, human: Actor, ai: Actor) -> None:
        self.objective = lab.add(Kind.OBJECTIVE, {"title": "O"}, human)
        self.question = lab.add(Kind.QUESTION, {"text": "Q"}, human, edges=[(EdgeType.DECOMPOSES, self.objective.entity_id)])
        self.hypothesis = lab.add(Kind.HYPOTHESIS, {"text": "H"}, ai, edges=[(EdgeType.ANSWERS, self.question.entity_id)])
        self.experiment = lab.add(Kind.EXPERIMENT, {"text": "E"}, human, edges=[(EdgeType.TESTS, self.hypothesis.entity_id)])
        self.evidence = lab.add(
            Kind.EVIDENCE,
            {"text": "ev"},
            human,
            edges=[(EdgeType.SUPPORTS, self.hypothesis.entity_id), (EdgeType.DERIVES_FROM, self.experiment.entity_id)],
            evidence_label=EvidenceLabel.EXECUTED,
        )
        self.finding = lab.add(
            Kind.FINDING,
            {"text": "F"},
            ai,
            edges=[(EdgeType.DERIVES_FROM, self.experiment.entity_id)],
            evidence_label=EvidenceLabel.INFERRED,
        )


@pytest.fixture
def chain(lab, human, ai) -> Chain:
    return Chain(lab, human, ai)
