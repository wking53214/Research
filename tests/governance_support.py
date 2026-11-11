"""Shared helpers for the governance port tests. TEST-ONLY keys throughout.

Every key here comes from tests/ed25519_signer.py: seeds derived from public labels, or the
published RFC 8032 test seed. None of them is a real key and none may be enrolled anywhere
outside these tests and examples/governance_demo.py.
"""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Any

from conftest import TENANT
from ed25519_signer import IssuerTestKey

from research_lab.canonical import canonical_json
from research_lab.clock import StepClock
from research_lab.governance import grant_signing_bytes, make_issuer
from research_lab.lab import Lab
from research_lab.records import Actor, ActorKind
from research_lab.store import Event, Principal, event_hash

START = "2026-06-01T12:00:00Z"
ISSUED = "2026-06-01T11:00:00Z"
EXPIRES = "2026-06-08T12:00:00Z"

BOARD = "governance-board"
RELEASE = "release-system"

# TEST-ONLY keys (public seeds). board and release are enrolled; outsider never is.
BOARD_KEY = IssuerTestKey("board")
RELEASE_KEY = IssuerTestKey("release")
OUTSIDER_KEY = IssuerTestKey("outsider")
KEYS = {BOARD: BOARD_KEY, RELEASE: RELEASE_KEY}


def issuers() -> list[dict[str, str]]:
    return [
        make_issuer(BOARD, "human_body", BOARD_KEY.public_key_hex),
        make_issuer(RELEASE, "system", RELEASE_KEY.public_key_hex),
    ]


def new_lab(path: str, clock=None, tenant: str = TENANT, **options: Any) -> Lab:
    principal = Principal("alice", frozenset({tenant}))
    return Lab.create(path, tenant, principal, issuers(), clock or StepClock(START), **options)


def nonce(n: int) -> str:
    """A deterministic 16-byte test nonce."""
    return hashlib.sha256(f"test nonce {n}".encode()).hexdigest()[:32]


def sign(grant: dict[str, Any], key: IssuerTestKey | None = None) -> dict[str, Any]:
    """Sign with the TEST key enrolled for the grant's issuer (or the key given)."""
    key = key or KEYS[grant["issuer_id"]]
    fields = {name: value for name, value in grant.items() if name != "signature"}
    return {**fields, "signature": key.sign(grant_signing_bytes(fields)).hex()}


_counter = [1000]


def signed_grant(lab: Lab, entity_id: str, to: str, issuer_id: str = BOARD, key: IssuerTestKey | None = None, **fields: Any) -> dict[str, Any]:
    """A grant for the entity's current version, signed by the issuer's TEST key."""
    _counter[0] += 1
    template = lab.grant_template(
        entity_id,
        to,
        issuer_id,
        fields.pop("reason", f"{to} by {issuer_id}"),
        fields.pop("nonce", nonce(_counter[0])),
        fields.pop("issued_at", ISSUED),
        fields.pop("expires_at", EXPIRES),
    )
    template.update(fields)
    return sign(template, key)


def recommend(lab: Lab, entity_id: str, reviewer: Actor | None = None) -> None:
    reviewer = reviewer or Actor("bob", ActorKind.HUMAN)
    for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
        lab.transition(entity_id, stage, reviewer, "r")


def rehash(events: list[Event]) -> list[Event]:
    """What an attacker with write access to an unsigned, unanchored log can do: recompute
    every hash so that the chain verifies again after an edit."""
    out: list[Event] = []
    prev = "0" * 64
    for seq, event in enumerate(events):
        digest = event_hash(seq, event.tenant, event.event_type, event.payload, prev)
        out.append(Event(seq, event.tenant, event.event_type, event.payload, prev, digest, None, None))
        prev = digest
    return out


def write_raw_store(path: str, events: list[Event]) -> None:
    """Write events straight into a new SQLite file, with no validation at all."""
    from research_lab.store import _SCHEMA

    conn = sqlite3.connect(path, isolation_level=None)
    conn.executescript(_SCHEMA)
    for event in events:
        conn.execute(
            "INSERT INTO events (seq, tenant, event_type, payload, prev_hash, hash, key_id, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (event.seq, event.tenant, event.event_type, canonical_json(event.payload), event.prev_hash, event.hash, event.key_id, event.signature),
        )
    conn.close()
