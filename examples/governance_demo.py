"""Authenticated governance: a forged disposition is refused, a signed grant is applied,
a replay is refused.

Run: python examples/governance_demo.py

    ******************************************************************************
    THIS DEMO SIGNS WITH A TEST-ONLY KEY. tests/ed25519_signer.py is a reference
    signer for tests: its seed is derived from a public label, so the "private" key
    is public, and it is not constant time. Nothing here is a real governance key.
    In real use the board signs OUTSIDE the lab (an HSM, a KMS, a hardware key, a
    CNS identity) and the lab only ever sees the public key and the signature.
    ******************************************************************************

The store is AUTHENTICATED: its genesis enrolls the board's PUBLIC key. An AI then tries
the increment 1 attack (invent an actor id, call it SYSTEM, quote the public issuer id) and
two forgeries with a key of its own; all are refused and nothing is written. The board signs
a grant for the exact version of the finding; the AI relays it, which is allowed, because
submitting is not authority. Replaying the grant is refused. Offline, a bundle of the store
re-verifies the grant from the file alone. The clock is injected, so the run is deterministic.
"""

from __future__ import annotations

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

from ed25519_signer import IssuerTestKey  # noqa: E402  (TEST-ONLY signer, see the banner above)

from research_lab.clock import StepClock  # noqa: E402
from research_lab.export import export_bundle, verify_bundle  # noqa: E402
from research_lab.governance import make_issuer  # noqa: E402
from research_lab.lab import Lab  # noqa: E402
from research_lab.lifecycle import LifecycleError  # noqa: E402
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind  # noqa: E402
from research_lab.store import Principal  # noqa: E402

TENANT = "demo-tenant"
PRINCIPAL = Principal("demo-operator", frozenset({TENANT}))
BOARD = "governance-board"
AI = Actor("model-1", ActorKind.AI, provider="demo-vendor", model_family="demo-family")
REVIEWER = Actor("reviewer-1", ActorKind.HUMAN)

BANNER = "TEST-ONLY KEYS: this demo signs with tests/ed25519_signer.py; nothing here is a real governance key"


def attempt(label: str, call) -> bool:
    try:
        call()
    except LifecycleError as exc:
        print(f"  REFUSED  {label}: {type(exc).__name__}: {str(exc)[:96]}")
        return False
    print(f"  APPLIED  {label}")
    return True


def main() -> int:
    print(BANNER)
    board_key = IssuerTestKey("demo board")  # held by the board; the lab never sees it
    ai_key = IssuerTestKey("demo ai")  # a key the AI made up for itself; enrolled nowhere
    with tempfile.TemporaryDirectory() as workdir:
        db = os.path.join(workdir, "lab.sqlite")
        issuer = make_issuer(BOARD, "human_body", board_key.public_key_hex)
        with Lab.create(db, TENANT, PRINCIPAL, [issuer], StepClock("2026-06-01T09:00:00Z")) as lab:
            print(f"== store created: governance mode {lab.governance_mode}; enrolled {issuer['issuer_id']} ({issuer['kind']}, {issuer['key_id']})")
            finding = lab.add(Kind.FINDING, {"text": "the cache is the bottleneck"}, AI, evidence_label=EvidenceLabel.INFERRED)
            for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
                lab.transition(finding.entity_id, stage, REVIEWER, "checked")
            fid = finding.entity_id
            print(f"== finding by {AI.id} is {lab.graph.node(fid).status} at version {lab.graph.node(fid).latest.version}")

            print("== 1. the AI tries to accept its own lab's finding without the board")
            events = lab.store.count()
            claim = Actor("model-2-relabelled", ActorKind.SYSTEM)
            attempt("claim kind SYSTEM and quote the public issuer id (attack A5)", lambda: lab.govern(fid, "ACCEPTED", claim, BOARD, "x"))
            template = lab.grant_template(fid, "ACCEPTED", BOARD, "accepted", "00" * 16, "2026-06-01T09:00:00Z", "2026-06-02T09:00:00Z")
            forged = {**template, "signature": ai_key.sign(lab.grant_signing_bytes(template)).hex()}
            attempt("a grant naming the board, signed with the AI's own key", lambda: lab.apply_grant(forged, AI))
            attempt("the same grant with no signature at all", lambda: lab.apply_grant(template, AI))
            print(f"  status {lab.graph.node(fid).status}; events written by the attempts: {lab.store.count() - events}")

            print("== 2. the board signs a grant for this exact version; the AI relays it")
            grant = lab.grant_template(fid, "ACCEPTED", BOARD, "Reproduced twice; the board accepts.", "a1" * 16, "2026-06-01T09:00:00Z", "2026-06-02T09:00:00Z")
            to_sign = lab.grant_signing_bytes(grant)
            print(f"  bytes to sign ({len(to_sign)}): {to_sign[:44]!r}...")
            signed = {**grant, "signature": board_key.sign(to_sign).hex()}  # OUTSIDE the lab in real use
            attempt("relay the board's signed grant (submitted by the AI)", lambda: lab.apply_grant(signed, AI))
            print(f"  status {lab.graph.node(fid).status}; submitted by kind {lab.graph.node(fid).latest.origin.kind.value}; authority: signature of {BOARD}")

            print("== 3. replay and tampering")
            attempt("the same grant a second time", lambda: lab.apply_grant(signed, AI))
            attempt("the same grant with the target edited to ADMITTED", lambda: lab.apply_grant({**signed, "to": "ADMITTED"}, AI))
            fresh = lab.grant_template(fid, "ADMITTED", BOARD, "admit", "a1" * 16, "2026-06-01T09:00:00Z", "2026-06-02T09:00:00Z")
            reuse = {**fresh, "signature": board_key.sign(lab.grant_signing_bytes(fresh)).hex()}
            attempt("a new, validly signed grant that reuses the nonce", lambda: lab.apply_grant(reuse, AI))

            result = lab.verify()
            report = result.governance
            print(f"== verify: ok={result.ok} mode={report['mode']} authenticated={report['authenticated']} unauthenticated={report['unauthenticated']}")
            bundle = os.path.join(workdir, "bundle.jsonl")
            export_bundle(lab.store, bundle)
            genesis_hash = report["genesis_hash"]
        offline = verify_bundle(bundle, expected_genesis_hash=genesis_hash, require_authenticated=True)
        print(f"== offline, from the bundle file alone: ok={offline.ok} grants re-verified={offline.governance['authenticated']}")
        ok = result.ok and offline.ok and report["authenticated"] == 1 and report["unauthenticated"] == 0
    print(BANNER)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
