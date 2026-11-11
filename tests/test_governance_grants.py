"""The authenticated governance port: signed grants in an AUTHENTICATED store.

Refusals first. Every refusal is checked the same way: the right error, the event count
identical, and the store still opens and verifies. All keys are TEST-ONLY (see
tests/governance_support.py).
"""

import sqlite3

import pytest
from conftest import TENANT
from governance_support import (
    BOARD,
    BOARD_KEY,
    EXPIRES,
    ISSUED,
    OUTSIDER_KEY,
    RELEASE,
    RELEASE_KEY,
    START,
    issuers,
    new_lab,
    nonce,
    recommend,
    rehash,
    sign,
    signed_grant,
    write_raw_store,
)

from research_lab.canonical import canonical_json
from research_lab.clock import FixedClock, StepClock
from research_lab.governance import (
    GrantRefused,
    grant_digest,
    grant_signing_bytes,
    make_issuer,
    verify_grant_signature,
)
from research_lab.graph import EVENT_TRANSITION, Graph, PolicyViolation
from research_lab.lab import Lab, verify_store
from research_lab.lifecycle import AuthorityError, SelfReviewError, TransitionError
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind
from research_lab.store import GENESIS, AppendRefused, ConcurrentWriteConflict, EventStore, IntegrityError, event_hash

SUBMITTER = Actor("clerk-7", ActorKind.HUMAN)
AI_RELAY = Actor("model-2", ActorKind.AI, provider="vendor", model_family="family")


@pytest.fixture
def alab(db_path):
    lab = new_lab(db_path)
    yield lab
    lab.close()


@pytest.fixture
def finding(alab, ai):
    """An AI-authored finding that human review has moved to RECOMMENDED (version 4)."""
    record = alab.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED)
    recommend(alab, record.entity_id)
    return record.entity_id


def refused(lab, db_path, principal, call, match, error=GrantRefused):
    """call() must raise, write nothing and leave a store that opens and verifies."""
    count = lab.store.count()
    statuses = {entity_id: node.status for entity_id, node in lab.graph.nodes.items()}
    with pytest.raises(error, match=match):
        call()
    assert lab.store.count() == count
    assert {entity_id: node.status for entity_id, node in lab.graph.nodes.items()} == statuses
    assert Graph.rebuild(lab.store.events()) == lab.graph
    with Lab.open(db_path, TENANT, principal, StepClock(START)) as again:
        assert again.store.count() == count and again.verify().ok


def governance_event(lab, grant, actor, entity_id=None, to=None, reason=None, at=START):
    """A TRANSITION event payload that carries a grant, built by hand the way a forger would."""
    fields = {name: value for name, value in grant.items() if name != "signature"}
    node = lab.graph.node(entity_id or fields["entity_id"])
    to = to or fields["to"]
    provenance = {"type": "governance_disposition", "issuer_id": fields["issuer_id"], "reason": fields["reason"], "grant_digest": grant_digest(fields)}
    record = node.latest.next_version(origin=actor, created_at=at, disposition=to, provenance=(provenance,))
    return {
        "record": record.to_dict(),
        "from": node.status,
        "to": to,
        "actor": actor.to_dict(),
        "reason": reason or fields["reason"],
        "governance": {"issuer_id": fields["issuer_id"], "grant": fields, "signature": grant.get("signature")},
    }


# refusals: the signature


def test_grant_without_a_signature_is_refused(alab, db_path, principal, finding):
    grant = signed_grant(alab, finding, "ACCEPTED")
    unsigned = {name: value for name, value in grant.items() if name != "signature"}
    refused(alab, db_path, principal, lambda: alab.apply_grant(unsigned, SUBMITTER), "no signature")
    refused(alab, db_path, principal, lambda: alab.apply_grant({**unsigned, "signature": None}, SUBMITTER), "no signature")
    refused(alab, db_path, principal, lambda: alab.apply_grant({**unsigned, "signature": ""}, SUBMITTER), "128 lowercase hex")


def test_grant_with_a_bad_signature_is_refused(alab, db_path, principal, finding):
    grant = signed_grant(alab, finding, "ACCEPTED")
    flipped = bytearray(bytes.fromhex(grant["signature"]))
    flipped[40] ^= 1
    for bad in (flipped.hex(), "00" * 64, "ab" * 64, grant["signature"][:-2], grant["signature"] + "00", grant["signature"].upper()):
        refused(alab, db_path, principal, lambda bad=bad: alab.apply_grant({**grant, "signature": bad}, SUBMITTER), "signature")
    assert alab.graph.node(finding).status == "RECOMMENDED"


@pytest.mark.parametrize(
    "field, value",
    [
        ("reason", "a different reason"),
        ("to", "ADMITTED"),
        ("to", "WITHDRAWN"),
        ("expires_at", "2030-01-01T00:00:00Z"),
        ("issued_at", "2026-01-01T00:00:00Z"),
        ("nonce", nonce(1)),
        ("issuer_id", RELEASE),
        ("entity_version", 5),
        ("record_digest", "0" * 64),
        ("tenant", "other"),
    ],
)
def test_tampering_with_any_signed_field_is_refused(alab, db_path, principal, finding, field, value):
    grant = signed_grant(alab, finding, "ACCEPTED")
    assert grant[field] != value
    tampered = {**grant, field: value}
    refused(alab, db_path, principal, lambda: alab.apply_grant(tampered, SUBMITTER), "does not verify|tenant 'other'")


def test_grant_signed_by_a_key_that_is_not_the_issuers_is_refused(alab, db_path, principal, finding):
    wrong_key = signed_grant(alab, finding, "ACCEPTED", key=OUTSIDER_KEY)
    refused(alab, db_path, principal, lambda: alab.apply_grant(wrong_key, SUBMITTER), "does not verify under the enrolled key")
    # The key of a DIFFERENT enrolled issuer does not speak for this one either.
    other_enrolled = signed_grant(alab, finding, "ACCEPTED", issuer_id=BOARD, key=RELEASE_KEY)
    refused(alab, db_path, principal, lambda: alab.apply_grant(other_enrolled, SUBMITTER), "does not verify under the enrolled key")


def test_grant_from_an_issuer_that_is_not_enrolled_is_refused(alab, db_path, principal, finding):
    grant = signed_grant(alab, finding, "ACCEPTED", issuer_id="mallory", key=OUTSIDER_KEY)
    refused(alab, db_path, principal, lambda: alab.apply_grant(grant, SUBMITTER), "'mallory' is not enrolled")


# refusals: what the grant is bound to


def test_grant_for_another_tenant_is_refused(alab, db_path, principal, finding, tmp_path, ai):
    # A grant validly signed by the same board key, for the same entity id, in another tenant.
    other = new_lab(str(tmp_path / "other.sqlite"), tenant="other")
    elsewhere = other.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED)
    recommend(other, elsewhere.entity_id)
    foreign = signed_grant(other, elsewhere.entity_id, "ACCEPTED")
    other.close()
    assert foreign["tenant"] == "other"
    refused(alab, db_path, principal, lambda: alab.apply_grant(foreign, SUBMITTER), "tenant 'other', not this store's tenant 'acme'")
    relabelled = sign({**signed_grant(alab, finding, "ACCEPTED"), "tenant": "other"})
    refused(alab, db_path, principal, lambda: alab.apply_grant(relabelled, SUBMITTER), "tenant 'other'")


def test_grant_for_another_entity_is_refused(alab, db_path, principal, finding, ai):
    second = alab.add(Kind.FINDING, {"text": "second"}, ai, evidence_label=EvidenceLabel.INFERRED)
    recommend(alab, second.entity_id)
    grant = signed_grant(alab, finding, "ACCEPTED")
    # Re-pointing the grant breaks the signature.
    refused(alab, db_path, principal, lambda: alab.apply_grant({**grant, "entity_id": second.entity_id}, SUBMITTER), "does not verify")
    # A forged event that uses the grant for the first finding to accept the second.
    payload = governance_event(alab, grant, SUBMITTER, entity_id=second.entity_id)
    refused(alab, db_path, principal, lambda: alab.store.append(EVENT_TRANSITION, payload), "the grant is for entity", PolicyViolation)
    assert alab.graph.node(second.entity_id).status == "RECOMMENDED"
    alab.apply_grant(grant, SUBMITTER)  # the grant itself was never used up by the attempts
    assert alab.graph.node(finding).status == "ACCEPTED" and alab.graph.node(second.entity_id).status == "RECOMMENDED"


def test_grant_for_a_stale_version_is_refused_even_when_the_status_is_the_same_again(alab, db_path, principal, finding, reviewer):
    grant = signed_grant(alab, finding, "ACCEPTED")
    assert grant["entity_version"] == 4
    alab.transition(finding, "REPRODUCED", reviewer, "reviewer has second thoughts")
    refused(alab, db_path, principal, lambda: alab.apply_grant(grant, SUBMITTER), "disposes version 4 but the current version is 5")
    alab.transition(finding, "RECOMMENDED", reviewer, "recommended again")
    assert alab.graph.node(finding).status == "RECOMMENDED"  # same status as when the grant was signed
    refused(alab, db_path, principal, lambda: alab.apply_grant(grant, SUBMITTER), "disposes version 4 but the current version is 6")
    alab.apply_grant(signed_grant(alab, finding, "ACCEPTED"), SUBMITTER)  # a fresh grant for version 6 works


def test_grant_with_the_wrong_record_digest_is_refused(alab, db_path, principal, finding):
    earlier = alab.graph.node(finding).versions[2].digest  # a real digest, of version 3
    for wrong in ("0" * 64, earlier):
        grant = signed_grant(alab, finding, "ACCEPTED", record_digest=wrong)
        refused(alab, db_path, principal, lambda grant=grant: alab.apply_grant(grant, SUBMITTER), "record_digest is not the digest of version 4")
    future = signed_grant(alab, finding, "ACCEPTED", entity_version=5)
    refused(alab, db_path, principal, lambda: alab.apply_grant(future, SUBMITTER), "disposes version 5 but the current version is 4")


def test_grant_for_an_unknown_entity_is_refused(alab, db_path, principal, finding):
    grant = sign({**signed_grant(alab, finding, "ACCEPTED"), "entity_id": "finding_0000000000000000"})
    refused(alab, db_path, principal, lambda: alab.apply_grant(grant, SUBMITTER), "unknown entity", Exception)


# refusals: time


def test_expired_grant_is_refused(db_path, principal, ai):
    clock = StepClock(START)
    lab = new_lab(db_path, clock)
    f = lab.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(lab, f)
    grant = signed_grant(lab, f, "ACCEPTED", issued_at="2026-06-01T11:00:00Z", expires_at="2026-06-01T11:59:59Z")
    refused(lab, db_path, principal, lambda: lab.apply_grant(grant, SUBMITTER), "the grant expired at 2026-06-01T11:59:59Z")
    lab.clock = FixedClock("2026-06-01T12:30:00Z")
    at_the_instant = signed_grant(lab, f, "ACCEPTED", expires_at="2026-06-01T12:30:00Z")
    refused(lab, db_path, principal, lambda: lab.apply_grant(at_the_instant, SUBMITTER), "expired")  # expires_at is exclusive
    one_second_left = signed_grant(lab, f, "ACCEPTED", expires_at="2026-06-01T12:30:01Z")
    assert lab.apply_grant(one_second_left, SUBMITTER).disposition == "ACCEPTED"
    lab.close()


def test_grant_issued_in_the_future_is_refused_beyond_the_skew(db_path, principal, ai):
    lab = new_lab(db_path, FixedClock("2026-06-01T12:00:00Z"))
    assert lab.graph.grant_skew_seconds == 300  # the documented default
    f = lab.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(lab, f)
    too_early = signed_grant(lab, f, "ACCEPTED", issued_at="2026-06-01T12:05:01Z")
    refused(lab, db_path, principal, lambda: lab.apply_grant(too_early, SUBMITTER), "issued in the future")
    far = signed_grant(lab, f, "ACCEPTED", issued_at="2027-01-01T00:00:00Z", expires_at="2027-01-02T00:00:00Z")
    refused(lab, db_path, principal, lambda: lab.apply_grant(far, SUBMITTER), "issued in the future")
    within_skew = signed_grant(lab, f, "ACCEPTED", issued_at="2026-06-01T12:05:00Z")
    assert lab.apply_grant(within_skew, SUBMITTER).disposition == "ACCEPTED"
    lab.close()


def test_skew_is_fixed_at_genesis_and_zero_means_zero(db_path, principal, ai):
    lab = new_lab(db_path, FixedClock("2026-06-01T12:00:00Z"), grant_skew_seconds=0)
    assert lab.store.genesis()["grant_skew_seconds"] == 0
    f = lab.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(lab, f)
    one_second_ahead = signed_grant(lab, f, "ACCEPTED", issued_at="2026-06-01T12:00:01Z")
    refused(lab, db_path, principal, lambda: lab.apply_grant(one_second_ahead, SUBMITTER), "issued in the future")
    assert lab.apply_grant(signed_grant(lab, f, "ACCEPTED", issued_at="2026-06-01T12:00:00Z"), SUBMITTER).disposition == "ACCEPTED"
    lab.close()


@pytest.mark.parametrize("issued, expires", [("2026-06-02T00:00:00Z", "2026-06-01T00:00:00Z"), (ISSUED, ISSUED), ("yesterday", EXPIRES), (ISSUED, "2026-06-08 12:00:00")])
def test_malformed_time_window_is_refused(alab, db_path, principal, finding, issued, expires):
    template = alab.grant_template(finding, "ACCEPTED", BOARD, "r", nonce(2), ISSUED, EXPIRES)
    template.update(issued_at=issued, expires_at=expires)
    signature = BOARD_KEY.sign(b"research-lab/governance-grant/1\n" + canonical_json(template).encode("ascii")).hex()
    refused(alab, db_path, principal, lambda: alab.apply_grant({**template, "signature": signature}, SUBMITTER), "expires_at|issued_at")


# refusals: single use


def test_the_same_grant_cannot_be_applied_twice(alab, db_path, principal, finding):
    grant = signed_grant(alab, finding, "ACCEPTED")
    alab.apply_grant(grant, SUBMITTER)
    refused(alab, db_path, principal, lambda: alab.apply_grant(grant, SUBMITTER), "nonce was already used")
    refused(alab, db_path, principal, lambda: alab.apply_grant(grant, AI_RELAY), "nonce was already used")
    assert len(alab.graph.node(finding).versions) == 5


def test_a_nonce_cannot_be_reused_with_different_content(alab, db_path, principal, finding, ai):
    second = alab.add(Kind.FINDING, {"text": "second"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(alab, second)
    first = signed_grant(alab, finding, "ACCEPTED", nonce=nonce(7))
    alab.apply_grant(first, SUBMITTER)
    # Validly signed, a different entity, a different transition, a different issuer: same nonce.
    for reuse in (
        signed_grant(alab, second, "ACCEPTED", nonce=nonce(7)),
        signed_grant(alab, finding, "ADMITTED", nonce=nonce(7)),
        signed_grant(alab, second, "ACCEPTED", issuer_id=RELEASE, nonce=nonce(7)),
    ):
        refused(alab, db_path, principal, lambda reuse=reuse: alab.apply_grant(reuse, SUBMITTER), "nonce was already used")
    alab.close()
    with Lab.open(db_path, TENANT, principal, StepClock(START)) as again:  # the used set is rebuilt from the log
        assert again.graph.used_grant_nonces == {nonce(7)}
        with pytest.raises(GrantRefused, match="nonce was already used"):
            again.apply_grant(signed_grant(again, second, "ACCEPTED", nonce=nonce(7)), SUBMITTER)
        again.apply_grant(signed_grant(again, second, "ACCEPTED", nonce=nonce(8)), SUBMITTER)


@pytest.mark.parametrize("bad", ["", "abcd", "00" * 15, "00" * 33, "0" * 33, "AB" * 16, "zz" * 16, 12345678901234567890123456789012, None])
def test_malformed_nonce_is_refused(alab, db_path, principal, finding, bad):
    template = alab.grant_template(finding, "ACCEPTED", BOARD, "r", nonce(3), ISSUED, EXPIRES)
    template["nonce"] = bad
    signature = BOARD_KEY.sign(b"research-lab/governance-grant/1\n" + canonical_json(template).encode("ascii")).hex()
    refused(alab, db_path, principal, lambda: alab.apply_grant({**template, "signature": signature}, SUBMITTER), "nonce must be 16 to 32 bytes")


def test_nonce_of_32_bytes_is_accepted(alab, finding):
    assert alab.apply_grant(signed_grant(alab, finding, "ACCEPTED", nonce="ab" * 32), SUBMITTER).disposition == "ACCEPTED"


# refusals: lifecycle and authority rules that still hold


def test_issuer_that_authored_the_finding_cannot_accept_it(alab, db_path, principal, reviewer):
    own = alab.add(Kind.FINDING, {"text": "the board's own finding"}, Actor(BOARD, ActorKind.HUMAN), evidence_label=EvidenceLabel.INFERRED)
    recommend(alab, own.entity_id)
    grant = signed_grant(alab, own.entity_id, "ACCEPTED", issuer_id=BOARD)
    refused(alab, db_path, principal, lambda: alab.apply_grant(grant, SUBMITTER), "issuer 'governance-board' authored this finding", SelfReviewError)
    other_issuer = signed_grant(alab, own.entity_id, "ACCEPTED", issuer_id=RELEASE)
    assert alab.apply_grant(other_issuer, SUBMITTER).disposition == "ACCEPTED"


def test_issuer_that_filed_the_challenge_cannot_resolve_it(alab, db_path, principal, finding):
    challenge = alab.file_challenge(finding, "we doubt it", Actor(BOARD, ActorKind.HUMAN), [{"type": "evidence_ref", "ref": "r"}])
    grant = signed_grant(alab, challenge.entity_id, "DISMISSED", issuer_id=BOARD)
    refused(alab, db_path, principal, lambda: alab.apply_grant(grant, SUBMITTER), "filed this challenge and may not resolve it", SelfReviewError)


def test_grant_cannot_skip_the_lifecycle_or_make_a_lab_transition(alab, db_path, principal, ai, finding):
    proposed = alab.add(Kind.FINDING, {"text": "new"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    skip = signed_grant(alab, proposed, "ACCEPTED")
    refused(alab, db_path, principal, lambda: alab.apply_grant(skip, SUBMITTER), "PROPOSED -> ACCEPTED is not an allowed transition", TransitionError)
    admit = signed_grant(alab, finding, "ADMITTED")
    refused(alab, db_path, principal, lambda: alab.apply_grant(admit, SUBMITTER), "RECOMMENDED -> ADMITTED is not an allowed transition", TransitionError)
    review = signed_grant(alab, proposed, "REVIEWED")
    refused(alab, db_path, principal, lambda: alab.apply_grant(review, SUBMITTER), "not a governance transition", AuthorityError)
    lab_withdrawal = signed_grant(alab, finding, "WITHDRAWN")  # RECOMMENDED -> WITHDRAWN is a lab transition
    refused(alab, db_path, principal, lambda: alab.apply_grant(lab_withdrawal, SUBMITTER), "not a governance transition", AuthorityError)
    objective = alab.add(Kind.OBJECTIVE, {"title": "O"}, SUBMITTER).entity_id
    wrong_kind = signed_grant(alab, objective, "ACCEPTED")
    refused(alab, db_path, principal, lambda: alab.apply_grant(wrong_kind, SUBMITTER), "apply to findings and challenges", AuthorityError)
    nonsense = signed_grant(alab, finding, "BLESSED")
    refused(alab, db_path, principal, lambda: alab.apply_grant(nonsense, SUBMITTER), "not a finding stage", TransitionError)


@pytest.mark.parametrize("field, value", [("reason", ""), ("reason", "   "), ("reason", None), ("v", 2), ("v", True), ("entity_version", "4"), ("entity_version", 0), ("to", "")])
def test_malformed_fields_are_refused_even_when_validly_signed(alab, db_path, principal, finding, field, value):
    template = alab.grant_template(finding, "ACCEPTED", BOARD, "r", nonce(4), ISSUED, EXPIRES)
    template[field] = value
    signature = BOARD_KEY.sign(b"research-lab/governance-grant/1\n" + canonical_json(template).encode("ascii")).hex()
    refused(alab, db_path, principal, lambda: alab.apply_grant({**template, "signature": signature}, SUBMITTER), "grant")


def test_unknown_missing_and_non_nfc_fields_are_refused(alab, db_path, principal, finding):
    grant = signed_grant(alab, finding, "ACCEPTED")
    refused(alab, db_path, principal, lambda: alab.apply_grant({**grant, "scope": "everything"}, SUBMITTER), "unexpected \\['scope'\\]")
    missing = {name: value for name, value in grant.items() if name != "expires_at"}
    refused(alab, db_path, principal, lambda: alab.apply_grant(missing, SUBMITTER), "missing \\['expires_at'\\]")
    decomposed = {**grant, "reason": "résumé"}  # NFD; canonical JSON would silently change it
    refused(alab, db_path, principal, lambda: alab.apply_grant(decomposed, SUBMITTER), "NFC")
    for not_an_object in (None, "grant", [grant], 7):
        refused(alab, db_path, principal, lambda item=not_an_object: alab.apply_grant(item, SUBMITTER), "JSON object")


# refusals: the old claim-based path, which is attack A5


def test_ai_inventing_an_id_and_claiming_system_is_refused_a5(alab, db_path, principal, finding):
    """Attack A5: an AI invents an actor id, labels itself SYSTEM and quotes a public issuer id."""
    invented = Actor("model-2-relabelled", ActorKind.SYSTEM)
    for issuer_id in (BOARD, RELEASE, "gov-1"):
        refused(alab, db_path, principal, lambda i=issuer_id: alab.govern(finding, "ACCEPTED", invented, i, "x"), "this store is AUTHENTICATED")
    # Even a genuine-looking HUMAN actor named after the issuer has no authority without a signature.
    refused(alab, db_path, principal, lambda: alab.govern(finding, "ACCEPTED", Actor(BOARD, ActorKind.HUMAN), BOARD, "x"), "this store is AUTHENTICATED")
    assert alab.graph.node(finding).status == "RECOMMENDED"


def test_ai_claiming_system_cannot_resolve_a_challenge_y2(alab, db_path, principal, finding, ai):
    """Attack Y2: another AI claims SYSTEM and dismisses a challenge."""
    challenge = alab.file_challenge(finding, "looks wrong", ai, [{"type": "evidence_ref", "ref": "r"}]).entity_id
    claim = Actor("model-9", ActorKind.SYSTEM)
    for to in ("DISMISSED", "UPHELD"):
        refused(alab, db_path, principal, lambda to=to: alab.govern(challenge, to, claim, BOARD, "x"), "this store is AUTHENTICATED")
    assert alab.graph.node(challenge).status == "OPEN"


def legacy_form_payload(lab, entity_id, to, actor, issuer_id):
    """The increment 1 governance event: an issuer id and nothing else."""
    node = lab.graph.node(entity_id)
    record = node.latest.next_version(
        origin=actor, created_at=START, disposition=to, provenance=({"type": "governance_disposition", "issuer_id": issuer_id, "reason": "claimed"},)
    )
    return {"record": record.to_dict(), "from": node.status, "to": to, "actor": actor.to_dict(), "reason": "claimed", "governance": {"issuer_id": issuer_id}}


def test_claim_based_governance_event_is_refused_at_write_time_by_lab_store_and_bare_store(alab, db_path, principal, finding):
    human_claim = Actor("someone", ActorKind.HUMAN)
    payload = legacy_form_payload(alab, finding, "ACCEPTED", human_claim, BOARD)
    refused(alab, db_path, principal, lambda: alab.store.append(EVENT_TRANSITION, payload), "needs a signed grant", PolicyViolation)
    alab.close()
    bare = EventStore.open(db_path, TENANT, principal)  # the mandatory validator is attached by default
    count = bare.count()
    with pytest.raises(PolicyViolation, match="needs a signed grant"):
        bare.append(EVENT_TRANSITION, payload)
    assert bare.count() == count
    bare.close()
    Lab.open(db_path, TENANT, principal, StepClock(START)).close()


# refusals: forged grant events written around the Lab


def forged_events(lab, finding):
    """Grant events a forger without an enrolled private key can build."""
    good = signed_grant(lab, finding, "ACCEPTED")
    outsider = signed_grant(lab, finding, "ACCEPTED", key=OUTSIDER_KEY)
    unenrolled = signed_grant(lab, finding, "ACCEPTED", issuer_id="mallory", key=OUTSIDER_KEY)
    garbage = {**good, "signature": "11" * 64}
    reason_edit = {**good, "reason": "edited after signing"}
    return {
        "outsider key": (governance_event(lab, outsider, AI_RELAY), "does not verify"),
        "unenrolled issuer": (governance_event(lab, unenrolled, AI_RELAY), "is not enrolled"),
        "garbage signature": (governance_event(lab, garbage, AI_RELAY), "does not verify"),
        "edited reason": (governance_event(lab, reason_edit, AI_RELAY), "does not verify"),
        "event reason differs from grant": (governance_event(lab, good, AI_RELAY, reason="another reason"), "exactly the grant's"),
        "event to differs from grant": (governance_event(lab, good, AI_RELAY, to="WITHDRAWN"), "exactly the grant's|not the event's to"),
        "no signature": (governance_event(lab, {k: v for k, v in good.items() if k != "signature"}, AI_RELAY), "no signature"),
        "extra governance key": (
            {**(p := governance_event(lab, good, AI_RELAY)), "governance": {**p["governance"], "override": True}},
            "exactly \\{issuer_id, grant, signature\\}",
        ),
        "extra key inside the event's grant": (
            {**(p := governance_event(lab, good, AI_RELAY)), "governance": {**p["governance"], "grant": {**p["governance"]["grant"], "signature": good["signature"]}}},
            "unexpected \\['signature'\\]",
        ),
        "issuer_id differs from grant": (
            {**(p := governance_event(lab, good, AI_RELAY)), "governance": {**p["governance"], "issuer_id": RELEASE}},
            "issuer_id differs",
        ),
    }


def test_forged_grant_events_are_refused_at_write_time_through_a_bare_store(alab, db_path, principal, finding):
    cases = forged_events(alab, finding)
    alab.close()
    bare = EventStore.open(db_path, TENANT, principal)
    count = bare.count()
    for name, (payload, match) in cases.items():
        with pytest.raises(PolicyViolation, match=match):
            bare.append(EVENT_TRANSITION, payload)
        assert bare.count() == count, name
    bare.close()
    with Lab.open(db_path, TENANT, principal, StepClock(START)) as again:
        assert again.graph.node(finding).status == "RECOMMENDED" and again.verify().ok


@pytest.mark.parametrize("case", ["outsider key", "unenrolled issuer", "garbage signature", "edited reason", "event reason differs from grant", "no signature"])
def test_forged_grant_event_written_through_the_unsafe_opt_out_is_refused_on_replay(alab, db_path, principal, finding, case):
    payload, match = forged_events(alab, finding)[case]
    alab.close()
    unsafe = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)
    unsafe.append(EVENT_TRANSITION, payload)  # nothing checks it here; that is what the opt-out means
    unsafe.close()
    with pytest.raises(PolicyViolation, match=match):
        Lab.open(db_path, TENANT, principal, StepClock(START))
    with EventStore.open(db_path, TENANT, principal) as bare:
        result = verify_store(bare)
        assert not result.ok and not result.policy_checked
        assert any("policy violation" in problem for problem in result.problems)


def test_legacy_form_event_written_through_the_unsafe_opt_out_is_refused_on_replay(alab, db_path, principal, finding):
    payload = legacy_form_payload(alab, finding, "ACCEPTED", Actor("sys-claim", ActorKind.SYSTEM), BOARD)
    alab.close()
    unsafe = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)
    unsafe.append(EVENT_TRANSITION, payload)
    unsafe.close()
    with pytest.raises(PolicyViolation, match="needs a signed grant"):
        Lab.open(db_path, TENANT, principal, StepClock(START))


def test_backdated_or_replayed_grant_events_are_refused_on_replay(alab, db_path, principal, finding):
    """A grant event whose lab time is outside the window, and a second event reusing a
    nonce, are refused by the replay exactly as by the write path."""
    expired = signed_grant(alab, finding, "ACCEPTED", issued_at="2026-06-01T11:00:00Z", expires_at="2026-06-01T11:30:00Z")
    payload = governance_event(alab, expired, AI_RELAY, at="2026-06-01T12:00:00Z")
    with pytest.raises(PolicyViolation, match="expired"):
        alab.store.append(EVENT_TRANSITION, payload)
    alab.close()
    unsafe = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)
    unsafe.append(EVENT_TRANSITION, payload)
    unsafe.close()
    with pytest.raises(PolicyViolation, match="expired"):
        Lab.open(db_path, TENANT, principal, StepClock(START))


# refusals: genesis


def test_second_genesis_is_refused_on_write_and_on_replay(alab, db_path, principal, finding):
    mallory = make_issuer("mallory", "human_body", OUTSIDER_KEY.public_key_hex)
    payload = {"schema_version": 2, "tenant": TENANT, "governance_mode": "AUTHENTICATED", "governance_issuers": [mallory], "grant_skew_seconds": 300, "principals": ["alice"]}
    with pytest.raises(AppendRefused, match="fixed at genesis"):
        alab.store.append(GENESIS, payload)
    downgrade = {"schema_version": 2, "tenant": TENANT, "governance_mode": "UNAUTHENTICATED_LEGACY", "governance_issuers": ["mallory"], "principals": ["alice"]}
    with pytest.raises(AppendRefused, match="fixed at genesis"):
        alab.store.append(GENESIS, downgrade)
    head = alab.store.head()
    alab.close()
    for attempt in (payload, downgrade):
        seq = head.seq + 1
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.execute(
            "INSERT INTO events (seq, tenant, event_type, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
            (seq, TENANT, GENESIS, canonical_json(attempt), head.hash, event_hash(seq, TENANT, GENESIS, attempt, head.hash)),
        )
        conn.close()
        with pytest.raises(IntegrityError, match="second genesis"):
            Lab.open(db_path, TENANT, principal, StepClock(START))
        bare = EventStore.open(db_path, TENANT, principal)
        with pytest.raises(PolicyViolation, match="GENESIS: second genesis"):
            Graph.rebuild(bare.events())
        assert bare.governance_mode == "AUTHENTICATED" and bare.governance_issuers == frozenset({BOARD, RELEASE})
        bare.close()
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.execute("DROP TRIGGER IF EXISTS events_no_delete")
        conn.execute("DELETE FROM events WHERE seq = ?", (seq,))
        conn.close()


def test_no_event_type_touches_issuers_keys_or_mode(alab, db_path, principal, finding):
    for event_type in ("ISSUER_ADDED", "KEY_ROTATED", "GOVERNANCE_MODE", "ENROLL"):
        refused(alab, db_path, principal, lambda t=event_type: alab.store.append(t, {"issuer_id": "mallory", "public_key": OUTSIDER_KEY.public_key_hex}), "unknown event type", PolicyViolation)
    for cls in (Lab, EventStore, Graph):
        assert not [name for name in dir(cls) if any(word in name.lower() for word in ("enroll", "rotate", "revoke", "set_mode", "add_key"))]


def test_tampered_genesis_key_or_mode_is_detected_at_open(alab, db_path, principal, finding):
    alab.apply_grant(signed_grant(alab, finding, "ACCEPTED"), SUBMITTER)
    genesis = alab.store.genesis()
    alab.close()
    swapped = dict(genesis, governance_issuers=[make_issuer(BOARD, "human_body", OUTSIDER_KEY.public_key_hex), genesis["governance_issuers"][1]])
    downgraded = {"schema_version": 2, "tenant": TENANT, "governance_mode": "UNAUTHENTICATED_LEGACY", "governance_issuers": [BOARD], "principals": ["alice"]}
    for tampered in (swapped, downgraded):
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.execute("DROP TRIGGER IF EXISTS events_no_update")
        conn.execute("UPDATE events SET payload = ? WHERE seq = 0", (canonical_json(tampered),))
        conn.close()
        with pytest.raises(IntegrityError, match="seq 0: hash mismatch"):
            Lab.open(db_path, TENANT, principal, StepClock(START))
        with EventStore.open(db_path, TENANT, principal) as bare:
            assert not verify_store(bare).ok


def test_genesis_rewritten_and_whole_chain_rehashed_breaks_the_grants_already_recorded(alab, db_path, principal, finding, tmp_path):
    """An attacker who rewrites the whole file can fix every hash, but not the signatures:
    swapping the board's key (or downgrading the mode) makes the recorded grant fail."""
    alab.apply_grant(signed_grant(alab, finding, "ACCEPTED"), SUBMITTER)
    events = alab.store.events()
    genesis_hash = events[0].hash
    genesis = events[0].payload
    swapped = dict(genesis, governance_issuers=[make_issuer(BOARD, "human_body", OUTSIDER_KEY.public_key_hex), genesis["governance_issuers"][1]])
    forged = rehash([type(events[0])(0, TENANT, GENESIS, swapped, "", "", None, None), *events[1:]])
    path = str(tmp_path / "rewritten.sqlite")
    write_raw_store(path, forged)
    with EventStore.open(path, TENANT, principal) as bare:
        assert bare.verify().ok  # the chain alone is satisfied: every hash was recomputed
        result = verify_store(bare)
        assert not result.ok and any("does not verify under the enrolled key" in problem for problem in result.problems)
    with pytest.raises(PolicyViolation, match="does not verify under the enrolled key"):
        Lab.open(path, TENANT, principal, StepClock(START))
    assert forged[0].hash != genesis_hash


def test_recorded_gap_a_fully_rewritten_store_with_the_attackers_own_key_verifies_unless_the_genesis_is_pinned(db_path, principal, ai, tmp_path):
    """A recorded limitation, asserted so that it cannot be forgotten: with no anchor and no
    store signer, someone who can replace the whole file can write a new genesis that
    enrolls THEIR key and sign their own grants. Everything in that file verifies. The only
    defence is to compare the genesis hash (or the enrolled public keys) with a value
    obtained out of band, which is why verify reports genesis_hash."""
    honest = new_lab(db_path)
    f = honest.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(honest, f)
    pinned = honest.verify().governance["genesis_hash"]
    honest.close()
    path = str(tmp_path / "attacker.sqlite")
    theirs = Lab.create(path, TENANT, principal, [make_issuer(BOARD, "human_body", OUTSIDER_KEY.public_key_hex)], StepClock(START))
    g = theirs.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(theirs, g)
    theirs.apply_grant(signed_grant(theirs, g, "ACCEPTED", key=OUTSIDER_KEY), SUBMITTER)
    result = theirs.verify()
    theirs.close()
    assert result.ok and result.governance["authenticated"] == 1
    assert result.governance["genesis_hash"] != pinned  # the pin is what tells the two stores apart


def test_recorded_gap_the_lab_clock_is_trusted_so_a_backdated_event_can_use_an_expired_grant(alab, db_path, principal, finding):
    """A recorded limitation, asserted. The grant's window is compared with the timestamp of
    the version the event writes, and whoever writes the event chooses that timestamp (the
    injected clock, `--at`, or a raw append). An expired grant that was never used can
    therefore be applied by someone who backdates the event. The grant still authorizes only
    this transition of this exact version, once."""
    expired = signed_grant(alab, finding, "ACCEPTED", issued_at="2026-06-01T11:00:00Z", expires_at="2026-06-01T11:30:00Z")
    with pytest.raises(GrantRefused, match="expired"):
        alab.apply_grant(expired, AI_RELAY)  # the honest clock refuses it
    backdated = governance_event(alab, expired, AI_RELAY, at="2026-06-01T11:15:00Z")
    alab.store.append(EVENT_TRANSITION, backdated)
    assert alab.graph.node(finding).status == "ACCEPTED"
    alab.close()
    with Lab.open(db_path, TENANT, principal, StepClock(START)) as again:
        assert again.verify().ok and again.verify().governance["authenticated"] == 1
        with pytest.raises(GrantRefused, match="nonce was already used"):
            again.apply_grant(expired, AI_RELAY)


def test_recorded_gap_code_running_inside_the_lab_process_can_poison_the_store_but_not_pass_replay(alab, db_path, principal, finding):
    """A recorded limitation, asserted. The validator is in-process state. Code running in
    the lab's own process can overwrite the live graph's enrolled key (or use the unsafe
    opt-out) and get a forged grant written. It does not survive: the next open and every
    verify read the genesis from the log, refuse the forged event and refuse the store.
    That is a denial of service on the store, not a forged disposition that verifies."""
    alab.graph.governance_keys[BOARD] = make_issuer(BOARD, "human_body", OUTSIDER_KEY.public_key_hex)
    forged = signed_grant(alab, finding, "ACCEPTED", key=OUTSIDER_KEY)
    assert alab.apply_grant(forged, AI_RELAY).disposition == "ACCEPTED"  # written, in this process only
    alab.close()
    with pytest.raises(PolicyViolation, match="does not verify under the enrolled key"):
        Lab.open(db_path, TENANT, principal, StepClock(START))
    with EventStore.open(db_path, TENANT, principal) as bare:
        result = verify_store(bare)
        assert not result.ok and result.governance is None


# what is allowed


def test_valid_grant_accepts_then_a_second_grant_admits(alab, db_path, principal, finding):
    accept = signed_grant(alab, finding, "ACCEPTED", reason="Reproduced twice; the board accepts.")
    accepted = alab.apply_grant(accept, SUBMITTER)
    assert accepted.disposition == "ACCEPTED" and accepted.version == 5 and accepted.origin == SUBMITTER
    assert accepted.provenance == (
        {"type": "governance_disposition", "issuer_id": BOARD, "reason": "Reproduced twice; the board accepts.", "grant_digest": grant_digest({k: v for k, v in accept.items() if k != "signature"})},
    )
    admit = signed_grant(alab, finding, "ADMITTED", issuer_id=RELEASE)  # the "system" kind issuer
    assert admit["entity_version"] == 5 and admit["record_digest"] == accepted.digest
    admitted = alab.apply_grant(admit, SUBMITTER)
    assert admitted.disposition == "ADMITTED" and [r.disposition for r in alab.graph.history(finding)][-3:] == ["RECOMMENDED", "ACCEPTED", "ADMITTED"]
    event = alab.store.head()
    assert event.payload["governance"] == {"issuer_id": RELEASE, "grant": {k: v for k, v in admit.items() if k != "signature"}, "signature": admit["signature"]}
    result = alab.verify()
    assert result.ok and result.policy_checked
    report = result.governance
    assert report["mode"] == "AUTHENTICATED" and report["authenticated"] == 2 and report["unauthenticated"] == 0
    assert [(d["to"], d["issuer_id"], d["authenticated"], d["key_id"]) for d in report["dispositions"]] == [
        ("ACCEPTED", BOARD, True, issuers()[0]["key_id"]),
        ("ADMITTED", RELEASE, True, issuers()[1]["key_id"]),
    ]
    count = alab.store.count()
    alab.close()
    with Lab.open(db_path, TENANT, principal, StepClock(START)) as again:
        assert again.store.count() == count and again.graph.node(finding).status == "ADMITTED"
        assert Graph.rebuild(again.store.events()) == again.graph
        assert again.verify().governance == report


def test_ai_actor_relaying_a_valid_grant_is_allowed(alab, db_path, principal, finding, ai):
    """Submission is not authority. An AI that was handed a signed grant may submit it; so
    may the finding's own AI author. Neither could have produced the signature."""
    record = alab.apply_grant(signed_grant(alab, finding, "ACCEPTED"), AI_RELAY)
    assert record.disposition == "ACCEPTED" and record.origin.kind is ActorKind.AI
    assert alab.graph.node(finding).author == ai
    by_author = alab.apply_grant(signed_grant(alab, finding, "ADMITTED"), ai)
    assert by_author.disposition == "ADMITTED" and by_author.origin == ai
    dispositions = alab.verify().governance["dispositions"]
    assert [d["submitted_by"]["kind"] for d in dispositions] == ["AI", "AI"] and all(d["authenticated"] for d in dispositions)
    alab.close()
    Lab.open(db_path, TENANT, principal, StepClock(START)).close()


def test_governance_withdrawal_of_accepted_and_admitted_findings_goes_through_grants(alab, db_path, principal, finding, ai, reviewer):
    alab.apply_grant(signed_grant(alab, finding, "ACCEPTED"), SUBMITTER)
    with pytest.raises(AuthorityError, match="governance-only"):
        alab.transition(finding, "WITHDRAWN", reviewer, "the lab cannot")
    refused(alab, db_path, principal, lambda: alab.govern(finding, "WITHDRAWN", Actor("gov", ActorKind.HUMAN), BOARD, "claim"), "this store is AUTHENTICATED")
    withdrawn = alab.apply_grant(signed_grant(alab, finding, "WITHDRAWN", reason="superseded by new evidence"), SUBMITTER)
    assert withdrawn.disposition == "WITHDRAWN"
    second = alab.add(Kind.FINDING, {"text": "second"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(alab, second)
    alab.apply_grant(signed_grant(alab, second, "ACCEPTED"), SUBMITTER)
    alab.apply_grant(signed_grant(alab, second, "ADMITTED"), SUBMITTER)
    assert alab.apply_grant(signed_grant(alab, second, "WITHDRAWN", issuer_id=RELEASE), AI_RELAY).disposition == "WITHDRAWN"
    terminal = signed_grant(alab, second, "ACCEPTED")
    refused(alab, db_path, principal, lambda: alab.apply_grant(terminal, SUBMITTER), "WITHDRAWN -> ACCEPTED is not an allowed transition", TransitionError)
    assert alab.verify().governance["authenticated"] == 5


def test_challenges_are_upheld_and_dismissed_through_grants(alab, db_path, principal, finding, ai, reviewer):
    alab.apply_grant(signed_grant(alab, finding, "ACCEPTED"), SUBMITTER)
    first = alab.file_challenge(finding, "counterexample", ai, [{"type": "evidence_ref", "ref": "r1"}]).entity_id
    second = alab.file_challenge(finding, "weak", reviewer, [{"type": "evidence_ref", "ref": "r2"}]).entity_id
    with pytest.raises(AuthorityError, match="governance-only"):
        alab.transition(first, "UPHELD", reviewer, "the lab cannot")
    upheld = alab.apply_grant(signed_grant(alab, first, "UPHELD", reason="the challenge is right"), SUBMITTER)
    dismissed = alab.apply_grant(signed_grant(alab, second, "DISMISSED", issuer_id=RELEASE), AI_RELAY)
    assert upheld.disposition == "UPHELD" and dismissed.disposition == "DISMISSED"
    assert alab.graph.node(finding).status == "ACCEPTED"  # upholding a challenge does not withdraw the finding
    assert alab.graph.open_challenges(finding) == []
    again = signed_grant(alab, first, "DISMISSED")
    refused(alab, db_path, principal, lambda: alab.apply_grant(again, SUBMITTER), "UPHELD -> DISMISSED is not an allowed transition", TransitionError)
    summary = alab.graph.challenge_summary(finding)
    assert [item["status"] for item in summary] == ["UPHELD", "DISMISSED"]
    assert summary[0]["resolution"]["provenance"][0]["issuer_id"] == BOARD


def test_two_labs_holding_grants_for_the_same_version_only_one_wins(db_path, principal, ai):
    one = new_lab(db_path)
    f = one.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(one, f)
    two = Lab.open(db_path, TENANT, principal, StepClock(START))
    first, second = signed_grant(one, f, "ACCEPTED"), signed_grant(two, f, "ACCEPTED", issuer_id=RELEASE)
    one.apply_grant(first, SUBMITTER)
    count = one.store.count()
    with pytest.raises(ConcurrentWriteConflict, match=r"another writer appended 1 event.*version 5 does not follow 5"):
        two.apply_grant(second, SUBMITTER)  # two's graph was stale; the store checked against the real head
    assert two.store.count() == count and two.graph == one.graph
    one.close()
    two.close()


def test_grant_template_and_signing_bytes_are_exactly_what_the_verifier_checks(alab, finding):
    template = alab.grant_template(finding, "ACCEPTED", BOARD, "why", nonce(9), ISSUED, EXPIRES)
    node = alab.graph.node(finding)
    assert template == {
        "v": 1,
        "tenant": TENANT,
        "entity_id": finding,
        "entity_version": node.latest.version,
        "record_digest": node.latest.digest,
        "to": "ACCEPTED",
        "issuer_id": BOARD,
        "nonce": nonce(9),
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        "reason": "why",
    }
    data = alab.grant_signing_bytes(template)
    assert data == grant_signing_bytes(template) == b"research-lab/governance-grant/1\n" + canonical_json(template).encode("ascii")
    assert data.count(b"\n") == 1 and b"signature" not in data
    signature = BOARD_KEY.sign(data).hex()
    assert alab.grant_signing_bytes({**template, "signature": signature}) == data  # the signature is never signed
    assert verify_grant_signature(template, signature, alab.graph.governance_keys)["issuer_id"] == BOARD
    assert alab.apply_grant({**template, "signature": signature}, SUBMITTER).disposition == "ACCEPTED"
    defaults = alab.grant_template(finding, "ADMITTED", BOARD, "why", nonce(10))
    assert defaults["issued_at"] < defaults["expires_at"]  # lab clock, plus 24 hours


def test_an_authenticated_store_with_no_issuers_can_never_record_a_disposition(db_path, principal, ai):
    lab = Lab.create(db_path, TENANT, principal, [], StepClock(START))
    assert lab.governance_mode == "AUTHENTICATED" and lab.graph.governance_issuers == frozenset()
    f = lab.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(lab, f)
    template = lab.grant_template(f, "ACCEPTED", BOARD, "r", nonce(11), ISSUED, EXPIRES)
    refused(lab, db_path, principal, lambda: lab.apply_grant(sign(template), SUBMITTER), "is not enrolled")
    refused(lab, db_path, principal, lambda: lab.govern(f, "ACCEPTED", Actor("gov", ActorKind.HUMAN), BOARD, "x"), "this store is AUTHENTICATED")
    lab.close()
