"""Offline verification: a bundle of an AUTHENTICATED store carries everything needed to
re-verify every governance grant (the genesis public keys and the full signed grants), and
a tampered grant is detected from the file alone, even after the attacker has recomputed
every hash in the chain. TEST-ONLY keys."""

import json

import pytest
from conftest import TENANT
from governance_support import (
    BOARD,
    BOARD_KEY,
    OUTSIDER_KEY,
    RELEASE,
    issuers,
    new_lab,
    recommend,
    rehash,
    signed_grant,
)

from research_lab.canonical import canonical_json
from research_lab.export import BUNDLE_SCHEMA, ExportRefused, export_bundle, read_bundle, verify_bundle
from research_lab.governance import grant_signing_bytes, make_issuer, verify_grant_signature
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind
from research_lab.store import Event, EventStore

SUBMITTER = Actor("clerk-7", ActorKind.HUMAN)


@pytest.fixture
def bundle(db_path, ai, tmp_path):
    """A bundle with two grant-authorized dispositions; the store is closed afterwards."""
    lab = new_lab(db_path)
    f = lab.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(lab, f)
    lab.apply_grant(signed_grant(lab, f, "ACCEPTED"), SUBMITTER)
    lab.apply_grant(signed_grant(lab, f, "ADMITTED", issuer_id=RELEASE), SUBMITTER)
    out = str(tmp_path / "bundle.jsonl")
    export_bundle(lab.store, out)
    lab.close()
    return out


def rewrite(path, header, events):
    """Write a bundle by hand, the way an attacker would: header consistent, every hash recomputed."""
    events = rehash(events)
    header = dict(header, event_count=len(events), head_hash=events[-1].hash, governance_issuers=events[0].payload["governance_issuers"])
    with open(path, "w", encoding="ascii") as handle:
        handle.write("\n".join([canonical_json(header)] + [canonical_json(event.to_dict()) for event in events]) + "\n")


def edit_grant(events, seq, **changes):
    out = list(events)
    payload = json.loads(json.dumps(events[seq].payload))
    for path, value in changes.items():
        target = payload
        *parents, last = path.split("__")
        for name in parents:
            target = target[name]
        target[last] = value
    out[seq] = Event(seq, events[seq].tenant, events[seq].event_type, payload, "", "", None, None)
    return out


# detection


def test_tampered_grant_in_a_bundle_is_detected_by_the_chain(bundle):
    with open(bundle, encoding="ascii") as handle:
        lines = [line for line in handle.read().split("\n") if line]
    accept = json.loads(lines[6])
    assert accept["payload"]["governance"]["grant"]["to"] == "ACCEPTED"
    accept["payload"]["governance"]["grant"]["reason"] = "edited in the bundle"
    lines[6] = json.dumps(accept, sort_keys=True, separators=(",", ":"))
    with open(bundle, "w", encoding="ascii") as handle:
        handle.write("\n".join(lines) + "\n")
    result = verify_bundle(bundle)
    assert not result.ok and any("seq 5: hash mismatch" in problem for problem in result.problems)


@pytest.mark.parametrize(
    "changes, match",
    [
        ({"governance__grant__reason": "edited, then every hash recomputed", "reason": "edited, then every hash recomputed"}, "does not verify under the enrolled key"),
        ({"governance__grant__expires_at": "2099-01-01T00:00:00Z"}, "does not verify under the enrolled key"),
        ({"governance__grant__nonce": "cd" * 16}, "does not verify under the enrolled key"),
        ({"governance__signature": "00" * 64}, "does not verify under the enrolled key"),
        ({"governance__grant__issuer_id": RELEASE, "governance__issuer_id": RELEASE}, "does not verify under the enrolled key"),
        ({"governance__signature": None}, "no signature"),
        ({"governance": {"issuer_id": BOARD}}, "needs a signed grant"),
    ],
)
def test_tampered_grant_is_detected_from_the_file_alone_even_after_a_full_rehash(bundle, tmp_path, changes, match):
    header, events = read_bundle(bundle)
    forged = str(tmp_path / "forged.jsonl")
    rewrite(forged, header, edit_grant(events, 5, **changes))
    result = verify_bundle(forged)
    assert not result.ok and not result.policy_checked and result.governance is None
    assert any("policy violation: seq 5" in problem and match in problem for problem in result.problems), result.problems
    # The chain by itself is satisfied: only the signature check catches this.
    assert not any("hash mismatch" in problem or "prev_hash" in problem for problem in result.problems)


def test_bundle_with_a_swapped_genesis_key_fails_the_recorded_grants(bundle, tmp_path):
    header, events = read_bundle(bundle)
    genesis = dict(events[0].payload)
    genesis["governance_issuers"] = [make_issuer(BOARD, "human_body", OUTSIDER_KEY.public_key_hex), genesis["governance_issuers"][1]]
    forged = str(tmp_path / "forged.jsonl")
    rewrite(forged, header, [Event(0, TENANT, "GENESIS", genesis, "", "", None, None), *events[1:]])
    result = verify_bundle(forged)
    assert not result.ok and any("does not verify under the enrolled key of issuer 'governance-board'" in p for p in result.problems)


def test_recorded_gap_a_bundle_rewritten_as_legacy_is_reported_unauthenticated_not_refused(bundle, tmp_path):
    """A recorded limitation, asserted. Someone who can rewrite the whole file can replace
    the genesis with an UNAUTHENTICATED_LEGACY one and recompute every hash. The grant events
    then pass the legacy claim rules (a HUMAN submitter, an issuer id in the list), so the
    file verifies. What the file can no longer do is look authenticated: the report says
    UNAUTHENTICATED_LEGACY, counts zero authenticated dispositions, and its genesis hash is
    not the original one. A verifier that needs authenticated governance must check the
    mode and pin the genesis hash."""
    header, events = read_bundle(bundle)
    genesis = {"schema_version": 2, "tenant": TENANT, "governance_mode": "UNAUTHENTICATED_LEGACY", "governance_issuers": [BOARD, RELEASE], "principals": ["alice"]}
    forged = str(tmp_path / "forged.jsonl")
    rewrite(forged, dict(header, governance_mode="UNAUTHENTICATED_LEGACY"), [Event(0, TENANT, "GENESIS", genesis, "", "", None, None), *events[1:]])
    result = verify_bundle(forged)
    assert result.ok
    assert result.governance["mode"] == "UNAUTHENTICATED_LEGACY"
    assert result.governance["authenticated"] == 0 and result.governance["unauthenticated"] == 2
    assert result.governance["genesis_hash"] != events[0].hash
    original = verify_bundle(bundle).governance
    assert original["mode"] == "AUTHENTICATED" and original["authenticated"] == 2 and original["genesis_hash"] == events[0].hash


def test_header_mode_and_issuers_must_match_the_genesis(bundle, tmp_path):
    header, events = read_bundle(bundle)
    lines = [canonical_json(event.to_dict()) for event in events]
    for change, match in (
        ({"governance_mode": "UNAUTHENTICATED_LEGACY"}, "header governance_mode differs from genesis"),
        ({"governance_issuers": [make_issuer(BOARD, "human_body", OUTSIDER_KEY.public_key_hex)]}, "header governance_issuers differ from genesis"),
        ({"governance_issuers": [BOARD, RELEASE]}, "header governance_issuers differ from genesis"),
        ({"governance_issuers": "governance-board"}, "header governance_issuers differ from genesis"),
        ({"store_schema_version": 1}, "header store_schema_version mismatch"),
    ):
        path = str(tmp_path / "h.jsonl")
        with open(path, "w", encoding="ascii") as handle:
            handle.write("\n".join([canonical_json(dict(header, **change)), *lines]) + "\n")
        result = verify_bundle(path)
        assert not result.ok and any(match in problem for problem in result.problems), (change, result.problems)
    missing = {k: v for k, v in header.items() if k != "governance_mode"}
    path = str(tmp_path / "m.jsonl")
    with open(path, "w", encoding="ascii") as handle:
        handle.write("\n".join([canonical_json(missing), *lines]) + "\n")
    assert any("header governance_mode differs from genesis" in p for p in verify_bundle(path).problems)


def test_export_refuses_a_store_holding_a_forged_grant(db_path, principal, ai, tmp_path):
    lab = new_lab(db_path)
    f = lab.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(lab, f)
    forged = signed_grant(lab, f, "ACCEPTED", key=OUTSIDER_KEY)
    fields = {k: v for k, v in forged.items() if k != "signature"}
    node = lab.graph.node(f)
    from research_lab.governance import grant_provenance

    record = node.latest.next_version(origin=SUBMITTER, created_at="2026-06-01T12:00:00Z", disposition="ACCEPTED", provenance=(grant_provenance(fields),))
    payload = {"record": record.to_dict(), "from": "RECOMMENDED", "to": "ACCEPTED", "actor": SUBMITTER.to_dict(), "reason": fields["reason"], "governance": {"issuer_id": BOARD, "grant": fields, "signature": forged["signature"]}}
    lab.close()
    unsafe = EventStore.open(db_path, TENANT, principal, unsafe_unvalidated=True)
    unsafe.append("TRANSITION", payload)
    with pytest.raises(ExportRefused, match="does not verify under the enrolled key"):
        export_bundle(unsafe, str(tmp_path / "never.jsonl"))
    unsafe.close()
    assert not (tmp_path / "never.jsonl").exists()


# what verifies


def test_bundle_of_an_authenticated_store_reverifies_every_grant_offline(bundle):
    header, events = read_bundle(bundle)
    assert header["bundle_schema"] == BUNDLE_SCHEMA and header["store_schema_version"] == 2
    assert header["governance_mode"] == "AUTHENTICATED" and header["governance_issuers"] == issuers()
    result = verify_bundle(bundle)
    assert result.ok and result.policy_checked and result.events_checked == 7
    report = result.governance
    assert report["mode"] == "AUTHENTICATED" and report["authenticated"] == 2 and report["unauthenticated"] == 0
    assert report["genesis_hash"] == events[0].hash
    assert [d["to"] for d in report["dispositions"]] == ["ACCEPTED", "ADMITTED"] and all(d["authenticated"] for d in report["dispositions"])


def test_a_reader_with_only_the_file_can_check_a_grant_with_two_function_calls(bundle):
    """What 'any reader can re-verify offline' means, spelled out: the genesis line gives the
    public keys, the event gives the grant and signature, and nothing else is needed."""
    _, events = read_bundle(bundle)
    keys = {record["issuer_id"]: record for record in events[0].payload["governance_issuers"]}
    governance = events[5].payload["governance"]
    issuer = verify_grant_signature(governance["grant"], governance["signature"], keys)
    assert issuer["issuer_id"] == BOARD and issuer["public_key"] == BOARD_KEY.public_key_hex
    from research_lab.crypto import ed25519

    assert ed25519.verify(BOARD_KEY.public_key, bytes.fromhex(governance["signature"]), grant_signing_bytes(governance["grant"]))
    assert events[5].payload["record"]["parents"] == [{"entity_id": governance["grant"]["entity_id"], "version": governance["grant"]["entity_version"]}]
    assert events[4].payload["record"]["digest"] == governance["grant"]["record_digest"]  # the exact version disposed


def test_export_is_deterministic_for_an_authenticated_store(db_path, ai, tmp_path):
    lab = new_lab(db_path)
    f = lab.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(lab, f)
    lab.apply_grant(signed_grant(lab, f, "ACCEPTED", nonce="ab" * 16), SUBMITTER)
    one, two = str(tmp_path / "1.jsonl"), str(tmp_path / "2.jsonl")
    export_bundle(lab.store, one)
    export_bundle(lab.store, two)
    lab.close()
    with open(one, "rb") as a, open(two, "rb") as b:
        assert a.read() == b.read()


def test_pinned_genesis_hash_and_required_authentication_turn_the_recorded_gaps_into_failures(bundle, tmp_path, db_path, principal):
    header, events = read_bundle(bundle)
    pinned = events[0].hash
    assert verify_bundle(bundle, expected_genesis_hash=pinned, require_authenticated=True).ok
    wrong_pin = verify_bundle(bundle, expected_genesis_hash="0" * 64)
    assert not wrong_pin.ok and any("is not the expected" in problem for problem in wrong_pin.problems)
    # The legacy rewrite of the gap test above: fine by itself, refused by either expectation.
    genesis = {"schema_version": 2, "tenant": TENANT, "governance_mode": "UNAUTHENTICATED_LEGACY", "governance_issuers": [BOARD, RELEASE], "principals": ["alice"]}
    forged = str(tmp_path / "forged.jsonl")
    rewrite(forged, dict(header, governance_mode="UNAUTHENTICATED_LEGACY"), [Event(0, TENANT, "GENESIS", genesis, "", "", None, None), *events[1:]])
    assert verify_bundle(forged).ok
    by_pin = verify_bundle(forged, expected_genesis_hash=pinned)
    assert not by_pin.ok and any("is not the expected" in problem for problem in by_pin.problems)
    by_mode = verify_bundle(forged, require_authenticated=True)
    assert not by_mode.ok
    assert any("governance mode is UNAUTHENTICATED_LEGACY, but AUTHENTICATED is required" in problem for problem in by_mode.problems)
    assert any("2 governance disposition(s) are unauthenticated" in problem for problem in by_mode.problems)
    # The same two expectations on a live store.
    from research_lab.lab import verify_store

    with EventStore.open(db_path, TENANT, principal) as store:
        assert verify_store(store, expected_genesis_hash=pinned, require_authenticated=True).ok
        assert not verify_store(store, expected_genesis_hash="f" * 64).ok


def test_expectations_fail_closed_when_the_replay_did_not_complete(bundle, tmp_path):
    header, events = read_bundle(bundle)
    forged = str(tmp_path / "forged.jsonl")
    rewrite(forged, header, edit_grant(events, 5, governance__signature="00" * 64))
    result = verify_bundle(forged, require_authenticated=True)
    assert not result.ok and any("governance expectations could not be checked" in problem for problem in result.problems)
