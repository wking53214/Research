"""Governance modes and genesis schema v2: what a genesis may enroll, the explicit legacy
opt-out, and stores written before the governance port (schema_version 1).

tests/fixtures/legacy_v1/ was written by the code as it was BEFORE this port (git commit
d0bb8de): bundle_v1.jsonl is that code's export of a 14-event store with three claim-based
governance dispositions, and expected_v1.json is that code's graph.to_dict() of the same
store. The tests below load them with the current code.
"""

import json
import os
import warnings

import pytest
from conftest import ISSUERS, LEGACY_MODE, ROOT, TENANT
from governance_support import (
    BOARD,
    BOARD_KEY,
    OUTSIDER_KEY,
    RELEASE_KEY,
    issuers,
    new_lab,
    recommend,
    rehash,
    signed_grant,
    write_raw_store,
)

from research_lab.clock import StepClock
from research_lab.export import export_bundle, read_bundle, verify_bundle
from research_lab.governance import (
    GovernanceError,
    GrantRefused,
    UnauthenticatedGovernanceWarning,
    key_fingerprint,
    make_issuer,
    read_genesis,
)
from research_lab.graph import Graph, PolicyViolation
from research_lab.lab import Lab
from research_lab.lifecycle import AuthorityError
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind
from research_lab.store import GENESIS, SCHEMA_VERSION, Event, EventStore, IntegrityError, StoreError

FIXTURES = os.path.join(ROOT, "tests", "fixtures", "legacy_v1")
PK = BOARD_KEY.public_key_hex


# enrollment refusals


@pytest.mark.parametrize("kind", ["ai", "AI", "model", "Model", "human", "HUMAN_BODY", "external", "", None, 7])
def test_enrolling_an_ai_or_any_unknown_issuer_kind_is_refused(db_path, principal, kind):
    with pytest.raises(GovernanceError, match="is refused"):
        make_issuer("model-1", kind, PK)
    record = {**make_issuer("model-1", "system", PK), "kind": kind}
    with pytest.raises(StoreError, match="is refused"):
        EventStore.create(db_path, TENANT, principal, [record])
    assert not os.path.exists(db_path)  # refused before any file is written
    if isinstance(kind, str) and kind.lower() in ("ai", "model"):
        with pytest.raises(GovernanceError, match="an AI or model can never be a governance issuer"):
            make_issuer("model-1", kind, PK)


@pytest.mark.parametrize(
    "public_key, match",
    [
        ("00" * 32, "off curve or small order"),  # the all-zero key
        ("01" + "00" * 31, "off curve or small order"),  # the identity point
        ("ec" + "ff" * 30 + "7f", "off curve or small order"),  # y = p - 1, order 2
        ("02" + "00" * 31, "off curve or small order"),  # y = 2 is not on the curve
        ("ff" * 32, "off curve or small order"),  # non-canonical y
        (PK.upper(), "64 lowercase hex"),
        (PK[:-2], "64 lowercase hex"),
        (PK + "00", "64 lowercase hex"),
        ("zz" * 32, "64 lowercase hex"),
        (bytes.fromhex(PK), "64 lowercase hex"),
        (None, "64 lowercase hex"),
    ],
)
def test_enrolling_a_bad_public_key_is_refused(db_path, principal, public_key, match):
    with pytest.raises(GovernanceError, match=match):
        make_issuer(BOARD, "human_body", public_key)
    assert not os.path.exists(db_path)


def test_malformed_issuer_records_are_refused_at_creation(db_path, principal):
    good = make_issuer(BOARD, "human_body", PK)
    assert good == {"issuer_id": BOARD, "kind": "human_body", "alg": "ed25519", "public_key": PK, "key_id": key_fingerprint(PK)}
    assert good["key_id"].startswith("ed25519:") and len(good["key_id"]) == len("ed25519:") + 16  # a label, not a digest
    cases = [
        ([{**good, "alg": "hmac-sha256"}], "alg 'hmac-sha256' is not 'ed25519'"),
        ([{**good, "key_id": "ed25519:0000000000000000"}], "key_id is not the fingerprint label"),
        ([{**good, "private_key": "00" * 32}], "fields must be exactly"),
        ([{k: v for k, v in good.items() if k != "key_id"}], "fields must be exactly"),
        ([{**good, "issuer_id": ""}], "issuer_id must be a non-empty string"),
        ([good, dict(good)], "enrolled twice"),
        ([good, make_issuer("second-name", "system", PK)], "already enrolled under another issuer"),
        ([BOARD], "plain issuer ids need governance_mode 'UNAUTHENTICATED_LEGACY', chosen explicitly"),
        (ISSUERS, "plain issuer ids need governance_mode"),
        (BOARD, "must be a sequence"),
        (good, "must be a sequence"),
        (None, "must be a sequence"),
    ]
    for issuer_list, match in cases:
        with pytest.raises(StoreError, match=match):
            EventStore.create(db_path, TENANT, principal, issuer_list)
        assert not os.path.exists(db_path)


def test_mode_and_skew_arguments_are_checked(db_path, principal):
    with pytest.raises(StoreError, match="is not one of"):
        EventStore.create(db_path, TENANT, principal, [], governance_mode="NONE")
    with pytest.raises(StoreError, match="is not one of"):
        EventStore.create(db_path, TENANT, principal, ISSUERS, governance_mode="unauthenticated_legacy")
    for skew in (-1, 3601, 1.5, "300", True, None):
        with pytest.raises(StoreError, match="grant_skew_seconds must be an integer from 0 to 3600"):
            EventStore.create(db_path, TENANT, principal, issuers(), grant_skew_seconds=skew)
    with pytest.raises(StoreError, match="non-empty issuer ids"):
        EventStore.create(db_path, TENANT, principal, issuers(), governance_mode=LEGACY_MODE)  # records in a legacy store
    assert not os.path.exists(db_path)


# genesis as written


def test_new_store_is_authenticated_by_default_and_its_genesis_enrolls_keys(db_path, principal):
    store = EventStore.create(db_path, TENANT, principal, list(reversed(issuers())))
    assert SCHEMA_VERSION == 2
    assert store.genesis() == {
        "schema_version": 2,
        "tenant": TENANT,
        "governance_mode": "AUTHENTICATED",
        "governance_issuers": issuers(),  # sorted by issuer id
        "grant_skew_seconds": 300,
        "principals": ["alice"],
    }
    assert store.governance_mode == "AUTHENTICATED"
    assert store.governance_issuers == frozenset({BOARD, "release-system"})
    assert "public_key" in store.genesis()["governance_issuers"][0] and "private" not in json.dumps(store.genesis())
    store.close()
    with Lab.open(db_path, TENANT, principal, StepClock()) as lab:
        assert lab.governance_mode == "AUTHENTICATED"
        assert lab.graph.governance_keys[BOARD]["public_key"] == PK
        report = lab.verify().governance
        assert report["mode"] == "AUTHENTICATED" and report["dispositions"] == []
        assert report["enrolled"] == [{k: i[k] for k in ("issuer_id", "kind", "alg", "key_id")} for i in issuers()]
        assert report["genesis_hash"] == lab.store.events()[0].hash


def test_legacy_mode_must_be_explicit_warns_and_is_recorded(db_path, principal):
    with pytest.warns(UnauthenticatedGovernanceWarning, match="not by a signature"):
        store = EventStore.create(db_path, TENANT, principal, ISSUERS, governance_mode=LEGACY_MODE)
    assert store.genesis() == {"schema_version": 2, "tenant": TENANT, "governance_mode": "UNAUTHENTICATED_LEGACY", "governance_issuers": ISSUERS, "principals": ["alice"]}
    assert store.governance_mode == "UNAUTHENTICATED_LEGACY"
    store.close()
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # an AUTHENTICATED store raises no warning
        EventStore.create(db_path + ".2", TENANT, principal, issuers()).close()


# genesis shapes refused on replay (written around the store, hashes all valid)


def genesis_event(payload):
    return rehash([Event(0, TENANT, GENESIS, payload, "", "", None, None)])


@pytest.mark.parametrize(
    "payload, match",
    [
        ({"schema_version": 3, "tenant": TENANT, "governance_mode": "AUTHENTICATED", "governance_issuers": [], "grant_skew_seconds": 300, "principals": ["alice"]}, "schema_version 3"),
        ({"schema_version": 1, "tenant": TENANT, "governance_mode": "AUTHENTICATED", "governance_issuers": ["gov-1"], "principals": ["alice"]}, "schema_version 1 genesis has no governance_mode"),
        ({"schema_version": 2, "tenant": TENANT, "governance_issuers": ["gov-1"], "principals": ["alice"]}, "missing field 'governance_mode'"),
        ({"schema_version": 2, "tenant": TENANT, "governance_mode": "OPEN", "governance_issuers": [], "principals": ["alice"]}, "governance_mode 'OPEN'"),
        ({"schema_version": 2, "tenant": TENANT, "governance_mode": "AUTHENTICATED", "governance_issuers": ["gov-1"], "grant_skew_seconds": 300, "principals": ["alice"]}, "enrolls issuer records"),
        ({"schema_version": 2, "tenant": TENANT, "governance_mode": "AUTHENTICATED", "governance_issuers": [], "principals": ["alice"]}, "missing field 'grant_skew_seconds'"),
        ({"schema_version": 2, "tenant": TENANT, "governance_mode": "AUTHENTICATED", "governance_issuers": [], "grant_skew_seconds": 999999, "principals": ["alice"]}, "grant_skew_seconds must be"),
        ({"schema_version": 2, "tenant": TENANT, "governance_mode": "AUTHENTICATED", "governance_issuers": [], "grant_skew_seconds": 300, "principals": ["alice"], "governance_override": True}, "genesis fields must be exactly"),
        ({"schema_version": 2, "tenant": TENANT, "governance_mode": "UNAUTHENTICATED_LEGACY", "governance_issuers": ["g"], "grant_skew_seconds": 300, "principals": ["alice"]}, "no meaning in UNAUTHENTICATED_LEGACY"),
        ({"schema_version": 2, "tenant": TENANT, "governance_mode": "UNAUTHENTICATED_LEGACY", "governance_issuers": [{"issuer_id": "g"}], "principals": ["alice"]}, "list of non-empty ids"),
    ],
)
def test_malformed_genesis_is_refused_on_replay(tmp_path, principal, payload, match):
    path = str(tmp_path / "forged.sqlite")
    write_raw_store(path, genesis_event(payload))
    # An unsupported schema_version is already refused by the chain layer (IntegrityError);
    # everything else is refused by the policy replay.
    with pytest.raises((PolicyViolation, IntegrityError), match=match):
        Lab.open(path, TENANT, principal, StepClock())
    with pytest.raises(PolicyViolation, match=match):
        Graph.rebuild(genesis_event(payload))


def test_genesis_enrolling_an_ai_issuer_or_a_bad_key_is_refused_on_replay(tmp_path, principal):
    good = make_issuer(BOARD, "human_body", PK)
    base = {"schema_version": 2, "tenant": TENANT, "governance_mode": "AUTHENTICATED", "grant_skew_seconds": 300, "principals": ["alice"]}
    for record, match in (({**good, "kind": "ai"}, "an AI or model can never be a governance issuer"), ({**good, "public_key": "00" * 32, "key_id": key_fingerprint("00" * 32)}, "small order")):
        with pytest.raises(PolicyViolation, match=match):
            Graph.rebuild(genesis_event({**base, "governance_issuers": [record]}))


# UNAUTHENTICATED_LEGACY behaves as increment 1 did, and says so


def test_legacy_store_governs_by_claim_as_before_and_reports_unauthenticated(lab, db_path, principal, chain, reviewer, gov):
    """The `lab` fixture is an explicit UNAUTHENTICATED_LEGACY store."""
    assert lab.governance_mode == "UNAUTHENTICATED_LEGACY" and lab.graph.governance_keys == {}
    f = chain.finding.entity_id
    recommend(lab, f, reviewer)
    accepted = lab.govern(f, "ACCEPTED", gov, "gov-1", "board accepts")
    assert accepted.provenance == ({"type": "governance_disposition", "issuer_id": "gov-1", "reason": "board accepts"},)
    with pytest.raises(AuthorityError, match="actor kind AI"):
        lab.govern(f, "ADMITTED", Actor("gov-1", ActorKind.AI), "gov-1", "ai")
    result = lab.verify()
    assert result.ok
    assert result.governance["mode"] == "UNAUTHENTICATED_LEGACY"
    assert result.governance["authenticated"] == 0 and result.governance["unauthenticated"] == 1
    assert [(d["to"], d["issuer_id"], d["authenticated"]) for d in result.governance["dispositions"]] == [("ACCEPTED", "gov-1", False)]
    assert "key_id" not in result.governance["dispositions"][0]
    assert result.to_dict()["governance"]["unauthenticated"] == 1


def test_recorded_gap_a5_and_y2_are_still_allowed_in_legacy_mode_and_reported_unauthenticated(lab, chain, reviewer, ai):
    """A recorded gap, asserted: in UNAUTHENTICATED_LEGACY mode an invented actor id that
    claims kind SYSTEM and quotes the public issuer id still records dispositions (attacks
    A5 and Y2). That is what the mode means; the report says unauthenticated."""
    f = chain.finding.entity_id
    recommend(lab, f, reviewer)
    assert lab.govern(f, "ACCEPTED", Actor("model-2-relabelled", ActorKind.SYSTEM), "gov-1", "x").disposition == "ACCEPTED"
    challenge = lab.file_challenge(f, "looks wrong", ai, [{"type": "evidence_ref", "ref": "r"}]).entity_id
    assert lab.govern(challenge, "DISMISSED", Actor("model-9", ActorKind.SYSTEM), "gov-1", "x").disposition == "DISMISSED"
    report = lab.verify().governance
    assert report["authenticated"] == 0 and report["unauthenticated"] == 2
    assert all(d["authenticated"] is False for d in report["dispositions"])


def test_legacy_store_refuses_grants_it_cannot_verify(lab, db_path, principal, chain, reviewer):
    f = chain.finding.entity_id
    recommend(lab, f, reviewer)
    count = lab.store.count()
    template = {
        "v": 1, "tenant": TENANT, "entity_id": f, "entity_version": 4, "record_digest": lab.graph.node(f).latest.digest, "to": "ACCEPTED",
        "issuer_id": "gov-1", "nonce": "ab" * 16, "issued_at": "2026-01-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z", "reason": "r",
    }  # fmt: skip
    signature = OUTSIDER_KEY.sign(lab.grant_signing_bytes(template)).hex()
    with pytest.raises(GrantRefused, match="UNAUTHENTICATED_LEGACY: it enrolls no keys"):
        lab.apply_grant({**template, "signature": signature}, Actor("clerk", ActorKind.HUMAN))
    with pytest.raises(GrantRefused, match="it enrolls no keys"):
        lab.graph.check_grant({**template, "signature": signature}, "2026-06-01T00:00:00Z")
    assert lab.store.count() == count


def test_authenticated_store_refuses_the_legacy_govern_call(db_path, principal, ai):
    lab = new_lab(db_path)
    f = lab.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(lab, f)
    count = lab.store.count()
    for actor in (Actor(BOARD, ActorKind.HUMAN), Actor("sys-1", ActorKind.SYSTEM), Actor("gov-1", ActorKind.AI)):
        with pytest.raises(GrantRefused, match=r"this store is AUTHENTICATED: Lab\.govern .* is refused; submit a grant signed by an enrolled governance key"):
            lab.govern(f, "ACCEPTED", actor, BOARD, "board accepts")
    assert lab.store.count() == count and lab.graph.node(f).status == "RECOMMENDED"
    assert issubclass(GrantRefused, AuthorityError)  # callers that caught AuthorityError still catch it
    lab.close()


# stores written before the governance port (schema_version 1)


def load_v1(tmp_path):
    header, events = read_bundle(os.path.join(FIXTURES, "bundle_v1.jsonl"))
    with open(os.path.join(FIXTURES, "expected_v1.json"), encoding="utf-8") as handle:
        expected = json.load(handle)
    path = str(tmp_path / "v1.sqlite")
    write_raw_store(path, events)
    return path, header, events, expected


def test_v1_fixture_is_what_the_old_code_wrote(tmp_path):
    _path, header, events, expected = load_v1(tmp_path)
    assert events[0].payload == {"schema_version": 1, "tenant": "acme", "governance_issuers": ["gov-1"], "principals": ["alice"]}
    assert "governance_mode" not in header and header["store_schema_version"] == 1
    assert len(events) == expected["events"] == 14 and events[-1].hash == expected["head_hash"]
    assert read_genesis(events[0].payload).mode == "UNAUTHENTICATED_LEGACY"


def test_v1_store_opens_and_replays_exactly_as_before_in_legacy_mode(tmp_path, principal):
    path, _, _events, expected = load_v1(tmp_path)
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # opening an old store is not an error and raises nothing
        lab = Lab.open(path, TENANT, principal, StepClock("2026-03-01T00:00:00Z"))
    assert lab.governance_mode == "UNAUTHENTICATED_LEGACY" and lab.store.governance_mode == "UNAUTHENTICATED_LEGACY"
    assert lab.store.governance_issuers == frozenset({"gov-1"})
    assert lab.store.head().hash == expected["head_hash"]  # nothing was rewritten
    now = lab.graph.to_dict()
    old = expected["graph"]
    assert {key: now[key] for key in old} == old  # every field the old code derived is identical
    assert sorted(set(now) - set(old)) == ["dispositions", "governance_keys", "governance_mode", "grant_skew_seconds", "used_grant_nonces"]
    result = lab.verify()
    assert result.ok and result.policy_checked and result.events_checked == 14
    assert result.governance["mode"] == "UNAUTHENTICATED_LEGACY"
    assert result.governance["authenticated"] == 0 and result.governance["unauthenticated"] == 3
    assert [(d["to"], d["authenticated"]) for d in result.governance["dispositions"]] == [("ACCEPTED", False), ("ADMITTED", False), ("DISMISSED", False)]
    # It keeps working the old way, and only the old way.
    g = expected["finding_g"]
    assert lab.govern(g, "ACCEPTED", Actor("gov-1", ActorKind.HUMAN), "gov-1", "accepted later").disposition == "ACCEPTED"
    with pytest.raises(AuthorityError, match="not in the genesis governance issuer set"):
        lab.govern(g, "ADMITTED", Actor("gov-1", ActorKind.HUMAN), "mallory", "fake issuer")
    assert lab.store.count() == 15 and lab.store.genesis()["schema_version"] == 1
    lab.close()
    with Lab.open(path, TENANT, principal, StepClock()) as again:
        assert again.verify().governance["unauthenticated"] == 4


def test_v1_bundle_written_by_the_old_code_still_verifies_and_new_export_of_a_v1_store_round_trips(tmp_path, principal):
    old_bundle = os.path.join(FIXTURES, "bundle_v1.jsonl")
    result = verify_bundle(old_bundle)
    assert result.ok and result.policy_checked and result.governance["mode"] == "UNAUTHENTICATED_LEGACY"
    assert result.governance["unauthenticated"] == 3 and result.governance["authenticated"] == 0
    path, _, _, expected = load_v1(tmp_path)
    out = str(tmp_path / "again.jsonl")
    with EventStore.open(path, TENANT, principal) as store:
        export_bundle(store, out)
    header, events = read_bundle(out)
    assert header["store_schema_version"] == 1 and header["governance_mode"] == "UNAUTHENTICATED_LEGACY" and header["governance_issuers"] == ["gov-1"]
    assert events[-1].hash == expected["head_hash"] and verify_bundle(out).ok
    # The event lines are byte for byte what the old exporter wrote; only the header gained a field.
    with open(old_bundle, encoding="ascii") as a, open(out, encoding="ascii") as b:
        assert a.read().split("\n")[1:] == b.read().split("\n")[1:]


def test_v1_store_cannot_be_upgraded_in_place_by_appending(tmp_path, principal):
    path, _, _, _ = load_v1(tmp_path)
    with EventStore.open(path, TENANT, principal) as store:
        upgrade = {"schema_version": 2, "tenant": TENANT, "governance_mode": "AUTHENTICATED", "governance_issuers": issuers(), "grant_skew_seconds": 300, "principals": ["alice"]}
        with pytest.raises(StoreError, match="fixed at genesis"):
            store.append(GENESIS, upgrade)
        assert store.count() == 14


def test_authenticated_grant_cannot_be_used_in_a_legacy_copy_of_the_same_tenant(db_path, principal, ai, lab, chain, reviewer):
    """A grant is only as good as the genesis that enrolls its key: the same signed grant
    means nothing to a store whose genesis enrolls no keys."""
    source = new_lab(db_path + ".auth")
    f = source.add(Kind.FINDING, {"text": "F"}, ai, evidence_label=EvidenceLabel.INFERRED).entity_id
    recommend(source, f)
    grant = signed_grant(source, f, "ACCEPTED")
    source.close()
    with pytest.raises(GrantRefused, match="it enrolls no keys"):
        lab.apply_grant(grant, Actor("clerk", ActorKind.HUMAN))
    assert RELEASE_KEY.public_key_hex != PK
