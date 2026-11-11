"""The governance port through the command line: init --issuer, governance sign-bytes,
governance apply, and what verify and show report. Signing happens here in the test, with a
TEST-ONLY key, because the command line never signs."""

import json
import os
import subprocess
import sys

import pytest
from conftest import ROOT
from governance_support import BOARD, BOARD_KEY, OUTSIDER_KEY, RELEASE, RELEASE_KEY, nonce

from research_lab import cli
from research_lab.cli import build_parser, main
from research_lab.export import verify_bundle
from research_lab.governance import key_fingerprint

AT = "2026-06-01T12:00:00Z"
BOARD_ARG = f"{BOARD}:human_body:{BOARD_KEY.public_key_hex}"
RELEASE_ARG = f"{RELEASE}:system:{RELEASE_KEY.public_key_hex}"


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    data = json.loads(captured.out) if captured.out.strip() else None
    return code, data, captured.err


def common(db, at=AT):
    return ["--db", db, "--tenant", "acme", "--principal", "alice", "--at", at]


def actor(name="alice", kind="HUMAN"):
    return ["--actor", name, "--actor-kind", kind]


@pytest.fixture
def store(capsys, tmp_path):
    """An AUTHENTICATED store made through the CLI, with a finding at RECOMMENDED made
    through the Python API (the thin CLI has no command that adds a finding)."""
    db = str(tmp_path / "cli.sqlite")
    code, data, err = run(capsys, "init", *common(db), "--issuer", BOARD_ARG, "--issuer", RELEASE_ARG)
    assert code == 0 and err == ""
    from research_lab.clock import FixedClock
    from research_lab.lab import Lab
    from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind
    from research_lab.store import Principal

    with Lab.open(db, "acme", Principal("alice", frozenset({"acme"})), FixedClock(AT)) as lab:
        finding = lab.add(Kind.FINDING, {"text": "F"}, Actor("model-1", ActorKind.AI, "vendor", "family"), evidence_label=EvidenceLabel.INFERRED)
        for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
            lab.transition(finding.entity_id, stage, Actor("bob", ActorKind.HUMAN), "r")
    return db, finding.entity_id, data


def sign_bytes(capsys, db, entity, to, issuer=BOARD, n=1, extra=()):
    code, data, err = run(capsys, "governance", "sign-bytes", *common(db), "--entity", entity, "--to", to, "--issuer-id", issuer, "--reason", f"{to} by {issuer}", "--nonce", nonce(n), *extra)
    assert code == 0, err
    return data


def write_grant(tmp_path, grant, signature, name="grant.json"):
    path = str(tmp_path / name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({**grant, "signature": signature}, handle)
    return path


# refusals


@pytest.mark.parametrize(
    "value, match",
    [
        ("gov-1", "is not ID:KIND:PUBKEYHEX"),
        (f"{BOARD}:human_body", "is not ID:KIND:PUBKEYHEX"),
        (f":human_body:{BOARD_KEY.public_key_hex}", "is not ID:KIND:PUBKEYHEX"),
        (f"model-1:ai:{BOARD_KEY.public_key_hex}", "an AI or model can never be a governance issuer"),
        (f"model-1:model:{BOARD_KEY.public_key_hex}", "an AI or model can never be a governance issuer"),
        (f"{BOARD}:HUMAN:{BOARD_KEY.public_key_hex}", "is refused"),
        (f"{BOARD}:human_body:{'00' * 32}", "off curve or small order"),
        (f"{BOARD}:human_body:{BOARD_KEY.public_key_hex[:-1]}", "64 lowercase hex"),
        (f"{BOARD}:human_body:{BOARD_KEY.public_key_hex.upper()}", "64 lowercase hex"),
    ],
)
def test_init_refuses_bad_issuer_arguments_and_creates_nothing(capsys, tmp_path, value, match):
    db = tmp_path / "bad.sqlite"
    code, data, err = run(capsys, "init", *common(str(db)), "--issuer", value)
    assert code == 1 and data is None and match in json.loads(err)["message"]
    assert not db.exists()


def test_init_refuses_the_same_issuer_or_key_twice(capsys, tmp_path):
    db = tmp_path / "bad.sqlite"
    code, _, err = run(capsys, "init", *common(str(db)), "--issuer", BOARD_ARG, "--issuer", BOARD_ARG)
    assert code == 1 and "enrolled twice" in err
    code, _, err = run(capsys, "init", *common(str(db)), "--issuer", BOARD_ARG, "--issuer", f"other:system:{BOARD_KEY.public_key_hex}")
    assert code == 1 and "already enrolled under another issuer" in err and not db.exists()


def test_apply_refuses_unsigned_forged_tampered_and_replayed_grants(capsys, tmp_path, store):
    db, finding, _ = store
    data = sign_bytes(capsys, db, finding, "ACCEPTED")
    grant, message = data["grant"], bytes.fromhex(data["signing_bytes_hex"])
    good = BOARD_KEY.sign(message).hex()
    events = verify_count(capsys, db)

    def apply(path, who=("model-2", "AI")):
        extra = ["--provider", "vendor", "--model-family", "family"] if who[1] == "AI" else []
        return run(capsys, "governance", "apply", *common(db), *actor(*who), *extra, "--grant", path)

    unsigned = str(tmp_path / "unsigned.json")
    with open(unsigned, "w", encoding="utf-8") as handle:
        json.dump(grant, handle)
    cases = [
        (unsigned, "no signature"),
        (write_grant(tmp_path, grant, OUTSIDER_KEY.sign(message).hex(), "outsider.json"), "does not verify under the enrolled key"),
        (write_grant(tmp_path, grant, RELEASE_KEY.sign(message).hex(), "other-issuer.json"), "does not verify under the enrolled key"),
        (write_grant(tmp_path, {**grant, "reason": "edited"}, good, "edited.json"), "does not verify under the enrolled key"),
        (write_grant(tmp_path, {**grant, "to": "ADMITTED"}, good, "to.json"), "does not verify under the enrolled key"),
        (write_grant(tmp_path, grant, "00" * 64, "zero.json"), "does not verify under the enrolled key"),
        (str(tmp_path / "missing.json"), "cannot read grant file"),
    ]
    for path, match in cases:
        code, out, err = apply(path)
        assert code == 1 and out is None and match in json.loads(err)["message"], path
        assert verify_count(capsys, db) == events
    not_json = tmp_path / "not.json"
    not_json.write_text("{this is not json", encoding="utf-8")
    code, _, err = apply(str(not_json))
    assert code == 1 and "cannot read grant file" in err
    expired_code, _, expired_err = run(capsys, "governance", "apply", *common(db, at="2026-06-03T00:00:00Z"), *actor(), "--grant", write_grant(tmp_path, grant, good))
    assert expired_code == 1 and "the grant expired at 2026-06-02T12:00:00Z" in expired_err
    assert verify_count(capsys, db) == events

    code, out, err = apply(write_grant(tmp_path, grant, good))  # an AI relays the valid grant: allowed
    assert code == 0 and out["record"]["disposition"] == "ACCEPTED" and out["governance"]["authenticated"] is True
    code, _, err = apply(write_grant(tmp_path, grant, good))  # replay
    assert code == 1 and "nonce was already used" in err
    assert verify_count(capsys, db) == events + 1


def verify_count(capsys, db):
    code, data, _ = run(capsys, "verify", *common(db))
    assert code == 0 and data["ok"]
    return data["events_checked"]


def test_sign_bytes_refuses_unknown_issuer_entity_and_legacy_store(capsys, tmp_path, store):
    db, finding, _ = store
    code, _, err = run(capsys, "governance", "sign-bytes", *common(db), "--entity", finding, "--to", "ACCEPTED", "--issuer-id", "mallory", "--reason", "r")
    assert code == 1 and "'mallory' is not enrolled" in err
    code, _, err = run(capsys, "governance", "sign-bytes", *common(db), "--entity", "finding_nope", "--to", "ACCEPTED", "--issuer-id", BOARD, "--reason", "r")
    assert code == 1 and "unknown entity" in err
    code, _, err = run(capsys, "governance", "sign-bytes", *common(db), "--entity", finding, "--to", "ACCEPTED", "--issuer-id", BOARD, "--reason", "r", "--nonce", "abc")
    assert code == 1 and "nonce must be 16 to 32 bytes" in err
    legacy = str(tmp_path / "legacy.sqlite")
    assert run(capsys, "init", *common(legacy), "--issuer", "gov-1", "--unauthenticated-governance")[0] == 0
    code, _, err = run(capsys, "governance", "sign-bytes", *common(legacy), "--entity", "x", "--to", "ACCEPTED", "--issuer-id", "gov-1", "--reason", "r")
    assert code == 1 and "UNAUTHENTICATED_LEGACY: it enrolls no keys" in err


def test_cli_has_no_key_generation_and_no_private_key_handling():
    parser = build_parser()
    text = parser.format_help()
    for action in parser._subparsers._group_actions:  # every subcommand's help
        for name, sub in action.choices.items():
            text += name + sub.format_help()
            for nested in getattr(sub, "_subparsers", None)._group_actions if getattr(sub, "_subparsers", None) else []:
                for nested_name, nested_sub in nested.choices.items():
                    text += nested_name + nested_sub.format_help()
    lowered = text.lower()
    for word in ("keygen", "generate-key", "--private", "--secret", "--seed", "--sign-with", "private-key"):
        assert word not in lowered, word
    assert "sign-bytes" in lowered and "apply" in lowered
    with open(cli.__file__, encoding="utf-8") as handle:
        source = handle.read()
    assert "ed25519_signer" not in source and "def sign(" not in source
    assert "never generates a key and never reads, holds or asks for a private key" in source


# flows


def test_init_enrolls_issuers_and_reports_the_mode(store):
    _, _, data = store
    assert data["governance_mode"] == "AUTHENTICATED" and "governance_warning" not in data
    genesis = data["genesis"]
    assert genesis["schema_version"] == 2 and genesis["governance_mode"] == "AUTHENTICATED" and genesis["grant_skew_seconds"] == 300
    assert genesis["governance_issuers"] == [
        {"issuer_id": BOARD, "kind": "human_body", "alg": "ed25519", "public_key": BOARD_KEY.public_key_hex, "key_id": key_fingerprint(BOARD_KEY.public_key_hex)},
        {"issuer_id": RELEASE, "kind": "system", "alg": "ed25519", "public_key": RELEASE_KEY.public_key_hex, "key_id": key_fingerprint(RELEASE_KEY.public_key_hex)},
    ]


def test_init_issuer_id_may_contain_colons_and_skew_is_configurable(capsys, tmp_path):
    db = str(tmp_path / "c.sqlite")
    code, data, _ = run(capsys, "init", *common(db), "--issuer", f"urn:org:board:human_body:{BOARD_KEY.public_key_hex}", "--grant-skew-seconds", "30")
    assert code == 0 and data["genesis"]["governance_issuers"][0]["issuer_id"] == "urn:org:board" and data["genesis"]["grant_skew_seconds"] == 30
    code, _, err = run(capsys, "init", *common(str(tmp_path / "d.sqlite")), "--grant-skew-seconds", "99999")
    assert code == 1 and "grant_skew_seconds" in err


def test_init_without_issuers_is_authenticated_with_no_possible_disposition(capsys, tmp_path):
    code, data, err = run(capsys, "init", *common(str(tmp_path / "empty.sqlite")))
    assert code == 0 and err == ""
    assert data["governance_mode"] == "AUTHENTICATED" and data["genesis"]["governance_issuers"] == []


def test_unauthenticated_governance_flag_is_explicit_loud_and_recorded(capsys, tmp_path):
    db = str(tmp_path / "legacy.sqlite")
    code, data, err = run(capsys, "init", *common(db), "--issuer", "gov-1", "--unauthenticated-governance")
    assert code == 0
    warning = json.loads(err)
    assert warning["warning"] == "UnauthenticatedGovernance" and "not by a signature" in warning["message"]
    assert data["governance_mode"] == "UNAUTHENTICATED_LEGACY" and "reported as unauthenticated" in data["governance_warning"]
    assert data["genesis"] == {"schema_version": 2, "tenant": "acme", "governance_mode": "UNAUTHENTICATED_LEGACY", "governance_issuers": ["gov-1"], "principals": ["alice"]}
    code, data, _ = run(capsys, "verify", *common(db))
    assert code == 0 and data["governance_mode"] == "UNAUTHENTICATED_LEGACY" and "governance_warning" in data
    assert data["governance"]["mode"] == "UNAUTHENTICATED_LEGACY"
    # Without the flag, a plain issuer id is refused and the message says how to opt out.
    code, _, err = run(capsys, "init", *common(str(tmp_path / "x.sqlite")), "--issuer", "gov-1")
    assert code == 1 and "--unauthenticated-governance" in err


def test_sign_bytes_then_apply_then_verify_show_and_export(capsys, tmp_path, store):
    db, finding, _ = store
    data = sign_bytes(capsys, db, finding, "ACCEPTED")
    grant = data["grant"]
    assert grant == {
        "v": 1, "tenant": "acme", "entity_id": finding, "entity_version": 4, "record_digest": grant["record_digest"], "to": "ACCEPTED",
        "issuer_id": BOARD, "nonce": nonce(1), "issued_at": AT, "expires_at": "2026-06-02T12:00:00Z", "reason": f"ACCEPTED by {BOARD}",
    }  # fmt: skip
    message = bytes.fromhex(data["signing_bytes_hex"])
    assert message.startswith(b"research-lab/governance-grant/1\n{") and message.decode("ascii") == data["signing_bytes_utf8"]
    assert json.loads(message.split(b"\n", 1)[1]) == grant
    assert data["nonce_source"] == "given" and data["current_status"] == "RECOMMENDED"
    assert data["sign_with"] == {"issuer_id": BOARD, "kind": "human_body", "alg": "ed25519", "key_id": key_fingerprint(BOARD_KEY.public_key_hex), "public_key": BOARD_KEY.public_key_hex}
    before = verify_count(capsys, db)  # sign-bytes wrote nothing

    signature = BOARD_KEY.sign(message).hex()  # the external signer: here, a TEST-ONLY key
    code, out, err = run(capsys, "governance", "apply", *common(db), *actor("clerk-7"), "--grant", write_grant(tmp_path, grant, signature))
    assert code == 0 and err == ""
    assert out["record"]["disposition"] == "ACCEPTED" and out["record"]["version"] == 5
    assert out["governance"]["authenticated"] is True and out["governance"]["issuer_id"] == BOARD and out["governance"]["grant_nonce"] == nonce(1)

    second = sign_bytes(capsys, db, finding, "ADMITTED", issuer=RELEASE, n=2, extra=("--issued-at", "2026-06-01T11:00:00Z", "--expires-at", "2026-06-01T13:00:00Z"))
    assert second["grant"]["entity_version"] == 5 and second["grant"]["expires_at"] == "2026-06-01T13:00:00Z"
    signature = RELEASE_KEY.sign(bytes.fromhex(second["signing_bytes_hex"])).hex()
    code, out, _ = run(capsys, "governance", "apply", *common(db), *actor("release-bot", "SYSTEM"), "--grant", write_grant(tmp_path, second["grant"], signature, "admit.json"))
    assert code == 0 and out["record"]["disposition"] == "ADMITTED"

    code, verified, _ = run(capsys, "verify", *common(db))
    assert code == 0 and verified["ok"] and verified["events_checked"] == before + 2
    assert verified["governance_mode"] == "AUTHENTICATED" and "governance_warning" not in verified
    assert verified["governance"]["authenticated"] == 2 and verified["governance"]["unauthenticated"] == 0
    assert [(d["to"], d["authenticated"], d["issuer_id"]) for d in verified["governance"]["dispositions"]] == [("ACCEPTED", True, BOARD), ("ADMITTED", True, RELEASE)]
    assert len(verified["governance"]["genesis_hash"]) == 64

    code, shown, _ = run(capsys, "show", *common(db), "--entity", finding)
    assert code == 0 and shown["status"] == "ADMITTED" and shown["governance_mode"] == "AUTHENTICATED"
    assert [(d["version"], d["to"], d["authenticated"], d["key_id"]) for d in shown["governance_dispositions"]] == [
        (5, "ACCEPTED", True, key_fingerprint(BOARD_KEY.public_key_hex)),
        (6, "ADMITTED", True, key_fingerprint(RELEASE_KEY.public_key_hex)),
    ]

    bundle = str(tmp_path / "bundle.jsonl")
    assert run(capsys, "export", *common(db), "--out", bundle)[0] == 0
    offline = verify_bundle(bundle)
    assert offline.ok and offline.governance["authenticated"] == 2


def test_sign_bytes_generates_a_fresh_nonce_when_none_is_given(capsys, store):
    db, finding, _ = store
    args = ["governance", "sign-bytes", *common(db), "--entity", finding, "--to", "ACCEPTED", "--issuer-id", BOARD, "--reason", "r"]
    one, two = run(capsys, *args)[1], run(capsys, *args)[1]
    assert one["nonce_source"] == two["nonce_source"] == "generated"
    assert len(one["grant"]["nonce"]) == 32 and one["grant"]["nonce"] != two["grant"]["nonce"]


def test_legacy_cli_store_shows_dispositions_as_unauthenticated(capsys, tmp_path):
    db = str(tmp_path / "legacy.sqlite")
    assert run(capsys, "init", *common(db), "--issuer", "gov-1", "--unauthenticated-governance")[0] == 0
    from research_lab.clock import FixedClock
    from research_lab.lab import Lab
    from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind
    from research_lab.store import Principal

    with Lab.open(db, "acme", Principal("alice", frozenset({"acme"})), FixedClock(AT)) as lab:
        f = lab.add(Kind.FINDING, {"text": "F"}, Actor("model-1", ActorKind.AI, "vendor", "family"), evidence_label=EvidenceLabel.INFERRED).entity_id
        for stage in ("REVIEWED", "REPRODUCED", "RECOMMENDED"):
            lab.transition(f, stage, Actor("bob", ActorKind.HUMAN), "r")
        lab.govern(f, "ACCEPTED", Actor("gov-1", ActorKind.HUMAN), "gov-1", "claimed")
    code, shown, _ = run(capsys, "show", *common(db), "--entity", f)
    assert code == 0 and shown["governance_mode"] == "UNAUTHENTICATED_LEGACY" and "governance_warning" in shown
    assert [(d["to"], d["authenticated"]) for d in shown["governance_dispositions"]] == [("ACCEPTED", False)]
    code, verified, _ = run(capsys, "verify", *common(db))
    assert verified["governance"]["unauthenticated"] == 1 and verified["governance"]["authenticated"] == 0
    code, _, err = run(capsys, "governance", "apply", *common(db), *actor(), "--grant", str(tmp_path / "none.json"))
    assert code == 1 and "cannot read grant file" in err


def test_governance_commands_work_as_a_module_subprocess(tmp_path, store):
    db, finding, _ = store
    base = [sys.executable, "-m", "research_lab"]
    env_args = dict(capture_output=True, text=True, cwd=ROOT, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    out = subprocess.run([*base, "governance", "sign-bytes", *common(db), "--entity", finding, "--to", "ACCEPTED", "--issuer-id", BOARD, "--reason", "ok", "--nonce", nonce(5)], **env_args)
    assert out.returncode == 0, out.stderr
    data = json.loads(out.stdout)
    path = write_grant(tmp_path, data["grant"], BOARD_KEY.sign(bytes.fromhex(data["signing_bytes_hex"])).hex())
    applied = subprocess.run([*base, "governance", "apply", *common(db), *actor("clerk"), "--grant", path], **env_args)
    assert applied.returncode == 0, applied.stderr
    assert json.loads(applied.stdout)["record"]["disposition"] == "ACCEPTED"
    usage = subprocess.run([*base, "governance"], **env_args)
    assert usage.returncode == 2


def test_verify_can_pin_the_genesis_hash_and_require_authenticated_governance(capsys, tmp_path, store):
    db, _, _ = store
    code, data, _ = run(capsys, "verify", *common(db))
    pinned = data["governance"]["genesis_hash"]
    code, data, _ = run(capsys, "verify", *common(db), "--expect-genesis-hash", pinned, "--require-authenticated")
    assert code == 0 and data["ok"]
    code, data, _ = run(capsys, "verify", *common(db), "--expect-genesis-hash", "0" * 64)
    assert code == 1 and not data["ok"] and any("is not the expected" in problem for problem in data["problems"])
    legacy = str(tmp_path / "legacy.sqlite")
    assert run(capsys, "init", *common(legacy), "--issuer", "gov-1", "--unauthenticated-governance")[0] == 0
    assert run(capsys, "verify", *common(legacy))[0] == 0
    code, data, _ = run(capsys, "verify", *common(legacy), "--require-authenticated")
    assert code == 1 and any("AUTHENTICATED is required" in problem for problem in data["problems"])
