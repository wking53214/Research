import json

import pytest
from conftest import ISSUERS, TENANT, tamper

from research_lab import export as export_module
from research_lab.clock import StepClock
from research_lab.export import BUNDLE_SCHEMA, BundleError, ExportRefused, export_bundle, read_bundle, verify_bundle
from research_lab.lab import Lab
from research_lab.records import Kind
from research_lab.store import HmacSigner


def rewrite(path: str, lines: list[str]) -> None:
    with open(path, "w", encoding="ascii") as handle:
        handle.write("\n".join(lines) + "\n")


def lines_of(path: str) -> list[str]:
    with open(path, encoding="ascii") as handle:
        return [line for line in handle.read().split("\n") if line]


def test_export_then_verify_from_file_alone(lab, chain, tmp_path):
    out = str(tmp_path / "bundle.jsonl")
    info = export_bundle(lab.store, out)
    lab.close()  # the store is closed: verification below uses the file only
    assert info.event_count == 7 and info.tenant == TENANT
    header, events = read_bundle(out)
    assert header["bundle_schema"] == BUNDLE_SCHEMA and header["governance_issuers"] == ISSUERS
    assert len(events) == 7
    result = verify_bundle(out)
    assert result.ok and result.events_checked == 7 and result.head_hash == info.head_hash


def test_export_is_deterministic(lab, chain, human, tmp_path):
    first, second = str(tmp_path / "a.jsonl"), str(tmp_path / "b.jsonl")
    export_bundle(lab.store, first)
    export_bundle(lab.store, second)
    assert open(first, "rb").read() == open(second, "rb").read()
    lab.add(Kind.OBJECTIVE, {"title": "more"}, human)
    third = str(tmp_path / "c.jsonl")
    export_bundle(lab.store, third)
    assert open(first, "rb").read() != open(third, "rb").read()


def test_tampered_bundle_lines_are_detected(lab, chain, tmp_path):
    out = str(tmp_path / "bundle.jsonl")
    export_bundle(lab.store, out)
    original = lines_of(out)

    edited = list(original)
    event = json.loads(edited[3])
    event["payload"]["record"]["body"]["text"] = "edited"
    edited[3] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    rewrite(out, edited)
    result = verify_bundle(out)
    assert not result.ok and any("seq 2: hash mismatch" in p for p in result.problems)

    deleted = original[:3] + original[4:]
    rewrite(out, deleted)
    result = verify_bundle(out)
    assert not result.ok and any("position 2: seq 3" in p for p in result.problems)
    assert any("event_count" in p for p in result.problems)

    reordered = original[:2] + [original[3], original[2]] + original[4:]
    rewrite(out, reordered)
    assert not verify_bundle(out).ok

    truncated = original[:-1]
    rewrite(out, truncated)
    result = verify_bundle(out)
    assert not result.ok and any("head_hash" in p for p in result.problems)


def test_tampered_bundle_header_is_detected(lab, chain, tmp_path):
    out = str(tmp_path / "bundle.jsonl")
    export_bundle(lab.store, out)
    original = lines_of(out)
    header = json.loads(original[0])

    wrong_tenant = dict(header, tenant="other")
    rewrite(out, [json.dumps(wrong_tenant)] + original[1:])
    result = verify_bundle(out)
    assert not result.ok and any("genesis tenant 'acme' is not 'other'" in p for p in result.problems)
    assert any("wrong tenant" in p for p in result.problems)

    wrong_issuers = dict(header, governance_issuers=["mallory"])
    rewrite(out, [json.dumps(wrong_issuers)] + original[1:])
    result = verify_bundle(out)
    assert not result.ok and any("governance_issuers" in p for p in result.problems)

    rewrite(out, [json.dumps(dict(header, bundle_schema="other/9"))] + original[1:])
    with pytest.raises(BundleError, match="schema"):
        verify_bundle(out)


def test_malformed_and_empty_bundles_are_refused(tmp_path):
    out = str(tmp_path / "bad.jsonl")
    rewrite(out, ["not json"])
    with pytest.raises(BundleError, match="malformed"):
        verify_bundle(out)
    with open(out, "w") as handle:
        handle.write("")
    with pytest.raises(BundleError, match="empty"):
        verify_bundle(out)


def test_export_refuses_a_store_that_does_not_verify(lab, chain, db_path, tmp_path):
    raw = tamper(db_path)
    raw.execute("DELETE FROM events WHERE seq = 3")
    raw.close()
    out = str(tmp_path / "bundle.jsonl")
    with pytest.raises(ExportRefused, match="refusing to export"):
        export_bundle(lab.store, out)
    assert not (tmp_path / "bundle.jsonl").exists()
    assert not (tmp_path / "bundle.jsonl.tmp").exists()


def test_signed_bundle_verifies_with_signer(db_path, principal, human, tmp_path):
    # Changed after verification: export now replays lab policy, so the store is built through
    # a Lab (a bare "NOTE" event is an unknown event type and is refused by replay).
    signer = HmacSigner(bytes(range(32)), "key-a")
    lab = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), signer=signer)
    lab.add(Kind.OBJECTIVE, {"title": "signed"}, human)
    store = lab.store
    out = str(tmp_path / "signed.jsonl")
    export_bundle(store, out, require_signed=True)
    lab.close()
    assert verify_bundle(out, signer=signer, require_signed=True).signatures_checked == 2
    assert not verify_bundle(out, require_signed=True).ok
    assert not verify_bundle(out, signer=HmacSigner(bytes(32), "key-a")).ok


def test_import_is_not_implemented():
    assert not hasattr(export_module, "import_bundle")
    assert not hasattr(export_module, "merge_bundle")
