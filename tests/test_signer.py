import pytest
from conftest import ISSUERS, TENANT

from research_lab.store import MIN_KEY_BYTES, EventStore, HmacSigner, StoreError

KEY = bytes(range(32))


def test_signer_refuses_to_run_without_a_key():
    with pytest.raises(StoreError, match="explicit key"):
        HmacSigner(None, "k")  # type: ignore[arg-type]
    with pytest.raises(StoreError, match="explicit key"):
        HmacSigner("not-bytes", "k")  # type: ignore[arg-type]


def test_signer_refuses_short_key():
    with pytest.raises(StoreError, match=f"at least {MIN_KEY_BYTES}"):
        HmacSigner(b"x" * (MIN_KEY_BYTES - 1), "k")
    with pytest.raises(StoreError):
        HmacSigner(b"", "k")


def test_signer_requires_a_key_id_label():
    with pytest.raises(StoreError, match="key id"):
        HmacSigner(KEY, "")


def test_sign_and_verify():
    signer = HmacSigner(KEY, "key-a")
    sig = signer.sign(b"data")
    assert len(sig) == 64
    assert signer.verify(b"data", sig)
    assert not signer.verify(b"other", sig)
    assert not signer.verify(b"data", "00" * 32)
    assert not signer.verify(b"data", None)  # type: ignore[arg-type]
    assert signer.key_id == "key-a"


def test_signed_store_verifies_and_wrong_key_fails(db_path, principal):
    signer = HmacSigner(KEY, "key-a")
    # Chain-layer test with a bare "NOTE" event: opened without the policy validator.
    store = EventStore.create(db_path, TENANT, principal, ISSUERS, signer=signer, unsafe_unvalidated=True)
    store.append("NOTE", {"i": 1})
    events = store.events()
    assert all(e.key_id == "key-a" and e.signature for e in events)
    result = store.verify(require_signed=True)
    assert result.ok and result.signatures_checked == 2
    store.close()

    wrong = EventStore.open(db_path, TENANT, principal, signer=HmacSigner(bytes(32), "key-a"))
    result = wrong.verify()
    assert not result.ok and any("signature invalid" in p for p in result.problems)
    wrong.close()


def test_unsigned_store_fails_when_signatures_are_required(db_path, principal):
    store = EventStore.create(db_path, TENANT, principal, ISSUERS)
    assert store.verify().ok
    result = store.verify(require_signed=True)
    assert not result.ok and any("unsigned event" in p for p in result.problems)
    store.close()


def test_signed_store_opened_without_signer_reports_unverified(db_path, principal):
    signer = HmacSigner(KEY, "key-a")
    EventStore.create(db_path, TENANT, principal, ISSUERS, signer=signer).close()
    store = EventStore.open(db_path, TENANT, principal)
    result = store.verify()
    assert result.ok and result.unverified_signatures == 1 and result.signatures_checked == 0
    strict = store.verify(require_signed=True)
    assert not strict.ok and any("no matching signer" in p for p in strict.problems)
    store.close()
