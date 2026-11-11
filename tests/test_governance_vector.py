"""The worked GovernanceGrant test vector of docs/GOVERNANCE_PORT.md.

The key pair is the published RFC 8032 section 7.1 TEST 1 pair: a TEST-ONLY key whose
secret seed is public knowledge. It is used so that anyone can reproduce the signature
with any Ed25519 implementation. When this file was written an independent library
produced the same signature and verified it. Never enroll this key anywhere real.
"""

import hashlib
import os

import ed25519_signer as signer
from conftest import ROOT

from research_lab.canonical import canonical_json
from research_lab.crypto import ed25519
from research_lab.governance import (
    GRANT_DOMAIN,
    GRANT_FIELDS,
    grant_digest,
    grant_signing_bytes,
    key_fingerprint,
    make_issuer,
    split_signed_grant,
    verify_grant_signature,
)

RFC8032_TEST1_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"  # public TEST seed
PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
KEY_ID = "ed25519:21fe31dfa154a261"

GRANT = {
    "v": 1,
    "tenant": "acme",
    "entity_id": "finding_0123456789abcdef",
    "entity_version": 4,
    "record_digest": "bee6b421074d7797be6caefdad0a38c47417c9b2c2f43e7c54b68344354225cd",
    "to": "ACCEPTED",
    "issuer_id": "governance-board",
    "nonce": "000102030405060708090a0b0c0d0e0f",
    "issued_at": "2026-06-01T12:00:00Z",
    "expires_at": "2026-06-02T12:00:00Z",
    "reason": "Reproduced twice; the board accepts.",
}
CANONICAL_JSON = (
    '{"entity_id":"finding_0123456789abcdef","entity_version":4,"expires_at":"2026-06-02T12:00:00Z",'
    '"issued_at":"2026-06-01T12:00:00Z","issuer_id":"governance-board","nonce":"000102030405060708090a0b0c0d0e0f",'
    '"reason":"Reproduced twice; the board accepts.",'
    '"record_digest":"bee6b421074d7797be6caefdad0a38c47417c9b2c2f43e7c54b68344354225cd",'
    '"tenant":"acme","to":"ACCEPTED","v":1}'
)
SIGNING_BYTES_HEX = (
    "72657365617263682d6c61622f676f7665726e616e63652d6772616e742f310a7b22656e746974795f6964223a2266696e64696e675f"
    "30313233343536373839616263646566222c22656e746974795f76657273696f6e223a342c22657870697265735f6174223a22323032"
    "362d30362d30325431323a30303a30305a222c226973737565645f6174223a22323032362d30362d30315431323a30303a30305a222c"
    "226973737565725f6964223a22676f7665726e616e63652d626f617264222c226e6f6e6365223a223030303130323033303430353036"
    "303730383039306130623063306430653066222c22726561736f6e223a22526570726f64756365642074776963653b2074686520626f"
    "61726420616363657074732e222c227265636f72645f646967657374223a226265653662343231303734643737393762653663616566"
    "646164306133386334373431376339623263326634336537633534623638333434333534323235636422"
    "2c2274656e616e74223a2261636d65222c22746f223a224143434550544544222c2276223a317d"
)
SIGNING_BYTES_SHA256 = "0af6966582156a2bdf0f8492cc4db72fd5a982a564876b4428a1b0c10826e04c"
SIGNATURE = (
    "59c2f0558a576409f356a5e76511a7ebbe6341c36f73299522731a4d54a06e0a"
    "a245329a7cdbd1640bfc73bc20fdc525f1a29afdab23d94c390f859081df2a05"
)


def test_signing_bytes_are_the_domain_line_then_the_canonical_json():
    data = grant_signing_bytes(GRANT)
    assert GRANT_DOMAIN == b"research-lab/governance-grant/1\n"
    assert canonical_json(GRANT) == CANONICAL_JSON
    assert data == GRANT_DOMAIN + CANONICAL_JSON.encode("ascii")
    assert data.hex() == SIGNING_BYTES_HEX and len(data) == 405
    assert hashlib.sha256(data).hexdigest() == SIGNING_BYTES_SHA256 == grant_digest(GRANT)
    assert tuple(GRANT) == GRANT_FIELDS and len(GRANT_FIELDS) == 11


def test_vector_signature_verifies_and_any_change_breaks_it():
    keys = {"governance-board": make_issuer("governance-board", "human_body", PUBLIC_KEY)}
    assert keys["governance-board"]["key_id"] == KEY_ID == key_fingerprint(PUBLIC_KEY)
    assert ed25519.verify(bytes.fromhex(PUBLIC_KEY), bytes.fromhex(SIGNATURE), bytes.fromhex(SIGNING_BYTES_HEX))
    assert verify_grant_signature(GRANT, SIGNATURE, keys)["public_key"] == PUBLIC_KEY
    fields, signature = split_signed_grant({**GRANT, "signature": SIGNATURE})
    assert fields == GRANT and signature == SIGNATURE
    for name, value in (("reason", "Reproduced once; the board accepts."), ("to", "ADMITTED"), ("entity_version", 5), ("tenant", "acme2"), ("nonce", "000102030405060708090a0b0c0d0e10")):
        assert not ed25519.verify(bytes.fromhex(PUBLIC_KEY), bytes.fromhex(SIGNATURE), grant_signing_bytes({**GRANT, name: value})), name


def test_test_only_signer_reproduces_the_vector():
    seed = bytes.fromhex(RFC8032_TEST1_SEED)
    assert signer.public_key(seed).hex() == PUBLIC_KEY
    assert signer.sign(seed, bytes.fromhex(SIGNING_BYTES_HEX)).hex() == SIGNATURE


def test_the_document_states_exactly_this_vector():
    with open(os.path.join(ROOT, "docs", "GOVERNANCE_PORT.md"), encoding="utf-8") as handle:
        text = handle.read()
    for value in (PUBLIC_KEY, KEY_ID, CANONICAL_JSON, SIGNING_BYTES_HEX, SIGNING_BYTES_SHA256, SIGNATURE, RFC8032_TEST1_SEED, "research-lab/governance-grant/1"):
        assert value in text, value
