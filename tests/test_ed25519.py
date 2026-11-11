"""The verify-only Ed25519 implementation: RFC 8032 section 7.1 vectors, then refusals.

The vectors are the published ones (secret seed, public key, message, signature). The
1023-byte TEST 1024 vector of the RFC is not reproduced here: it could not be fetched
offline and was not typed from memory. The four below were confirmed three ways when this
file was written: the test-only signer re-derives each public key and signature from the
seed, the package verifier accepts them, and an independent library agreed on both.
"""

import hashlib

import ed25519_signer as signer
import pytest

from research_lab.crypto import ed25519

L = 2**252 + 27742317777372353535851937790883648493
P = 2**255 - 19

RFC8032_VECTORS = [
    (
        "TEST 1",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "TEST 2",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "TEST 3",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        "TEST SHA(abc)",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
]
IDS = [vector[0] for vector in RFC8032_VECTORS]

PK = bytes.fromhex(RFC8032_VECTORS[2][2])
MSG = bytes.fromhex(RFC8032_VECTORS[2][3])
SIG = bytes.fromhex(RFC8032_VECTORS[2][4])


def encode(x: int, y: int) -> bytes:
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


SQRT_M1 = pow(2, (P - 1) // 4, P)
# The eight points of order 1, 2, 4 and 8, in every encoding a strict decoder could meet.
SMALL_ORDER = [
    encode(0, 1),  # identity, order 1
    encode(0, P - 1),  # order 2
    encode(SQRT_M1, 0),  # order 4; y = 0 with sign 0 or 1 is the all-zero key and its twin
    encode(P - SQRT_M1, 0),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),  # order 8
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),  # order 8
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
]


# negative first


def test_s_plus_l_malleability_is_refused():
    s = int.from_bytes(SIG[32:], "little")
    assert s < L
    malleated = SIG[:32] + (s + L).to_bytes(32, "little")
    assert malleated != SIG
    assert ed25519.verify(PK, SIG, MSG)
    assert not ed25519.verify(PK, malleated, MSG)
    assert not ed25519.verify(PK, SIG[:32] + L.to_bytes(32, "little"), MSG)  # S = L exactly
    assert not ed25519.verify(PK, SIG[:32] + b"\xff" * 32, MSG)


@pytest.mark.parametrize("index", range(64))
def test_every_byte_of_the_signature_matters(index):
    for bit in (0, 7):
        flipped = bytearray(SIG)
        flipped[index] ^= 1 << bit
        assert not ed25519.verify(PK, bytes(flipped), MSG)


def test_bit_flips_in_message_and_key_are_refused():
    for index in range(len(MSG)):
        for bit in range(8):
            flipped = bytearray(MSG)
            flipped[index] ^= 1 << bit
            assert not ed25519.verify(PK, SIG, bytes(flipped))
    assert not ed25519.verify(PK, SIG, MSG + b"\x00")
    assert not ed25519.verify(PK, SIG, MSG[:-1])
    assert not ed25519.verify(PK, SIG, b"")
    for index in range(32):
        flipped = bytearray(PK)
        flipped[index] ^= 1
        assert not ed25519.verify(bytes(flipped), SIG, MSG)


@pytest.mark.parametrize("length", [0, 1, 31, 33, 64])
def test_wrong_length_public_keys_are_refused(length):
    assert not ed25519.verify((PK * 3)[:length], SIG, MSG)
    assert not ed25519.is_valid_public_key((PK * 3)[:length])


@pytest.mark.parametrize("length", [0, 1, 32, 63, 65, 128])
def test_truncated_and_oversized_signatures_are_refused(length):
    assert not ed25519.verify(PK, (SIG * 3)[:length], MSG)


def test_wrong_types_are_refused_not_raised():
    assert not ed25519.verify(PK.hex(), SIG, MSG)  # type: ignore[arg-type]
    assert not ed25519.verify(PK, SIG.hex(), MSG)  # type: ignore[arg-type]
    assert not ed25519.verify(PK, SIG, "af82")  # type: ignore[arg-type]
    assert not ed25519.verify(None, SIG, MSG)  # type: ignore[arg-type]
    assert not ed25519.is_valid_public_key("00" * 32)  # type: ignore[arg-type]
    assert ed25519.verify(bytearray(PK), bytearray(SIG), bytearray(MSG))


def test_all_zero_key_and_identity_point_are_refused():
    zero, identity = bytes(32), encode(0, 1)
    assert zero in SMALL_ORDER and identity in SMALL_ORDER
    for key in (zero, identity):
        assert not ed25519.is_valid_public_key(key)
        assert not ed25519.verify(key, SIG, MSG)
    # With the identity as "public key", R = [S]B verifies for ANY message under a lax
    # verifier: that forgery is exactly what the small-order rule refuses.
    s = 5
    forged_r = signer._encode(signer._scalarmult(s, signer.B))
    forged = forged_r + s.to_bytes(32, "little")
    assert not ed25519.verify(identity, forged, b"any message at all")


@pytest.mark.parametrize("key", SMALL_ORDER, ids=[k.hex()[:12] for k in SMALL_ORDER])
def test_small_order_public_keys_are_refused(key):
    point = ed25519._decode(key)
    assert point is not None, "these encodings are on the curve; they are refused for their order"
    assert ed25519._small_order(point)
    assert not ed25519.is_valid_public_key(key)
    assert not ed25519.verify(key, SIG, MSG)
    # S = 0 and R = identity satisfies the equation for a small-order key when k is a multiple
    # of its order; refused whatever k turns out to be.
    assert not ed25519.verify(key, encode(0, 1) + bytes(32), MSG)


@pytest.mark.parametrize("r_bytes", SMALL_ORDER, ids=[k.hex()[:12] for k in SMALL_ORDER])
def test_small_order_r_is_refused(r_bytes):
    assert not ed25519.verify(PK, r_bytes + SIG[32:], MSG)
    assert not ed25519.verify(PK, r_bytes + bytes(32), MSG)


def test_non_canonical_and_off_curve_encodings_are_refused():
    non_canonical = [
        (P).to_bytes(32, "little"),  # y = p, the same residue as y = 0
        (P + 1).to_bytes(32, "little"),  # y = p + 1, the same residue as the identity's y = 1
        (2**255 - 1).to_bytes(32, "little"),  # y = 2^255 - 1 >= p
        b"\xff" * 32,
        encode(1, 1),  # x = 0 with the sign bit set: "negative zero"
        (1 | (1 << 255)).to_bytes(32, "little"),
    ]
    for data in non_canonical:
        assert ed25519._decode(data) is None
        assert not ed25519.is_valid_public_key(data)
        assert not ed25519.verify(data, SIG, MSG)
        assert not ed25519.verify(PK, data + SIG[32:], MSG)
    off_curve = [y.to_bytes(32, "little") for y in range(2, 40) if ed25519._recover_x(y, 0) is None]
    assert len(off_curve) >= 5  # about half of all y values have no x
    for data in off_curve:
        assert not ed25519.is_valid_public_key(data)
        assert not ed25519.verify(data, SIG, MSG)
        assert not ed25519.verify(PK, data + SIG[32:], MSG)


def test_signature_from_another_key_or_for_another_message_is_refused():
    other = signer.seed_for_tests("another key")
    other_pk = signer.public_key(other)
    assert not ed25519.verify(other_pk, SIG, MSG)
    assert not ed25519.verify(PK, signer.sign(other, MSG), MSG)
    assert ed25519.verify(other_pk, signer.sign(other, MSG), MSG)
    assert not ed25519.verify(other_pk, signer.sign(other, MSG), MSG + b"!")


# positive


@pytest.mark.parametrize("name, seed, public, message, signature", RFC8032_VECTORS, ids=IDS)
def test_rfc8032_vectors_verify(name, seed, public, message, signature):
    assert ed25519.verify(bytes.fromhex(public), bytes.fromhex(signature), bytes.fromhex(message))
    assert ed25519.is_valid_public_key(bytes.fromhex(public))


@pytest.mark.parametrize("name, seed, public, message, signature", RFC8032_VECTORS, ids=IDS)
def test_test_only_signer_reproduces_the_rfc8032_vectors(name, seed, public, message, signature):
    assert signer.public_key(bytes.fromhex(seed)).hex() == public
    assert signer.sign(bytes.fromhex(seed), bytes.fromhex(message)).hex() == signature


def test_sha_abc_vector_message_is_the_sha512_of_abc():
    assert hashlib.sha512(b"abc").hexdigest() == RFC8032_VECTORS[3][3]


def test_signer_and_verifier_agree_on_many_deterministic_messages():
    for n in range(40):
        seed = signer.seed_for_tests(f"agreement {n}")
        message = hashlib.sha512(str(n).encode()).digest() * (n % 4) + bytes(range(n))
        public, signature = signer.public_key(seed), signer.sign(seed, message)
        assert ed25519.is_valid_public_key(public)
        assert ed25519.verify(public, signature, message)
        tampered = bytearray(signature)
        tampered[n % 64] ^= 0x10
        assert not ed25519.verify(public, bytes(tampered), message)


def test_the_package_has_no_signer():
    public = {name for name in dir(ed25519) if not name.startswith("_")}
    assert public == {"PUBLIC_KEY_BYTES", "SIGNATURE_BYTES", "annotations", "hashlib", "is_valid_public_key", "verify"}
    with open(ed25519.__file__, encoding="utf-8") as handle:
        source = handle.read()
    for word in ("def sign", "def keygen", "def generate", "private_key", "secret_key", "import secrets", "os.urandom"):
        assert word not in source, word
