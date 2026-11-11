"""Ed25519 signature verification (RFC 8032, pure Ed25519), standard library only.

VERIFY ONLY. This module has no signer, no key generation and never sees a private key.
The lab holds public keys and checks signatures that a governance body produced somewhere
else (an HSM, a KMS, a hardware key, a CNS identity). A test-only reference signer lives in
tests/ed25519_signer.py and is never imported by the package.

Strictness. verify() returns False, never raises, for every input it does not accept:

* the public key is not exactly 32 bytes, or the signature is not exactly 64 bytes;
* the public key or R is a non-canonical encoding (y >= p, or x = 0 with the sign bit set)
  or is not a point on the curve;
* the public key or R is a small-order point (one of the 8 points whose order divides 8;
  this includes the identity and the all-zero encoding);
* S >= L (the malleable form S + L of a valid signature is refused);
* the cofactorless equation [S]B = R + [k]A does not hold, k = SHA-512(R || A || M) mod L.

The cofactorless equation is the stricter of the two RFC 8032 allows. A public key of mixed
order (a prime-order point plus a small-order component) is not rejected by a subgroup
check; only pure small-order keys are. That is the same choice common strict verifiers
make and it is stated here rather than hidden.

Timing. Everything this module touches is public (public key, message, signature), so the
arithmetic is not constant time and does not need to be. Do not reuse this code for signing.

Speed. Python integers, extended coordinates, about one double-and-add per bit: a few
milliseconds per signature. Governance dispositions are rare events; that is enough.
"""

from __future__ import annotations

import hashlib

PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

_Point = tuple[int, int, int, int]  # extended homogeneous coordinates (X, Y, Z, T), x*y = T/Z

_IDENTITY: _Point = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int | None:
    """x for a canonical y, or None when no point has this y or the encoding is not canonical."""
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decode(data: bytes) -> _Point | None:
    if len(data) != PUBLIC_KEY_BYTES:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _add(a: _Point, b: _Point) -> _Point:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % _P
    bb = (y1 + x1) * (y2 + x2) % _P
    cc = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar: int, point: _Point) -> _Point:
    result = _IDENTITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _equal(a: _Point, b: _Point) -> bool:
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _small_order(point: _Point) -> bool:
    return _equal(_mul(8, point), _IDENTITY)


_BASE_Y = 4 * pow(5, -1, _P) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
if _BASE_X is None:  # cannot happen; a wrong constant must fail at import, not verify wrongly
    raise RuntimeError("ed25519 base point constant is wrong")
_BASE: _Point = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def is_valid_public_key(public_key: bytes) -> bool:
    """True when public_key is a canonical encoding of a curve point that is not small order."""
    if not isinstance(public_key, (bytes, bytearray)):
        return False
    point = _decode(bytes(public_key))
    return point is not None and not _small_order(point)


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """True only when signature is a strict Ed25519 signature of message under public_key."""
    if not isinstance(public_key, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
        return False
    if not isinstance(message, (bytes, bytearray)):
        return False
    public_key, signature, message = bytes(public_key), bytes(signature), bytes(message)
    if len(public_key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    a_point = _decode(public_key)
    if a_point is None or _small_order(a_point):
        return False
    r_bytes = signature[:32]
    r_point = _decode(r_bytes)
    if r_point is None or _small_order(r_point):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _L
    return _equal(_mul(s, _BASE), _add(r_point, _mul(k, a_point)))
