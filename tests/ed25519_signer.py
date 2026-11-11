"""TEST-ONLY reference Ed25519 signer. NOT part of the research_lab package.

This file exists so the tests and examples/governance_demo.py can produce signatures to
feed the lab's verify-only implementation. It is deliberately outside research_lab/: the
package has no signer and never handles a private key. Do not use this for anything real:

* it is not constant time (it leaks the key through timing);
* the seeds below are derived from fixed public labels, so the "private" keys are public.

It shares no code with research_lab/crypto/ed25519.py (its own arithmetic, written separately), so the RFC 8032 vectors cross-check the two.

Real signing is external: an HSM, a KMS, a hardware key or a CNS identity signs the bytes
that docs/GOVERNANCE_PORT.md specifies.
"""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)  # noqa: E741


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * I % P
    if x % 2 != 0:
        x = P - x
    return x


BY = 4 * pow(5, P - 2, P) % P
BX = _xrecover(BY)
B = (BX, BY, 1, BX * BY % P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(e: int, p):
    q = (0, 1, 1, 0)
    for bit in reversed(range(e.bit_length())):
        q = _add(q, q)
        if (e >> bit) & 1:
            q = _add(q, p)
    return q


def _encode(p) -> bytes:
    x, y, z, _ = p
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _encode(_scalarmult(a, B))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _expand(seed)
    pk = _encode(_scalarmult(a, B))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_bytes = _encode(_scalarmult(r, B))
    k = int.from_bytes(hashlib.sha512(r_bytes + pk + message).digest(), "little") % L
    s = (r + k * a) % L
    return r_bytes + s.to_bytes(32, "little")


def seed_for_tests(label: str) -> bytes:
    """A deterministic TEST seed derived from a public label. Never a real key."""
    return hashlib.sha256(b"research-lab TEST-ONLY seed, not a real key: " + label.encode("utf-8")).digest()


class IssuerTestKey:
    """A TEST-ONLY issuer key pair: holds a public test seed and signs with it."""

    def __init__(self, label: str, seed: bytes | None = None) -> None:
        self.label = label
        self._seed = seed_for_tests(label) if seed is None else seed
        self.public_key = public_key(self._seed)
        self.public_key_hex = self.public_key.hex()

    def sign(self, message: bytes) -> bytes:
        return sign(self._seed, message)
