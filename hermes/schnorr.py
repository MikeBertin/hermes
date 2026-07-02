"""Schnorr signatures (BIP-340) — the signature scheme Taproot brought to Bitcoin.

ECDSA was a workaround: Schnorr's scheme was patented, so Bitcoin launched
without it. The patent is long dead, and BIP-340 (activated with Taproot, 2021)
finally adds it. Same curve, same keys — a different, *cleaner* equation:

    sign:    s = k + e·d          (no modular inverse anywhere)
    verify:  s·G == R + e·P       where e = H(R.x ‖ P.x ‖ m)

That linearity is the superpower ECDSA never had: signatures and keys *add*.
Two cosigners can sum their public keys and produce one joint signature that
verifies against the sum (MuSig) — an n-of-n multisig indistinguishable from,
and as cheap as, a single-sig payment.

BIP-340 conventions implemented here:
- **Tagged hashes** — every hash is domain-separated:
  ``sha256(sha256(tag) ‖ sha256(tag) ‖ msg)``, so a hash from one context can
  never be replayed in another.
- **x-only public keys** — 32 bytes, just ``P.x``; of the two points with that
  x, the even-Y one is implied (``lift_x``). Signing negates ``d`` or ``k``
  as needed so the implied point is the one used.
- **Deterministic nonces** — ``k`` is a tagged hash of (aux_rand ⊕ d) ‖ P.x ‖ m,
  BIP-340's built-in answer to the nonce-reuse catastrophe (see ecdsa.py).

Verified against the official BIP-340 test vectors, including the must-fail rows.
"""

from __future__ import annotations

from .curve import G, N, P, Point
from .sha256 import sha256


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """``sha256(sha256(tag) ‖ sha256(tag) ‖ msg)`` — BIP-340's domain-separated
    hash. The doubled 64-byte prefix fills exactly one SHA-256 block, so
    implementations can precompute the tag's midstate."""
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def lift_x(x: int) -> Point:
    """The point with x-coordinate ``x`` and *even* y — how a 32-byte x-only
    public key becomes a point. secp256k1's prime is ≡ 3 mod 4, so the square
    root is a single exponentiation. Raises if ``x`` is not on the curve."""
    if not 0 < x < P:
        raise ValueError("x-only pubkey out of field range")
    c = (pow(x, 3, P) + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if pow(y, 2, P) != c:
        raise ValueError("x is not on the curve")
    if y % 2 == 1:
        y = P - y
    return Point(x, y)


def pubkey_gen(secret: int) -> bytes:
    """The 32-byte x-only public key for ``secret``: just the x of d·G."""
    if not 1 <= secret < N:
        raise ValueError("secret out of range 1..n-1")
    return (secret * G).x.num.to_bytes(32, "big")


def _xor32(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def sign(secret: int, msg: bytes, aux_rand: bytes = bytes(32)) -> bytes:
    """BIP-340 sign: 64 bytes, ``R.x ‖ s``. Deterministic for a given
    ``(secret, msg, aux_rand)``; the 32-byte ``aux_rand`` salts the nonce and
    may be all zeros (the test vectors use both)."""
    if not 1 <= secret < N:
        raise ValueError("secret out of range 1..n-1")
    if len(aux_rand) != 32:
        raise ValueError("aux_rand must be 32 bytes")
    point = secret * G
    d = secret if point.y.num % 2 == 0 else N - secret   # even-Y convention
    px = point.x.num.to_bytes(32, "big")

    t = _xor32(d.to_bytes(32, "big"), tagged_hash("BIP0340/aux", aux_rand))
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + px + msg), "big") % N
    if k0 == 0:
        raise ValueError("bad nonce: k == 0")
    R = k0 * G
    k = k0 if R.y.num % 2 == 0 else N - k0               # even-Y for R too
    rx = R.x.num.to_bytes(32, "big")

    e = int.from_bytes(tagged_hash("BIP0340/challenge", rx + px + msg), "big") % N
    sig = rx + ((k + e * d) % N).to_bytes(32, "big")
    if not verify(px, msg, sig):                          # reference impl self-check
        raise RuntimeError("created an invalid signature")
    return sig


def verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    """BIP-340 verify: ``s·G == R + e·P``, with ``R`` required to have even y
    and the x-coordinate in ``sig[:32]``."""
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    try:
        point = lift_x(int.from_bytes(pubkey, "big"))
    except ValueError:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig[:32] + pubkey + msg), "big") % N
    # R = s·G - e·P  (subtracting = adding the negated point)
    neg_eP = e * Point(point.x, P - point.y.num)
    R = s * G + neg_eP
    if R.is_infinity or R.y.num % 2 == 1 or R.x.num != r:
        return False
    return True
