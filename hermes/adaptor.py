"""Schnorr adaptor signatures — the engine behind PTLCs (point time-locked
contracts), Lightning's Taproot-era replacement for HTLCs.

An HTLC (demo 14) locks a payment to a *hash*: reveal a preimage whose SHA-256
matches and you're paid. A PTLC locks it to a *point* ``T = t·G``: a signature is
issued in "encrypted" form (a **pre-signature**) that only becomes valid once
someone adds the secret scalar ``t``. Crucially, publishing the completed
signature **reveals** ``t`` — anyone holding the pre-signature can subtract it
back out. So ``t`` plays the preimage's role, but it travels as an ordinary
Schnorr signature: nothing on-chain looks special, and each hop can offset ``T``
by a random tweak so the hops can't be linked (the privacy win over HTLCs, which
expose the same hash at every hop).

This builds BIP-340 adaptor signatures from scratch — the completed signature is
a genuine 64-byte BIP-340 signature that :func:`hermes.schnorr.verify` accepts —
including the even-Y bookkeeping BIP-340 demands of the effective nonce.
"""

from __future__ import annotations

from .curve import G, N, Point
from .schnorr import lift_x, tagged_hash


def _xonly(point: Point) -> bytes:
    return int(point.x.num).to_bytes(32, "big")


def _has_even_y(point: Point) -> bool:
    return int(point.y.num) % 2 == 0


def _negate(point: Point) -> Point:
    return (N - 1) * point                      # -P (scalar −1)


def _challenge(nonce_point: Point, pubkey: Point, msg: bytes) -> int:
    return int.from_bytes(
        tagged_hash("BIP0340/challenge", _xonly(nonce_point) + _xonly(pubkey) + msg), "big") % N


def adaptor_point(secret: int) -> Point:
    """The public point ``T = t·G`` a payment is locked to; ``t`` is the secret
    that both settles the payment and, once revealed, unlocks the hop before it."""
    return secret * G


def _nonce(d: int, px: bytes, msg: bytes, T: Point) -> int:
    k = int.from_bytes(
        tagged_hash("HermesAdaptor/nonce", d.to_bytes(32, "big") + px + msg + _xonly(T)), "big") % N
    return k or 1


def presign(secret: int, msg: bytes, adaptor: Point, k: int | None = None):
    """Create a pre-signature over ``msg`` under the adaptor point ``T``.

    It is a valid-looking Schnorr commitment whose effective nonce is ``R0 + T``,
    but it is *not yet* a valid signature — completing it needs ``t`` such that
    ``t·G == T``. Returns ``(R0, s')`` where ``R0 = k·G`` is the nonce *without*
    the adaptor."""
    point = secret * G
    d = secret if _has_even_y(point) else N - secret       # BIP-340 even-Y key
    pubkey = d * G
    px = _xonly(pubkey)
    if k is None:
        k = _nonce(d, px, msg, adaptor)
    r0 = k * G
    effective = r0 + adaptor                                # the nonce the challenge commits to
    e = _challenge(effective, pubkey, msg)
    # BIP-340 forces the effective nonce to even Y; if it is odd, the verifier
    # will lift its x to −(R0+T), so the signer flips the sign of k accordingly.
    s_prime = ((k if _has_even_y(effective) else -k) + e * d) % N
    return r0, s_prime


def presig_verify(pubkey_xonly: bytes, msg: bytes, adaptor: Point, presig) -> bool:
    """Verify a pre-signature really commits to ``T``: adapting it with the matching
    ``t`` is *guaranteed* to yield a valid signature — checkable without knowing ``t``."""
    r0, s_prime = presig
    pubkey = lift_x(int.from_bytes(pubkey_xonly, "big"))
    effective = r0 + adaptor
    e = _challenge(effective, pubkey, msg)
    expected = (r0 if _has_even_y(effective) else _negate(r0)) + e * pubkey
    return s_prime * G == expected


def adapt(presig, adaptor_secret: int) -> bytes:
    """Complete a pre-signature with the adaptor secret ``t`` into a real 64-byte
    BIP-340 signature ``r_x ‖ s``."""
    r0, s_prime = presig
    effective = r0 + adaptor_secret * G
    s = (s_prime + (adaptor_secret if _has_even_y(effective) else -adaptor_secret)) % N
    return _xonly(effective) + s.to_bytes(32, "big")


def extract(presig, signature: bytes, adaptor: Point) -> int:
    """Recover the adaptor secret ``t`` from a pre-signature and the completed
    signature — the step that lets a routing node learn the secret and pull its
    own payment. Returns ``t`` with ``t·G == T``."""
    r0, s_prime = presig
    s = int.from_bytes(signature[32:64], "big")
    effective = r0 + adaptor
    return ((s - s_prime) if _has_even_y(effective) else (s_prime - s)) % N
