"""ECDSA signing and verification on secp256k1 — including the nonce-reuse attack.

A signature proves you know the private key for a public point without revealing
it. The one catch: every signature needs a fresh, secret random nonce ``k``. Reuse
``k`` across two different messages and anyone can recover your private key with
schoolbook algebra. That mistake has drained real wallets (and broke the PS3's
code-signing). :func:`recover_secret_from_reused_nonce` does exactly that.
"""

from __future__ import annotations

import secrets
from typing import NamedTuple

from .curve import G, N, Point


class Signature(NamedTuple):
    r: int
    s: int


def _inv(a: int) -> int:
    return pow(a, -1, N)


def sign(secret: int, z: int, k: int | None = None, low_s: bool = True) -> Signature:
    """Sign message hash ``z`` with ``secret``.

    Pass an explicit ``k`` to demonstrate nonce reuse. ``low_s`` applies BIP-62
    canonicalization (real Bitcoin requires it) — turn it off for the reuse demo
    so the recovery algebra stays clean.
    """
    if k is None:
        k = secrets.randbelow(N - 1) + 1
    r = (k * G).x.num % N
    if r == 0:
        raise ValueError("bad nonce produced r == 0; choose another k")
    s = (_inv(k) * (z + r * secret)) % N
    if s == 0:
        raise ValueError("bad nonce produced s == 0; choose another k")
    if low_s and s > N // 2:
        s = N - s
    return Signature(r, s)


def verify(point: Point, z: int, sig: Signature) -> bool:
    if not (1 <= sig.r < N and 1 <= sig.s < N):
        return False
    s_inv = _inv(sig.s)
    u = (z * s_inv) % N
    v = (sig.r * s_inv) % N
    R = u * G + v * point
    return (not R.is_infinity) and R.x.num % N == sig.r


def recover_secret_from_reused_nonce(
    z1: int, sig1: Signature, z2: int, sig2: Signature
) -> int:
    """Recover the private key from two signatures that reused the same nonce.

    Both signatures share ``r`` (because ``r`` only depends on ``k``). From
    ``s = k^-1 (z + r d)`` for each message:

        k = (z1 - z2) / (s1 - s2)
        d = (s1 * k - z1) / r
    """
    if sig1.r != sig2.r:
        raise ValueError("signatures do not share a nonce (r differs)")
    r = sig1.r
    k = ((z1 - z2) * _inv((sig1.s - sig2.s) % N)) % N
    return ((sig1.s * k - z1) * _inv(r)) % N
