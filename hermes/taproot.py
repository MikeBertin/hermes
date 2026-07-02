"""Taproot outputs (BIP-341, key path) — tweak a key, get a ``bc1p…`` address.

A Taproot output locks coins to a single x-only key ``Q``, but ``Q`` is never
a bare wallet key. It is the *internal* key ``P`` shifted by a hash of itself:

    t = int(tagged_hash("TapTweak", P.x))  mod n
    Q = P + t·G

Spending by key path is just a Schnorr signature with the tweaked secret
``d + t``. The point of the ceremony: the tweak can also commit to a Merkle
tree of alternative spending scripts (the "script path"). Key-path spends
reveal nothing — a plain payment, a MuSig multisig vault, and a key with a
hidden script tree all look identical on-chain: 34 bytes, one signature.

The address is simply witness v1 + ``Q.x`` in bech32m (BIP-350): ``bc1p…``.

Verified against the BIP-341 wallet test vectors and the BIP-86 derivation
vectors (seed phrase → m/86'/0'/0'/0/0 → address).
"""

from __future__ import annotations

from .bech32 import encode_segwit
from .curve import G, N
from .schnorr import lift_x, tagged_hash

_HRP = {False: "bc", True: "tb"}


def tap_tweak(internal_key: bytes) -> int:
    """The scalar ``t`` a key-path-only output is tweaked by: a tagged hash of
    the internal key itself (no script tree committed)."""
    if len(internal_key) != 32:
        raise ValueError("internal key must be 32 bytes (x-only)")
    return int.from_bytes(tagged_hash("TapTweak", internal_key), "big") % N


def output_key(internal_key: bytes) -> bytes:
    """``Q = P + t·G`` — the tweaked, x-only key the scriptPubKey carries."""
    point = lift_x(int.from_bytes(internal_key, "big"))
    Q = point + tap_tweak(internal_key) * G
    if Q.is_infinity:
        raise ValueError("tweaked key is the point at infinity")
    return Q.x.num.to_bytes(32, "big")


def p2tr_address(internal_key: bytes, testnet: bool = False) -> str:
    """The ``bc1p…`` / ``tb1p…`` address for a key-path-only Taproot output:
    witness v1 + ``Q.x``, bech32m-encoded."""
    return encode_segwit(_HRP[testnet], 1, output_key(internal_key))


def tweak_secret(secret: int) -> int:
    """The secret that signs for the *tweaked* key — what a wallet actually
    uses for a key-path spend. If ``d·G`` has odd y the secret is negated
    first (the x-only even-Y convention), then the tweak is added."""
    point = secret * G
    d = secret if point.y.num % 2 == 0 else N - secret
    internal = point.x.num.to_bytes(32, "big")
    return (d + tap_tweak(internal)) % N
