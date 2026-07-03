"""MuSig2 key aggregation (BIP-327) — n signatures become one.

Schnorr's linearity (see schnorr.py) means public keys and signatures *add*.
MuSig2 turns that party trick into a protocol: n cosigners aggregate their
public keys into ONE x-only key, run a two-round signing ceremony, and the
result is a plain 64-byte BIP-340 signature. On-chain, the n-of-n vault is
indistinguishable from — and costs exactly the same as — a lone signer.
Compare the 2-of-3 P2WSH vault (transaction.py): its witness carries every
signature and the whole script; a MuSig2 vault carries 64 bytes, full stop.

Why not just sum the keys? Because the last cosigner to reveal theirs could
choose ``P_mallory - P_everyone_else`` and own the sum (the *rogue-key
attack*). KeyAgg blinds each key with a per-key coefficient:

    L   = H("KeyAgg list", pk_1 ‖ … ‖ pk_n)
    a_i = H("KeyAgg coefficient", L ‖ pk_i)      (the 2nd distinct key gets a_i = 1)
    Q   = Σ a_i·P_i

Nobody can aim at a chosen aggregate without inverting the hash.

Why TWO nonces per signer (the "2" in MuSig2)? A single aggregated nonce lets
an attacker open many parallel sessions and steer the combined challenge with
Wagner's generalized-birthday algorithm. Each signer instead commits to a
*pair* (R₁, R₂), and the session binds them with ``b = H(aggnonce ‖ Q.x ‖ m)``
into an effective nonce ``R = R₁ + b·R₂`` — b isn't known until every nonce is
fixed, so there is nothing to steer. Signing stays two rounds: swap nonces,
swap partial signatures.

The ceremony (what the round-trip actually carries):

    round 1:  each signer i sends pubnonce  (R_i1 ‖ R_i2, 66 bytes)
    round 2:  each signer i sends s_i = k_i1 + b·k_i2 + e·a_i·d_i
    combine:  s = Σ s_i  →  (R.x ‖ s) verifies under Q via plain BIP-340

Tweaking (``apply_tweak``) folds a Taproot TapTweak — or a BIP-32 derivation
step — into the aggregate, so the vault hides behind an ordinary ``bc1p…``
address (taproot.py).

BIP-327 conventions implemented here:
- Inputs are 33-byte *compressed* ("plain") public keys, NOT x-only — the
  aggregate is only reduced to x-only at the very end.
- ``secnonce`` is single-use by construction: signing zeroizes it in place,
  so accidental reuse raises instead of leaking the key (see ecdsa.py for
  what reuse costs).
- Misbehaving participants raise ``InvalidContributionError`` naming the
  culprit — a real coordinator must know *who* to hold accountable.

Scope: the n-of-n path plus tweaks. Adaptor signatures and the deterministic
(stateless) signer variant are out of scope. Verified against the official
BIP-327 vectors: key_agg, nonce_gen, nonce_agg, sign_verify, tweak, sig_agg —
including every error case.
"""

from __future__ import annotations

import os
from typing import List, NamedTuple, Optional, Tuple

from .curve import G, INFINITY, N, P, Point
from .schnorr import lift_x, tagged_hash


class InvalidContributionError(Exception):
    """A participant sent garbage. ``signer`` is their index (None = the
    aggregator), ``contrib`` is what was bad: "pubkey", "pubnonce",
    "aggnonce", or "psig"."""

    def __init__(self, signer: Optional[int], contrib: str):
        self.signer = signer
        self.contrib = contrib
        super().__init__(f"invalid {contrib} (signer {signer})")


# --- point <-> bytes (BIP-327 wire formats) -----------------------------------

def xbytes(point: Point) -> bytes:
    """32-byte x-only serialization."""
    return point.x.num.to_bytes(32, "big")


def cbytes(point: Point) -> bytes:
    """33-byte compressed ("plain") serialization: 02/03 parity prefix + x."""
    prefix = b"\x02" if point.y.num % 2 == 0 else b"\x03"
    return prefix + xbytes(point)


def cbytes_ext(point: Point) -> bytes:
    """Like :func:`cbytes` but the point at infinity is 33 zero bytes — the
    aggregate nonce needs this (cosigners' nonces can legitimately cancel)."""
    if point.is_infinity:
        return bytes(33)
    return cbytes(point)


def cpoint(data: bytes) -> Point:
    """Parse a 33-byte compressed point. Raises ValueError on anything that
    isn't a valid on-curve encoding with an 02/03 prefix."""
    if len(data) != 33:
        raise ValueError("x is not a valid compressed point.")
    try:
        point = lift_x(int.from_bytes(data[1:33], "big"))
    except ValueError:
        raise ValueError("x is not a valid compressed point.")
    if data[0] == 2:
        return point
    if data[0] == 3:
        return Point(point.x, P - point.y.num)
    raise ValueError("x is not a valid compressed point.")


def cpoint_ext(data: bytes) -> Point:
    """Like :func:`cpoint` but 33 zero bytes decode to the point at infinity."""
    if data == bytes(33):
        return INFINITY
    return cpoint(data)


def plain_pubkey(secret: int) -> bytes:
    """The 33-byte compressed public key for ``secret`` — the form BIP-327
    aggregates (x-only would lose the parity the coefficients depend on)."""
    if not 1 <= secret < N:
        raise ValueError("The secret key must be an integer in the range 1..n-1.")
    return cbytes(secret * G)


def key_sort(pubkeys: List[bytes]) -> List[bytes]:
    """Lexicographic ordering — how cosigners agree on a canonical key list
    (KeyAgg is order-sensitive: same keys, different order, different Q)."""
    return sorted(pubkeys)


# --- KeyAgg: n public keys -> one ---------------------------------------------

class KeyAggContext(NamedTuple):
    """The aggregate key plus the accumulators tweaking maintains:
    ``gacc`` (±1 mod n) tracks parity flips, ``tacc`` the summed tweaks —
    signers need both to shift their partial signatures to match."""

    Q: Point
    gacc: int
    tacc: int


def get_xonly_pk(keyagg_ctx: KeyAggContext) -> bytes:
    """The 32-byte x-only aggregate — what a Taproot output actually carries."""
    return xbytes(keyagg_ctx.Q)


def hash_keys(pubkeys: List[bytes]) -> bytes:
    """``L`` — one tagged hash committing to the entire ordered key list."""
    return tagged_hash("KeyAgg list", b"".join(pubkeys))


def get_second_key(pubkeys: List[bytes]) -> bytes:
    """The first key that differs from ``pubkeys[0]`` (zeros if all equal) —
    it gets coefficient 1, an optimization the spec allows because a rogue
    second key still can't aim the sum once every *other* key is blinded."""
    for pk in pubkeys[1:]:
        if pk != pubkeys[0]:
            return pk
    return bytes(33)


def key_agg_coeff(pubkeys: List[bytes], pk: bytes) -> int:
    """The rogue-key-killing coefficient ``a_i`` for ``pk``."""
    return _key_agg_coeff_internal(pubkeys, pk, get_second_key(pubkeys))


def _key_agg_coeff_internal(pubkeys: List[bytes], pk: bytes, pk2: bytes) -> int:
    if pk == pk2:
        return 1
    L = hash_keys(pubkeys)
    return int.from_bytes(tagged_hash("KeyAgg coefficient", L + pk), "big") % N


def key_agg(pubkeys: List[bytes]) -> KeyAggContext:
    """``Q = Σ a_i·P_i`` — aggregate n plain public keys into one."""
    pk2 = get_second_key(pubkeys)
    Q = INFINITY
    for i, pk in enumerate(pubkeys):
        try:
            point = cpoint(pk)
        except ValueError:
            raise InvalidContributionError(i, "pubkey")
        Q = Q + _key_agg_coeff_internal(pubkeys, pk, pk2) * point
    # Q = infinity would need the coefficients to conspire across a hash —
    # negligible, and not triggerable by any signer.
    assert not Q.is_infinity
    return KeyAggContext(Q, 1, 0)


def apply_tweak(keyagg_ctx: KeyAggContext, tweak: bytes, is_xonly: bool) -> KeyAggContext:
    """Shift the aggregate: ``Q' = g·Q + t·G``. An x-only tweak (Taproot's
    TapTweak) first negates Q if its y is odd — that is ``g = n-1`` — because
    the tweak commits to the x-only form. A plain tweak (BIP-32 step) never
    negates. The accumulators carry the correction into signing."""
    if len(tweak) != 32:
        raise ValueError("The tweak must be a 32-byte array.")
    Q, gacc, tacc = keyagg_ctx
    g = N - 1 if is_xonly and Q.y.num % 2 == 1 else 1
    t = int.from_bytes(tweak, "big")
    if t >= N:
        raise ValueError("The tweak must be less than n.")
    Q_ = g * Q + t * G
    if Q_.is_infinity:
        raise ValueError("The result of tweaking cannot be infinity.")
    return KeyAggContext(Q_, g * gacc % N, (t + g * tacc) % N)


def key_agg_and_tweak(pubkeys: List[bytes], tweaks: List[bytes], is_xonly: List[bool]) -> KeyAggContext:
    """KeyAgg then the whole tweak chain — the session's view of the key."""
    if len(tweaks) != len(is_xonly):
        raise ValueError("The `tweaks` and `is_xonly` arrays must have the same length.")
    ctx = key_agg(pubkeys)
    for tweak, xonly in zip(tweaks, is_xonly):
        ctx = apply_tweak(ctx, tweak, xonly)
    return ctx


# --- round 1: nonces -----------------------------------------------------------

def _nonce_hash(rand: bytes, pk: bytes, aggpk: bytes, i: int, msg_prefixed: bytes, extra_in: bytes) -> int:
    buf = rand
    buf += len(pk).to_bytes(1, "big") + pk
    buf += len(aggpk).to_bytes(1, "big") + aggpk
    buf += msg_prefixed
    buf += len(extra_in).to_bytes(4, "big") + extra_in
    buf += i.to_bytes(1, "big")
    return int.from_bytes(tagged_hash("MuSig/nonce", buf), "big")


def nonce_gen_internal(rand_: bytes, sk: Optional[bytes], pk: bytes,
                       aggpk: Optional[bytes], msg: Optional[bytes],
                       extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    """The deterministic core of :func:`nonce_gen` (exposed for the official
    vectors, which fix ``rand_``). Everything the signer knows — secret key,
    aggregate key, message — is folded into the two nonces, so even a weak
    ``rand_`` degrades gracefully rather than repeating a nonce."""
    if sk is not None:
        rand = bytes(a ^ b for a, b in zip(sk, tagged_hash("MuSig/aux", rand_)))
    else:
        rand = rand_
    if aggpk is None:
        aggpk = b""
    if msg is None:
        msg_prefixed = b"\x00"
    else:
        msg_prefixed = b"\x01" + len(msg).to_bytes(8, "big") + msg
    if extra_in is None:
        extra_in = b""
    k1 = _nonce_hash(rand, pk, aggpk, 0, msg_prefixed, extra_in) % N
    k2 = _nonce_hash(rand, pk, aggpk, 1, msg_prefixed, extra_in) % N
    assert k1 != 0 and k2 != 0                        # negligible probability
    pubnonce = cbytes(k1 * G) + cbytes(k2 * G)
    # secnonce also records WHOSE nonce this is; sign() refuses a mismatch.
    secnonce = bytearray(k1.to_bytes(32, "big") + k2.to_bytes(32, "big") + pk)
    return secnonce, pubnonce


def nonce_gen(sk: Optional[bytes], pk: bytes, aggpk: Optional[bytes] = None,
              msg: Optional[bytes] = None, extra_in: Optional[bytes] = None) -> Tuple[bytearray, bytes]:
    """Round 1: make this signer's nonce pair. Returns ``(secnonce, pubnonce)``
    — keep the first secret and NEVER reuse it; broadcast the second."""
    if sk is not None and len(sk) != 32:
        raise ValueError("The optional byte array sk must have length 32.")
    if aggpk is not None and len(aggpk) != 32:
        raise ValueError("The optional byte array aggpk must have length 32.")
    return nonce_gen_internal(os.urandom(32), sk, pk, aggpk, msg, extra_in)


def nonce_agg(pubnonces: List[bytes]) -> bytes:
    """Sum everyone's pubnonces slot-wise: ``(ΣR_i1, ΣR_i2)``, 66 bytes.
    Either sum may be the point at infinity (encoded as zeros) if nonces
    cancel — harmless, the session substitutes G downstream."""
    aggnonce = b""
    for j in (0, 1):
        R_j = INFINITY
        for i, pubnonce in enumerate(pubnonces):
            try:
                R_ij = cpoint(pubnonce[j * 33:(j + 1) * 33])
            except ValueError:
                raise InvalidContributionError(i, "pubnonce")
            R_j = R_j + R_ij
        aggnonce += cbytes_ext(R_j)
    return aggnonce


# --- round 2: partial signatures -----------------------------------------------

class SessionContext(NamedTuple):
    """Everything all signers must agree on before round 2: the aggregate
    nonce, the ordered key list, the tweak chain, and the message."""

    aggnonce: bytes
    pubkeys: List[bytes]
    tweaks: List[bytes]
    is_xonly: List[bool]
    msg: bytes


def get_session_values(session_ctx: SessionContext) -> Tuple[Point, int, int, int, Point, int]:
    """Derive the session's shared numbers: the (tweaked) aggregate key Q, its
    accumulators, the nonce-binding coefficient ``b``, the effective nonce
    ``R = R₁ + b·R₂``, and the BIP-340 challenge ``e``."""
    aggnonce, pubkeys, tweaks, is_xonly, msg = session_ctx
    Q, gacc, tacc = key_agg_and_tweak(pubkeys, tweaks, is_xonly)
    b = int.from_bytes(tagged_hash("MuSig/noncecoef", aggnonce + xbytes(Q) + msg), "big") % N
    try:
        R_1 = cpoint_ext(aggnonce[0:33])
        R_2 = cpoint_ext(aggnonce[33:66])
    except ValueError:
        raise InvalidContributionError(None, "aggnonce")
    R_ = R_1 + b * R_2
    R = R_ if not R_.is_infinity else G          # canceled nonces: substitute G
    e = int.from_bytes(tagged_hash("BIP0340/challenge", xbytes(R) + xbytes(Q) + msg), "big") % N
    return Q, gacc, tacc, b, R, e


def get_session_key_agg_coeff(session_ctx: SessionContext, point: Point) -> int:
    """This signer's ``a_i`` — their key must actually be in the session."""
    pk = cbytes(point)
    if pk not in session_ctx.pubkeys:
        raise ValueError("The signer's pubkey must be included in the list of pubkeys.")
    return key_agg_coeff(session_ctx.pubkeys, pk)


def partial_sign(secnonce: bytearray, sk: bytes, session_ctx: SessionContext) -> bytes:
    """Round 2 (*Sign* in the BIP): this signer's 32-byte share
    ``s_i = k₁ + b·k₂ + e·a_i·d_i``. Zeroizes ``secnonce`` in place first, so
    signing twice with the same nonce raises instead of leaking the key."""
    Q, gacc, _, b, R, e = get_session_values(session_ctx)
    k1_ = int.from_bytes(secnonce[0:32], "big")
    k2_ = int.from_bytes(secnonce[32:64], "big")
    secnonce[:64] = bytes(64)                     # single-use, enforced
    if not 0 < k1_ < N:
        raise ValueError("first secnonce value is out of range.")
    if not 0 < k2_ < N:
        raise ValueError("second secnonce value is out of range.")
    k1 = k1_ if R.y.num % 2 == 0 else N - k1_     # even-Y convention for R
    k2 = k2_ if R.y.num % 2 == 0 else N - k2_
    d_ = int.from_bytes(sk, "big")
    if not 0 < d_ < N:
        raise ValueError("secret key value is out of range.")
    point = d_ * G
    if cbytes(point) != bytes(secnonce[64:97]):
        raise ValueError("Public key does not match nonce_gen argument")
    a = get_session_key_agg_coeff(session_ctx, point)
    g = 1 if Q.y.num % 2 == 0 else N - 1          # even-Y convention for Q
    d = g * gacc * d_ % N                         # fold parity flips into d
    s = (k1 + b * k2 + e * a * d) % N
    psig = s.to_bytes(32, "big")
    pubnonce = cbytes(k1_ * G) + cbytes(k2_ * G)
    # The BIP's mandated self-check: a partial sig we emit must verify.
    assert partial_sig_verify_internal(psig, pubnonce, cbytes(point), session_ctx)
    return psig


def partial_sig_verify(psig: bytes, pubnonces: List[bytes], pubkeys: List[bytes],
                       tweaks: List[bytes], is_xonly: List[bool], msg: bytes, i: int) -> bool:
    """Check signer ``i``'s share *before* aggregating — the accountability
    step. A bad share caught here names its author; caught after aggregation
    it only proves *someone* cheated."""
    if len(pubnonces) != len(pubkeys):
        raise ValueError("The `pubnonces` and `pubkeys` arrays must have the same length.")
    if len(tweaks) != len(is_xonly):
        raise ValueError("The `tweaks` and `is_xonly` arrays must have the same length.")
    session_ctx = SessionContext(nonce_agg(pubnonces), pubkeys, tweaks, is_xonly, msg)
    return partial_sig_verify_internal(psig, pubnonces[i], pubkeys[i], session_ctx)


def partial_sig_verify_internal(psig: bytes, pubnonce: bytes, pk: bytes,
                                session_ctx: SessionContext) -> bool:
    """``s_i·G == R_i + e·a_i·P_i`` — the per-signer analogue of BIP-340
    verification, with this signer's effective nonce ``R_i = R_i1 + b·R_i2``
    (negated when the session's R needed negating)."""
    Q, gacc, _, b, R, e = get_session_values(session_ctx)
    s = int.from_bytes(psig, "big")
    if s >= N:
        return False
    R_s = cpoint(pubnonce[0:33]) + b * cpoint(pubnonce[33:66])
    if R.y.num % 2 == 1:
        R_s = Point(R_s.x, P - R_s.y.num)
    point = cpoint(pk)
    a = get_session_key_agg_coeff(session_ctx, point)
    g = 1 if Q.y.num % 2 == 0 else N - 1
    g_ = g * gacc % N
    return s * G == R_s + (e * a * g_ % N) * point


def partial_sig_agg(psigs: List[bytes], session_ctx: SessionContext) -> bytes:
    """Combine: ``s = Σ s_i + e·g·tacc`` (the tweak's contribution enters once,
    here). Returns ``R.x ‖ s`` — a standard 64-byte BIP-340 signature that
    ``schnorr.verify`` accepts against the aggregate x-only key."""
    Q, _, tacc, _, R, e = get_session_values(session_ctx)
    s = 0
    for i, psig in enumerate(psigs):
        s_i = int.from_bytes(psig, "big")
        if s_i >= N:
            raise InvalidContributionError(i, "psig")
        s = (s + s_i) % N
    g = 1 if Q.y.num % 2 == 0 else N - 1
    s = (s + e * g * tacc) % N
    return xbytes(R) + s.to_bytes(32, "big")
