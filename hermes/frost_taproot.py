"""BIP-340 / Taproot FROST — a threshold signature that actually spends Bitcoin.

Demo 15's FROST follows RFC 9591 exactly, but that ciphersuite's challenge hash
isn't BIP-340's, so its 65-byte signature can't spend a Taproot output. This
re-skins the *same* FROST protocol to the BIP-340 challenge and its x-only,
even-Y conventions, so the aggregate is a genuine 64-byte BIP-340 signature that
:func:`hermes.schnorr.verify` accepts.

Wrapped in BIP-341's TapTweak, the group key becomes a ``bc1p…`` address, and any
``t`` of ``n`` officers can produce a **key-path spend** of it — indistinguishable
on-chain from a lone signer. A true t-of-n Taproot vault. There is no finalised
BIP with test vectors for this yet, so correctness is pinned by self-consistency
against our (vector-anchored) ``schnorr.verify`` and ``taproot`` modules.

The subtlety over RFC 9591 is the sign flips BIP-340 forces on the effective
nonce ``R``, the group key ``P``, and the tweaked output key ``Q`` whenever any of
them has an odd y-coordinate.
"""

from __future__ import annotations

from . import frost
from .curve import G, N, Point
from .schnorr import lift_x, tagged_hash
from .taproot import output_key, p2tr_address, tap_tweak


def _xonly(point: Point) -> bytes:
    return int(point.x.num).to_bytes(32, "big")


def _sign_of(point: Point) -> int:
    """+1 if the point has even y (BIP-340's canonical form), −1 otherwise."""
    return 1 if int(point.y.num) % 2 == 0 else -1


def _challenge(nonce_point: Point, pubkey_xonly: bytes, msg: bytes) -> int:
    return int.from_bytes(
        tagged_hash("BIP0340/challenge", _xonly(nonce_point) + pubkey_xonly + msg), "big") % N


# --- core BIP-340 FROST: verifies under the x-only group key -----------------
def sign(identifier: int, secret_share: int, group_public_key: Point,
         nonces: tuple, msg: bytes, commitment_list: list) -> int:
    """A BIP-340 signature share. Identical to RFC 9591's share (demo 15) except
    the challenge is BIP-340's and the effective nonce/key parities flip the
    signs: ``z_i = g_R·(k_h + ρ_i·k_b) + g_P·λ_i·s_i·c``."""
    binding_factor_list = frost.compute_binding_factors(group_public_key, commitment_list, msg)
    binding_factor = dict(binding_factor_list)[identifier]
    group_commitment = frost.compute_group_commitment(commitment_list, binding_factor_list)
    lambda_i = frost.derive_interpolating_value([i for i, _, _ in commitment_list], identifier)
    c = _challenge(group_commitment, _xonly(group_public_key), msg)
    g_r, g_p = _sign_of(group_commitment), _sign_of(group_public_key)
    hiding_nonce, binding_nonce = nonces
    return (g_r * (hiding_nonce + binding_nonce * binding_factor)
            + g_p * lambda_i * secret_share * c) % N


def aggregate(commitment_list: list, msg: bytes, group_public_key: Point, sig_shares: list) -> bytes:
    """Combine shares into a 64-byte BIP-340 signature ``R.x ‖ z``."""
    binding_factor_list = frost.compute_binding_factors(group_public_key, commitment_list, msg)
    group_commitment = frost.compute_group_commitment(commitment_list, binding_factor_list)
    return _xonly(group_commitment) + (sum(sig_shares) % N).to_bytes(32, "big")


# --- Taproot key-path spend: verifies under the tweaked output key -----------
def vault_address(group_public_key: Point, testnet: bool = False) -> str:
    """The ``bc1p…`` address for the FROST group key used as a Taproot internal
    key (BIP-341 key-path, TapTweak applied)."""
    return p2tr_address(_xonly(group_public_key), testnet)


def output_xonly(group_public_key: Point) -> bytes:
    return output_key(_xonly(group_public_key))


def _tweak_context(group_public_key: Point):
    internal = _xonly(group_public_key)
    t = tap_tweak(internal)
    q_point = lift_x(int.from_bytes(internal, "big")) + t * G     # the actual output key Q
    return t, q_point


def taproot_sign(identifier: int, secret_share: int, group_public_key: Point,
                 nonces: tuple, msg: bytes, commitment_list: list) -> int:
    """A signature share for a *key-path spend* of the vault: signs for the
    TapTweaked output key ``Q``. The challenge uses ``Q``'s x-only key, and the
    share carries the combined ``g_Q·g_P`` sign flip; the tweak term is added
    once at aggregation."""
    t, q_point = _tweak_context(group_public_key)
    binding_factor_list = frost.compute_binding_factors(group_public_key, commitment_list, msg)
    binding_factor = dict(binding_factor_list)[identifier]
    group_commitment = frost.compute_group_commitment(commitment_list, binding_factor_list)
    lambda_i = frost.derive_interpolating_value([i for i, _, _ in commitment_list], identifier)
    c = _challenge(group_commitment, _xonly(q_point), msg)
    g_r, g_p, g_q = _sign_of(group_commitment), _sign_of(group_public_key), _sign_of(q_point)
    hiding_nonce, binding_nonce = nonces
    return (g_r * (hiding_nonce + binding_nonce * binding_factor)
            + c * g_q * g_p * lambda_i * secret_share) % N


def taproot_aggregate(commitment_list: list, msg: bytes, group_public_key: Point, sig_shares: list) -> bytes:
    """Combine the taproot shares, adding the one-off tweak term ``c·g_Q·t``, into
    a 64-byte BIP-340 signature that spends the ``bc1p…`` vault key-path."""
    t, q_point = _tweak_context(group_public_key)
    binding_factor_list = frost.compute_binding_factors(group_public_key, commitment_list, msg)
    group_commitment = frost.compute_group_commitment(commitment_list, binding_factor_list)
    c = _challenge(group_commitment, _xonly(q_point), msg)
    g_q = _sign_of(q_point)
    z = (sum(sig_shares) + c * g_q * t) % N
    return _xonly(group_commitment) + z.to_bytes(32, "big")
