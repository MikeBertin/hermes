"""BIP-340 / Taproot FROST — the threshold signature that spends a bc1p vault.

No finalised BIP with test vectors exists, so correctness is pinned by
self-consistency: over many random group keys and every 2-of-3 signing subset
(which between them exercise all the even/odd-y parity combinations of the nonce
R, the group key P, and the tweaked output key Q), the aggregate must verify as a
genuine BIP-340 signature via the vector-anchored ``schnorr.verify`` — both under
the raw group key (core) and under the TapTweaked output key (a real key-path
spend of the vault address).
"""

import secrets

from hermes import frost, frost_taproot, schnorr, taproot
from hermes.bech32 import decode_segwit
from hermes.curve import G, N


def _rand():
    return 1 + secrets.randbelow(N - 1)


def _run(secret, coeff, signer_ids, msg, taproot_spend):
    shares, group_pubkey = frost.trusted_dealer_keygen(secret, [coeff], 3)
    share_of = dict(shares)
    nonces, commitments = {}, []
    for i in signer_ids:
        nonce, commit = frost.commit(share_of[i], secrets.token_bytes(32), secrets.token_bytes(32))
        nonces[i] = nonce
        commitments.append((i, commit[0], commit[1]))
    commitments.sort()
    if taproot_spend:
        shs = [frost_taproot.taproot_sign(i, share_of[i], group_pubkey, nonces[i], msg, commitments)
               for i in signer_ids]
        sig = frost_taproot.taproot_aggregate(commitments, msg, group_pubkey, shs)
        pubkey = frost_taproot.output_xonly(group_pubkey)
    else:
        shs = [frost_taproot.sign(i, share_of[i], group_pubkey, nonces[i], msg, commitments)
               for i in signer_ids]
        sig = frost_taproot.aggregate(commitments, msg, group_pubkey, shs)
        pubkey = frost_taproot._xonly(group_pubkey)
    return schnorr.verify(pubkey, msg, sig), group_pubkey, sig


def test_core_bip340_frost_verifies_across_parities():
    for _ in range(12):
        secret, coeff = _rand(), _rand()
        for subset in ([1, 2], [1, 3], [2, 3]):
            ok, _, _ = _run(secret, coeff, subset, secrets.token_bytes(32), taproot_spend=False)
            assert ok is True


def test_taproot_frost_key_path_spends_the_vault():
    for _ in range(12):
        secret, coeff = _rand(), _rand()
        for subset in ([1, 2], [1, 3], [2, 3]):
            ok, _, _ = _run(secret, coeff, subset, secrets.token_bytes(32), taproot_spend=True)
            assert ok is True


def test_vault_address_is_bc1p_committing_to_the_output_key():
    _, group_pubkey = frost.trusted_dealer_keygen(_rand(), [_rand()], 3)
    address = frost_taproot.vault_address(group_pubkey)
    assert address.startswith("bc1p")
    witver, program = decode_segwit("bc", address)
    assert witver == 1
    # the address commits to the TapTweaked output key of the FROST group key
    assert bytes(program) == frost_taproot.output_xonly(group_pubkey)
    assert bytes(program) == taproot.output_key(frost_taproot._xonly(group_pubkey))


def test_below_threshold_share_does_not_verify():
    # a single signer produces a signature for their own share, not the group key
    secret, coeff = _rand(), _rand()
    shares, group_pubkey = frost.trusted_dealer_keygen(secret, [coeff], 3)
    share_of = dict(shares)
    msg = b"lone signer"
    nonce, commit = frost.commit(share_of[1], secrets.token_bytes(32), secrets.token_bytes(32))
    commitments = [(1, commit[0], commit[1])]
    z = frost_taproot.sign(1, share_of[1], group_pubkey, nonce, msg, commitments)
    sig = frost_taproot.aggregate(commitments, msg, group_pubkey, [z])
    assert schnorr.verify(frost_taproot._xonly(group_pubkey), msg, sig) is False


def test_wrong_share_does_not_verify():
    # a signer using someone else's secret share yields an invalid aggregate
    secret, coeff = _rand(), _rand()
    shares, group_pubkey = frost.trusted_dealer_keygen(secret, [coeff], 3)
    share_of = dict(shares)
    msg = b"threshold spend"
    n1, c1 = frost.commit(share_of[1], secrets.token_bytes(32), secrets.token_bytes(32))
    n2, c2 = frost.commit(share_of[2], secrets.token_bytes(32), secrets.token_bytes(32))
    commitments = [(1, c1[0], c1[1]), (2, c2[0], c2[1])]
    z1 = frost_taproot.sign(1, share_of[1], group_pubkey, n1, msg, commitments)
    z2 = frost_taproot.sign(2, share_of[3], group_pubkey, n2, msg, commitments)  # wrong share!
    sig = frost_taproot.aggregate(commitments, msg, group_pubkey, [z1, z2])
    assert schnorr.verify(frost_taproot._xonly(group_pubkey), msg, sig) is False
