"""FROST DKG (PedPoP) — distributed key generation with no trusted dealer.

RFC 9591 standardises only FROST *signing*, so there are no official DKG vectors. Instead
we pin correctness by self-consistency: a full 2-of-3 ceremony runs, every proof of
possession and every Feldman sub-share verifies, the shares Shamir-reconstruct to the group
key, and — the real proof — the DKG output produces a signature the (RFC-9591-vector-anchored)
``frost.verify`` accepts. The group secret is never assembled anywhere in the flow.
"""

from hermes import frost, frost_dkg
from hermes.curve import G, N
from hermes.keys import PublicKey

MSG = b"pay the vault"

# Each participant picks their own degree-(t-1) polynomial. Threshold t = 2, so two
# coefficients each: [a0 (their secret contribution), a1]. Distinct per participant.
POLYS = {
    1: [0x1111111111111111111111111111111111111111111111111111111111111111,
        0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a],
    2: [0x2222222222222222222222222222222222222222222222222222222222222222,
        0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b],
    3: [0x3333333333333333333333333333333333333333333333333333333333333333,
        0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c],
}
PARTICIPANTS = [1, 2, 3]


def _run_dkg():
    """Drive a full PedPoP ceremony among all PARTICIPANTS, asserting every check, and
    return {id: (secret_share, verification_share)} plus the group public key."""
    # --- round 1: everyone broadcasts commitments + a proof of possession ---
    commitments, proofs = {}, {}
    for i in PARTICIPANTS:
        commitments[i], proofs[i] = frost_dkg.round1_commit(i, POLYS[i], f"pop-rand-{i}".encode())
    # every participant verifies every other's proof of possession
    for i in PARTICIPANTS:
        assert frost_dkg.verify_pop(i, commitments[i], proofs[i]) is True

    # --- round 2: each participant sends f_i(j) to j, and j verifies it ---
    result = {}
    for j in PARTICIPANTS:                       # the recipient
        received = []
        for i in PARTICIPANTS:                   # the sender
            share_ij = frost_dkg.secret_share_for(POLYS[i], j)
            assert frost_dkg.verify_share(j, commitments[i], share_ij) is True
            received.append(share_ij)
        secret_share, group_pubkey, verification_share = frost_dkg.finalize(
            received, [commitments[i] for i in PARTICIPANTS])
        result[j] = (secret_share, verification_share, group_pubkey)
    return result


def test_dkg_agrees_on_one_group_key():
    result = _run_dkg()
    keys = {PublicKey(result[i][2]).sec() for i in PARTICIPANTS}
    assert len(keys) == 1                        # everyone derived the identical group key
    # and it is exactly the sum of the participants' secret contributions · G
    group_secret = sum(POLYS[i][0] for i in PARTICIPANTS) % N
    assert result[1][2] == group_secret * G


def test_dkg_verification_shares_interpolate_to_the_group_key():
    # any t=2 of the public verification shares Lagrange-interpolate back to the group key
    result = _run_dkg()
    group_pubkey = result[1][2]
    for signers in ([1, 2], [1, 3], [2, 3]):
        acc = None
        for i in signers:
            lam = frost.derive_interpolating_value(signers, i)
            term = lam * result[i][1]            # λ_i · (s_i · G)
            acc = term if acc is None else acc + term
        assert acc == group_pubkey


def test_dkg_shares_reconstruct_the_never_assembled_secret():
    # the shares ARE Shamir shares of Σ a_j0 — reconstructing proves it (the reconstruction
    # is exactly the step DKG exists to avoid ever performing in practice).
    result = _run_dkg()
    for signers in ([1, 2], [2, 3]):
        secret = sum(frost.derive_interpolating_value(signers, i) * result[i][0]
                     for i in signers) % N
        assert secret * G == result[1][2]        # s·G == group key
    # no single participant's material equals the secret
    group_secret = sum(POLYS[i][0] for i in PARTICIPANTS) % N
    for i in PARTICIPANTS:
        assert result[i][0] != group_secret


def test_dkg_output_signs_a_valid_frost_signature():
    # THE proof: feed the DKG shares straight into demo 15's signer. Any 2 of 3 sign,
    # and the aggregate verifies under the DKG group key.
    result = _run_dkg()
    group_pubkey = result[1][2]
    for signers in ([1, 2], [1, 3], [2, 3]):
        commitment_list, nonce_map = [], {}
        for i in signers:
            nonces, (hcom, bcom) = frost.commit(
                result[i][0], f"hn-{i}".encode(), f"bn-{i}".encode())
            nonce_map[i] = nonces
            commitment_list.append((i, hcom, bcom))
        commitment_list.sort()
        shares = [frost.sign(i, result[i][0], group_pubkey, nonce_map[i], MSG, commitment_list)
                  for i in signers]
        signature = frost.aggregate(commitment_list, MSG, group_pubkey, shares)
        assert frost.verify(MSG, signature, group_pubkey) is True


def test_dkg_rejects_a_tampered_subshare():
    commitment, _ = frost_dkg.round1_commit(1, POLYS[1], b"r")
    good = frost_dkg.secret_share_for(POLYS[1], 2)
    assert frost_dkg.verify_share(2, commitment, good) is True
    assert frost_dkg.verify_share(2, commitment, good + 1) is False       # off by one
    assert frost_dkg.verify_share(3, commitment, good) is False           # wrong recipient index


def test_dkg_rejects_a_forged_proof_of_possession():
    commitment, proof = frost_dkg.round1_commit(1, POLYS[1], b"r")
    r_point, mu = proof
    assert frost_dkg.verify_pop(1, commitment, (r_point, (mu + 1) % N)) is False   # bad μ
    assert frost_dkg.verify_pop(2, commitment, proof) is False                     # wrong identifier
    # a participant who doesn't know a0 can't forge: commit to a0·G but prove with a different a0
    fake_commitment = [(POLYS[1][0] + 7) * G] + commitment[1:]
    assert frost_dkg.verify_pop(1, fake_commitment, proof) is False
