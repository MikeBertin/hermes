"""FROST threshold Schnorr (RFC 9591, ciphersuite FROST(secp256k1, SHA-256)).

Anchored byte-for-byte to the official Appendix E.5 test vector: a 2-of-3 group
where participants 1 and 3 sign the message "test". Every intermediate value the
RFC publishes — shares, nonces, commitments, binding factors, signature shares,
and the aggregate signature — is reproduced exactly, then the signature is
verified and the threshold semantics are checked.
"""

from hermes import frost
from hermes.curve import G, N
from hermes.keys import PublicKey

H = lambda s: bytes.fromhex(s)


# --- Appendix E.5 published values -------------------------------------------
GROUP_SECRET = 0x0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114
GROUP_PUBKEY = "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f"
COEFF1 = 0xfbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579
MSG = H("74657374")   # "test"

SHARES = {
    1: 0x08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c,
    2: 0x04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984,
    3: 0x00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc,
}
# per-signer round-one randomness / expected nonces & commitments / binding factors
P1 = dict(
    hr=H("7ea5ed09af19f6ff21040c07ec2d2adbd35b759da5a401d4c99dd26b82391cb2"),
    br=H("47acab018f116020c10cb9b9abdc7ac10aae1b48ca6e36dc15acb6ec9be5cdc5"),
    hn=0x841d3a6450d7580b4da83c8e618414d0f024391f2aeb511d7579224420aa81f0,
    bn=0x8d2624f532af631377f33cf44b5ac5f849067cae2eacb88680a31e77c79b5a80,
    hc="03c699af97d26bb4d3f05232ec5e1938c12f1e6ae97643c8f8f11c9820303f1904",
    bc="02fa2aaccd51b948c9dc1a325d77226e98a5a3fe65fe9ba213761a60123040a45e",
    bf=0x3e08fe561e075c653cbfd46908a10e7637c70c74f0a77d5fd45d1a750c739ec6,
    sig=0xc4fce1775a1e141fb579944166eab0d65eefe7b98d480a569bbbfcb14f91c197,
)
P3 = dict(
    hn=0x2b19b13f193f4ce83a399362a90cdc1e0ddcd83e57089a7af0bdca71d47869b2,
    bn=0x7a443bde83dc63ef52dda354005225ba0e553243402a4705ce28ffaafe0f5b98,
    hc="03077507ba327fc074d2793955ef3410ee3f03b82b4cdc2370f71d865beb926ef6",
    bc="02ad53031ddfbbacfc5fbda3d3b0c2445c8e3e99cbc4ca2db2aa283fa68525b135",
    bf=0x93f79041bb3fd266105be251adaeb5fd7f8b104fb554a4ba9a0becea48ddbfd7,
    sig=0x0160fd0d388932f4826d2ebcd6b9eaba734f7c71cf25b4279a4ca2581e47b18d,
)
SIG = "0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324"

SEC = lambda pt: PublicKey(pt).sec().hex()


def test_keygen_shares_match_vector():
    shares, group_pubkey = frost.trusted_dealer_keygen(GROUP_SECRET, [COEFF1], 3)
    assert SEC(group_pubkey) == GROUP_PUBKEY
    for identifier, value in shares:
        assert value == SHARES[identifier]


def test_nonce_generation_matches_vector():
    # P1's nonces are H3(randomness || share), deterministic given the randomness
    assert frost.nonce_generate(SHARES[1], P1["hr"]) == P1["hn"]
    assert frost.nonce_generate(SHARES[1], P1["br"]) == P1["bn"]
    (hn, bn), (hc, bc) = frost.commit(SHARES[1], P1["hr"], P1["br"])
    assert (hn, bn) == (P1["hn"], P1["bn"])
    assert SEC(hc) == P1["hc"] and SEC(bc) == P1["bc"]


def _commitment_list():
    return [
        (1, PublicKey.parse(H(P1["hc"])).point, PublicKey.parse(H(P1["bc"])).point),
        (3, PublicKey.parse(H(P3["hc"])).point, PublicKey.parse(H(P3["bc"])).point),
    ]


def test_binding_factors_match_vector():
    group_pubkey = GROUP_SECRET * G
    factors = dict(frost.compute_binding_factors(group_pubkey, _commitment_list(), MSG))
    assert factors[1] == P1["bf"]
    assert factors[3] == P3["bf"]


def test_signature_shares_match_vector():
    group_pubkey = GROUP_SECRET * G
    commitments = _commitment_list()
    z1 = frost.sign(1, SHARES[1], group_pubkey, (P1["hn"], P1["bn"]), MSG, commitments)
    z3 = frost.sign(3, SHARES[3], group_pubkey, (P3["hn"], P3["bn"]), MSG, commitments)
    assert z1 == P1["sig"]
    assert z3 == P3["sig"]


def test_aggregate_and_verify_match_vector():
    group_pubkey = PublicKey.parse(H(GROUP_PUBKEY)).point
    commitments = _commitment_list()
    signature = frost.aggregate(commitments, MSG, group_pubkey, [P1["sig"], P3["sig"]])
    assert frost.serialize_signature(signature).hex() == SIG
    # and it verifies as a plain Schnorr signature under the group key
    assert frost.verify(MSG, signature, group_pubkey) is True


def test_share_verification_pins_a_bad_share():
    group_pubkey = GROUP_SECRET * G
    commitments = _commitment_list()
    bfl = frost.compute_binding_factors(group_pubkey, commitments, MSG)
    R = frost.compute_group_commitment(commitments, bfl)
    ok = frost.verify_share(1, SHARES[1] * G, P1["sig"], group_pubkey, R, commitments, bfl, MSG)
    assert ok is True
    # a corrupted share fails its own check (identifiable abort)
    bad = frost.verify_share(1, SHARES[1] * G, (P1["sig"] + 1) % N, group_pubkey, R, commitments, bfl, MSG)
    assert bad is False


# --- threshold semantics: any t of n sign; a full end-to-end round -----------
def _run_ceremony(signer_ids):
    """A full 2-of-3 ceremony over an arbitrary signing subset, deterministic
    randomness for reproducibility."""
    shares, group_pubkey = frost.trusted_dealer_keygen(GROUP_SECRET, [COEFF1], 3)
    share_of = dict(shares)
    msg = b"threshold spend"
    nonces, commitments = {}, []
    for i in signer_ids:
        seed = bytes([i]) * 32
        nonce, commit = frost.commit(share_of[i], b"h" + seed[:31], b"b" + seed[:31])
        nonces[i] = nonce
        commitments.append((i, commit[0], commit[1]))
    commitments.sort()
    shares_out = [frost.sign(i, share_of[i], group_pubkey, nonces[i], msg, commitments)
                  for i in signer_ids]
    sig = frost.aggregate(commitments, msg, group_pubkey, shares_out)
    return frost.verify(msg, sig, group_pubkey)


def test_any_two_of_three_produce_a_valid_signature():
    assert _run_ceremony([1, 2]) is True
    assert _run_ceremony([1, 3]) is True
    assert _run_ceremony([2, 3]) is True


def test_lagrange_recombines_the_shares_to_the_secret():
    # any 2 shares Lagrange-interpolate back to the group secret at x=0
    shares, _ = frost.trusted_dealer_keygen(GROUP_SECRET, [COEFF1], 3)
    share_of = dict(shares)
    for subset in ([1, 2], [1, 3], [2, 3]):
        s = 0
        for i in subset:
            lam = frost.derive_interpolating_value(subset, i)
            s = (s + lam * share_of[i]) % N
        assert s == GROUP_SECRET
