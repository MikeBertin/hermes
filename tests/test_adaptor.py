"""Schnorr adaptor signatures / PTLCs.

There is no official vector set for adaptor signatures, so correctness is pinned
by *exhaustive self-consistency*: over many random keys, messages, and adaptor
secrets (exercising both parities of the effective nonce), a completed
pre-signature must verify as a genuine BIP-340 signature via the vector-anchored
``schnorr.verify``, and ``extract`` must recover exactly the adaptor secret.
"""

import secrets

from hermes import adaptor, schnorr
from hermes.curve import G, N


def _rand():
    return 1 + secrets.randbelow(N - 1)


def test_adaptor_roundtrip_many_random_cases():
    for _ in range(64):                         # both nonce parities occur ~50/50
        d = _rand()
        t = _rand()
        msg = secrets.token_bytes(32)
        pubkey = schnorr.pubkey_gen(d)          # x-only
        T = adaptor.adaptor_point(t)

        presig = adaptor.presign(d, msg, T)
        # the pre-signature is provably completable, without knowing t
        assert adaptor.presig_verify(pubkey, msg, T, presig) is True

        # completing it yields a REAL BIP-340 signature
        sig = adaptor.adapt(presig, t)
        assert schnorr.verify(pubkey, msg, sig) is True

        # and publishing that signature reveals the adaptor secret
        recovered = adaptor.extract(presig, sig, T)
        assert recovered == t
        assert recovered * G == T


def test_presig_alone_is_not_a_valid_signature():
    d, t = _rand(), _rand()
    msg = secrets.token_bytes(32)
    pubkey = schnorr.pubkey_gen(d)
    T = adaptor.adaptor_point(t)
    r0, s_prime = adaptor.presign(d, msg, T)
    # naively reading (R0.x || s') as a signature must NOT verify — t is missing
    forged = adaptor._xonly(r0) + s_prime.to_bytes(32, "big")
    assert schnorr.verify(pubkey, msg, forged) is False


def test_presig_verify_rejects_wrong_adaptor_or_key():
    d, t = _rand(), _rand()
    msg = secrets.token_bytes(32)
    pubkey = schnorr.pubkey_gen(d)
    T = adaptor.adaptor_point(t)
    presig = adaptor.presign(d, msg, T)
    assert adaptor.presig_verify(pubkey, msg, adaptor.adaptor_point(_rand()), presig) is False
    assert adaptor.presig_verify(schnorr.pubkey_gen(_rand()), msg, T, presig) is False
    assert adaptor.presig_verify(pubkey, secrets.token_bytes(32), T, presig) is False


def test_wrong_secret_cannot_complete():
    d, t = _rand(), _rand()
    msg = secrets.token_bytes(32)
    pubkey = schnorr.pubkey_gen(d)
    T = adaptor.adaptor_point(t)
    presig = adaptor.presign(d, msg, T)
    bad = adaptor.adapt(presig, _rand())        # completed with the wrong t
    assert schnorr.verify(pubkey, msg, bad) is False


# --- PTLC routing: one adaptor secret settles a whole path -------------------
def test_ptlc_route_one_point_settles_both_hops():
    # Alice -> Bob -> Carol. Carol picks the secret t and its point T = t·G.
    alice, bob, carol = _rand(), _rand(), _rand()
    t = _rand()
    T = adaptor.adaptor_point(t)
    msg_ab = b"Alice->Bob PTLC commitment"
    msg_bc = b"Bob->Carol PTLC commitment"

    # each hop's payment is a pre-signature locked to the SAME point T
    presig_ab = adaptor.presign(alice, msg_ab, T)     # Alice's payment to Bob
    presig_bc = adaptor.presign(bob, msg_bc, T)       # Bob's payment to Carol
    assert adaptor.presig_verify(schnorr.pubkey_gen(alice), msg_ab, T, presig_ab)
    assert adaptor.presig_verify(schnorr.pubkey_gen(bob), msg_bc, T, presig_bc)

    # SETTLE BACKWARD: Carol completes the Bob->Carol signature with t (she's paid)
    sig_bc = adaptor.adapt(presig_bc, t)
    assert schnorr.verify(schnorr.pubkey_gen(bob), msg_bc, sig_bc)

    # Bob sees the completed signature on-chain, extracts t, and uses it to pull
    # his own payment from Alice — the same secret unlocks the hop before.
    t_learned = adaptor.extract(presig_bc, sig_bc, T)
    assert t_learned == t
    sig_ab = adaptor.adapt(presig_ab, t_learned)
    assert schnorr.verify(schnorr.pubkey_gen(alice), msg_ab, sig_ab)


def test_ptlc_hops_can_be_unlinkable_via_a_tweak():
    # Privacy: each hop can offset the point by a random tweak so the T's differ.
    # Bob forwards with T' = T + y·G; learning t' lets him recover t = t' - y.
    t, y = _rand(), _rand()
    T = adaptor.adaptor_point(t)
    T_next = adaptor.adaptor_point((t + y) % N)        # = T + y·G, a different point
    assert adaptor._xonly(T) != adaptor._xonly(T_next)

    bob = _rand()
    msg = b"forwarded hop"
    presig = adaptor.presign(bob, msg, T_next)
    sig = adaptor.adapt(presig, (t + y) % N)
    assert schnorr.verify(schnorr.pubkey_gen(bob), msg, sig)
    t_next = adaptor.extract(presig, sig, T_next)
    assert (t_next - y) % N == t                        # Bob peels the tweak back to t
