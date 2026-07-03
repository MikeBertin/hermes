"""Lightning payment channels (BOLT-3): key derivation, per-commitment secrets,
and the revocation/penalty mechanism.

Anchored byte-for-byte to the official BOLT-3 test vectors:
  * Appendix D — per-commitment secret generation.
  * Appendix E — key derivation (localpubkey/privkey, revocationpubkey/privkey).
Plus an end-to-end channel lifecycle (open → update → revoke → cheat → punish),
with every spend of a ``to_local`` output run through our own Script VM so the
OP_IF / OP_CHECKSEQUENCEVERIFY branches are actually exercised.
"""

from hermes import PublicKey, sign, verify
from hermes.curve import G
from hermes.ecdsa import parse_der, ser_sig
from hermes.script import Script, evaluate
from hermes.lightning import (
    derive_pubkey, derive_privkey, derive_revocation_pubkey, derive_revocation_privkey,
    per_commitment_secret, funding_script, funding_address, to_local_script,
    commitment_tx, sign_funding, penalty_tx, sign_penalty, sign_to_local_delayed,
)


def _pt(hexsec):
    return PublicKey.parse(bytes.fromhex(hexsec)).point


def _sec(point):
    return PublicKey(point).sec().hex()


# --- BOLT-3 Appendix D: per-commitment secret generation ---------------------
def test_bolt3_appendix_d_generation():
    cases = [
        ("00" * 32, 281474976710655,
         "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148"),
        ("FF" * 32, 281474976710655,
         "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc"),
        ("FF" * 32, 0xaaaaaaaaaaa,
         "56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528"),
        ("FF" * 32, 0x555555555555,
         "9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31"),
        ("01" * 32, 1,
         "915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c"),
    ]
    for seed_hex, index, expected in cases:
        assert per_commitment_secret(bytes.fromhex(seed_hex), index).hex() == expected


# --- BOLT-3 Appendix E: key derivation ---------------------------------------
BASE_SECRET = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
PER_COMMITMENT_SECRET = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
BASE_POINT = "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
PER_COMMITMENT_POINT = "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486"


def test_bolt3_appendix_e_basepoints():
    # the published points are just the secrets times G
    assert _sec(BASE_SECRET * G) == BASE_POINT
    assert _sec(PER_COMMITMENT_SECRET * G) == PER_COMMITMENT_POINT


def test_bolt3_appendix_e_pubkey_derivation():
    localpubkey = derive_pubkey(_pt(BASE_POINT), _pt(PER_COMMITMENT_POINT))
    assert _sec(localpubkey) == \
        "0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"


def test_bolt3_appendix_e_privkey_derivation():
    localprivkey = derive_privkey(BASE_SECRET, _pt(PER_COMMITMENT_POINT))
    assert localprivkey == \
        0xcbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f
    # the derived private key must produce the derived public key
    assert _sec(localprivkey * G) == \
        "0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"


def test_bolt3_appendix_e_revocation_pubkey():
    revpub = derive_revocation_pubkey(_pt(BASE_POINT), _pt(PER_COMMITMENT_POINT))
    assert _sec(revpub) == \
        "02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0"


def test_bolt3_appendix_e_revocation_privkey():
    revpriv = derive_revocation_privkey(BASE_SECRET, PER_COMMITMENT_SECRET)
    assert revpriv == \
        0xd09ffff62ddb2297ab000cc85bcb4283fdeb6aa052affbc9dddcf33b61078110
    # the crux: the blinded private key, assembled from BOTH secrets, matches the
    # revocation public key that was built from the two POINTS.
    assert _sec(revpriv * G) == \
        "02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0"


# --- funding output ----------------------------------------------------------
def test_funding_is_sorted_2of2():
    a = PublicKey(111 * G).sec()
    b = PublicKey(222 * G).sec()
    # both peers derive the identical script regardless of argument order
    assert funding_script(a, b).raw_serialize() == funding_script(b, a).raw_serialize()
    assert funding_address(a, b).startswith("bc1q")


# --- a full channel lifecycle: open -> update -> revoke -> cheat -> punish ----
class ChannelParty:
    """Bundle a party's long-term secrets/points for the lifecycle test."""
    def __init__(self, base):
        self.funding = base + 1
        self.funding_pub = PublicKey(self.funding * G).sec()
        self.payment = base + 2                       # to_remote key (P2WPKH)
        self.payment_pub = PublicKey(self.payment * G).sec()
        self.delayed_basepoint_secret = base + 3
        self.delayed_basepoint = self.delayed_basepoint_secret * G
        self.revocation_basepoint_secret = base + 4
        self.revocation_basepoint = self.revocation_basepoint_secret * G
        self.seed = (base % 256).to_bytes(1, "big") * 32


TO_SELF_DELAY = 144
FUNDING_TXID = bytes.fromhex("11" * 32)


def _alice_commitment(alice, bob, index, alice_amt, bob_amt):
    """Build Alice's commitment for a given state: her balance sits behind the
    to_local (revocation) script, Bob's is a plain to_remote."""
    pcs = per_commitment_secret(alice.seed, index)
    ppc = int.from_bytes(pcs, "big") * G
    # revocation key uses BOB's basepoint + ALICE's per-commitment point
    revocation_pub = PublicKey(derive_revocation_pubkey(bob.revocation_basepoint, ppc)).sec()
    delayed_pub = PublicKey(derive_pubkey(alice.delayed_basepoint, ppc)).sec()
    commit = commitment_tx(
        FUNDING_TXID, 0,
        to_local_amount=alice_amt, to_remote_amount=bob_amt,
        revocation_pubkey=revocation_pub, local_delayed_pubkey=delayed_pub,
        to_self_delay=TO_SELF_DELAY, remote_pubkey=bob.payment_pub,
    )
    return commit, pcs, ppc


def _vm_spend_to_local(spend_tx, commitment, privkey, revocation, sequence):
    """Sign and run a to_local spend through the Script VM, returning validity.
    The input's nSequence is committed to by BIP-143, so set it before signing."""
    spend_tx.inputs[0].sequence = sequence
    z = spend_tx.sig_hash_bip143(0, commitment.to_local_script, commitment.to_local_amount)
    flat_sig = ser_sig(sign(privkey, z))
    selector = b"\x01" if revocation else b""       # truthy -> IF (revocation) path
    unlock = Script([flat_sig, selector])
    return evaluate(unlock + commitment.to_local_script, z=z, sequence=sequence)


def test_channel_lifecycle_and_penalty():
    alice, bob = ChannelParty(1000), ChannelParty(2000)
    funding_amount = 10_000_000

    # --- open: the commitment's funding spend is a valid 2-of-2 signature ---
    state1, pcs1, ppc1 = _alice_commitment(alice, bob, index=1, alice_amt=8_000_000, bob_amt=2_000_000)
    sign_funding(state1.tx, 0, funding_amount, alice.funding, bob.funding)
    assert state1.tx.verify_input_p2wsh_multisig(0, funding_amount) is True

    # --- update to state 2 (Alice pays Bob 5M) and REVOKE state 1 ----------
    _state2, _pcs2, _ppc2 = _alice_commitment(alice, bob, index=2, alice_amt=3_000_000, bob_amt=7_000_000)
    # revoking state 1 = Alice hands Bob her per-commitment secret for index 1.
    # Bob can now assemble the revocation private key for state 1's to_local.
    rev_priv = derive_revocation_privkey(bob.revocation_basepoint_secret, int.from_bytes(pcs1, "big"))
    # it matches the revocation pubkey baked into state 1's to_local script
    assert PublicKey(rev_priv * G).sec() == state1.to_local_script.cmds[1]

    # --- cheat: Alice broadcasts the REVOKED state 1 (where she had 8M) -----
    # Bob punishes her by sweeping her whole to_local via the revocation branch.
    sweep = Script([0x00, PublicKey(bob.payment * G).hash160()])   # a P2WPKH sweep
    penalty = penalty_tx(state1, sweep)
    sign_penalty(penalty, 0, state1, rev_priv)

    # (a) the real DER witness signature verifies over the BIP-143 sighash
    z = penalty.sig_hash_bip143(0, state1.to_local_script, state1.to_local_amount)
    der_sig = penalty.inputs[0].witness[0]
    assert verify(rev_priv * G, z, parse_der(der_sig[:-1])) is True

    # (b) the Script VM runs the OP_IF revocation branch to TRUE
    assert _vm_spend_to_local(penalty_tx(state1, sweep), state1, rev_priv,
                              revocation=True, sequence=0) is True

    # a would-be thief WITHOUT the revocation key cannot take the branch
    assert _vm_spend_to_local(penalty_tx(state1, sweep), state1, 0xBADBAD,
                              revocation=True, sequence=0) is False


def test_to_local_delayed_path_respects_csv():
    alice, bob = ChannelParty(1000), ChannelParty(2000)
    state, pcs, ppc = _alice_commitment(alice, bob, index=1, alice_amt=8_000_000, bob_amt=2_000_000)
    alice_delayed_priv = derive_privkey(alice.delayed_basepoint_secret, ppc)
    sweep = Script([0x00, PublicKey(alice.payment * G).hash160()])

    # too soon: the ELSE branch's OP_CHECKSEQUENCEVERIFY rejects the spend
    early = penalty_tx(state, sweep)
    assert _vm_spend_to_local(early, state, alice_delayed_priv,
                              revocation=False, sequence=TO_SELF_DELAY - 1) is False
    # after the delay matures: Alice reclaims her own funds
    matured = penalty_tx(state, sweep)
    assert _vm_spend_to_local(matured, state, alice_delayed_priv,
                              revocation=False, sequence=TO_SELF_DELAY) is True


def test_penalty_witness_is_wire_serializable():
    # the signed penalty tx round-trips through parse/serialize (real wire format)
    alice, bob = ChannelParty(1000), ChannelParty(2000)
    state, pcs, ppc = _alice_commitment(alice, bob, index=1, alice_amt=8_000_000, bob_amt=2_000_000)
    rev_priv = derive_revocation_privkey(bob.revocation_basepoint_secret, int.from_bytes(pcs, "big"))
    sweep = Script([0x00, PublicKey(bob.payment * G).hash160()])
    penalty = penalty_tx(state, sweep)
    sign_penalty(penalty, 0, state, rev_priv)
    from hermes import Tx
    raw = penalty.serialize()
    assert Tx.parse(raw).serialize() == raw
