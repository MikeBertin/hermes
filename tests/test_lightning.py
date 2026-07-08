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
    htlc_offered_script, htlc_received_script, htlc_script, payment_hash,
    htlc_timeout_tx, htlc_success_tx, sign_htlc_timeout, sign_htlc_success,
)
from hermes import PrivateKey, hash160, sha256, ripemd160


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


# --- BOLT-3 Appendix C: HTLC witnessScripts, byte-for-byte -------------------
# The commitment-tx test vectors publish these keys and the exact HTLC scripts.
C_REVPUB = bytes.fromhex("0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19")
C_REMOTE_HTLC = bytes.fromhex("0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b")
C_LOCAL_HTLC = bytes.fromhex("030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7")


def test_bolt3_appendix_c_hash_precursors():
    # RIPEMD160(SHA256(revocationpubkey)) baked into every HTLC script
    assert hash160(C_REVPUB).hex() == "14011f7254d96b819c76986c277d115efce6f7b5"
    # RIPEMD160(payment_hash) for htlc 2 (preimage 0x0202..02) and htlc 0 (0x00..00)
    assert ripemd160(payment_hash(b"\x02" * 32)).hex() == "b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d1"
    assert ripemd160(payment_hash(b"\x00" * 32)).hex() == "b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6"


def test_bolt3_appendix_c_offered_htlc_script():
    # HTLC #2 (local->remote, offered), preimage 0x0202..02
    script = htlc_offered_script(C_REVPUB, C_REMOTE_HTLC, C_LOCAL_HTLC, payment_hash(b"\x02" * 32))
    assert script.raw_serialize().hex() == (
        "76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122c"
        "c726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a4694638"
        "4f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f"
        "7cd9a1d274bc63e3a9b5d188ac6868")


def test_bolt3_appendix_c_received_htlc_script():
    # HTLC #0 (remote->local, received), preimage 0x00..00, cltv_expiry 500
    script = htlc_received_script(C_REVPUB, C_REMOTE_HTLC, C_LOCAL_HTLC, payment_hash(b"\x00" * 32), 500)
    assert script.raw_serialize().hex() == (
        "76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122c"
        "c726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04"
        "250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca81"
        "3e21734b140639e752ae677502f401b175ac6868")


# --- Multi-hop routing: one preimage settles a whole path -------------------
HZ = int.from_bytes(sha256(b"htlc spend digest"), "big")


def _claim(script, secret, preimage):
    """Receiver spends an HTLC via the preimage (IF branch)."""
    unlock = Script([ser_sig(sign(secret, HZ)), preimage, b"\x01"])
    return evaluate(unlock + script, z=HZ)


def _refund(script, secret, locktime):
    """Sender reclaims an HTLC after the timeout (ELSE branch, needs locktime)."""
    unlock = Script([ser_sig(sign(secret, HZ)), b""])
    return evaluate(unlock + script, z=HZ, locktime=locktime)


def test_htlc_routing_one_preimage_settles_the_path():
    alice, bob, carol = PrivateKey(0xA11CE), PrivateKey(0xB0B), PrivateKey(0xCA401)
    apk, bpk, cpk = (k.public_key().sec() for k in (alice, bob, carol))

    # Carol invoices a payment: she picks the preimage, publishes only its hash.
    preimage = sha256(b"carol's secret")
    H = payment_hash(preimage)

    # The route sets up HTLCs FORWARD with DECREASING timeouts (the safety margin
    # each hop needs to claim upstream after being claimed downstream).
    cltv_ab, cltv_bc = 800_100, 800_060           # Alice->Bob expires later than Bob->Carol
    hop_ab = htlc_script(H, receiver_pubkey=bpk, sender_pubkey=apk, cltv_expiry=cltv_ab)
    hop_bc = htlc_script(H, receiver_pubkey=cpk, sender_pubkey=bpk, cltv_expiry=cltv_bc)
    assert cltv_ab > cltv_bc                       # the routing invariant

    # SETTLE BACKWARD: Carol reveals the preimage to claim from Bob...
    assert _claim(hop_bc, carol.secret, preimage) is True
    # ...now Bob knows the preimage and claims the SAME payment from Alice.
    assert _claim(hop_ab, bob.secret, preimage) is True

    # A wrong preimage cannot claim (the hashlock holds).
    assert _claim(hop_bc, carol.secret, sha256(b"guess")) is False
    # The right preimage but the wrong signer also fails (still needs a valid sig).
    assert _claim(hop_bc, alice.secret, preimage) is False


def test_htlc_timeout_refund_respects_cltv():
    alice, bob = PrivateKey(0xA11CE), PrivateKey(0xB0B)
    apk, bpk = alice.public_key().sec(), bob.public_key().sec()
    H = payment_hash(sha256(b"never revealed"))
    hop = htlc_script(H, receiver_pubkey=bpk, sender_pubkey=apk, cltv_expiry=800_100)

    # If Carol never reveals, Alice (the sender) refunds — but only after the timeout.
    assert _refund(hop, alice.secret, locktime=800_100) is True    # matured
    assert _refund(hop, alice.secret, locktime=800_099) is False   # one block too early
    # and the receiver can't take the refund branch (it checks the sender's key)
    assert _refund(hop, bob.secret, locktime=800_100) is False


# --- BOLT-3 Appendix C: second-stage HTLC transactions, byte-for-byte ---------
# The "commitment tx with all five HTLCs untrimmed (minimum feerate)" vector has
# local_feerate_per_kw = 0, so each second-stage output pays the full HTLC amount.
# Its signatures are deterministic (RFC6979), so we reproduce every HTLC-timeout /
# HTLC-success transaction *from the private keys* and match the published hex.
C_LOCAL_DELAYED = bytes.fromhex("03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c")
C_TO_SELF_DELAY = 144
C_LOCAL_HTLC_PRIV = 0xbb13b121cdc357cd2e608b0aea294afca36e2b34cf958e2e6451a2f274694491
C_REMOTE_HTLC_PRIV = 0x8deba327a7cc6d638ab0eb025770400a6184afcba6713c210d8d10e199ff2fda
# the commitment tx these all spend (its txid, natural byte order)
C_COMMIT_TXID = bytes.fromhex("ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b")[::-1]

# (htlc_output_index, amount_sat, cltv, preimage_hex, expected_tx_hex)
_OFFERED = [  # local->remote: HTLC-timeout  (htlc #2 -> output 1, htlc #3 -> output 3)
    (1, 2000, 502, "02" * 32, "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b01000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220649fe8b20e67e46cbb0d09b4acea87dbec001b39b08dee7bdd0b1f03922a8640022037c462dff79df501cecfdb12ea7f4de91f99230bb544726f6e04527b1f89600401483045022100803159dee7935dba4a1d36a61055ce8fd62caa528573cc221ae288515405a252022029c59e7cffce374fe860100a4a63787e105c3cf5156d40b12dd53ff55ac8cf3f01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000"),
    (3, 3000, 503, "03" * 32, "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b03000000000000000001b80b0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207bcbf4f60a9829b05d2dbab84ed593e0291836be715dc7db6b72a64caf646af802201e489a5a84f7c5cc130398b841d138d031a5137ac8f4c49c770a4959dc3c13630147304402203121d9b9c055f354304b016a36662ee99e1110d9501cb271b087ddb6f382c2c80220549882f3f3b78d9c492de47543cb9a697cecc493174726146536c5954dac748701008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000"),
]
_RECEIVED = [  # remote->local: HTLC-success
    (0, 1000, 500, "00" * 32, "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b00000000000000000001e8030000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d9e29616b8f3959f1d3d7f7ce893ffedcdc407717d0de8e37d808c91d3a7c50d022078c3033f6d00095c8720a4bc943c1b45727818c082e4e3ddbc6d3116435b624b014730440220636de5682ef0c5b61f124ec74e8aa2461a69777521d6998295dcea36bc3338110220165285594b23c50b28b82df200234566628a27bcd17f7f14404bd865354eb3ce012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000"),
    (2, 2000, 501, "01" * 32, "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b02000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220770fc321e97a19f38985f2e7732dd9fe08d16a2efa4bcbc0429400a447faf49102204d40b417f3113e1b0944ae0986f517564ab4acd3d190503faf97a6e420d4335201483045022100a437cc2ce77400ecde441b3398fea3c3ad8bdad8132be818227fe3c5b8345989022069d45e7fa0ae551ec37240845e2c561ceb2567eacf3076a6a43a502d05865faa012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000"),
    (4, 4000, 504, "04" * 32, "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b04000000000000000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022076dca5cb81ba7e466e349b7128cdba216d4d01659e29b96025b9524aaf0d1899022060de85697b88b21c749702b7d2cfa7dfeaa1f472c8f1d7d9c23f2bf968464b8701483045022100d9080f103cc92bac15ec42464a95f070c7fb6925014e673ee2ea1374d36a7f7502200c65294d22eb20d48564954d5afe04a385551919d8b2ddb4ae2459daaeee1d95012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000"),
]


def test_bolt3_appendix_c_htlc_timeout_txs():
    for htlc_index, amount, cltv, preimage_hex, expected in _OFFERED:
        # the payment_hash is baked into the script (though unused on the timeout branch)
        offered = htlc_offered_script(C_REVPUB, C_REMOTE_HTLC, C_LOCAL_HTLC,
                                      payment_hash(bytes.fromhex(preimage_hex)))
        sst = htlc_timeout_tx(C_COMMIT_TXID, htlc_index, htlc_amount=amount, cltv_expiry=cltv,
                              revocation_pubkey=C_REVPUB, local_delayed_pubkey=C_LOCAL_DELAYED,
                              to_self_delay=C_TO_SELF_DELAY)
        sign_htlc_timeout(sst, offered, amount, C_REMOTE_HTLC_PRIV, C_LOCAL_HTLC_PRIV)
        assert sst.tx.serialize().hex() == expected


def test_bolt3_appendix_c_htlc_success_txs():
    for htlc_index, amount, cltv, preimage_hex, expected in _RECEIVED:
        preimage = bytes.fromhex(preimage_hex)
        received = htlc_received_script(C_REVPUB, C_REMOTE_HTLC, C_LOCAL_HTLC,
                                        payment_hash(preimage), cltv)
        sst = htlc_success_tx(C_COMMIT_TXID, htlc_index, htlc_amount=amount,
                              revocation_pubkey=C_REVPUB, local_delayed_pubkey=C_LOCAL_DELAYED,
                              to_self_delay=C_TO_SELF_DELAY)
        sign_htlc_success(sst, received, amount, C_REMOTE_HTLC_PRIV, C_LOCAL_HTLC_PRIV, preimage)
        assert sst.tx.serialize().hex() == expected


def test_htlc_timeout_locktime_is_bound_by_the_signatures():
    # The offered-HTLC timeout branch has no CLTV in the *script*; the timelock is
    # enforced because <remotehtlcsig> commits (via BIP-143) to nLockTime=cltv_expiry.
    # Rewriting the tx to an earlier locktime invalidates the signature.
    htlc_index, amount, cltv, preimage_hex, expected = _OFFERED[0]
    offered = htlc_offered_script(C_REVPUB, C_REMOTE_HTLC, C_LOCAL_HTLC, payment_hash(bytes.fromhex(preimage_hex)))
    sst = htlc_timeout_tx(C_COMMIT_TXID, htlc_index, htlc_amount=amount, cltv_expiry=cltv,
                          revocation_pubkey=C_REVPUB, local_delayed_pubkey=C_LOCAL_DELAYED,
                          to_self_delay=C_TO_SELF_DELAY)
    sign_htlc_timeout(sst, offered, amount, C_REMOTE_HTLC_PRIV, C_LOCAL_HTLC_PRIV)
    remote_sig = sst.tx.inputs[0].witness[1]
    z_matured = sst.tx.sig_hash_bip143(0, offered, amount)
    assert verify(C_REMOTE_HTLC_PRIV * G, z_matured, parse_der(remote_sig[:-1])) is True
    sst.tx.locktime = cltv - 1                     # try to time out one block early
    z_early = sst.tx.sig_hash_bip143(0, offered, amount)
    assert verify(C_REMOTE_HTLC_PRIV * G, z_early, parse_der(remote_sig[:-1])) is False


def test_second_stage_output_is_a_revocable_to_local():
    # The payoff: a second-stage HTLC tx pays into a to_local output, so demo 13's
    # penalty machinery applies *recursively*. Built with keys we control so we can
    # exercise both spend paths through our Script VM.
    alice, bob = ChannelParty(1000), ChannelParty(2000)
    ppc = int.from_bytes(per_commitment_secret(alice.seed, 1), "big") * G
    revocation_pub = PublicKey(derive_revocation_pubkey(bob.revocation_basepoint, ppc)).sec()
    delayed_pub = PublicKey(derive_pubkey(alice.delayed_basepoint, ppc)).sec()

    sst = htlc_timeout_tx(bytes.fromhex("22" * 32), 0, htlc_amount=100_000, cltv_expiry=700_000,
                          revocation_pubkey=revocation_pub, local_delayed_pubkey=delayed_pub,
                          to_self_delay=TO_SELF_DELAY)
    sweep = Script([0x00, PublicKey(bob.payment * G).hash160()])

    # (a) if the commitment was revoked, the counterparty sweeps it instantly
    rev_priv = derive_revocation_privkey(bob.revocation_basepoint_secret,
                                         int.from_bytes(per_commitment_secret(alice.seed, 1), "big"))
    assert _vm_spend_to_local(penalty_tx(sst, sweep), sst, rev_priv, revocation=True, sequence=0) is True

    # (b) the owner reclaims via the delayed branch — but only after to_self_delay
    alice_delayed_priv = derive_privkey(alice.delayed_basepoint_secret, ppc)
    assert _vm_spend_to_local(penalty_tx(sst, sweep), sst, alice_delayed_priv,
                              revocation=False, sequence=TO_SELF_DELAY - 1) is False
    assert _vm_spend_to_local(penalty_tx(sst, sweep), sst, alice_delayed_priv,
                              revocation=False, sequence=TO_SELF_DELAY) is True
