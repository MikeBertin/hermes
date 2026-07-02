"""Negative-path tests — the rejection branches the known-answer vectors never
reach. Each of these pins a bug found in review: invalid mnemonics that crashed
(or passed), P2SH/wrong-network addresses silently paid as P2PKH, a multisig
verifier laxer than OP_CHECKMULTISIG, and Script VM stack underflow raising
instead of failing cleanly.
"""

import pytest

from hermes import bip39
from hermes.ecdsa import der, sign
from hermes.keys import PrivateKey
from hermes.script import (
    Script, evaluate,
    OP_CHECKMULTISIG, OP_CHECKSIG, OP_DROP, OP_DUP, OP_EQUAL, OP_EQUALVERIFY,
    OP_HASH160, OP_SHA256, OP_VERIFY, OP_2, OP_3,
)
from hermes.transaction import (
    Tx, TxInput, TxOutput, address_to_script, multisig_script, p2wpkh_script,
)


# --- BIP-39: invalid mnemonics must return False, never raise ------------------
VALID_12 = "abandon " * 11 + "about"          # the all-zero-entropy vector


def test_valid_mnemonic_still_accepted():
    assert bip39.is_valid(VALID_12)


@pytest.mark.parametrize("mnemonic", [
    "zoo",                                     # 1 word
    "zoo zoo",                                 # 2 words
    "zoo zoo zoo zoo",                         # 4 words (used to raise OverflowError)
    "abandon abandon abandon abandon abandon able",  # 6 words with a "valid" checksum
    "abandon " * 12 + "about",                 # 13 words
    "",                                        # empty
])
def test_wrong_word_count_is_invalid(mnemonic):
    assert not bip39.is_valid(mnemonic)
    with pytest.raises(ValueError):
        bip39.mnemonic_to_entropy(mnemonic)


def test_bad_checksum_is_invalid():
    assert not bip39.is_valid("abandon " * 11 + "zoo")


def test_unknown_word_is_invalid():
    assert not bip39.is_valid("abandon " * 11 + "hermes")


# --- addresses: only P2PKH / P2WPKH, and only on the right network -------------
P2PKH_MAIN = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"       # Bitcoin-wiki vector
P2SH_MAIN = "3P14159f73E4gFr7JterCCQh9QjiTjiZrG"       # version 0x05
P2SH_TEST = "2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX"      # version 0xc4
P2WPKH_MAIN = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"  # BIP-173 vector


def test_valid_addresses_still_accepted():
    assert address_to_script(P2PKH_MAIN).cmds[0] == OP_DUP
    assert address_to_script(P2WPKH_MAIN).cmds[0] == 0    # OP_0 <20 bytes>


@pytest.mark.parametrize("address", [P2SH_MAIN, P2SH_TEST])
def test_p2sh_addresses_are_rejected(address):
    with pytest.raises(ValueError, match="P2SH"):
        address_to_script(address)


def test_wrong_network_is_rejected():
    with pytest.raises(ValueError, match="network"):
        address_to_script(P2PKH_MAIN, testnet=True)       # mainnet addr, testnet send
    with pytest.raises(ValueError, match="network"):
        address_to_script(P2WPKH_MAIN, testnet=True)      # bc1 addr, testnet send
    # and the right network still passes
    assert address_to_script(P2PKH_MAIN, testnet=False)
    assert address_to_script(P2WPKH_MAIN, testnet=False)


def test_garbage_address_is_rejected():
    with pytest.raises(ValueError):
        address_to_script("not an address at all")


# --- P2WSH multisig: OP_CHECKMULTISIG-strict verification ----------------------
COSIGNERS = [0x11, 0x22, 0x33]
PUBKEYS = [PrivateKey(s).public_key().sec(True) for s in COSIGNERS]
WSCRIPT = multisig_script(2, PUBKEYS)
AMOUNT = 100_000


def _signed_spend(signers=(0x11, 0x22)):
    tx = Tx(2, [TxInput(bytes.fromhex("ab" * 32), 0)],
            [TxOutput(90_000, p2wpkh_script(bytes(20)))])
    tx.sign_input_p2wsh_multisig(0, list(signers), WSCRIPT, AMOUNT)
    return tx


def test_honest_spend_still_verifies():
    assert _signed_spend().verify_input_p2wsh_multisig(0, AMOUNT)


def test_extra_bogus_signature_fails():
    # 2 valid sigs + 1 wrong-key sig: consensus rejects (every sig must consume
    # a key); the old lax verifier counted "2 valid" and passed it
    tx = _signed_spend()
    z = tx.sig_hash_bip143(0, WSCRIPT, AMOUNT)
    bogus = der(sign(0x999999, z)) + b"\x01"
    w = tx.inputs[0].witness
    tx.inputs[0].witness = [w[0], w[1], w[2], bogus, w[3]]
    assert not tx.verify_input_p2wsh_multisig(0, AMOUNT)


def test_garbage_der_signature_fails_cleanly():
    tx = _signed_spend()
    w = tx.inputs[0].witness
    tx.inputs[0].witness = [w[0], w[1], b"\xde\xad\xbe\xef", w[3]]
    assert not tx.verify_input_p2wsh_multisig(0, AMOUNT)


def test_nonempty_dummy_element_fails():
    tx = _signed_spend()
    tx.inputs[0].witness[0] = b"\x01"          # NULLDUMMY violation
    assert not tx.verify_input_p2wsh_multisig(0, AMOUNT)


def test_duplicated_signature_fails():
    # the same valid sig twice can't satisfy 2-of-3: one key, one consumption
    tx = _signed_spend()
    w = tx.inputs[0].witness
    tx.inputs[0].witness = [w[0], w[1], w[1], w[3]]
    assert not tx.verify_input_p2wsh_multisig(0, AMOUNT)


# --- Script VM: stack underflow returns False, never raises --------------------
@pytest.mark.parametrize("cmds", [
    [OP_DROP],
    [OP_DUP],
    [OP_EQUAL],
    [b"\x01", OP_EQUAL],
    [OP_EQUALVERIFY],
    [OP_VERIFY],
    [OP_SHA256],
    [OP_HASH160],
    [OP_CHECKSIG],
    [b"\x01", OP_CHECKSIG],
    [OP_CHECKMULTISIG],
    [OP_3, OP_CHECKMULTISIG],                  # claims 3 keys, stack has none
    [b"\x01", OP_2, OP_3, OP_CHECKMULTISIG],   # too few keys for OP_3
])
def test_stack_underflow_fails_cleanly(cmds):
    assert evaluate(Script(cmds)) is False
