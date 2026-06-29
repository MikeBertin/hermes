"""Vectors for real transaction serialization, DER, and SIGHASH_ALL (Stage 7a).

The reference is a genuine legacy pay-to-public-key-hash transaction taken from
the Bitcoin mainnet (txid fba398fab715c17923873ab0bdea05649ab4dd697ac5ff1d16e89
c6aa1ae0c48, block 955925). If our sighash + DER are correct, the signature
already on-chain inside it must verify — a full offline proof that what we build
would be relayed by real nodes.
"""

import io

from hermes import PrivateKey, hash160
from hermes.keys import PublicKey
from hermes.ecdsa import der, parse_der, verify
from hermes.transaction import (
    Tx, TxInput, TxOutput, p2pkh_script, encode_varint, read_varint, SIGHASH_ALL,
)

REF_TX = bytes.fromhex(
    "02000000011f5e9c332a3939c39fdf3e5451e82242e8cc314ab7ba7afba36bb75006d2b122"
    "000000006a473044022071110e033ceb230310fcdd8a9fbba274df3ecaa082cc0b1fe744cb"
    "8ab0995ca202205f5b71588b721fe3de4bd8f93d73f0b01d60832fba946a394fd49df13ef1"
    "1e6501210254c0eddcd1db59f7c8c8703bdaf53ff0b1ebbb894ccb88e5adc7c6cd68e21d62"
    "fdffffff01161e44000000000016001472f6aaba7d284fc2bc97375c714c0925d7f9e05d14"
    "960e00"
)


# --- varint ---------------------------------------------------------------
def test_varint_roundtrip():
    for n in (0, 1, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000):
        assert read_varint(io.BytesIO(encode_varint(n))) == n


# --- serialization round-trip --------------------------------------------
def test_tx_parse_serialize_roundtrip():
    tx = Tx.parse(REF_TX)
    assert tx.serialize() == REF_TX          # lossless parse/serialize of a real tx
    assert tx.version == 2
    assert len(tx.inputs) == 1 and len(tx.outputs) == 1
    assert tx.outputs[0].amount == 4464150


# --- DER ------------------------------------------------------------------
def test_der_roundtrip_and_reencode():
    embedded = Tx.parse(REF_TX).inputs[0].script_sig.cmds[0]   # DER + sighash byte
    sig = parse_der(embedded[:-1])
    assert parse_der(der(sig)) == sig                          # encode/decode round-trip
    assert der(sig) == embedded[:-1]                           # matches the on-chain bytes


# --- the proof: the reference tx's own signature verifies -----------------
def test_reference_signature_verifies():
    tx = Tx.parse(REF_TX)
    sig_bytes, sec = tx.inputs[0].script_sig.cmds
    # a P2PKH prevout locks to hash160 of the spending public key
    prev_script = p2pkh_script(hash160(sec))
    z = tx.sig_hash(0, prev_script)
    assert verify(PublicKey.parse(sec).point, z, parse_der(sig_bytes[:-1])) is True
    assert sig_bytes[-1] == SIGHASH_ALL


# --- our own signing path round-trips -------------------------------------
def test_sign_and_verify_our_own_input():
    priv = PrivateKey(0xF00DBABE)
    prev_script = p2pkh_script(priv.public_key().hash160())
    tx = Tx(
        version=1,
        inputs=[TxInput(bytes(32), 0)],
        outputs=[TxOutput(90000, p2pkh_script(bytes(20)))],
        testnet=True,
    )
    tx.sign_input(0, priv.secret, prev_script)
    assert tx.verify_input(0, prev_script) is True
    assert Tx.parse(tx.serialize(), testnet=True).serialize() == tx.serialize()
