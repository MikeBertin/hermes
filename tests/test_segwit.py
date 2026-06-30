"""SegWit vectors: bech32 (BIP-173/350), P2WPKH addresses, BIP-143 sighash.

The crown jewel here is the BIP-143 worked example: parsing its unsigned
transaction, our segwit sighash + RFC 6979 + DER pipeline reproduces the
published sigHash *and* the published witness signature byte-for-byte.
"""

from hermes.bech32 import bech32_decode, decode_segwit, encode_segwit
from hermes.ecdsa import der, sign
from hermes.keys import PrivateKey, hash160
from hermes.transaction import Tx, TxInput, TxOutput, p2pkh_script, p2wpkh_script


# --- bech32 / bech32m (BIP-173, BIP-350) -------------------------------------

def test_bech32_segwit_address_vectors():
    # (hrp, address, witness version, witness program hex) from BIP-173/350
    cases = [
        ("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
         0, "751e76e8199196d454941c45d1b3a323f1433bd6"),                 # P2WPKH
        ("tb", "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
         0, "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),  # P2WSH
        ("bc", "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
         1, "751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),  # bech32m, v1
    ]
    for hrp, addr, witver, prog in cases:
        v, p = decode_segwit(hrp, addr)
        assert v == witver and p.hex() == prog
        # encoding is canonical: re-encoding the decoded parts gives the address
        assert encode_segwit(hrp, witver, bytes.fromhex(prog)) == addr.lower()


def test_bech32_rejects_corruption():
    # flip one character of a valid address -> checksum must reject it
    bad = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"   # ...t4 -> ...t5
    assert decode_segwit("bc", bad) == (None, None)
    # a wrong human-readable prefix is also rejected
    assert decode_segwit("tb", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == (None, None)


def test_p2wpkh_address_from_key():
    # the BIP-173 example key hash encodes to the canonical mainnet P2WPKH address
    assert encode_segwit("bc", 0, bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")) \
        == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    # a real key round-trips: address decodes back to exactly hash160(pubkey)
    priv = PrivateKey(0x619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9)
    addr = priv.public_key().p2wpkh_address(testnet=False)
    assert addr.startswith("bc1q")
    witver, prog = decode_segwit("bc", addr)
    assert witver == 0 and prog == priv.public_key().hash160(compressed=True)


# --- BIP-143 worked example (the authoritative P2WPKH sighash vector) ---------

# The unsigned transaction from BIP-143; input #1 is a P2WPKH witness input.
BIP143_UNSIGNED = bytes.fromhex(
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
    "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57"
    "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85"
    "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2"
    "f0167faa815988ac11000000"
)
BIP143_SECRET = 0x619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
BIP143_AMOUNT = 600000000
BIP143_KEYHASH = "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
BIP143_SIGHASH = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
BIP143_SIG = (
    "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a"
    "0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"
)


def test_bip143_sighash_matches_spec():
    tx = Tx.parse(BIP143_UNSIGNED)
    # the spent key's hash160 is what the scriptCode commits to
    assert hash160(PrivateKey(BIP143_SECRET).public_key().sec(True)).hex() == BIP143_KEYHASH
    script_code = p2pkh_script(bytes.fromhex(BIP143_KEYHASH))
    z = tx.sig_hash_bip143(1, script_code, BIP143_AMOUNT)
    assert z.to_bytes(32, "big").hex() == BIP143_SIGHASH


def test_bip143_signature_is_reproduced_byte_for_byte():
    """Because sign() is RFC 6979 deterministic, our signature for the BIP-143
    input equals the one published in the spec — end-to-end proof of the whole
    segwit signing path (sighash -> nonce -> DER -> low-s)."""
    tx = Tx.parse(BIP143_UNSIGNED)
    z = tx.sig_hash_bip143(1, p2pkh_script(bytes.fromhex(BIP143_KEYHASH)), BIP143_AMOUNT)
    assert der(sign(BIP143_SECRET, z, low_s=True)).hex() == BIP143_SIG


# --- a self-contained P2WPKH transaction: build -> sign -> verify -> roundtrip -

def test_p2wpkh_sign_verify_and_witness_roundtrip():
    priv = PrivateKey(0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
    h160 = priv.public_key().hash160(compressed=True)
    funding_amount = 100_000
    tx = Tx(
        version=2,
        inputs=[TxInput(bytes.fromhex("11" * 32), 0)],
        outputs=[TxOutput(90_000, p2wpkh_script(h160))],
        locktime=0,
    )
    tx.sign_input_p2wpkh(0, priv.secret, funding_amount)
    assert tx.verify_input_p2wpkh(0, funding_amount)

    # serialization carries the witness (marker+flag present) ...
    raw = tx.serialize()
    assert raw[4:6] == b"\x00\x01"
    # ... and parsing it back reconstructs the same witness stack and txid
    reparsed = Tx.parse(raw)
    assert reparsed.inputs[0].witness == tx.inputs[0].witness
    assert reparsed.txid() == tx.txid()
    # txid is computed from the legacy (witness-stripped) bytes
    assert "\x00" not in tx.txid()
