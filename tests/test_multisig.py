"""P2WSH m-of-n multisig — the witness-script form of multisig that hardware
wallets and treasury custody (Unchained, Sparrow, Casa) actually use.

The authoritative anchor is a real native-P2WSH 2-of-3 multisig transaction from
the chain (txid 440fe853…, via the libbitcoin worked example): if our BIP-143
sighash for P2WSH is correct, the two signatures already inside its witness must
verify against the keys in its witnessScript — an offline proof against the real
network, the same technique Stage 7a used for legacy P2PKH.
"""

from hermes.keys import PrivateKey
from hermes.sha256 import sha256
from hermes.transaction import (
    Tx, TxInput, TxOutput, multisig_script, p2wpkh_script, p2wsh_address,
)

# --- real on-chain native P2WSH 2-of-3 multisig (libbitcoin example) ----------
REAL_P2WSH_TX = bytes.fromhex(
    "0100000000010193a2db37b841b2a46f4e9bb63fe9c1012da3ab7fe30b9f9c974242778b5af8"
    "980000000000ffffffff01806fb307000000001976a914bbef244bcad13cffb68b5cef3017c7"
    "423675552288ac040047304402203cdcaf02a44e37e409646e8a506724e9e1394b890cb52429"
    "ea65bac4cc2403f1022024b934297bcd0c21f22cee0e48751c8b184cc3a0d704cae2684e1485"
    "8550af7d01483045022100feb4e1530c13e72226dc912dcd257df90d81ae22dbddb5a3c2f6d8"
    "6f81d47c8e022069889ddb76388fa7948aaa018b2480ac36132009bb9cfade82b651e88b4b13"
    "7a01695221026ccfb8061f235cc110697c0bfb3afb99d82c886672f6b9b5393b25a434c0cbf3"
    "2103befa190c0c22e2f53720b1be9476dcf11917da4665c44c9c71c3a2d28a933c352102be46"
    "dc245f58085743b1cc37c82f0d63a960efa43b5336534275fc469b49f4ac53ae00000000"
)
REAL_P2WSH_AMOUNT = 129_500_000
REAL_P2WSH_TXID = "440fe853c40f94bee4993008917fa6ee809ad52e4a0ceea8632b58be7895f558"


def test_real_onchain_p2wsh_multisig_verifies():
    tx = Tx.parse(REAL_P2WSH_TX)
    assert tx.txid() == REAL_P2WSH_TXID
    assert tx.serialize() == REAL_P2WSH_TX             # lossless witness roundtrip
    witness = tx.inputs[0].witness
    assert witness[0] == b""                           # the OP_CHECKMULTISIG dummy
    assert len(witness) == 4                           # empty + 2 sigs + witnessScript
    assert tx.verify_input_p2wsh_multisig(0, REAL_P2WSH_AMOUNT)


# --- a self-built 2-of-3 vault: any two cosigners can spend, no single one -----
COSIGNERS = [
    0x1111111111111111111111111111111111111111111111111111111111111111,
    0x2222222222222222222222222222222222222222222222222222222222222222,
    0x3333333333333333333333333333333333333333333333333333333333333333,
]
PUBKEYS = [PrivateKey(s).public_key().sec(True) for s in COSIGNERS]
WSCRIPT = multisig_script(2, PUBKEYS)
AMOUNT = 100_000


def _spend():
    return Tx(
        version=2,
        inputs=[TxInput(bytes.fromhex("aa" * 32), 0)],
        outputs=[TxOutput(90_000, p2wpkh_script(bytes(20)))],
    )


def test_p2wsh_address_is_bech32_of_script_sha256():
    addr = p2wsh_address(WSCRIPT, testnet=True)
    assert addr.startswith("tb1q")
    from hermes.bech32 import decode_segwit
    witver, program = decode_segwit("tb", addr)
    assert witver == 0 and program == sha256(WSCRIPT.raw_serialize()) and len(program) == 32


def test_any_two_of_three_can_spend():
    for combo in [(0, 1), (0, 2), (1, 2)]:
        tx = _spend()
        tx.sign_input_p2wsh_multisig(0, [COSIGNERS[i] for i in combo], WSCRIPT, AMOUNT)
        assert tx.verify_input_p2wsh_multisig(0, AMOUNT), combo


def test_one_signature_is_not_enough():
    tx = _spend()
    tx.sign_input_p2wsh_multisig(0, [COSIGNERS[0]], WSCRIPT, AMOUNT)
    assert not tx.verify_input_p2wsh_multisig(0, AMOUNT)


def test_signatures_must_be_in_pubkey_order():
    # OP_CHECKMULTISIG checks sigs against keys in order, so key2-before-key1 fails
    tx = _spend()
    tx.sign_input_p2wsh_multisig(0, [COSIGNERS[1], COSIGNERS[0]], WSCRIPT, AMOUNT)
    assert not tx.verify_input_p2wsh_multisig(0, AMOUNT)


def test_witness_serialization_roundtrip():
    tx = _spend()
    tx.sign_input_p2wsh_multisig(0, [COSIGNERS[0], COSIGNERS[1]], WSCRIPT, AMOUNT)
    raw = tx.serialize()
    assert raw[4:6] == b"\x00\x01"
    assert Tx.parse(raw).inputs[0].witness == tx.inputs[0].witness
