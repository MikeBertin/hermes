"""Hermes — Bitcoin from first principles.

A from-scratch Bitcoin implementation: the secp256k1 curve, SHA-256 and
RIPEMD-160, Base58Check, keys and addresses, and ECDSA — built with no crypto
dependencies, to be visualised in the browser. See PLAN.md.
"""

from .base58 import b58check_decode, b58check_encode, b58decode, b58encode
from .bech32 import bech32_decode, bech32_encode, decode_segwit, encode_segwit
from .curve import G, N, P, INFINITY, Point
from .ecdsa import (
    Signature, parse_sig, recover_secret_from_reused_nonce, rfc6979_k, ser_sig, sign, verify,
)
from .field import FieldElement
from .keys import PrivateKey, PublicKey, hash160
from .ripemd160 import ripemd160
from .sha256 import double_sha256, hmac_sha256, sha256
from .sha512 import hmac_sha512, pbkdf2_hmac_sha512, sha512
from .transaction import (
    Tx, TxInput, TxOutput, multisig_script, p2wpkh_script, p2wsh_script,
    p2wsh_address, p2pkh_script, address_to_script,
)
from .merkle import (
    merkle_root, merkle_proof, merkle_levels, verify_merkle_proof, root_from_txids,
)
from .bip32 import HDKey
from .bip39 import (
    entropy_to_mnemonic, is_valid, mnemonic_to_entropy, mnemonic_to_seed,
)
from . import schnorr
from .taproot import output_key, p2tr_address, tap_tweak, tweak_secret
from . import lightning
from . import frost
from . import adaptor

__all__ = [
    "FieldElement",
    "Point", "G", "N", "P", "INFINITY",
    "sha256", "double_sha256", "hmac_sha256", "ripemd160",
    "b58encode", "b58decode", "b58check_encode", "b58check_decode",
    "bech32_encode", "bech32_decode", "encode_segwit", "decode_segwit",
    "PrivateKey", "PublicKey", "hash160",
    "Signature", "sign", "verify", "recover_secret_from_reused_nonce",
    "rfc6979_k", "ser_sig", "parse_sig",
    "sha512", "hmac_sha512", "pbkdf2_hmac_sha512",
    "Tx", "TxInput", "TxOutput", "multisig_script", "p2pkh_script",
    "p2wpkh_script", "p2wsh_script", "p2wsh_address", "address_to_script",
    "merkle_root", "merkle_proof", "merkle_levels", "verify_merkle_proof", "root_from_txids",
    "HDKey", "entropy_to_mnemonic", "mnemonic_to_entropy", "mnemonic_to_seed", "is_valid",
    "schnorr", "tap_tweak", "output_key", "p2tr_address", "tweak_secret",
    "lightning", "frost", "adaptor",
]
