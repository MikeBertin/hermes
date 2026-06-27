"""Vectors for SHA-512, BIP-39 and BIP-32 (PLAN.md Stage 6).

The BIP test vectors are the official ones from the BIP-39 and BIP-32 specs."""

import hashlib
import os

from hermes.sha512 import sha512, hmac_sha512, pbkdf2_hmac_sha512
from hermes.bip39 import (
    entropy_to_mnemonic, mnemonic_to_entropy, mnemonic_to_seed, is_valid,
)
from hermes.bip32 import HDKey


# --- SHA-512 --------------------------------------------------------------
def test_sha512_vectors():
    assert sha512(b"").hex() == (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    )
    assert sha512(b"abc").hex() == (
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )


def test_sha512_matches_hashlib_random():
    for _ in range(30):
        msg = os.urandom(os.urandom(1)[0])
        assert sha512(msg).hex() == hashlib.sha512(msg).hexdigest()


def test_hmac_and_pbkdf2_match_hashlib():
    import hmac as _hmac
    assert hmac_sha512(b"key", b"The quick brown fox") == \
        _hmac.new(b"key", b"The quick brown fox", hashlib.sha512).digest()
    assert pbkdf2_hmac_sha512(b"password", b"salt", 100) == \
        hashlib.pbkdf2_hmac("sha512", b"password", b"salt", 100, 64)


# --- BIP-39 (official vector, entropy = all zeros) ------------------------
ZERO_MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon "
                 "abandon abandon abandon abandon about")
ZERO_SEED_TREZOR = (
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
    "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)


def test_bip39_entropy_to_mnemonic():
    assert entropy_to_mnemonic(bytes(16)) == ZERO_MNEMONIC


def test_bip39_roundtrip_and_validation():
    assert mnemonic_to_entropy(ZERO_MNEMONIC) == bytes(16)
    assert is_valid(ZERO_MNEMONIC)
    # corrupting the last word breaks the checksum
    assert not is_valid(ZERO_MNEMONIC.replace("about", "zoo"))


def test_bip39_seed_with_passphrase():
    assert mnemonic_to_seed(ZERO_MNEMONIC, "TREZOR").hex() == ZERO_SEED_TREZOR


# --- BIP-32 (official Test Vector 1) -------------------------------------
SEED1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
M_XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
M_XPUB = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
M_0H_XPRV = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
M_0H_1_XPRV = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
M_0H_1_XPUB = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"


def test_bip32_master():
    m = HDKey.from_seed(SEED1)
    assert m.xprv() == M_XPRV
    assert m.xpub() == M_XPUB


def test_bip32_hardened_and_normal_derivation():
    m = HDKey.from_seed(SEED1)
    assert m.derive_path("m/0'").xprv() == M_0H_XPRV
    assert m.derive_path("m/0'/1").xprv() == M_0H_1_XPRV
    assert m.derive_path("m/0'/1").xpub() == M_0H_1_XPUB
