"""Taproot key-path outputs (BIP-341) anchored two independent ways:

1. The official BIP-341 wallet test vector with no script tree — internal key
   -> tweak -> tweaked output key -> scriptPubKey address.
2. The BIP-86 derivation vectors — the standard seed phrase, derived through
   our own BIP-39 + BIP-32 code at m/86'/0'/0'/0/0, must land on the published
   internal key, output key, and ``bc1p…`` address. One test spanning the whole
   stack: mnemonic -> HD tree -> x-only key -> TapTweak -> bech32m.
"""

from hermes.bip32 import HDKey
from hermes.bip39 import mnemonic_to_seed
from hermes.curve import N
from hermes.schnorr import pubkey_gen, sign, verify
from hermes.taproot import output_key, p2tr_address, tap_tweak, tweak_secret

# --- BIP-341 wallet test vector (scriptTree: null) -----------------------------
B341_INTERNAL = bytes.fromhex("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d")
B341_TWEAK = "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70"
B341_OUTPUT = "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
B341_ADDRESS = "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5"


def test_bip341_tweak_vector():
    assert tap_tweak(B341_INTERNAL) == int(B341_TWEAK, 16)
    assert output_key(B341_INTERNAL).hex() == B341_OUTPUT
    assert p2tr_address(B341_INTERNAL) == B341_ADDRESS


# --- BIP-86: the whole stack, seed phrase to bc1p… ------------------------------
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
B86_INTERNAL = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
B86_OUTPUT = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
B86_ADDRESS = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"


def test_bip86_first_receiving_address():
    node = HDKey.from_seed(mnemonic_to_seed(MNEMONIC)).derive_path("m/86'/0'/0'/0/0")
    internal = pubkey_gen(node.secret)
    assert internal.hex() == B86_INTERNAL
    assert output_key(internal).hex() == B86_OUTPUT
    assert p2tr_address(internal) == B86_ADDRESS


def test_testnet_hrp():
    assert p2tr_address(B341_INTERNAL, testnet=True).startswith("tb1p")


# --- the key path actually spends: tweaked secret signs for the output key -----
def test_tweaked_secret_signs_for_output_key():
    for secret in (0xDEADBEEF, N - 0xDEADBEEF):     # even- and odd-Y internal keys
        internal = pubkey_gen(secret)
        q = output_key(internal)
        sig = sign(tweak_secret(secret), b"key-path spend")
        assert verify(q, b"key-path spend", sig)
        # and the *untweaked* secret must NOT sign for the output key
        assert not verify(q, b"key-path spend", sign(secret, b"key-path spend"))
