"""Known-answer vectors for the Hermes crypto core.

These are the correctness backbone described in PLAN.md §4. The browser JS
re-implementation (Stage 2) must reproduce the same answers.
"""

import hashlib

import pytest

from hermes import (
    G, N, INFINITY, Point,
    PrivateKey, PublicKey, hash160,
    b58check_encode, b58check_decode,
    sha256, double_sha256, hmac_sha256, ripemd160,
    sign, verify, recover_secret_from_reused_nonce, rfc6979_k,
)


# --- hashes ------------------------------------------------------------------

def test_sha256_vectors():
    assert sha256(b"").hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_matches_hashlib_random():
    import os
    for _ in range(50):
        msg = os.urandom(os.urandom(1)[0])
        assert sha256(msg).hex() == hashlib.sha256(msg).hexdigest()


def test_ripemd160_vectors():
    assert ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert ripemd160(b"message digest").hex() == (
        "5d0689ef49d2fae572b881b123a85ffa21595f36"
    )


# --- curve -------------------------------------------------------------------

def test_generator_on_curve_and_order():
    # G is a valid point (constructor would have raised otherwise)
    assert not G.is_infinity
    # n * G is the point at infinity (group order)
    assert (N * G) == INFINITY
    # (n+1) * G wraps back to G
    assert ((N + 1) * G) == G


def test_point_addition_consistency():
    assert (2 * G) == (G + G)
    assert (3 * G) == (G + G + G)
    assert (7 * G) == (3 * G) + (4 * G)


# Published secp256k1 value: the doubled generator 2G. Anchors the group law
# and SEC serialization against an external source.
_2G_X = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
_2G_Y = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A


def test_known_double_generator():
    p = 2 * G
    assert p.x.num == _2G_X and p.y.num == _2G_Y
    # SEC serialization of a known point
    assert PublicKey(p).sec(compressed=False).hex() == (
        "04" + f"{_2G_X:064x}" + f"{_2G_Y:064x}"
    )
    # _2G_Y is even -> compressed prefix 0x02
    assert PublicKey(p).sec(compressed=True).hex() == "02" + f"{_2G_X:064x}"


# --- address pipeline vector (pubkey -> hash160 -> address) -------------------
#
# From the Bitcoin wiki, "Technical background of version 1 Bitcoin addresses".
# This is a standalone *public key* example.
PUBKEY_UNCOMPRESSED = (
    "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522"
    "CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6"
).lower()
HASH160 = "010966776006953d5567439e5e39f86a0d273bee"
ADDRESS = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"


def test_address_pipeline():
    assert hash160(bytes.fromhex(PUBKEY_UNCOMPRESSED)).hex() == HASH160
    assert b58check_encode(b"\x00" + bytes.fromhex(HASH160)) == ADDRESS


def test_base58check_roundtrip():
    payload = b"\x00" + bytes.fromhex(HASH160)
    assert b58check_decode(b58check_encode(payload)) == payload


# --- WIF vector (private key -> WIF) -----------------------------------------
#
# A separate Bitcoin-wiki example: this private key encodes to this WIF string.
WIF_SECRET = 0x0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
WIF_UNCOMPRESSED = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"


def test_wif():
    assert PrivateKey(WIF_SECRET).wif(compressed=False) == WIF_UNCOMPRESSED


def test_address_assembly_is_consistent():
    # address() must equal manual version+hash160 assembly, across encodings.
    for secret in (1, 2, 0x12345DEADBEEF, WIF_SECRET):
        priv = PrivateKey(secret)
        for compressed in (True, False):
            for testnet in (False, True):
                version = b"\x6f" if testnet else b"\x00"
                expect = b58check_encode(version + priv.public_key().hash160(compressed))
                assert priv.address(compressed, testnet) == expect


# --- ECDSA -------------------------------------------------------------------

def test_sign_and_verify():
    priv = PrivateKey(WIF_SECRET)
    pub = priv.public_key().point
    z = int.from_bytes(sha256(b"Hermes flies"), "big")
    sig = sign(priv.secret, z)
    assert verify(pub, z, sig)
    # a different message must not verify against this signature
    z2 = int.from_bytes(sha256(b"forged"), "big")
    assert not verify(pub, z2, sig)


def test_nonce_reuse_recovers_private_key():
    priv = PrivateKey(WIF_SECRET)
    k = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF  # the fatal reused nonce
    z1 = int.from_bytes(sha256(b"send 1 BTC to Alice"), "big")
    z2 = int.from_bytes(sha256(b"send 1 BTC to Bob"), "big")
    sig1 = sign(priv.secret, z1, k=k, low_s=False)
    sig2 = sign(priv.secret, z2, k=k, low_s=False)
    recovered = recover_secret_from_reused_nonce(z1, sig1, z2, sig2)
    assert recovered == WIF_SECRET


# --- RFC 6979 deterministic nonces -------------------------------------------

def test_hmac_sha256_matches_stdlib_random():
    import hmac, os
    for _ in range(50):
        key = os.urandom(os.urandom(1)[0] % 80)   # vary length, incl. > block size
        msg = os.urandom(os.urandom(1)[0])
        assert hmac_sha256(key, msg) == hmac.new(key, msg, hashlib.sha256).digest()


def test_rfc6979_official_secp256k1_vector():
    """The canonical secp256k1 + SHA-256 RFC 6979 vector (message "sample").
    Same private key the RFC uses for P-256 in Appendix A.2.5, re-derived on
    secp256k1. Reproduced across many independent implementations."""
    secret = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    z = int.from_bytes(sha256(b"sample"), "big")
    assert rfc6979_k(secret, z) == (
        0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    )
    sig = sign(secret, z)
    assert sig.r == 0x432310E32CB80EB6503A26CE83CC165C783B870845FB8AAD6D970889FCD7A6C8
    assert sig.s == 0x530128B6B81C548874A6305D93ED071CA6E05074D85863D4056CE89B02BFAB69


def test_rfc6979_is_deterministic_and_verifies():
    priv = PrivateKey(WIF_SECRET)
    pub = priv.public_key().point
    z = int.from_bytes(sha256(b"Hermes flies"), "big")
    # signing twice yields byte-identical signatures (no RNG involved)
    assert sign(priv.secret, z) == sign(priv.secret, z)
    assert verify(pub, z, sign(priv.secret, z))
    # distinct messages get distinct nonces (otherwise the key would leak)
    z2 = int.from_bytes(sha256(b"Hermes flies again"), "big")
    assert rfc6979_k(priv.secret, z) != rfc6979_k(priv.secret, z2)
