"""Vectors for the Bitcoin Script stack machine (PLAN.md Stage 4)."""

from hermes import PrivateKey, hash160, sha256, sign
from hermes.ecdsa import ser_sig
from hermes.script import (
    Script, evaluate, encode_num, decode_num,
    OP_0, OP_2, OP_3, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_SHA256,
    OP_CHECKSIG, OP_CHECKMULTISIG, OP_CHECKLOCKTIMEVERIFY,
)

Z = int.from_bytes(sha256(b"a transaction to authorize"), "big")


def test_num_roundtrip():
    for n in (0, 1, 16, 127, 128, 255, 256, 1000, -1, -1000, 500000):
        assert decode_num(encode_num(n)) == n


# --- P2PKH ----------------------------------------------------------------
def test_p2pkh_valid_and_wrong_sig():
    priv = PrivateKey(0xC0FFEE)
    sec = priv.public_key().sec()
    h160 = hash160(sec)
    lock = Script([OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY, OP_CHECKSIG])

    good = Script([ser_sig(sign(priv.secret, Z)), sec])
    assert evaluate(good + lock, Z) is True

    # signature from the wrong key must fail OP_CHECKSIG
    wrong = Script([ser_sig(sign(PrivateKey(0xBADBAD).secret, Z)), sec])
    assert evaluate(wrong + lock, Z) is False


# --- multisig 2-of-3 ------------------------------------------------------
def test_multisig_2_of_3():
    keys = [PrivateKey(s) for s in (1001, 1002, 1003)]
    secs = [k.public_key().sec() for k in keys]
    lock = Script([OP_2, *secs, OP_3, OP_CHECKMULTISIG])

    # sign with keys 0 and 1 (order matters); OP_0 is the off-by-one dummy
    unlock = Script([OP_0, ser_sig(sign(keys[0].secret, Z)), ser_sig(sign(keys[1].secret, Z))])
    assert evaluate(unlock + lock, Z) is True

    # only one signature is not enough for a 2-of-3
    short = Script([OP_0, ser_sig(sign(keys[0].secret, Z)), ser_sig(sign(keys[0].secret, Z))])
    # two sigs but both from key0 -> second can't match a later distinct key in order
    assert evaluate(short + lock, Z) is False


# --- hash lock ------------------------------------------------------------
def test_hashlock():
    preimage = b"hermes-was-here"
    lock = Script([OP_SHA256, sha256(preimage), OP_EQUAL])
    assert evaluate(Script([preimage]) + lock, Z) is True
    assert evaluate(Script([b"wrong-secret"]) + lock, Z) is False


# --- time lock (CLTV) -----------------------------------------------------
def test_cltv():
    unlock_after = 800000
    lock = Script([encode_num(unlock_after), OP_CHECKLOCKTIMEVERIFY])
    # spending transaction's locktime has reached the threshold -> valid
    assert evaluate(lock, Z, locktime=800001) is True
    # too early -> invalid
    assert evaluate(lock, Z, locktime=799999) is False
