"""MuSig2 (BIP-327) against the complete official vector set
(bips/bip-0327/vectors/*.json, committed verbatim in tests/vectors/bip327/).

Covers key aggregation, nonce generation/aggregation, the two-round signing
ceremony, tweaking (plain + x-only/Taproot), and partial-signature
aggregation — including every error case, which pin down WHO gets blamed
(InvalidContributionError) and the exact ValueError messages. Ends with
end-to-end ceremonies: an n-of-n vault whose final signature is a plain
BIP-340 signature, including one behind a real Taproot output key.
"""

import json
import os

import pytest

from hermes import musig, schnorr, taproot
from hermes.curve import G, N
from hermes.musig import (
    InvalidContributionError,
    SessionContext,
    key_agg,
    key_agg_and_tweak,
    get_xonly_pk,
    key_sort,
    nonce_agg,
    nonce_gen_internal,
    partial_sig_agg,
    partial_sig_verify,
    partial_sign,
    plain_pubkey,
)

VECTOR_DIR = os.path.join(os.path.dirname(__file__), "vectors", "bip327")


def load(name):
    with open(os.path.join(VECTOR_DIR, name)) as f:
        return json.load(f)


def unhex_all(items):
    return [bytes.fromhex(x) for x in items]


def assert_expected_error(case, excinfo):
    """The vectors specify errors precisely: the culprit's index + what was
    bad for protocol violations, the exact message for precondition errors."""
    error = case["error"]
    if error["type"] == "invalid_contribution":
        assert isinstance(excinfo.value, InvalidContributionError)
        assert excinfo.value.signer == error["signer"]
        if "contrib" in error:
            assert excinfo.value.contrib == error["contrib"]
    elif error["type"] == "value":
        assert isinstance(excinfo.value, ValueError)
        assert str(excinfo.value) == error["message"]
    else:
        raise AssertionError(f"unknown error type {error['type']}")


# --- KeyAgg ---------------------------------------------------------------

KEY_AGG = load("key_agg_vectors.json")


@pytest.mark.parametrize("case", KEY_AGG["valid_test_cases"],
                         ids=[f"valid{i}" for i in range(len(KEY_AGG["valid_test_cases"]))])
def test_key_agg_valid(case):
    X = unhex_all(KEY_AGG["pubkeys"])
    pubkeys = [X[i] for i in case["key_indices"]]
    assert get_xonly_pk(key_agg(pubkeys)).hex().upper() == case["expected"]


@pytest.mark.parametrize("case", KEY_AGG["error_test_cases"],
                         ids=[c["comment"] for c in KEY_AGG["error_test_cases"]])
def test_key_agg_errors(case):
    X = unhex_all(KEY_AGG["pubkeys"])
    T = unhex_all(KEY_AGG["tweaks"])
    pubkeys = [X[i] for i in case["key_indices"]]
    tweaks = [T[i] for i in case["tweak_indices"]]
    with pytest.raises((InvalidContributionError, ValueError)) as excinfo:
        key_agg_and_tweak(pubkeys, tweaks, case["is_xonly"])
    assert_expected_error(case, excinfo)


# --- NonceGen (fixed rand_, so fully deterministic) ------------------------

NONCE_GEN = load("nonce_gen_vectors.json")


@pytest.mark.parametrize("case", NONCE_GEN["test_cases"],
                         ids=[f"case{i}" for i in range(len(NONCE_GEN["test_cases"]))])
def test_nonce_gen_vectors(case):
    def get(key):
        return bytes.fromhex(case[key]) if case[key] is not None else None

    secnonce, pubnonce = nonce_gen_internal(
        get("rand_"), get("sk"), get("pk"), get("aggpk"), get("msg"), get("extra_in"))
    assert bytes(secnonce).hex().upper() == case["expected_secnonce"]
    assert pubnonce.hex().upper() == case["expected_pubnonce"]


# --- NonceAgg ---------------------------------------------------------------

NONCE_AGG = load("nonce_agg_vectors.json")


@pytest.mark.parametrize("case", NONCE_AGG["valid_test_cases"],
                         ids=[f"valid{i}" for i in range(len(NONCE_AGG["valid_test_cases"]))])
def test_nonce_agg_valid(case):
    pnonce = unhex_all(NONCE_AGG["pnonces"])
    pubnonces = [pnonce[i] for i in case["pnonce_indices"]]
    assert nonce_agg(pubnonces).hex().upper() == case["expected"]


@pytest.mark.parametrize("case", NONCE_AGG["error_test_cases"],
                         ids=[c["comment"][:40] for c in NONCE_AGG["error_test_cases"]])
def test_nonce_agg_errors(case):
    pnonce = unhex_all(NONCE_AGG["pnonces"])
    pubnonces = [pnonce[i] for i in case["pnonce_indices"]]
    with pytest.raises(InvalidContributionError) as excinfo:
        nonce_agg(pubnonces)
    assert_expected_error(case, excinfo)


# --- Sign / partial-sig verify ----------------------------------------------

SIGN_VERIFY = load("sign_verify_vectors.json")
SV_SK = bytes.fromhex(SIGN_VERIFY["sk"])
SV_X = unhex_all(SIGN_VERIFY["pubkeys"])
SV_SECNONCES = unhex_all(SIGN_VERIFY["secnonces"])
SV_PNONCE = unhex_all(SIGN_VERIFY["pnonces"])
SV_AGGNONCES = unhex_all(SIGN_VERIFY["aggnonces"])
SV_MSGS = unhex_all(SIGN_VERIFY["msgs"])


def test_sign_verify_fixture_consistency():
    # The vector file documents its own internal relationships — prove them.
    assert SV_X[0] == plain_pubkey(int.from_bytes(SV_SK, "big"))
    k1 = int.from_bytes(SV_SECNONCES[0][0:32], "big")
    k2 = int.from_bytes(SV_SECNONCES[0][32:64], "big")
    assert SV_PNONCE[0] == musig.cbytes(k1 * G) + musig.cbytes(k2 * G)
    assert SV_AGGNONCES[0] == nonce_agg([SV_PNONCE[0], SV_PNONCE[1], SV_PNONCE[2]])
    # pnonce[0] + pnonce[3] cancel to the point at infinity (33+33 zero bytes)
    assert SV_AGGNONCES[1] == nonce_agg([SV_PNONCE[0], SV_PNONCE[3]]) == bytes(66)


@pytest.mark.parametrize("case", SIGN_VERIFY["valid_test_cases"],
                         ids=[f"valid{i}" for i in range(len(SIGN_VERIFY["valid_test_cases"]))])
def test_sign_valid(case):
    pubkeys = [SV_X[i] for i in case["key_indices"]]
    pubnonces = [SV_PNONCE[i] for i in case["nonce_indices"]]
    aggnonce = SV_AGGNONCES[case["aggnonce_index"]]
    assert nonce_agg(pubnonces) == aggnonce
    msg = SV_MSGS[case["msg_index"]]
    session_ctx = SessionContext(aggnonce, pubkeys, [], [], msg)
    psig = partial_sign(bytearray(SV_SECNONCES[0]), SV_SK, session_ctx)
    assert psig.hex().upper() == case["expected"]
    assert partial_sig_verify(psig, pubnonces, pubkeys, [], [], msg, case["signer_index"])


@pytest.mark.parametrize("case", SIGN_VERIFY["sign_error_test_cases"],
                         ids=[c["comment"][:40] for c in SIGN_VERIFY["sign_error_test_cases"]])
def test_sign_errors(case):
    pubkeys = [SV_X[i] for i in case["key_indices"]]
    aggnonce = SV_AGGNONCES[case["aggnonce_index"]]
    msg = SV_MSGS[case["msg_index"]]
    secnonce = bytearray(SV_SECNONCES[case["secnonce_index"]])
    session_ctx = SessionContext(aggnonce, pubkeys, [], [], msg)
    with pytest.raises((InvalidContributionError, ValueError)) as excinfo:
        partial_sign(secnonce, SV_SK, session_ctx)
    assert_expected_error(case, excinfo)


@pytest.mark.parametrize("case", SIGN_VERIFY["verify_fail_test_cases"],
                         ids=[c["comment"][:40] for c in SIGN_VERIFY["verify_fail_test_cases"]])
def test_verify_fail(case):
    sig = bytes.fromhex(case["sig"])
    pubkeys = [SV_X[i] for i in case["key_indices"]]
    pubnonces = [SV_PNONCE[i] for i in case["nonce_indices"]]
    msg = SV_MSGS[case["msg_index"]]
    assert not partial_sig_verify(sig, pubnonces, pubkeys, [], [], msg, case["signer_index"])


@pytest.mark.parametrize("case", SIGN_VERIFY["verify_error_test_cases"],
                         ids=[c["comment"][:40] for c in SIGN_VERIFY["verify_error_test_cases"]])
def test_verify_errors(case):
    sig = bytes.fromhex(case["sig"])
    pubkeys = [SV_X[i] for i in case["key_indices"]]
    pubnonces = [SV_PNONCE[i] for i in case["nonce_indices"]]
    msg = SV_MSGS[case["msg_index"]]
    with pytest.raises(InvalidContributionError) as excinfo:
        partial_sig_verify(sig, pubnonces, pubkeys, [], [], msg, case["signer_index"])
    assert_expected_error(case, excinfo)


# --- Tweaks (plain + x-only, through the full sign path) ---------------------

TWEAK = load("tweak_vectors.json")
TW_SK = bytes.fromhex(TWEAK["sk"])
TW_X = unhex_all(TWEAK["pubkeys"])
TW_SECNONCE = bytes.fromhex(TWEAK["secnonce"])
TW_PNONCE = unhex_all(TWEAK["pnonces"])
TW_AGGNONCE = bytes.fromhex(TWEAK["aggnonce"])
TW_TWEAKS = unhex_all(TWEAK["tweaks"])
TW_MSG = bytes.fromhex(TWEAK["msg"])


@pytest.mark.parametrize("case", TWEAK["valid_test_cases"],
                         ids=[c["comment"][:40] for c in TWEAK["valid_test_cases"]])
def test_tweak_valid(case):
    pubkeys = [TW_X[i] for i in case["key_indices"]]
    pubnonces = [TW_PNONCE[i] for i in case["nonce_indices"]]
    tweaks = [TW_TWEAKS[i] for i in case["tweak_indices"]]
    session_ctx = SessionContext(TW_AGGNONCE, pubkeys, tweaks, case["is_xonly"], TW_MSG)
    psig = partial_sign(bytearray(TW_SECNONCE), TW_SK, session_ctx)
    assert psig.hex().upper() == case["expected"]
    assert partial_sig_verify(psig, pubnonces, pubkeys, tweaks, case["is_xonly"],
                              TW_MSG, case["signer_index"])


@pytest.mark.parametrize("case", TWEAK["error_test_cases"],
                         ids=[c["comment"][:40] for c in TWEAK["error_test_cases"]])
def test_tweak_errors(case):
    pubkeys = [TW_X[i] for i in case["key_indices"]]
    tweaks = [TW_TWEAKS[i] for i in case["tweak_indices"]]
    session_ctx = SessionContext(TW_AGGNONCE, pubkeys, tweaks, case["is_xonly"], TW_MSG)
    with pytest.raises(ValueError) as excinfo:
        partial_sign(bytearray(TW_SECNONCE), TW_SK, session_ctx)
    assert_expected_error(case, excinfo)


# --- SigAgg: the sum is a plain BIP-340 signature ----------------------------

SIG_AGG = load("sig_agg_vectors.json")


@pytest.mark.parametrize("case", SIG_AGG["valid_test_cases"],
                         ids=[f"valid{i}" for i in range(len(SIG_AGG["valid_test_cases"]))])
def test_sig_agg_valid(case):
    X = unhex_all(SIG_AGG["pubkeys"])
    pnonce = unhex_all(SIG_AGG["pnonces"])
    tweak = unhex_all(SIG_AGG["tweaks"])
    psig = unhex_all(SIG_AGG["psigs"])
    msg = bytes.fromhex(SIG_AGG["msg"])

    pubnonces = [pnonce[i] for i in case["nonce_indices"]]
    aggnonce = bytes.fromhex(case["aggnonce"])
    assert aggnonce == nonce_agg(pubnonces)
    pubkeys = [X[i] for i in case["key_indices"]]
    tweaks = [tweak[i] for i in case["tweak_indices"]]
    psigs = [psig[i] for i in case["psig_indices"]]

    session_ctx = SessionContext(aggnonce, pubkeys, tweaks, case["is_xonly"], msg)
    sig = partial_sig_agg(psigs, session_ctx)
    assert sig.hex().upper() == case["expected"]
    # The payoff: the combined signature is ordinary BIP-340.
    aggpk = get_xonly_pk(key_agg_and_tweak(pubkeys, tweaks, case["is_xonly"]))
    assert schnorr.verify(aggpk, msg, sig)


@pytest.mark.parametrize("case", SIG_AGG["error_test_cases"],
                         ids=[c["comment"][:40] for c in SIG_AGG["error_test_cases"]])
def test_sig_agg_errors(case):
    X = unhex_all(SIG_AGG["pubkeys"])
    pnonce = unhex_all(SIG_AGG["pnonces"])
    tweak = unhex_all(SIG_AGG["tweaks"])
    psig = unhex_all(SIG_AGG["psigs"])
    msg = bytes.fromhex(SIG_AGG["msg"])

    pubnonces = [pnonce[i] for i in case["nonce_indices"]]
    pubkeys = [X[i] for i in case["key_indices"]]
    tweaks = [tweak[i] for i in case["tweak_indices"]]
    psigs = [psig[i] for i in case["psig_indices"]]

    session_ctx = SessionContext(nonce_agg(pubnonces), pubkeys, tweaks, case["is_xonly"], msg)
    with pytest.raises(InvalidContributionError) as excinfo:
        partial_sig_agg(psigs, session_ctx)
    assert_expected_error(case, excinfo)


# --- End-to-end ceremonies -----------------------------------------------------


def run_ceremony(secrets, msg, tweaks=(), is_xonly=()):
    """A full two-round MuSig2 signing among len(secrets) cosigners."""
    pubkeys = key_sort([plain_pubkey(d) for d in secrets])
    by_pk = {plain_pubkey(d): d for d in secrets}
    ordered = [by_pk[pk] for pk in pubkeys]
    aggpk = get_xonly_pk(key_agg_and_tweak(pubkeys, list(tweaks), list(is_xonly)))

    # round 1: everyone generates and shares a nonce pair
    nonces = [musig.nonce_gen(d.to_bytes(32, "big"), pk, aggpk, msg)
              for d, pk in zip(ordered, pubkeys)]
    pubnonces = [pn for _, pn in nonces]
    aggnonce = nonce_agg(pubnonces)

    # round 2: everyone emits a partial signature; each is checked, then summed
    session_ctx = SessionContext(aggnonce, pubkeys, list(tweaks), list(is_xonly), msg)
    psigs = []
    for i, (d, (secnonce, _)) in enumerate(zip(ordered, nonces)):
        psig = partial_sign(secnonce, d.to_bytes(32, "big"), session_ctx)
        assert partial_sig_verify(psig, pubnonces, pubkeys, list(tweaks),
                                  list(is_xonly), msg, i)
        psigs.append(psig)
    return aggpk, partial_sig_agg(psigs, session_ctx), nonces, session_ctx


def test_ceremony_3_of_3_is_plain_bip340():
    aggpk, sig, _, _ = run_ceremony([0xA11CE, 0xB0B, 0xCA401], b"hermes musig2 e2e" + bytes(15))
    assert len(sig) == 64
    assert schnorr.verify(aggpk, b"hermes musig2 e2e" + bytes(15), sig)


def test_ceremony_behind_taproot_output():
    # The vault story: KeyAgg -> internal key, TapTweak (x-only) -> the key a
    # bc1p address carries. The ceremony signs for the TWEAKED key directly.
    msg = bytes(range(32))
    secrets = [0xDEAD, 0xBEEF]
    pubkeys = key_sort([plain_pubkey(d) for d in secrets])
    internal = get_xonly_pk(key_agg(pubkeys))
    tweak = schnorr.tagged_hash("TapTweak", internal)
    aggpk, sig, _, _ = run_ceremony(secrets, msg, tweaks=[tweak], is_xonly=[True])
    # ...and that tweaked key is exactly taproot.py's output key for it.
    assert aggpk == taproot.output_key(internal)
    assert schnorr.verify(aggpk, msg, sig)


def test_secnonce_is_single_use():
    msg = bytes(32)
    _, _, nonces, session_ctx = run_ceremony([0x111, 0x222], msg)
    secnonce, _ = nonces[0]  # zeroized by the ceremony's partial_sign
    with pytest.raises(ValueError, match="secnonce value is out of range"):
        partial_sign(secnonce, (0x111).to_bytes(32, "big"), session_ctx)


def test_wrong_signer_index_fails_verify():
    msg = bytes(32)
    secrets = [0x111, 0x222]
    pubkeys = key_sort([plain_pubkey(d) for d in secrets])
    by_pk = {plain_pubkey(d): d for d in secrets}
    ordered = [by_pk[pk] for pk in pubkeys]
    nonces = [musig.nonce_gen(d.to_bytes(32, "big"), pk, None, msg)
              for d, pk in zip(ordered, pubkeys)]
    pubnonces = [pn for _, pn in nonces]
    session_ctx = SessionContext(nonce_agg(pubnonces), pubkeys, [], [], msg)
    psig0 = partial_sign(nonces[0][0], ordered[0].to_bytes(32, "big"), session_ctx)
    assert partial_sig_verify(psig0, pubnonces, pubkeys, [], [], msg, 0)
    assert not partial_sig_verify(psig0, pubnonces, pubkeys, [], [], msg, 1)


def test_key_agg_order_matters():
    # Same two keys, opposite order -> different aggregate. key_sort exists
    # so cosigners deterministically agree on ONE ordering.
    pk1, pk2 = plain_pubkey(0x111), plain_pubkey(0x222)
    assert get_xonly_pk(key_agg([pk1, pk2])) != get_xonly_pk(key_agg([pk2, pk1]))
