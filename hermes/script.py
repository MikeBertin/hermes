"""Bitcoin Script — a tiny, stack-based programming language.

Every coin is locked by a short script (the *scriptPubKey*) and spent by
prepending an unlocking script (the *scriptSig*). Concatenate the two, run them
on a stack machine, and if the stack is left holding "true", the spend is valid.
There are no loops — Script is deliberately not Turing-complete.

This implements the handful of opcodes the demos need: pay-to-public-key-hash,
multisig, a hash lock, and a time lock. Signatures here are flat r‖s bytes (see
ecdsa.ser_sig); real Bitcoin uses DER, which the transaction layer will add.
"""

from __future__ import annotations

from .ecdsa import parse_sig, verify as ecdsa_verify
from .keys import PublicKey, hash160
from .sha256 import sha256

# --- opcodes we support ------------------------------------------------------
OP_0 = 0
OP_1, OP_16 = 81, 96          # OP_1..OP_16 push the numbers 1..16
OP_2, OP_3 = 82, 83           # named for convenience (multisig m/n)
OP_DROP = 117
OP_DUP = 118
OP_EQUAL = 135
OP_EQUALVERIFY = 136
OP_VERIFY = 105
OP_SHA256 = 168
OP_HASH160 = 169
OP_CHECKSIG = 172
OP_CHECKMULTISIG = 174
OP_CHECKLOCKTIMEVERIFY = 177

OP_NAMES = {
    0: "OP_0", 105: "OP_VERIFY", 117: "OP_DROP", 118: "OP_DUP", 135: "OP_EQUAL",
    136: "OP_EQUALVERIFY", 168: "OP_SHA256", 169: "OP_HASH160", 172: "OP_CHECKSIG",
    174: "OP_CHECKMULTISIG", 177: "OP_CHECKLOCKTIMEVERIFY",
    **{80 + i: f"OP_{i}" for i in range(1, 17)},
}


def encode_num(n: int) -> bytes:
    """Bitcoin's minimal little-endian, sign-magnitude number encoding."""
    if n == 0:
        return b""
    out = bytearray()
    neg = n < 0
    a = abs(n)
    while a:
        out.append(a & 0xFF)
        a >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def decode_num(b: bytes) -> int:
    if b == b"":
        return 0
    le = b[::-1]
    neg = le[0] & 0x80
    result = le[0] & 0x7F
    for c in le[1:]:
        result = (result << 8) | c
    return -result if neg else result


def is_truthy(el: bytes) -> bool:
    # any non-zero byte is true (a lone 0x80 — negative zero — is still false)
    return any(b != 0 for b in el[:-1]) or (len(el) > 0 and el[-1] not in (0, 0x80))


def cmd_label(cmd) -> str:
    if isinstance(cmd, (bytes, bytearray)):
        h = bytes(cmd).hex()
        return "push ∅" if not h else f"push {h[:12]}{'…' if len(h) > 12 else ''}"
    return OP_NAMES.get(cmd, f"OP_{cmd}")


class Script:
    def __init__(self, cmds):
        self.cmds = list(cmds)

    def __add__(self, other: "Script") -> "Script":
        return Script(self.cmds + other.cmds)


class ScriptError(Exception):
    pass


def evaluate(script: Script, z: int = 0, locktime: int | None = None, trace: list | None = None):
    """Run a script on a fresh stack. Returns True if it ends truthy.
    If ``trace`` is a list, each step's (label, stack-snapshot) is appended."""
    stack: list[bytes] = []

    def snap(label):
        if trace is not None:
            trace.append((label, [s.hex() for s in stack]))

    snap("(start)")
    for cmd in script.cmds:
        if isinstance(cmd, (bytes, bytearray)):
            stack.append(bytes(cmd))
        elif cmd == OP_0:
            stack.append(b"")
        elif OP_1 <= cmd <= OP_16:
            stack.append(encode_num(cmd - 80))
        elif cmd == OP_DUP:
            if not stack:
                return False
            stack.append(stack[-1])
        elif cmd == OP_DROP:
            stack.pop()
        elif cmd == OP_EQUAL:
            stack.append(b"\x01" if stack.pop() == stack.pop() else b"")
        elif cmd == OP_EQUALVERIFY:
            if stack.pop() != stack.pop():
                snap(cmd_label(cmd) + "  ✗")
                return False
        elif cmd == OP_VERIFY:
            if not is_truthy(stack.pop()):
                snap(cmd_label(cmd) + "  ✗")
                return False
        elif cmd == OP_SHA256:
            stack.append(sha256(stack.pop()))
        elif cmd == OP_HASH160:
            stack.append(hash160(stack.pop()))
        elif cmd == OP_CHECKSIG:
            sec, sig = stack.pop(), stack.pop()
            try:
                ok = ecdsa_verify(PublicKey.parse(sec).point, z, parse_sig(sig))
            except Exception:
                ok = False
            stack.append(b"\x01" if ok else b"")
        elif cmd == OP_CHECKMULTISIG:
            ok = _checkmultisig(stack, z)
            stack.append(b"\x01" if ok else b"")
        elif cmd == OP_CHECKLOCKTIMEVERIFY:
            if locktime is None or not stack:
                return False
            required = decode_num(stack[-1])      # CLTV leaves the value on the stack
            if locktime < required:
                snap(cmd_label(cmd) + f"  ✗ (locktime {locktime} < {required})")
                return False
        else:
            return False
        snap(cmd_label(cmd))

    return bool(stack) and is_truthy(stack[-1])


def _checkmultisig(stack: list, z: int) -> bool:
    n = decode_num(stack.pop())
    sec_keys = [stack.pop() for _ in range(n)]        # popped top-first
    m = decode_num(stack.pop())
    sigs = [stack.pop() for _ in range(m)]            # popped top-first
    if not stack:
        return False
    stack.pop()                                       # the off-by-one dummy element
    try:
        points = [PublicKey.parse(s).point for s in sec_keys]
        parsed = [parse_sig(s) for s in sigs]
    except Exception:
        return False
    # both lists are in the same (reversed) stack order, so relative order holds
    for sig in parsed:
        while points:
            if ecdsa_verify(points.pop(0), z, sig):
                break
        else:
            return False
    return True
