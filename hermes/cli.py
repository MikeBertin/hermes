"""Hermes testnet CLI — build, sign, and broadcast a real Bitcoin transaction.

Workflow (testnet coins have no value; this is safe and free):

    python -m hermes.cli new                 # generate a fresh testnet address
    # ... fund that address from a testnet faucet ...
    python -m hermes.cli info                 # check the balance / UTXOs
    python -m hermes.cli send <dest> [--broadcast]   # spend it back

Without --broadcast, `send` only builds and prints the signed transaction for
review. The signed raw hex is what `web/testnet/` narrates.
"""

from __future__ import annotations

import json
import os
import sys

from .keys import PrivateKey
from .transaction import (
    Tx, TxInput, TxOutput, broadcast, fetch_utxos, p2pkh_from_address, p2pkh_script,
)

KEYFILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".testnet-key.json")
TESTNET = True


def _load() -> dict:
    if not os.path.exists(KEYFILE):
        sys.exit("No key yet — run:  python -m hermes.cli new")
    with open(KEYFILE) as f:
        return json.load(f)


def cmd_new() -> None:
    import secrets
    from .curve import N
    secret = secrets.randbelow(N - 1) + 1
    priv = PrivateKey(secret)
    addr = priv.address(compressed=True, testnet=TESTNET)
    with open(KEYFILE, "w") as f:
        json.dump({"secret": hex(secret), "address": addr}, f)
    print(f"testnet address: {addr}")
    print(f"saved to: {KEYFILE}")
    print("\nFund it from a testnet faucet, e.g.:")
    print("  https://coinfaucet.eu/en/btc-testnet/")
    print("  https://bitcoinfaucet.uo1.net/")
    print("\nThen:  python -m hermes.cli info")


def cmd_info() -> None:
    k = _load()
    utxos = fetch_utxos(k["address"], TESTNET)
    total = sum(u["value"] for u in utxos)
    print(f"address: {k['address']}")
    print(f"UTXOs:   {len(utxos)}   balance: {total} sat ({total / 1e8:.8f} tBTC)")
    for u in utxos:
        status = "confirmed" if u.get("status", {}).get("confirmed") else "unconfirmed"
        print(f"  {u['txid']}:{u['vout']}  {u['value']} sat  [{status}]")


def cmd_send(dest: str, do_broadcast: bool, fee: int = 300) -> None:
    k = _load()
    priv = PrivateKey(int(k["secret"], 16))
    h160 = priv.public_key().hash160()
    prev_script = p2pkh_script(h160)

    utxos = fetch_utxos(k["address"], TESTNET)
    if not utxos:
        sys.exit("No UTXOs — fund the address first (python -m hermes.cli info).")
    total = sum(u["value"] for u in utxos)
    send_amount = total - fee
    if send_amount <= 0:
        sys.exit(f"Balance {total} sat doesn't cover the {fee} sat fee.")

    tx = Tx(
        version=1,
        inputs=[TxInput(bytes.fromhex(u["txid"]), u["vout"]) for u in utxos],
        outputs=[TxOutput(send_amount, p2pkh_from_address(dest))],
        testnet=TESTNET,
    )
    for i in range(len(tx.inputs)):
        tx.sign_input(i, priv.secret, prev_script)

    raw = tx.serialize().hex()
    print(f"from:   {k['address']}")
    print(f"to:     {dest}")
    print(f"amount: {send_amount} sat   fee: {fee} sat   inputs: {len(utxos)}")
    print(f"txid:   {tx.txid()}")
    print(f"\nraw transaction:\n{raw}")

    if do_broadcast:
        print("\nbroadcasting…")
        txid = broadcast(raw, TESTNET)
        print(f"accepted! txid: {txid}")
        explorer = "https://blockstream.info/testnet/tx/" + txid
        print(f"explorer: {explorer}")
    else:
        print("\n(dry run — pass --broadcast to publish it)")


def main(argv: list[str]) -> None:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return
    cmd = argv[0]
    if cmd == "new":
        cmd_new()
    elif cmd == "info":
        cmd_info()
    elif cmd == "send":
        if len(argv) < 2:
            sys.exit("usage: send <dest-address> [--broadcast]")
        cmd_send(argv[1], "--broadcast" in argv)
    else:
        sys.exit(f"unknown command: {cmd}")


if __name__ == "__main__":
    main(sys.argv[1:])
