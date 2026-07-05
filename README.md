# Hermes

**Bitcoin from first principles.**
*Keys, signatures, and proof of work — built from nothing.*

A from-scratch Bitcoin implementation (in the spirit of Karpathy's *"A from-scratch tour
of Bitcoin in Python"*) turned into a suite of interactive browser visualisations. No crypto
libraries: the secp256k1 curve, SHA-256, RIPEMD-160, SHA-512, Base58Check, ECDSA — all by hand.

[![Seventeen interactive Bitcoin demos — the elliptic curve, mining, network consensus, Taproot and Lightning](web/demo.gif)](https://mikebertin.github.io/hermes/)

**▶ Live:** https://mikebertin.github.io/hermes/ — seventeen self-contained demos, from the elliptic
curve through to a **real transaction broadcast to the Bitcoin testnet**
([on-chain proof](https://blockstream.info/testnet/tx/f3771bf9d0d33ab8849ad54fae75b83f876cd39cd6af1d23ec9555cd86c46e08)),
a 2-of-3 multisig vault, trustless Merkle inclusion proofs, Taproot's Schnorr signatures, a
MuSig2 signing ceremony, a Lightning channel's revocation/penalty mechanism, a multi-hop HTLC
routed payment, FROST threshold signatures, PTLCs via Schnorr adaptor signatures, and a BIP-340
FROST Taproot vault.

## Why "Hermes"

Hermes was the Greek god of commerce *and* of boundaries, messages, and secrets — whence
*hermetic*, "sealed". Money, cryptography, and signed messages are his exact portfolio.

## The seventeen demos

Each is a single self-contained `index.html` — no build step, no framework, no dependencies.

| # | Demo | What it shows |
|---|------|---------------|
| 1 | **Curve** | secp256k1's group law made geometric — "private key = number, public key = point." Drag a scalar `k` and watch `P = k·G` build by chord-and-tangent. |
| 2 | **Key → Address** | The full pipeline priv → pubkey → SHA-256 → RIPEMD-160 → Base58Check, live. Flip one bit and watch the hash avalanche ripple the address. |
| 3 | **Sign & Forge** | ECDSA sign/verify — then the killer beat: **nonce reuse leaks the private key** (the PS3 bug), recovered on screen. |
| 4 | **Mine & Chain** | Double-SHA-256 proof of work — a live nonce grinder, then tamper a transaction and watch every later block turn red until you re-mine the cascade. |
| 5 | **Network + 51%** | Emergent consensus — gossip, forks, reorgs — and an attacker mining a private chain to reverse a "confirmed" payment. |
| 6 | **Real Testnet** | It's real. A captured Bitcoin testnet transaction narrated byte by byte, with the live explorer link. |
| 7 | **Script VM** | Bitcoin Script is a tiny stack language. Step a debugger through P2PKH, multisig, hashlock and timelock scripts. |
| 8 | **HD Wallet** | One seed phrase → a whole tree of addresses: BIP-39 mnemonic → seed → BIP-32 derivation, unfolding node by node. |
| 9 | **Multisig Vault** | Three keys, one `bc1q…` address, a 2-of-3 rule. A real P2WSH vault built by hand — choose who signs a withdrawal and watch the threshold decide. The shape of corporate Bitcoin custody. |
| 10 | **Merkle Proofs** | A block fingerprints every transaction in one 32-byte root. Click a transaction to reveal its inclusion proof — the `log₂(n)` sibling hashes a light wallet (or a proof-of-reserves check) needs, no full block required. |
| 11 | **Taproot & Schnorr** | Bitcoin's 2021 signature upgrade (BIP-340/341): x-only keys, `s = k + e·d` with no inverses, keys that **add** (two owners, one signature — the MuSig idea), and the TapTweak that turns a key into a `bc1p…` address. |
| 12 | **MuSig2** | Three cosigners aggregate into ONE key (BIP-327), run the two-round nonce/partial-signature ceremony, and produce a single 64-byte BIP-340 signature — an n-of-n vault indistinguishable from, and 4× cheaper than, demo 9's on-chain multisig. |
| 13 | **Lightning Channels** | Layer 2 (BOLT-3): open a 2-of-2 channel, pay off-chain thousands of times, and see the **revocation/penalty** mechanism that makes it trustless — publish a revoked commitment and the counterparty's revocation key sweeps *everything*. The `to_local` script (`OP_IF`/`OP_CHECKSEQUENCEVERIFY`), the blinded revocation key, and per-commitment secrets, all real. |
| 14 | **HTLC Routing** | Layer 2: Alice pays Carol *through* Bob with no direct channel. Each hop is a hash-time-locked contract (HTLC) on the same payment hash, so **one preimage settles the whole path** — and decreasing per-hop timelocks (`cltv_expiry_delta`) mean the router can never be left out of pocket. The BOLT-3 offered/received HTLC scripts are cross-checked byte-for-byte against the spec's Appendix C. |
| 15 | **FROST Threshold** | Threshold Schnorr (**RFC 9591**): any *t* of *n* key-holders — say **2 of 3** — produce one signature, and any *t-1* cannot. The group secret is Shamir-shared and *never reassembled*; signing folds the shares in via Lagrange interpolation. The `t-of-n` counterpart to MuSig2's `n-of-n`, with the from-scratch `expand_message_xmd` hashing reproducing the RFC's official test vector byte-for-byte. |
| 16 | **PTLC Routing** | The Taproot-era replacement for HTLCs: lock each hop to a **point** `T = t·G` instead of a hash, using a **Schnorr adaptor signature**. Completing the signature reveals the secret `t` — settling the path and unlocking the hop behind it — but it rides inside an ordinary signature, so hops are unlinkable and script-less. The completed signature is a genuine 64-byte BIP-340 signature `schnorr.verify` accepts. |
| 17 | **FROST Taproot Vault** | Re-skin FROST (demo 15) to the **BIP-340** challenge and its even-y conventions, so the threshold signature becomes a genuine 64-byte one — then wrap the group key in a BIP-341 **TapTweak** to get a `bc1p…` vault any **2 of 3** officers can **key-path spend**. On-chain it's one signature, byte-for-byte indistinguishable from a single wallet. The `t-of-n` Taproot vault. |

## The Python core

A canonical, readable, dependency-free implementation lives in [`hermes/`](hermes/). It is the
source of truth the browser demos visualise, cross-checked against official protocol test vectors
(BIP-39, BIP-32, BIP-340/341, BIP-327, BOLT-3, RFC 9591, on-chain transactions).

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest        # 213 tests — official BIP / BOLT / RFC vectors + rejection paths, all green
```

The testnet CLI builds, signs and broadcasts a real (valueless) testnet transaction:

```bash
.venv/bin/python -m hermes.cli new            # generate a fresh testnet address
.venv/bin/python -m hermes.cli info           # check UTXOs after funding from a faucet
.venv/bin/python -m hermes.cli send <addr> [--broadcast]
```

## Running the demos locally

```bash
cd web && python3 -m http.server 8011         # then open http://localhost:8011
```

The site is plain static files — `web/` is exactly what GitHub Pages serves.
