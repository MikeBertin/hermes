# Hermes

**Bitcoin from first principles.**
*Keys, signatures, and proof of work — built from nothing.*

A from-scratch Bitcoin implementation (in the spirit of Karpathy's *"A from-scratch tour
of Bitcoin in Python"*) turned into a suite of interactive browser visualisations. No crypto
libraries: the secp256k1 curve, SHA-256, RIPEMD-160, SHA-512, Base58Check, ECDSA — all by hand.

**▶ Live:** https://mikebertin.github.io/hermes/ — eight self-contained demos, from the elliptic
curve through to a **real transaction broadcast to the Bitcoin testnet**
([on-chain proof](https://blockstream.info/testnet/tx/f3771bf9d0d33ab8849ad54fae75b83f876cd39cd6af1d23ec9555cd86c46e08)).

Companion to [Chiron](https://mikebertin.github.io/chiron/) (computational physics),
[Empedocles](https://mikebertin.github.io/empedocles/) (evolutionary algorithms), and
**Plutus** (quantitative finance).

## Why "Hermes"

Hermes was the Greek god of commerce *and* of boundaries, messages, and secrets — whence
*hermetic*, "sealed". Money, cryptography, and signed messages are his exact portfolio.

## The eight demos

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

## The Python core

A canonical, readable, dependency-free implementation lives in [`hermes/`](hermes/). It is the
source of truth the browser demos visualise, cross-checked against official protocol test vectors
(BIP-39, BIP-32, on-chain transactions).

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest        # 37 known-answer vectors, all green
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
