# Hermes — Session Handover

> Quick entry point for picking the project back up. For the full staged history and every
> decision, see [PLAN.md](PLAN.md) (read its **Progress Log** at the bottom first). This file is
> the "where are we / what next" summary.

## TL;DR — the project is COMPLETE and SHIPPED

All 8 stages done. A from-scratch Bitcoin implementation (no crypto libraries) + 8 interactive
browser demos, culminating in a **real transaction broadcast to the Bitcoin testnet**.

- **Live:** https://mikebertin.github.io/hermes/
- **Repo:** https://github.com/MikeBertin/hermes (public)
- **On-chain proof:** testnet txid `f3771bf9d0d33ab8849ad54fae75b83f876cd39cd6af1d23ec9555cd86c46e08`
- **Tests:** `37/37` pytest green; JS cross-checked against the same vectors in-browser.

The 8 demos: Curve · Key→Address · Sign & Forge · Mine & Chain · Network/51% · Real Testnet ·
Script VM · HD Wallet.

## How to resume

```bash
cd /Users/m/.openclaw/workspace/projects/hermes

# Python core + tests  (system python is 3.14 + PEP-668, so ALWAYS use the project venv)
.venv/bin/python -m pytest -q

# Dev server for the web demos — use the preview tool / launch config "hermes-web" (port 8011),
# config lives in projects/.claude/launch.json (NOT projects/hermes/.claude). Or manually:
#   cd web && python3 -m http.server 8011

# Re-bake the network-sim JSON if you change hermes/network.py:
.venv/bin/python export.py

# The testnet CLI (testnet only — free, no value):
.venv/bin/python -m hermes.cli new            # generate a fresh address
.venv/bin/python -m hermes.cli info           # check UTXOs after funding
.venv/bin/python -m hermes.cli send <addr> [--broadcast]
```

## Repo map

```
hermes/            from-scratch Python core (the source of truth)
  field,curve      secp256k1            sha256,ripemd160,sha512   hashes by hand
  base58 keys ecdsa                     script  (stack VM + wire serialize)
  tx               SIMPLIFIED model used by the network sim
  transaction      REAL wire-format tx (serialize, SIGHASH_ALL, DER) — used for broadcast
  network          consensus + 51% simulators        bip32,bip39,english.txt  HD wallet
  cli              build/sign/broadcast a testnet tx
tests/             37 known-answer vectors (official BIP / on-chain tx vectors)
export.py          bakes web/network/data/*.json
web/               self-contained static site (this is what Pages serves)
  shared/          btc.js (core), wallet.js (BIP-32/39), demo.css, demo.js, test.html (vector harness)
  <demo>/index.html for each of the 8 demos; testnet/data/tx.json + network/data/*.json baked
  og.png           1200x630 social card
.github/workflows/pages.yml   deploys web/ to GitHub Pages on push to main
```

## Gotchas a cold session needs

- **Use `.venv`** — never the system python (3.14, externally-managed/PEP-668).
- **Two tx modules on purpose:** `hermes/tx.py` is the *simplified* UTXO model for the network
  sim; `hermes/transaction.py` is the *real* broadcastable wire format. Don't merge them.
- **`transaction.py` now does both legacy and SegWit.** Legacy P2PKH: `sign_input`/`sig_hash`.
  SegWit P2WPKH: `sign_input_p2wpkh`/`sig_hash_bip143` (commits to the input amount). `Tx.serialize()`
  auto-adds the marker/flag + witness when any input has one; `txid()` always hashes the legacy
  (witness-stripped) bytes.
- **`sign()` is deterministic (RFC 6979)** — re-signing the same tx reproduces the identical
  signature and txid. (Pass an explicit `k` only for the nonce-reuse demo.)
- **Pages = workflow, not legacy root.** Siblings (chiron/empedocles) serve from main-root; Hermes
  serves `web/` via the Actions workflow because it's a Python+site hybrid. Editing `web/` and
  pushing to `main` auto-redeploys.
- **Throwaway testnet key** is in `.testnet-key.json` (gitignored). It still holds the ~0.001 tBTC
  self-send output; spend it again anytime with `cli.py send`.
- **The testnet demo is baked** (`web/testnet/data/tx.json`) so it survives faucet/API rot — the
  live tx is captured statically, not re-fetched.

## Next steps (menu — nothing is required; the project is done)

1. **[quick win] Update `README.md`** — it still says "work in progress / demos coming". Refresh to
   "shipped & live", add the 8-demo table (mirror Plutus's README), and drop/keep sibling links as
   you like (the landing-page footer companion line was removed earlier per your call).
2. ✅ **RFC 6979 deterministic nonces** — DONE (2026-06-30). `ecdsa.rfc6979_k` + `hmac_sha256`;
   `sign()` is now deterministic by default. Mirrored in `btc.js`. Verified against the canonical
   secp256k1+SHA-256 vector (40 pytest / 45 in-browser).
3. ✅ **SegWit (P2WPKH + bech32 + BIP-143)** — DONE (2026-06-30). `bech32.py` (BIP-173/350),
   `PublicKey.p2wpkh_address`, and `transaction.py` segwit sighash + witness serialization;
   `cli.py send` now pays `bc1…`/`tb1…` via `address_to_script`. Mirrored in `btc.js`; the address
   demo shows the `bc1…` form. Reproduces the **BIP-143 worked example byte-for-byte** (46 pytest /
   48 in-browser). **Next bridge to Sovereign: 2-of-3 P2WSH multisig custody demo.**
4. **Merkle trees + SPV demo (a 9th card)** — was the deferred alternate in §7 of PLAN.md. Build a
   block's merkle root, show a merkle proof / how SPV wallets verify inclusion. Self-contained.
5. **Taproot / Schnorr signatures** — advanced; new signature scheme + key tweaking. Big but cool.
6. **Lightning / HTLC** — builds directly on the Script VM (hashlocks + timelocks are already there).
7. **Polish:** add Hermes to the siblings' footers (chiron/empedocles READMEs) if you want
   cross-linking; consider a short screen-capture GIF in the README.

## Verify-it-still-works checklist

```bash
.venv/bin/python -m pytest -q                                  # 37 passed
# dev server up, then open web/shared/test.html → "all 41 vectors pass"
# spot-check live: https://mikebertin.github.io/hermes/ and /testnet/ (real txid + explorer link)
```
