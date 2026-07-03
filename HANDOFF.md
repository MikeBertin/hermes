# Hermes — Session Handover

> Quick entry point for picking the project back up. For the full staged history and every
> decision, see [PLAN.md](PLAN.md) (read its **Progress Log** at the bottom first). This file is
> the "where are we / what next" summary.

## TL;DR — the project is COMPLETE and SHIPPED

All 8 stages done, plus a post-ship enhancement arc (RFC 6979 → SegWit → multisig → Merkle/SPV →
Taproot/Schnorr → MuSig2) and a review-hardening pass (negative tests). A from-scratch Bitcoin
implementation (no crypto libraries) + 12 interactive browser demos, culminating in a **real
transaction broadcast to the Bitcoin testnet**, a 2-of-3 multisig vault, trustless Merkle inclusion
proofs, BIP-340 Schnorr signatures with Taproot `bc1p…` addresses, and a full BIP-327 MuSig2
signing ceremony.

- **Live:** https://mikebertin.github.io/hermes/
- **Repo:** https://github.com/MikeBertin/hermes (public)
- **On-chain proof:** testnet txid `f3771bf9d0d33ab8849ad54fae75b83f876cd39cd6af1d23ec9555cd86c46e08`
- **Tests:** `176/176` pytest green (official BIP vectors + rejection paths); JS cross-checked
  against the same vectors in-browser (76/76).

The 12 demos: Curve · Key→Address · Sign & Forge · Mine & Chain · Network/51% · Real Testnet ·
Script VM · HD Wallet · Multisig Vault · Merkle Proofs · Taproot & Schnorr · MuSig2.

---

## ▶ NEXT SESSION: nothing is owed — an options menu

The enhancement arc has a natural next rung if wanted; otherwise the project simply stands.

1. **Lightning/HTLC** — the biggest remaining story. Builds directly on the Script VM's hashlocks
   + timelocks (demo 7) and the SegWit machinery: a payment channel (funding 2-of-2, commitment
   txs, revocation), or just the HTLC script itself routed across two hops. Python first, then a
   card. No official vector set — anchor to hand-built cases + a real mainnet HTLC if findable.
2. **FROST** (threshold Schnorr, t-of-n) — the natural sequel to MuSig2's n-of-n; there's an IETF
   draft (RFC 9591) with vectors, but it's ciphersuite-heavy — scope carefully.
3. **Polish** — README screen-capture GIF; sibling cross-links in chiron/empedocles footers.

MuSig2 notes a future session might need: `hermes/musig.py` mirrors the BIP-327 reference API
(names, error messages, blame semantics — `InvalidContributionError(signer, contrib)`), skipping
only adaptor signatures + deterministic signing. Official vectors live as JSON in
`tests/vectors/bip327/` (first suite to use file-based vectors; older suites inline them).
The JS mirror is the `musig*` family in `btc.js`; the card is `web/musig/` (lime `#a8d94b`).

---

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
  schnorr          BIP-340 Schnorr (tagged hashes, x-only keys, sign/verify)
  taproot          BIP-341 key path (TapTweak, output key, bc1p… addresses)
  musig            BIP-327 MuSig2 (KeyAgg, two-round ceremony, tweaks, partial-sig blame)
  cli              build/sign/broadcast a testnet tx
tests/             official BIP / on-chain vectors + negative rejection-path tests
  vectors/bip327/  the official BIP-327 JSON vectors, committed verbatim
export.py          bakes web/network/data/*.json
web/               self-contained static site (this is what Pages serves)
  shared/          btc.js (core), wallet.js (BIP-32/39), demo.css, demo.js, test.html (vector harness)
  <demo>/index.html for each of the 12 demos; testnet/data/tx.json + network/data/*.json baked
  og.png           1200x630 social card
.github/workflows/pages.yml   deploys web/ to GitHub Pages on push to main
```

## Gotchas a cold session needs

- **Use `.venv`** — never the system python (3.14, externally-managed/PEP-668).
- **The local dev server caches.** `python -m http.server` sends no cache headers, so the preview
  browser happily serves a stale `index.html` after edits. If a change "isn't showing", hard-bypass:
  `fetch("/", {cache:"reload"}).then(() => location.reload())` (or add a `?nocache=` query).
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
- **If the Pages deploy fails, do NOT `gh run rerun --failed`.** Seen 2026-07-02: the deploy step
  timed out GitHub-side (`deployment_queued` for 10 min — their infra, not us), and the re-run then
  failed with *"Multiple artifacts named github-pages"* because re-running the job uploads a second
  artifact into the same run. The fix is a **fresh run**: `gh workflow run pages.yml` (the workflow
  has `workflow_dispatch`).
- **Throwaway testnet key** is in `.testnet-key.json` (gitignored). It still holds the ~0.001 tBTC
  self-send output; spend it again anytime with `cli.py send`.
- **The testnet demo is baked** (`web/testnet/data/tx.json`) so it survives faucet/API rot — the
  live tx is captured statically, not re-fetched.
- **`web/og.png` lists the demo count + a pill per demo, so it goes stale when a card is added.**
  Source is committed at **`og-card.html`** (repo root). To regenerate: edit it (the "…interactive
  demos" line + add a `.pill`), then render via headless Chrome and downscale 2×→1×:
  ```bash
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless --disable-gpu \
    --force-device-scale-factor=2 --window-size=1200,630 --screenshot=og-2x.png \
    "file://$PWD/og-card.html"
  sips -z 630 1200 og-2x.png --out web/og.png
  ```

## Completed enhancement arc (details in PLAN.md's Progress Log)

1. ✅ **RFC 6979 deterministic nonces** (2026-06-30) — `ecdsa.rfc6979_k`; canonical vector.
2. ✅ **SegWit: P2WPKH + bech32 + BIP-143** (2026-06-30) — reproduces the BIP-143 worked example.
3. ✅ **2-of-3 P2WSH multisig — 9th card** (2026-06-30) — anchored to on-chain tx 440fe853….
4. ✅ **Merkle trees + SPV — 10th card** (2026-06-30) — anchored to block 100000's root.
5. ✅ **Review hardening + negative tests** (2026-07-02) — P2SH/bip39/multisig-verify fixes.
6. ✅ **Taproot & Schnorr — 11th card** (2026-07-02) — full BIP-340 CSV, BIP-341 wallet vector,
   BIP-86 end-to-end (mnemonic → m/86'/0'/0'/0/0 → `bc1p…`).
7. ✅ **MuSig2 — 12th card** (2026-07-03) — all six official BIP-327 vector files incl. every
   error case; two-round ceremony card with an accountability ("corrupt a share") beat.

## Verify-it-still-works checklist

```bash
.venv/bin/python -m pytest -q                                  # 176 passed
# dev server up, then open web/shared/test.html → "all 76 vectors pass"
# spot-check live: https://mikebertin.github.io/hermes/ and /testnet/ (real txid + explorer link)
```
