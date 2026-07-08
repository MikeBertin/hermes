# Hermes — Session Handover

> Quick entry point for picking the project back up. For the full staged history and every
> decision, see [PLAN.md](PLAN.md) (read its **Progress Log** at the bottom first). This file is
> the "where are we / what next" summary.

## TL;DR — the project is COMPLETE and SHIPPED

All 8 stages done, plus a post-ship enhancement arc (RFC 6979 → SegWit → multisig → Merkle/SPV →
Taproot/Schnorr → MuSig2 → Lightning → HTLC routing → FROST → PTLCs → BIP-340 FROST → HTLC
second-stage) and a review-hardening pass (negative tests). A from-scratch Bitcoin implementation (no
crypto libraries) + 18 interactive browser demos, culminating in a **real transaction broadcast to the
Bitcoin testnet**, a 2-of-3 multisig vault, trustless Merkle inclusion proofs, BIP-340 Schnorr
signatures with Taproot `bc1p…` addresses, a full BIP-327 MuSig2 signing ceremony, a Lightning
channel's BOLT-3 revocation/penalty mechanism, a multi-hop HTLC routed payment, RFC 9591 FROST
threshold signatures, PTLCs via Schnorr adaptor signatures, a BIP-340 FROST Taproot (t-of-n) vault,
and the HTLC-timeout/success second-stage transactions of a force-close.

- **Live:** https://mikebertin.github.io/hermes/
- **Repo:** https://github.com/MikeBertin/hermes (public)
- **On-chain proof:** testnet txid `f3771bf9d0d33ab8849ad54fae75b83f876cd39cd6af1d23ec9555cd86c46e08`
- **Tests:** `217/217` pytest green (official BIP / BOLT / RFC vectors + rejection paths); JS
  cross-checked against the same vectors in-browser (108/108).

The 18 demos: Curve · Key→Address · Sign & Forge · Mine & Chain · Network/51% · Real Testnet ·
Script VM · HD Wallet · Multisig Vault · Merkle Proofs · Taproot & Schnorr · MuSig2 · Lightning ·
HTLC Routing · FROST Threshold · PTLC Routing · FROST Taproot Vault · HTLC Second-Stage.

---

## ▶ NEXT SESSION: nothing is owed — an options menu

The enhancement arc has a natural next rung if wanted; otherwise the project simply stands.

1. ~~**Polish** — README screen-capture GIF of the demos.~~ ✅ Done 2026-07-04 (`web/demo.gif`,
   embedded as the README hero; regenerate with `demo-capture.js` — see gotchas below).
2. ~~**Lightning, deeper** — the HTLC *second-stage* transactions.~~ ✅ Done 2026-07-08 (18th card
   `web/second-stage/`; `htlc_timeout_tx`/`htlc_success_tx` + signers in `hermes/lightning.py`,
   reproduced byte-for-byte against BOLT-3 Appendix C). See the Progress Log for details.
3. **FROST DKG** — replace the trusted dealer with distributed key generation (each participant
   contributes; no single party ever holds the group secret). A natural depth-add to demos 15/17.
4. **Demo GIF, deeper** — add a 6th beat (the new second-stage card) to `web/demo.gif`.

Lightning notes a future session might need: `hermes/lightning.py` builds real BOLT-3 scripts —
`to_local_script`, the blinded revocation key (`derive_revocation_pubkey`/`_privkey`), and the HTLC
scripts (`htlc_offered_script`/`htlc_received_script`, anchored byte-for-byte to **BOLT-3 Appendix C**;
plus a canonical `htlc_script` the routing card uses). Channel derivations anchor to **Appendix E/D**.
The Script VM (`hermes/script.py` *and* the inline JS VM in `web/script/index.html`) now has
`OP_IF/NOTIF/ELSE/ENDIF`, `OP_CSV`, `OP_SWAP`, `OP_SIZE`; `evaluate()` takes `sequence`. JS mirror is
the `ln*` family in `btc.js`. Cards: `web/lightning/` (channel, `#ffd400`) and `web/routing/` (HTLC
routing, teal `#2dd4bf`). Both model the *logic* faithfully; the routing card uses the canonical HTLC
(not the full revocation-wrapped commitment HTLC — that's the "Lightning, deeper" item above).

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
  lightning        BOLT-3 channels (funding, revocation, to_local, penalty) + HTLC scripts (routing)
                   + second-stage HTLC-timeout/success txs (htlc_timeout_tx/htlc_success_tx + signers)
  frost            RFC 9591 threshold Schnorr (expand_message_xmd, Shamir keygen, Lagrange, sign/agg)
  frost_taproot    BIP-340 FROST — Taproot-spendable threshold (reuses frost + taproot; even-y flips)
  adaptor          BIP-340 Schnorr adaptor sigs / PTLCs (presign, adapt, extract — reuses schnorr)
  script           stack VM — OP_IF/NOTIF/ELSE/ENDIF + OP_CSV + OP_SWAP + OP_SIZE (evaluate: sequence arg)
  cli              build/sign/broadcast a testnet tx
tests/             official BIP / on-chain vectors + negative rejection-path tests
  vectors/bip327/  the official BIP-327 JSON vectors, committed verbatim
export.py          bakes web/network/data/*.json
web/               self-contained static site (this is what Pages serves)
  shared/          btc.js (core), wallet.js (BIP-32/39), demo.css, demo.js, test.html (vector harness)
  <demo>/index.html for each of the 18 demos; testnet/data/tx.json + network/data/*.json baked
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
- **`web/demo.gif` (README hero) is a scripted montage — regenerate, don't screen-record by hand.**
  `demo-capture.js` (repo root) drives the dev server through six beats with Playwright + the system
  Chrome (`npm i playwright` first; uses `channel:'chrome'`, no browser download) and records one
  `.webm`; a two-pass ffmpeg palette step turns it into the GIF. Full commands are in the file's
  header comment. Like `og.png`, it goes stale when a demo is added or a card's DOM/selectors change
  (the beats key off `#px`, `#mineBtn`, `#stepBtn`, `#signBtn`/`#jointSign`, `#payAB`). Two Network-card
  quirks the script works around: (1) its canvas scales x by the run's *final* height, so it only fills
  once Step reaches the end — hence the fast-forward `#stepBtn` loop instead of a timed Play; and (2)
  the canvas is a fixed `900×520` with the chain drawn at only 40% height, so at the capture viewport it
  frames with a big empty void below — the script shrinks `#tree.height` to `300` (a compact 3:1 strip)
  and `#resetC`s before building so the chain fills the frame with the legend/controls in view.

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
8. ✅ **Lightning: channel + revocation/penalty — 13th card** (2026-07-03) — first Layer-2 card.
   Extended both Script VMs with `OP_IF/NOTIF/ELSE/ENDIF` + `OP_CSV`; `hermes/lightning.py` with
   BOLT-3 key/revocation derivation, `per_commitment_secret`, the `to_local` script, and
   commitment/penalty txs. Anchored byte-for-byte to BOLT-3 Appendix D + E; full open→revoke→cheat→
   punish lifecycle verified through our Script VM.
9. ✅ **HTLC routing — 14th card** (2026-07-03) — the routing half of Lightning. Added `OP_SWAP` +
   `OP_SIZE`; real BOLT-3 `htlc_offered_script`/`htlc_received_script` (anchored byte-for-byte to
   Appendix C) + a canonical `htlc_script`. Multi-hop Alice→Bob→Carol: one preimage settles the path,
   decreasing timelocks keep the router safe, verified through the Script VM.
10. ✅ **FROST threshold — 15th card** (2026-07-04) — t-of-n threshold Schnorr, sequel to MuSig2.
    `hermes/frost.py` implements RFC 9591's `FROST(secp256k1, SHA-256)` incl. from-scratch
    `expand_message_xmd` (RFC 9380); anchored byte-for-byte to Appendix E.5 (2-of-3). JS mirror
    `frost*` in `btc.js`; card `web/frost/` (icy-lavender `#c4b5fd`). NOTE: RFC 9591's challenge
    hash isn't BIP-340, so the 65-byte sig is threshold Schnorr but *not* a Taproot spend.
11. ✅ **PTLCs / adaptor signatures — 16th card** (2026-07-04) — point-locked routing, the Taproot
    replacement for HTLCs. `hermes/adaptor.py`: BIP-340 Schnorr adaptor sigs (`presign`/`presig_verify`/
    `adapt`/`extract`) with even-Y parity handling; `adapt` yields a genuine 64-byte BIP-340 sig
    `schnorr.verify` accepts, `extract` reveals the adaptor secret. No official vectors → pinned by
    exhaustive self-consistency (64 random cases, both parities). JS mirror `adaptor*` in `btc.js`;
    card `web/ptlc/` (pink `#f472b6`).
12. ✅ **BIP-340 FROST Taproot vault — 17th card** (2026-07-04) — the Taproot-spendable sequel to
    demo 15. `hermes/frost_taproot.py` re-skins RFC 9591 FROST to BIP-340: core `sign`/`aggregate`
    (verify under the x-only group key) + `taproot_sign`/`taproot_aggregate` (TapTweak → a `bc1p`
    key-path spend), with even-y sign flips on R/P/Q. No vectors → self-consistency via
    `schnorr.verify` across random keys × subsets. JS mirror `frostBip340*`/`frostTaproot*`; card
    `web/frost-taproot/` (indigo `#818cf8`).
13. ✅ **HTLC second-stage — 18th card** (2026-07-08) — "Lightning, deeper": the on-chain resolution
    of a force-close with a pending HTLC. `hermes/lightning.py` gains `htlc_timeout_tx`/`htlc_success_tx`
    (they return a `Commitment`, so `penalty_tx`/`sign_to_local_delayed` sweep the second-stage
    `to_local` output unchanged — the penalty recurses) + `sign_htlc_timeout`/`sign_htlc_success`.
    **Anchored byte-for-byte** to BOLT-3 Appendix C: the "all five HTLCs untrimmed" (feerate 0) scenario
    is reproduced from the private keys, all five HTLC-timeout/success txs matching the published hex.
    JS: added a DER encoder + SegWit serializer + `lnHtlcTimeoutTx/SuccessTx` + `lnSignHtlcTimeout/Success`
    to `btc.js` (two byte-for-byte test.html checks). Card `web/second-stage/` (orange `#fb923c`, `.c18`):
    offered↔received toggle, real tx matching the vector, witness stack, a delay slider on the output.
    The raw BOLT-3 spec used for the vectors is `lightning/bolts` `03-transactions.md` Appendix C.

## Verify-it-still-works checklist

```bash
.venv/bin/python -m pytest -q                                  # 217 passed
# dev server up, then open web/shared/test.html → "all 108 vectors pass"
# spot-check live: https://mikebertin.github.io/hermes/ and /testnet/ (real txid + explorer link)
```
