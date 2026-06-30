# Hermes — Session Handover

> Quick entry point for picking the project back up. For the full staged history and every
> decision, see [PLAN.md](PLAN.md) (read its **Progress Log** at the bottom first). This file is
> the "where are we / what next" summary.

## TL;DR — the project is COMPLETE and SHIPPED

All 8 stages done, plus a post-ship enhancement arc (RFC 6979 → SegWit → multisig → Merkle/SPV). A
from-scratch Bitcoin implementation (no crypto libraries) + 10 interactive browser demos, culminating
in a **real transaction broadcast to the Bitcoin testnet**, a 2-of-3 multisig vault, and trustless
Merkle inclusion proofs.

- **Live:** https://mikebertin.github.io/hermes/
- **Repo:** https://github.com/MikeBertin/hermes (public)
- **On-chain proof:** testnet txid `f3771bf9d0d33ab8849ad54fae75b83f876cd39cd6af1d23ec9555cd86c46e08`
- **Tests:** `57/57` pytest green; JS cross-checked against the same vectors in-browser (53/53).

The 10 demos: Curve · Key→Address · Sign & Forge · Mine & Chain · Network/51% · Real Testnet ·
Script VM · HD Wallet · Multisig Vault · Merkle Proofs.

---

## ▶ NEXT SESSION: Taproot / Schnorr (the planned pick-up)

Build an **11th demo card**. This is the biggest of the remaining options (a brand-new signature
scheme), so do it in vector-anchored phases — same discipline as the rest of the repo: Python core
first, anchored to official vectors, then JS mirror, then the card. Mirror everything in `btc.js`.

**Phase A — Schnorr signatures (BIP-340), the foundation.** New file `hermes/schnorr.py`. Don't
touch the existing ECDSA path (`ecdsa.py`) — Schnorr is separate.
- **Tagged hashes:** `tagged_hash(tag, msg) = sha256(sha256(tag) + sha256(tag) + msg)`. We already
  have `sha256`. Every BIP-340/341 hash is tagged (tags: `"BIP0340/aux"`, `"BIP0340/nonce"`,
  `"BIP0340/challenge"`, later `"TapTweak"`, `"TapLeaf"`, `"TapBranch"`).
- **x-only pubkeys (32 bytes) + even-Y convention.** A pubkey is just `P.x`; whoever uses it assumes
  the even-Y point. When signing, if `P.y` is odd negate `d` (`d = n - d`); if the nonce point `R.y`
  is odd negate `k`.
- **Sign:** `e = int(tagged_hash("BIP0340/challenge", R.x ‖ P.x ‖ m)) mod n`; `sig = R.x ‖ ((k + e·d) mod n)`.
  Nonce: BIP-340 derives `k` from a tagged hash of (aux_rand ⊕ d) ‖ P.x ‖ m (deterministic; aux_rand
  may be 32 zero bytes). Implement that nonce function — it's what the test vectors use.
- **Verify:** `e = tagged_hash(challenge, r ‖ P.x ‖ m)`; check `s·G == R + e·P` with x-only/even-Y
  lifting (`lift_x`: given x, take the even-Y root — `P` is `≡3 mod 4` so `y = pow(c,(p+1)//4,p)`,
  we already do this in `PublicKey.parse`).
- **Anchor:** the official **BIP-340 test-vector CSV**
  (`github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv`) — index/secret/pubkey/aux_rand/
  message/signature/result rows, incl. must-fail cases. Fetch + bake like the other vectors.

**Phase B — P2TR address (BIP-341 key tweak).** Output key `Q = P + t·G`, where for a key-path-only
output `t = int(tagged_hash("TapTweak", P.x)) mod n`. The address is **witness v1 + `Q.x` (32 bytes)
→ bech32m** — and `bech32.py`'s `encode_segwit` ALREADY emits bech32m for witver ≥ 1, so a P2TR
address is `encode_segwit(hrp, 1, Q.x)` → `bc1p…`. Anchor against a known P2TR address vector (or the
BIP-341 test vectors). Add `PublicKey.p2tr_address` or a `taproot.py` helper.

**Phase C — the card** `web/taproot/` (an 11th card; accent unused so far — try a gold/orange like
`#f7a14b` or a magenta). Suggested content: Schnorr sign/verify (and the contrast with ECDSA —
linear, so signatures *add*), the x-only key + even-Y idea, the key-tweak → `bc1p…` address. Update
landing page (10→11, lede "Eleven", add `.c11`/`--taproot`), README table, and **re-render og.png**
(the card text says the demo count — see the og note in Gotchas; source is
`og-card.html` at repo root).

**Phase D — optional, the Sovereign tie-in.** **MuSig(2) key aggregation** — aggregate N pubkeys into
one Taproot output so an n-of-n multisig looks (and costs) like single-sig on-chain. This is the modern
custody frontier (where 2-of-3 vaults are heading) and pairs with the Multisig Vault card. Advanced;
only if Phases A–C land with room to spare. (Full BIP-341 key-path *sighash* + a real spend is also
optional — the address + Schnorr sig are the headline.)

**Effort:** Phase A is the real work (a from-scratch sig scheme); B is small (bech32m is done); C is a
standard card. Likely one focused session for A–C, MuSig as a stretch/second session.

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
- **`web/og.png` lists the demo count + a pill per demo, so it goes stale when a card is added.**
  Source is committed at **`og-card.html`** (repo root). To regenerate: edit it (the "…interactive
  demos" line + add a `.pill`), then render via headless Chrome and downscale 2×→1×:
  ```bash
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless --disable-gpu \
    --force-device-scale-factor=2 --window-size=1200,630 --screenshot=og-2x.png \
    "file://$PWD/og-card.html"
  sips -z 630 1200 og-2x.png --out web/og.png
  ```

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
3b. ✅ **2-of-3 multisig custody (9th demo card)** — DONE (2026-06-30). P2WSH multisig in
   `transaction.py` (`multisig_script`, `p2wsh_address`, `sign/verify_input_p2wsh_multisig`),
   mirrored in `btc.js`; new `web/multisig/` "Multisig Vault" card. Anchored to a real on-chain
   native-P2WSH 2-of-3 tx (txid 440fe853…). 52 pytest / 51 in-browser. **The site is now 9 demos.**
4. ✅ **Merkle trees + SPV (10th demo card)** — DONE (2026-06-30). `hermes/merkle.py` (root/proof/
   verify, odd-duplication) mirrored in `btc.js`; new `web/merkle/` "Merkle Proofs" card (SVG tree +
   highlighted proof path + tamper toggle). Anchored to real block 100000's root. 57 pytest / 53
   in-browser. **The site is now 10 demos.**
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
