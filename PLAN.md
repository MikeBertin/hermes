# Hermes — Build Plan

> **Bitcoin from first principles.** A from-scratch Bitcoin implementation (in the spirit of
> Karpathy's *"A from-scratch tour of Bitcoin in Python"* / `karpathy/cryptos`) turned into a
> suite of interactive browser visualisations. Companion to **Chiron** (computational physics),
> **Empedocles** (evolutionary algorithms), and **Plutus** (quant finance).

**Status:** SCOPED & LOCKED — no code written yet. This document is the source of truth for
multi-session handovers. Update the *Progress Log* at the bottom at the end of every session.

---

## 0. How to use this document (handover protocol)

This is a multi-session project. To keep token usage bounded, each session should:

1. **Read this file first.** It contains every locked decision and the full spec — you should
   not need to re-derive anything or re-read the whole codebase.
2. **Check the Progress Log** (bottom) for what's done and what's next.
3. Do the next stage (or the stage the user asks for). Stages are ordered so each produces
   something runnable/verifiable on its own.
4. **At end of session:** tick the stage checklist, append a dated entry to the Progress Log
   (what changed, what's next, any new decisions), and update the memory file
   `hermes-bitcoin-from-scratch.md`.
5. Keep the memory-file one-liner in `MEMORY.md` current.

**Golden rule:** the Python package is the *canonical, correct* implementation, cross-checked
against official protocol test vectors. The browser JS is a small re-implementation for snappy
interaction; it must agree with the same test vectors. When in doubt, Python wins.

---

## 1. Naming & identity

- **Codename: Hermes** — Greek god of commerce *and* of boundaries, messages, and secrets
  (whence "hermetic" = sealed). Money + cryptography + signed messages is his exact portfolio.
- **Tagline:** *"Bitcoin from first principles — keys, signatures, and proof of work, built from nothing."*
- **README framing** must earn the name (template = Plutus's "blind god of wealth" intro):
  a short myth paragraph tying Hermes to commerce + secrets + messengers, then the demos table,
  then cross-links to Chiron / Empedocles / Plutus, then "Running locally".
- GitHub Pages URL (to reserve in meta tags): `https://mikebertin.github.io/hermes/`

---

## 2. House style (mirror exactly — copy from chiron/index.html)

Locked conventions, identical to Chiron/Empedocles/Plutus:

- **Self-contained.** Each demo is a single `index.html` with inline `<style>` and vanilla JS +
  `<canvas>`. No build step, no framework, no npm. `fetch()` of baked JSON is allowed (needs a
  local server, documented in README).
- **Palette** (from chiron): `--bg:#0a0a0f; --panel:#13131c; --line:#23232f; --ink:#e7e7ef;
  --muted:#8a8a9c;` plus one **accent colour per demo** (see table in §5). Mono font
  `"SF Mono",ui-monospace,Menlo,Consolas,monospace`; sans `ui-sans-serif,system-ui,...`.
- **Landing page**: `.badge` (uppercase tracked-out codename) → gradient-text `<h1>` →
  `.lede` paragraph → `.grid` of accent-coloured `a.card`s (thumb canvas + tag + h2 + blurb +
  "Open →") → `footer` with myth note + sibling links. Cards lift on hover and tint to their
  accent. Reuse chiron's exact CSS as the starting point.
- Full OpenGraph + Twitter meta block (see chiron head), pointing at `og.png` (1200×630).
- Each demo page: title + one-paragraph explainer up top, the canvas/controls, and a short
  "what am I looking at / why it matters" note. Keep copy tight and confident.

---

## 3. Architecture (locked)

```
projects/hermes/
├── PLAN.md                 # this file
├── README.md               # myth + demos table + run instructions
├── og.png                  # 1200×630 social card (built last)
├── hermes/                 # ── canonical from-scratch Python package ──
│   ├── __init__.py
│   ├── field.py            # finite-field element mod p
│   ├── curve.py            # secp256k1: Point, group law, scalar mult (k·G)
│   ├── sha256.py           # SHA-256 from scratch (Karpathy did this by hand)
│   ├── ripemd160.py        # RIPEMD-160 from scratch
│   ├── base58.py           # Base58 + Base58Check
│   ├── keys.py             # priv key, pub key, WIF, P2PKH address
│   ├── ecdsa.py            # sign / verify; deterministic + explicit-nonce modes
│   ├── script.py           # Bitcoin Script stack VM + opcode set
│   ├── tx.py               # tx structure, serialization, sighash (SIGHASH_ALL)
│   ├── node.py             # a single node: chain, mempool, fork-choice
│   ├── network.py          # multi-node gossip sim + 51% attack scenario
│   ├── bip39.py            # mnemonic <-> seed (PBKDF2-HMAC-SHA512)
│   ├── bip32.py            # HD key derivation (CKD, paths)
│   └── cli.py              # derive keys; build/sign/broadcast a real testnet tx
├── tests/                  # pytest, drive everything off official test vectors
│   └── vectors/            # JSON of known-answer vectors (see §4)
├── export.py               # bakes JSON run-data into web/<demo>/data/ (Plutus pattern)
└── web/
    ├── index.html          # landing page (8 cards)
    ├── shared/             # optional: shared.css, btc.js (small JS/BigInt crypto reimpl)
    ├── curve/index.html
    ├── address/index.html
    ├── sign/index.html
    ├── mine/index.html
    ├── network/index.html  # consumes baked JSON from export.py
    ├── testnet/index.html
    ├── script/index.html
    └── wallet/index.html
```

**Bridge policy:** interactive primitives (curve, address, sign, mine, script, wallet) get a
small JS/BigInt reimplementation in `web/shared/btc.js` so input is instant — JS has native
`BigInt`, and secp256k1 is just modular arithmetic, so this is ~300–400 lines. The **network**
demo is data-heavy and non-interactive in its core, so it plays back **pre-baked JSON runs** from
`export.py`. The **testnet** demo is driven by the Python `cli.py` (real serialization + real
broadcast); the web page narrates/visualises a captured real transaction. **No Pyodide** unless a
demo genuinely needs live arbitrary-Python — current plan: not needed.

**secp256k1 constants** (so no session re-derives them):
```
p  = 2**256 - 2**32 - 977
a  = 0,  b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A6855419 9C47D08FFB10D4B8  (concat, no space)
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
h  = 1
```
Mainnet P2PKH version byte `0x00`, testnet `0x6F`. WIF prefix main `0x80`, test `0xEF`.
Base58Check payload = `version || data`, checksum = first 4 bytes of `sha256(sha256(payload))`.

---

## 4. Test-vector strategy (correctness backbone)

Everything is validated against known-answer vectors so the Python and JS impls can't silently
diverge. Store as JSON in `tests/vectors/`. Minimum set:

- **Curve:** `G`, `2G`, `3G` coordinates; a known `k·G` (use Karpathy's worked example).
- **Hashes:** `sha256("")`, `sha256("abc")`, `ripemd160("")`, known double-SHA-256.
- **Keys/address:** a fixed private key → its WIF and P2PKH address (mainnet + testnet).
- **ECDSA:** fixed key + message + fixed nonce k → exact `(r, s)`; verify true/false cases.
- **Nonce reuse:** two messages signed with the *same* k → recovered private key matches.
- **BIP-39:** official test vector (entropy → mnemonic → seed) from the BIP-39 spec.
- **BIP-32:** official Test Vector 1 (seed → master xprv/xpub → `m/0'` child).
- **Script:** P2PKH spend evaluates to true; a wrong signature evaluates to false.
- **Tx:** a known raw tx serializes to the expected hex; sighash matches a reference.

CI is overkill for a demo repo; a `pytest` run that's green is the bar.

---

## 5. The eight demos

Accent colours are suggestions — pick a coherent 8-hue set on the landing page (extend chiron's
blue/amber/teal). Each demo: **what it shows · key interaction · visual · data source.**

### Layer 1 — Primitives (the Karpathy arc)

**1. Curve** — *accent: electric blue*
- Shows: secp256k1's group law made geometric; "private key = number, public key = point."
- Interaction: drag a scalar `k` (slider/odometer); watch `P = k·G` and the chord-and-tangent
  point-addition construction animate. Toggle: real-number curve (for geometric intuition) vs
  the finite-field scatter over a small prime (to show it's really discrete).
- Visual: the cubic curve, the add/double construction lines, the resulting point.
- Data: live JS (`btc.js`).

**2. Key → Address** — *accent: amber*
- Shows: the full pipeline priv(256-bit) → pubkey(point) → SHA-256 → RIPEMD-160 → +version →
  Base58Check address. Plus the WIF encoding of the private key.
- Interaction: type/randomise a private key; every downstream stage updates live. Flip a single
  bit on any intermediate and watch the **hash avalanche** ripple the address.
- Visual: a vertical pipeline of byte-blocks, each stage labelled, bytes coloured.
- Data: live JS.

**3. Sign & Forge** — *accent: red*
- Shows: ECDSA sign/verify, then the killer beat — **nonce reuse leaks the private key**
  (the PS3 / Android-wallet bug), recovered on screen.
- Interaction: sign a message → see `(r, s)`; verify (tamper the message → verify fails). Then
  "Forge" panel: sign two different messages with the *same* k, and watch the page algebraically
  recover the secret key: `k = (z1 - z2)/(s1 - s2)`, `d = (s1·k - z1)/r`.
- Visual: signature components; the recovery worked step by step.
- Data: live JS.

**4. Mine & Chain** — *accent: orange*
- Shows: double-SHA-256 proof-of-work and an immutable chain.
- Interaction: a live miner grinding the header nonce under an adjustable difficulty target,
  with a hashrate readout and leading-zero meter. Then a small chain of blocks linked by
  prev-hash: edit a transaction in block N and watch every subsequent block turn red (invalid)
  until you re-mine the cascade.
- Visual: spinning nonce + hash, target bar; a row of block cards with link arrows.
- Data: live JS (real header serialization; difficulty dialled down for snappy mining).

### Layer 2 — Systems (the differentiators)

**5. Network + 51% attack** — *accent: violet*
- Shows: emergent consensus — gossip, natural forks, reorgs — and why confirmations matter.
- Interaction: scrub/play a simulated run of N nodes mining (Poisson) and propagating blocks
  with latency; watch two blocks found at once create a fork that resolves to the longest/most-
  work chain, orphaning the loser. Then the **51% scenario**: an attacker mines a private chain,
  releases it, overtakes the public chain, and a payment that looked "confirmed" gets reversed.
  Slider for attacker hashpower → probability of a successful double-spend vs confirmations.
- Visual: a growing block-DAG/tree, coloured by miner; the attacker's hidden chain revealed.
- Data: **pre-baked JSON** from `export.py` (a few representative seeded runs). Core sim lives
  in `hermes/network.py`; web just plays it back.

**6. Testnet** — *accent: green*
- Shows: it's real. Construct, sign, serialize and **broadcast an actual Bitcoin testnet tx**.
- Interaction: the page narrates a captured real transaction — inputs (a funded UTXO), sighash,
  signature, raw hex — and links to it confirming on a public explorer (blockstream.info or
  mempool.space testnet). A "build your own" path documents the CLI flow.
- Visual: the raw-hex tx with fields annotated; the live explorer link / confirmation count.
- Data: produced by `hermes/cli.py`. **Requires the user** to fund a generated testnet address
  from a faucet before the real broadcast (one-time, when this stage is built).
- Broadcast API: `POST` raw hex to blockstream testnet `/api/tx` (fallback mempool.space).
  Input type: legacy P2PKH, `SIGHASH_ALL`.

**7. Script VM** — *accent: teal*
- Shows: Bitcoin Script is a tiny stack language; build the interpreter.
- Interaction: step a debugger through scripts — P2PKH
  (`OP_DUP OP_HASH160 <h> OP_EQUALVERIFY OP_CHECKSIG`), bare multisig (`OP_CHECKMULTISIG`),
  a hashlock (`OP_HASH160 <h> OP_EQUAL`), and a timelock (`OP_CHECKLOCKTIMEVERIFY`). Watch the
  stack push/pop per opcode; toggle a wrong input to see it fail.
- Visual: the script listing with a program counter; the live stack.
- Data: live JS (mirror of `hermes/script.py`).

**8. HD Wallet** — *accent: gold*
- Shows: real wallet machinery — one seed phrase → a whole tree of addresses.
- Interaction: enter/generate a 12-word BIP-39 mnemonic; watch mnemonic → seed (PBKDF2) →
  BIP-32 master key → derived child addresses along `m/44'/1'/0'/0/i` (testnet coin type).
  Reveal the tree node by node; change one word → entirely different tree.
- Visual: an unfolding derivation tree; addresses at the leaves.
- Data: live JS (BIP-39 wordlist bundled; mirror of `hermes/bip32.py`/`bip39.py`).

---

## 6. Build stages (ordered; each ends runnable/verifiable)

Each stage has a **Definition of Done (DoD)**. Tick the box when met.

- [x] **Stage 0 — Skeleton.** Created `projects/hermes/` with `hermes/` package, `tests/`,
      `pyproject.toml` (pytest `pythonpath=["."]`), `.gitignore`, README stub, `.venv` (pytest).
      Note: system Python is 3.14 + PEP-668 externally-managed, so we use a project `.venv`.
- [x] **Stage 1 — Crypto core.** `field`, `curve`, `sha256`, `ripemd160`, `base58`, `keys`,
      `ecdsa` built from scratch; `tests/test_core.py` has 12 passing vectors. DoD MET: green
      against SHA-256/RIPEMD-160 KATs (+50 random hashlib cross-checks), published 2G curve
      coords, Bitcoin-wiki address + WIF vectors, ECDSA sign/verify, and nonce-reuse recovery.
      Run: `cd projects/hermes && .venv/bin/python -m pytest -q`.
- [x] **Stage 2 — `btc.js`.** Ported the whole core to JS/BigInt in `web/shared/btc.js`
      (hashes via Uint32 ops, curve/keys/ecdsa via native BigInt). In-page harness
      `web/shared/test.html` runs the same vectors + 25 random SHA-256 cross-checks vs native
      `crypto.subtle`. DoD MET: **41/41 pass** in-browser, console clean. Served via launch
      config `hermes-web` (port 8011, `--directory hermes/web`) in `projects/.claude/launch.json`.
- [x] **Stage 3 — Primitive demos.** Landing page `web/index.html` (8 cards: 4 live + 4
      "coming soon") + the four demos, all self-contained on shared `web/shared/demo.css` +
      `demo.js` (hover popovers) + `btc.js`. DoD MET — verified in-browser, console clean:
      `curve/` (real-ℝ chord/tangent + finite-field k·G scatter over F223),
      `address/` (live pipeline + bit-flip avalanche; matches known WIF/address for the test key),
      `sign/` (ECDSA sign→valid, tamper→invalid, nonce-reuse recovers the exact private key),
      `mine/` (live PoW grinder + tamper-the-chain cascade). Accents per demo set on `:root`.
- [x] **Stage 4 — Script.** `hermes/script.py` (stack VM + opcodes) + `tests/test_script.py`
      (5 vectors). Added `PublicKey.parse` (SEC + modular sqrt) & `ecdsa.ser_sig/parse_sig`;
      mirrored `secDecode` in `btc.js`. `web/script/` is a step-debugger with 4 presets
      (P2PKH, 2-of-3 multisig, hashlock, CLTV) + a Tamper toggle. DoD MET — 17/17 pytest;
      all 4 presets valid + tampered-invalid in-browser, console clean. (Sigs are flat r‖s here,
      not DER — the real DER+sighash comes with tx.py in Stage 5/7.)
- [x] **Stage 5 — Tx + Network sim.** `hermes/tx.py` (Tx/TxIn/TxOut, txid, UTXO, conflict
      detection), `hermes/network.py` (`simulate_consensus` w/ forks+reorgs+lane layout;
      `simulate_51` race; `double_spend_probability` Monte-Carlo). `export.py` bakes
      `web/network/data/{consensus,probabilities}.json`. `web/network/` has two tabs: animated
      block-tree (forks/orphans/reorgs, dynamic longest-chain highlight) + the 51% double-spend
      (q & confirmations sliders, baked P readout, live race animation). DoD MET — 24/24 pytest;
      both tabs verified in-browser (reorgs show, P matches baked grid, reversal animates), console
      clean. Note: no `node.py` (folded into network.py); consensus baked from Python, race
      animated live in JS with P from the baked grid.
- [x] **Stage 6 — HD wallet.** From-scratch `sha512.py` (+ HMAC-SHA512, PBKDF2), `bip39.py`
      (mnemonic↔entropy↔seed; `hermes/english.txt` wordlist, sha256-verified), `bip32.py`
      (HDKey, CKD, xprv/xpub serialization). `tests/test_wallet.py` covers official BIP-39 + BIP-32
      Test Vector 1 (32/32 total). JS mirror `web/shared/wallet.js` (BigInt SHA-512, ~348ms
      PBKDF2); `web/wallet/` derivation-tree demo (generate 12/24, passphrase, mainnet/testnet).
      DoD MET — JS reproduces all vectors + canonical abandon…about address (fp 73c5da0a, addr
      1LqBGSKuX5y…); verified in-browser, console clean. Wordlist fetched at web/wallet/wordlist.txt.
- [x] **Stage 7 — Testnet. DONE — a real tx is on-chain.** txid
      `f3771bf9d0d33ab8849ad54fae75b83f876cd39cd6af1d23ec9555cd86c46e08` (confirmed, testnet,
      102507 sat self-send, 300 sat fee). `web/testnet/` narrates it from baked
      `web/testnet/data/tx.json` (13-field byte breakdown). Card live.
      *7a:* `hermes/transaction.py` (real wire-format Tx/TxIn/TxOut,
      varint, SIGHASH_ALL, sign/verify), DER in `ecdsa.py` (`der`/`parse_der`), `Script.raw_serialize`/
      `parse_raw`. `tests/test_transaction.py` proves it against a REAL on-chain legacy P2PKH tx
      (fba398fa…, block 955925) — our sighash+DER verify its live signature (37/37 pytest).
      `hermes/cli.py` (`new`/`info`/`send [--broadcast]`) + testnet API helpers (`fetch_utxos`,
      `broadcast`) via blockstream. *7b PENDING USER:* testnet address generated =
      `mnGLT42un82fQGtWpC7K6pppWcjSf2wpi6` (key in gitignored `.testnet-key.json`); **user funds it
      from a faucet**, then `python -m hermes.cli info` → `send <dest> --broadcast` (confirm tx
      first). *7c TODO:* `web/testnet/` narrates the captured txid (bake raw hex + field breakdown).
- [x] **Stage 8 — Polish & ship.** `web/og.png` (1200×630, rendered from an HTML card via headless
      Chrome). GitHub Pages enabled via Actions workflow `.github/workflows/pages.yml` deploying the
      `web/` folder (Pages build_type=workflow, since the repo is a hybrid Python+site). Live at
      https://mikebertin.github.io/hermes/. DoD: site loads on Pages; all 8 demos reachable.

Rough sequencing: Stages 1–3 are one natural chunk (the Karpathy arc, demoable). 4–6 are the
systems middle. 7–8 close it out. Expect ~3–5 sessions depending on depth.

---

## 7. Open questions / decisions log

- **Locked:** name = Hermes; flagship scope; all 8 demos; Python canonical + JS reimpl bridge;
  no Pyodide; pure self-contained web; GitHub Pages.
- **Open:** final 8-colour accent palette (decide on landing page). Whether to also do a Merkle/
  SPV mini-demo later (deferred — not in the 8). Whether to bundle the full 2048-word BIP-39
  list inline or fetch it (lean: inline, it's ~13KB).
- **Needs user action when reached:** Stage 7 faucet funding; possibly a real GitHub repo +
  Pages enablement at Stage 8.

## 8. Risks / watch-items

- **RIPEMD-160 from scratch** is fiddly — vectors first. (Acceptable fallback: note it's the one
  primitive Python's `hashlib` may expose via `new('ripemd160')`, but prefer from-scratch for the
  "from nothing" claim; keep hashlib as a cross-check oracle in tests.)
- **JS/Python divergence** — mitigated by shared vectors (§4); never ship a demo whose JS hasn't
  passed them.
- **Testnet flakiness** — faucets and broadcast APIs come and go; keep the captured txid static in
  the page so the demo survives even if the live build path rots.
- **Scope creep** — 8 demos is already a lot; resist adding more until shipped.

---

## 9. Progress Log

_Append a dated entry every session: what changed · what's next · new decisions._

- **2026-06-27** — Project scoped and locked through discussion (name, flagship ambition, all 8
  demos, architecture, bridge policy). This PLAN.md written.
- **2026-06-27** — **Stages 0 + 1 DONE.** Scaffolded repo and built the full from-scratch crypto
  core (`hermes/`: field, curve/secp256k1, sha256, ripemd160, base58, keys, ecdsa). 12/12
  vector tests pass via project `.venv`. Caught & fixed one bad fixture (had chained a privkey
  from the wiki's WIF example to a pubkey from its address example — not a real pair); re-anchored
  the curve on the published 2G coordinates. **Next: Stage 2** — port the core to JS/BigInt in
  `web/shared/btc.js` with an in-page assert harness against the same vectors, then Stage 3
  (the four primitive demos: curve, address, sign, mine).
- **2026-06-27** — **Stage 2 DONE.** `web/shared/btc.js` is the full JS/BigInt port (global
  `Hermes`); `web/shared/test.html` is the vector harness. 41/41 pass in-browser (incl. native
  `crypto.subtle` SHA-256 cross-checks), console clean. Added `hermes-web` launch config (port
  8011) to `projects/.claude/launch.json`. **Next: Stage 3** — the four primitive demos
  (curve → address → sign → mine) on `btc.js`, each a self-contained `web/<demo>/index.html` in
  chiron house style.
- **2026-06-27** — **Stage 3 DONE.** Landing page + all four primitive demos built and verified
  in-browser (console clean): `curve` (real chord/tangent + F223 k·G scatter), `address` (live
  HASH160→Base58Check pipeline + bit-flip avalanche), `sign` (ECDSA + nonce-reuse key recovery),
  `mine` (live PoW + tamper-the-chain). Shared chrome in `web/shared/demo.css` + `demo.js`
  (popovers). The Layer-1 / Karpathy arc is now demoable end-to-end. **Next: Stage 4** — the
  Script stack-VM (`hermes/script.py` + vectors, then `web/script/` step-debugger). NOTE on Stage
  4+: these need tx.py/script.py which don't exist yet — fresh build, Python-first then JS mirror.
- **2026-06-27** — Repo housekeeping: Hermes is now its own git repo, pushed to
  github.com/MikeBertin/hermes (now **public**). Landing-page footer companion links removed.
- **2026-06-27** — **Stage 4 DONE.** Script stack-VM: `hermes/script.py` + 5 vectors (17/17
  pytest); `web/script/` step-debugger with P2PKH / 2-of-3 multisig / hashlock / CLTV presets +
  Tamper toggle, verified in-browser (all valid + tampered-invalid, console clean). Added
  `PublicKey.parse`, `ecdsa.ser_sig/parse_sig`, and `secDecode` in btc.js. Script card now live on
  the landing page. **Next: Stage 5** — Tx + Network sim (`tx.py`, `node.py`, `network.py`,
  `export.py` baking JSON runs) → `web/network/` with the 51% double-spend. This is the heaviest
  stage; build tx serialization first, then the sim, then bake representative runs for the web.
- **2026-06-27** — **Stage 5 DONE.** `tx.py` + `network.py` + `export.py`; `web/network/` with the
  forks/reorgs tree and the 51% double-spend (live race + baked Python probability grid). 24/24
  pytest; verified in-browser, console clean. Network card live on the landing page. **Next:
  Stage 6 — HD Wallet** (BIP-39/32). Needs a from-scratch **SHA-512** (for HMAC-SHA512 + PBKDF2)
  which we don't have yet — build sha512.py first, then bip39.py/bip32.py against the official BIP
  test vectors, then `web/wallet/` (mnemonic → seed → derivation tree). Bundle the 2048-word list
  inline (~13KB).
- **2026-06-27** — **Stage 6 DONE.** From-scratch SHA-512/HMAC/PBKDF2 + BIP-39 + BIP-32
  (`hermes/sha512.py`, `bip39.py`, `bip32.py`, `hermes/english.txt`). 32/32 pytest vs official
  BIP-39/BIP-32 vectors. JS mirror `web/shared/wallet.js` (BigInt SHA-512), `web/wallet/`
  derivation-tree demo — verified in-browser (matches canonical abandon…about fp 73c5da0a / addr
  1LqBGSKuX5y…), console clean. Wallet card live. **Next: Stage 7 — Real Testnet** (capstone).
  Needs real DER signatures + a legacy P2PKH tx serializer + SIGHASH_ALL (extend `tx.py`),
  `cli.py` to build/sign/broadcast, a faucet-funded testnet addr (**USER ACTION**: generate, user
  funds), broadcast via blockstream/mempool.space testnet API, then `web/testnet/` narrating the
  captured txid. Then Stage 8 polish/ship (og.png, GitHub Pages).
- **2026-06-29** — **Stage 7a DONE.** Real tx engine: `hermes/transaction.py` (wire serialization,
  SIGHASH_ALL, sign/verify), DER (`ecdsa.der`/`parse_der`), `Script.raw_serialize`/`parse_raw`.
  Verified OFFLINE against a real mainnet legacy-P2PKH tx fetched from blockstream (fba398fa…) —
  our sighash+DER verify its on-chain signature. 37/37 pytest. `cli.py` + testnet fetch/broadcast
  helpers built. (Note: caught a transcription typo in my first hardcoded reference tx → switched
  to a live-fetched, code-verified fixture.) **7b PENDING USER FUNDING:** addr
  `mnGLT42un82fQGtWpC7K6pppWcjSf2wpi6`. Next: user funds via faucet → `cli.py info` → build+confirm
  +broadcast → capture txid → build `web/testnet/` (7c).
- **2026-06-29** — **Stage 7 COMPLETE.** User funded the testnet address; built+signed a self-send,
  user confirmed, broadcast via blockstream — **accepted & confirmed on-chain**: txid
  `f3771bf9…c46e08`. Baked `web/testnet/data/tx.json` (13-field byte breakdown) and built
  `web/testnet/` narrating the real tx (annotated raw hex, explorer link). All 8 demo cards now
  live. 37/37 pytest. **ONLY Stage 8 left — polish & ship:** og.png (1200×630 social card), then
  GitHub Pages (serve `web/` — repo is already public). Optionally add sibling cross-links.
- **2026-06-29** — **Stage 8 DONE — PROJECT COMPLETE & SHIPPED.** Made `web/og.png` (1200×630 via
  headless Chrome from an HTML card). Enabled GitHub Pages via Actions workflow
  (`.github/workflows/pages.yml`, build_type=workflow) deploying `web/`. Live at
  https://mikebertin.github.io/hermes/. All 8 stages done; flagship shipped. (Siblings serve Pages
  from main-root legacy; Hermes uses a workflow since it's a Python+site hybrid.)
- **2026-06-30** — **README refreshed to shipped state.** Replaced the stale "🚧 work in progress /
  demos coming" framing with the live Pages link + on-chain testnet proof link, added the 8-demo
  table (Plutus-style), the `cli.py` testnet usage, and a local-run section. Docs now match reality;
  no code change. (Remaining items are all optional — see HANDOFF.md menu: RFC 6979, SegWit, Merkle/
  SPV, Taproot, Lightning.)
- **2026-06-30** — **RFC 6979 deterministic nonces DONE** (post-ship enhancement #2). Added
  `hmac_sha256` (sha256.py) and `ecdsa.rfc6979_k`; `sign()` now derives `k` deterministically by
  default, so signing is reproducible (same tx → same txid) — removes the random-nonce caveat and is
  what real wallets do. Mirrored in `web/shared/btc.js` (`hmacSha256`/`rfc6979K`). Verified against
  the canonical secp256k1 + SHA-256 vector (message "sample", k=a6e3c57d…), cross-checked our
  from-scratch HMAC vs stdlib over random inputs: **40/40 pytest, 45/45 in-browser, console clean.**
  Added project-local `.claude/launch.json` (serves `web/` on 8011) so the preview tool works from
  the hermes root. **Next on the Sovereign-aligned arc: SegWit (P2WPKH + bech32 + BIP-143)** →
  then 2-of-3 multisig custody. (RFC 6979 was the warm-up; SegWit is the real bridge to how modern
  custody — the thing Sovereign sets up in Phase 1 — actually works.)
- **2026-06-30** — **SegWit DONE** (post-ship enhancement #3, the Sovereign-aligned bridge).
  New `hermes/bech32.py` (BIP-173 bech32 + BIP-350 bech32m: encode/decode/convertbits + segwit
  address validation). `PublicKey.p2wpkh_address` (native `bc1…`/`tb1…`). `transaction.py` gained
  the BIP-143 segwit sighash (`sig_hash_bip143`, commits to the spent amount), per-input witness
  fields, marker/flag serialization (txid still hashes the legacy form), and `sign_input_p2wpkh`/
  `verify_input_p2wpkh`. `address_to_script` routes base58↔bech32 so `cli.py send` now pays
  `bc1…`/`tb1…`. JS mirror in `btc.js` (`encodeSegwit`/`p2wpkhAddress` + bech32 machinery); the
  `address/` demo shows the `bc1…` form beside the legacy address. **Validation:** reproduces the
  **BIP-143 worked example byte-for-byte** (parsed its unsigned tx → our sighash + RFC 6979 + DER +
  low-s == its published sigHash *and* witness signature), plus BIP-173/350 address vectors.
  **46/46 pytest, 48/48 in-browser, console clean.** **Next: 2-of-3 P2WSH multisig custody demo** —
  the direct "this is what Sovereign's Phase-1 custody actually is" card (builds on this SegWit work;
  P2WSH = the witness-script form of multisig that Unchained/Sparrow use).
- **2026-06-30** — **2-of-3 multisig custody DONE — a 9th demo card shipped** (enhancement #4, the
  Sovereign-aligned capstone). `transaction.py`: `multisig_script` (OP_m … OP_n CHECKMULTISIG),
  `p2wsh_script`/`p2wsh_address` (bech32 of SHA-256(witnessScript)), `sign_input_p2wsh_multisig`/
  `verify_input_p2wsh_multisig` (BIP-143 scriptCode = the witnessScript; witness = empty + m sigs +
  script). JS mirror in `btc.js`: `multisigScript`, `p2wshAddress`, and a compact `sigHashBip143`
  for the demo's real spend. **New `web/multisig/` card** ("Multisig Vault", accent #ef88c8): three
  cosigners → one P2WSH `bc1q…` address, an adjustable m-of-3 policy, and a "who signs the
  withdrawal" panel that runs the real threshold (any 2 of 3 release; the broadcast witness carries
  exactly m sigs). Landing page now 9 cards; README updated (8→9, 52 vectors). **Validation:** anchored
  to a **real on-chain native-P2WSH 2-of-3 tx** (txid 440fe853…, libbitcoin example) — our BIP-143
  sighash verifies its on-chain witness signatures; plus self-built threshold/ordering/roundtrip
  tests. **52/52 pytest, 51/51 in-browser, console clean.** Framing kept generic (a "why treasuries
  custody this way" note), no private project named. **The post-ship arc (RFC 6979 → SegWit →
  multisig) is complete.** Remaining menu options: Merkle/SPV, Taproot/Schnorr, Lightning.
- **2026-06-30** — **Merkle trees + SPV DONE — a 10th demo card shipped** (enhancement #5). New
  `hermes/merkle.py`: `merkle_root`/`merkle_levels` (Bitcoin odd-duplication), `merkle_proof`/
  `verify_merkle_proof` (O(log n) inclusion proof), `root_from_txids` (display↔internal byte order).
  JS mirror in `btc.js` (`merkleRoot`/`merkleProof`/`merkleLevels`/`verifyMerkleProof`). **New
  `web/merkle/` card** ("Merkle Proofs", accent #4dc9e6): an SVG tree over an adjustable 5–8-tx
  block; click a tx to light up its proof path (selected→cyan, siblings→amber, computed-up→pink),
  with a tamper toggle and a proof-of-reserves note. Landing page now 10 cards; README updated.
  **Validation:** anchored to **real Bitcoin block 100000's merkle root** (4 txs → header root
  f3e94742…), + proof/tamper/odd-duplication/single-leaf tests. **57/57 pytest, 53/53 in-browser,
  console clean.** Remaining optional menu: Taproot/Schnorr, Lightning.
- **2026-07-02** — **Review hardening: rejection paths (Python + JS) + negative tests.** Fixed three
  review-found bugs: `address_to_script` silently paid P2SH addresses as P2PKH (now validates the
  version byte + optional network check, CLI passes testnet); `bip39` accepted 6-word mnemonics /
  crashed on other bad word counts (now requires 12/15/18/21/24); `verify_input_p2wsh_multisig` was
  laxer than consensus (now OP_CHECKMULTISIG-strict: exactly m sigs, each consumes a key in order,
  NULLDUMMY enforced). Plus: Script-VM stack underflow returns False (was IndexError), b58decode
  raises ValueError on bad chars, BIP-32 invalid-child guard (Python + JS), JS `encodeVarint` 4-byte
  guard, JS `sign()` r/s zero guards. New `tests/test_negative.py` (32 cases). **89/89 pytest,
  53/53 in-browser.**
- **2026-07-02** — **Taproot & Schnorr DONE — an 11th demo card shipped** (enhancement #6, the big
  one: a from-scratch signature scheme). New `hermes/schnorr.py` (BIP-340: `tagged_hash`, `lift_x`,
  x-only `pubkey_gen`, deterministic-nonce `sign`, `verify`) and `hermes/taproot.py` (BIP-341 key
  path: `tap_tweak`, `output_key` Q = P + t·G, `p2tr_address` via the existing bech32m encoder,
  `tweak_secret` for key-path spends). JS mirror in `btc.js` (`taggedHash`/`liftX`/`schnorrPubkey`/
  `schnorrSign`/`schnorrVerify`/`tapTweak`/`taprootOutputKey`/`p2trAddress`/`taprootTweakSecret`).
  **New `web/taproot/` card** ("Taproot & Schnorr", accent #f7a14b): Schnorr sign/verify with the
  ECDSA-vs-Schnorr equation contrast, a "signatures add" key-aggregation demo (two cosigners → one
  joint key → one 64-byte sig; the MuSig doorway), and the live TapTweak pipeline P.x → t → Q.x →
  `bc1p…`. Landing page now 11 cards; README + og.png refreshed. **Validation:** the complete
  official **BIP-340 test-vector CSV** (all 19 rows: signing byte-for-byte incl. the 2022-12
  variable-length messages, and every must-fail verification row), the **BIP-341 wallet vector**
  (internal → tweak → output key → bc1p address), and **BIP-86** end-to-end (standard mnemonic →
  our BIP-39/32 stack at m/86'/0'/0'/0/0 → published internal/output keys and address), plus a
  tweaked-secret key-path-spend roundtrip. **124/124 pytest, 62/62 in-browser, console clean.**
  Remaining optional menu: MuSig2 aggregation, Lightning/HTLC.
- **2026-07-03** — **MuSig2 DONE — a 12th demo card shipped** (enhancement #7, the payoff of the
  Taproot card's "signatures add" tease). New `hermes/musig.py` (BIP-327 complete minus adaptor
  sigs + deterministic signing, per scope): KeyAgg with rogue-key-killing coefficients (2nd-key=1
  rule), plain/x-only tweaking with gacc/tacc accumulators, two-nonce generation (`nonce_gen` +
  vector-testable `nonce_gen_internal`), nonce aggregation, `partial_sign` (secnonce zeroized in
  place — reuse raises), `partial_sig_verify` (accountability: names the culprit via
  `InvalidContributionError`), `partial_sig_agg` → a plain BIP-340 sig `schnorr.verify` accepts.
  Official vectors committed verbatim in `tests/vectors/bip327/*.json` (a new convention — first
  JSON-file vectors; earlier suites inline them) and driven by `tests/test_musig.py` (52 tests:
  all six vector files incl. every error case with exact messages/blame, + e2e ceremonies — one
  behind a real TapTweak whose aggregate == `taproot.output_key`). JS mirror in `btc.js`
  (`musig*` functions) + 14 new harness checks in `test.html`. **New `web/musig/` card**
  ("MuSig2", accent #a8d94b lime): 3 cosigners → KeyAgg → one `bc1p…` address, a staged
  round-1/round-2/combine ceremony UI, a "corrupt Carol's share" accountability beat, and the
  64 B vs 253 B receipt comparison vs demo 9. Landing page now 12 cards ("Twelve", `.c12`);
  README table + counts refreshed; og.png re-rendered (pills compacted to keep two rows).
  **176/176 pytest, 76/76 in-browser, console clean.** Remaining optional menu: Lightning/HTLC,
  FROST (threshold Schnorr), polish (README GIF, sibling cross-links).
- **2026-07-03** — **Lightning DONE — a 13th demo card shipped** (enhancement #8, the first Layer-2
  card). Scope (user-chosen): the **payment channel + revocation/penalty** mechanism with **real
  BOLT-3 scripts**, no in-flight HTLCs (HTLC routing is the deliberately-unbuilt other half).
  **Script-VM prerequisite:** added `OP_IF`/`OP_NOTIF`/`OP_ELSE`/`OP_ENDIF` (branch-exec stack) +
  `OP_CHECKSEQUENCEVERIFY` to `hermes/script.py` `evaluate()` (new `sequence` param) *and* the inline
  JS VM in `web/script/index.html` — which gained a 5th "Lightning to_local" preset (honest delayed
  path valid; spend-before-delay rejected by CSV). New `hermes/lightning.py`: sorted 2-of-2
  `funding_script`, BOLT-3 `derive_pubkey`/`derive_privkey`, the blinded `derive_revocation_pubkey`/
  `derive_revocation_privkey` (assemblable only from BOTH secrets), `per_commitment_secret`
  (Appendix D generate_from_seed), `to_local_script` (OP_IF rev / OP_ELSE CSV+DROP delayed), and
  `commitment_tx`/`penalty_tx`/`sign_*` (BIP-143 P2WSH). **Validation:** byte-for-byte **BOLT-3
  Appendix E** (key + revocation derivation) and **Appendix D** (secret generation) vectors, a full
  lifecycle test (open→update→revoke→cheat→penalty sweep verified through our own Script VM's IF/CSV
  branches), and CSV-immature / wrong-key negatives. JS mirror in `btc.js` (`ln*` family) + 14 new
  `test.html` checks against the same Appendix D/E vectors. **New `web/lightning/` card**
  ("Lightning Channels", accent #ffd400 electric-yellow, first `--lightning`/`.c13`): open a 2-of-2
  channel, pay off-chain (each payment mints a commitment + reveals the revoked state's secret), a
  revoked-state ledger with a "Bob broadcasts" penalty beat (Alice assembles the revocation key,
  sweeps 100%, real penalty-tx signature verified), and a cooperative-close path. Landing now 13
  cards ("Thirteen", Layer-2 tag); README table + counts; og.png re-rendered (pills compacted +
  trimmed to keep two rows: 13 pills, "testnet tx"/"Taproot"). **188/188 pytest, 90/90 in-browser,
  console clean.** Remaining optional menu: Lightning **HTLC routing** across hops (the sequel),
  FROST (threshold Schnorr), polish (README GIF, sibling cross-links).
- **2026-07-03** — **HTLC routing DONE — a 14th demo card shipped** (enhancement #9, the sequel to
  demo 13's channel half — the *routing* half of Lightning). **Script-VM prerequisite:** added the
  last two opcodes BOLT-3 HTLC scripts need — `OP_SWAP` + `OP_SIZE` — to `hermes/script.py` and the
  inline JS VM. `hermes/lightning.py` gained the real BOLT-3 `htlc_offered_script` +
  `htlc_received_script` (revocation / preimage / timeout branches, using OP_SIZE-32 to pick the
  preimage-vs-timeout path), a canonical `htlc_script` (hashlock-or-timeout — the logical contract a
  hop enforces, which the card walks through), and `payment_hash`. **Validation:** the offered and
  received HTLC witnessScripts match **BOLT-3 Appendix C byte-for-byte** (htlc #2 offered, htlc #0
  received incl. the RIPEMD160(payment_hash) precursors), plus a multi-hop routing test (one preimage
  settles Alice→Bob→Carol, both hops claimed through the Script VM; wrong preimage / wrong signer
  fail; timeout refund respects CLTV; the cltv_AB > cltv_BC invariant). JS mirror (`lnHtlc*` in
  `btc.js`) + 2 test.html checks anchoring the same Appendix C script hex. **New `web/routing/` card**
  ("HTLC Routing", accent #2dd4bf teal, `--routing`/`.c14`): a 3-node A→B→C route, invoice→lock→
  settle (the preimage revealed and flowing backward, real hashlock + signature verification) with a
  "Carol never reveals" timeout path showing every sender refunded. Landing now 14 cards
  ("Fourteen", two Layer-2 cards), README table + counts, og.png re-rendered (14 pills, 7+7).
  **194/194 pytest, 92/92 in-browser, console clean.** Remaining optional menu: FROST (threshold
  Schnorr), polish (README GIF, sibling cross-links).
