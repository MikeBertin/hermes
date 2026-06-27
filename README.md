# Hermes

**Bitcoin from first principles.**
*Keys, signatures, and proof of work — built from nothing.*

A from-scratch Bitcoin implementation (in the spirit of Karpathy's *"A from-scratch tour
of Bitcoin in Python"*) turned into a suite of interactive browser visualisations. No crypto
libraries: the secp256k1 curve, SHA-256, RIPEMD-160, Base58Check, ECDSA — all by hand.

🔒 *Private while in progress — not yet published.* See [PLAN.md](PLAN.md) for the full build plan.

Companion to [Chiron](https://mikebertin.github.io/chiron/) (computational physics),
[Empedocles](https://mikebertin.github.io/empedocles/) (evolutionary algorithms), and
**Plutus** (quantitative finance).

## Why "Hermes"

Hermes was the Greek god of commerce *and* of boundaries, messages, and secrets — whence
*hermetic*, "sealed". Money, cryptography, and signed messages are his exact portfolio.

## The Python core

A canonical, readable, dependency-free implementation lives in [`hermes/`](hermes/). It is the
source of truth the browser demos visualise.

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest        # runs the known-answer vector suite
```

## The demos *(coming — see PLAN.md)*

Eight interactive, self-contained web demos in `web/`, from the elliptic curve through to a
real testnet transaction. Run locally with `cd web && python3 -m http.server`.
