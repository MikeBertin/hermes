// Hermes — Bitcoin from scratch, in the browser.
//
// A self-contained JS/BigInt re-implementation of the canonical Python core in
// hermes/. No dependencies. It MUST agree with the Python on every known-answer
// vector (see shared/test.html and tests/test_core.py) — when in doubt, Python
// wins. Exposes a single global `Hermes`.
(function () {
  "use strict";

  // --- byte helpers ----------------------------------------------------------
  const _enc = new TextEncoder();
  const utf8 = (s) => _enc.encode(s);
  const hexToBytes = (h) => {
    const a = new Uint8Array(h.length / 2);
    for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
    return a;
  };
  const bytesToHex = (b) =>
    Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const bytesToBigInt = (b) => {
    let n = 0n;
    for (const x of b) n = (n << 8n) | BigInt(x);
    return n;
  };
  const bigIntToBytes = (v, len) => {
    const o = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) {
      o[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return o;
  };
  const concatBytes = (...arrs) => {
    let len = 0;
    for (const a of arrs) len += a.length;
    const o = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) {
      o.set(a, off);
      off += a.length;
    }
    return o;
  };

  // --- SHA-256 ---------------------------------------------------------------
  const _SHA_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const _rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

  function _pad(msg, lengthLittleEndian) {
    const ml = msg.length;
    const padLen = ((56 - ((ml + 1) % 64)) + 64) % 64;
    const total = ml + 1 + padLen + 8;
    const m = new Uint8Array(total);
    m.set(msg, 0);
    m[ml] = 0x80;
    new DataView(m.buffer).setBigUint64(
      total - 8,
      BigInt(ml) * 8n,
      lengthLittleEndian
    );
    return m;
  }

  function sha256(msg) {
    const m = _pad(msg, false);
    const dv = new DataView(m.buffer);
    const H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
      0x1f83d9ab, 0x5be0cd19,
    ]);
    const w = new Uint32Array(64);
    for (let off = 0; off < m.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3];
      let e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + _SHA_K[i] + w[i]) >>> 0;
        const S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i], false);
    return out;
  }
  const doubleSha256 = (m) => sha256(sha256(m));

  // --- RIPEMD-160 ------------------------------------------------------------
  const _RL = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
  ];
  const _RR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
  ];
  const _SL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
  ];
  const _SR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
  ];
  const _KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const _KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  const _rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  function _f(j, x, y, z) {
    if (j < 16) return (x ^ y ^ z) >>> 0;
    if (j < 32) return ((x & y) | (~x & z)) >>> 0;
    if (j < 48) return ((x | ~y) ^ z) >>> 0;
    if (j < 64) return ((x & z) | (y & ~z)) >>> 0;
    return (x ^ (y | ~z)) >>> 0;
  }

  function ripemd160(msg) {
    const m = _pad(msg, true);
    const dv = new DataView(m.buffer);
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe,
      h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const x = new Uint32Array(16);
    for (let off = 0; off < m.length; off += 64) {
      for (let i = 0; i < 16; i++) x[i] = dv.getUint32(off + i * 4, true);
      let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
      let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
      for (let j = 0; j < 80; j++) {
        const rnd = (j / 16) | 0;
        let t = (_rotl((al + _f(j, bl, cl, dl) + x[_RL[j]] + _KL[rnd]) >>> 0, _SL[j]) + el) >>> 0;
        al = el; el = dl; dl = _rotl(cl, 10); cl = bl; bl = t;
        t = (_rotl((ar + _f(79 - j, br, cr, dr) + x[_RR[j]] + _KR[rnd]) >>> 0, _SR[j]) + er) >>> 0;
        ar = er; er = dr; dr = _rotl(cr, 10); cr = br; br = t;
      }
      const t = (h1 + cl + dr) >>> 0;
      h1 = (h2 + dl + er) >>> 0;
      h2 = (h3 + el + ar) >>> 0;
      h3 = (h4 + al + br) >>> 0;
      h4 = (h0 + bl + cr) >>> 0;
      h0 = t;
    }
    const out = new Uint8Array(20);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, h0, true); odv.setUint32(4, h1, true);
    odv.setUint32(8, h2, true); odv.setUint32(12, h3, true);
    odv.setUint32(16, h4, true);
    return out;
  }
  const hash160 = (b) => ripemd160(sha256(b));

  // --- Base58 / Base58Check --------------------------------------------------
  const _ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const _B58 = {};
  for (let i = 0; i < _ALPHABET.length; i++) _B58[_ALPHABET[i]] = i;

  function b58encode(bytes) {
    let n = bytesToBigInt(bytes);
    let out = "";
    while (n > 0n) {
      const r = n % 58n;
      out = _ALPHABET[Number(r)] + out;
      n /= 58n;
    }
    let pad = 0;
    for (const b of bytes) {
      if (b === 0) pad++;
      else break;
    }
    return "1".repeat(pad) + out;
  }
  function b58decode(str) {
    let n = 0n;
    for (const ch of str) n = n * 58n + BigInt(_B58[ch]);
    const body = [];
    while (n > 0n) {
      body.unshift(Number(n & 0xffn));
      n >>= 8n;
    }
    let pad = 0;
    for (const ch of str) {
      if (ch === "1") pad++;
      else break;
    }
    return concatBytes(new Uint8Array(pad), Uint8Array.from(body));
  }
  function b58checkEncode(payload) {
    const checksum = doubleSha256(payload).slice(0, 4);
    return b58encode(concatBytes(payload, checksum));
  }
  function b58checkDecode(str) {
    const raw = b58decode(str);
    const payload = raw.slice(0, -4);
    const checksum = raw.slice(-4);
    if (bytesToHex(doubleSha256(payload).slice(0, 4)) !== bytesToHex(checksum))
      throw new Error("bad Base58Check checksum");
    return payload;
  }

  // --- secp256k1 -------------------------------------------------------------
  const P = 2n ** 256n - 2n ** 32n - 977n;
  const A = 0n;
  const B = 7n;
  const N =
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const Gx =
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const Gy =
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
  const G = { x: Gx, y: Gy };
  const INFINITY = null;

  const mod = (a, m) => ((a % m) + m) % m;
  function modPow(b, e, m) {
    b = mod(b, m);
    let r = 1n;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % m;
      b = (b * b) % m;
      e >>= 1n;
    }
    return r;
  }
  const modInv = (a, m) => modPow(a, m - 2n, m); // m must be prime (P or N)

  function ptDouble(p) {
    if (!p) return null;
    if (p.y === 0n) return null;
    const s = mod((3n * p.x * p.x + A) * modInv(2n * p.y, P), P);
    const x = mod(s * s - 2n * p.x, P);
    const y = mod(s * (p.x - x) - p.y, P);
    return { x, y };
  }
  function ptAdd(p, q) {
    if (!p) return q;
    if (!q) return p;
    if (p.x === q.x && p.y !== q.y) return null; // vertical -> infinity
    if (p.x === q.x && p.y === q.y) return ptDouble(p);
    const s = mod((q.y - p.y) * modInv(mod(q.x - p.x, P), P), P);
    const x = mod(s * s - p.x - q.x, P);
    const y = mod(s * (p.x - x) - p.y, P);
    return { x, y };
  }
  function ptMul(k, p) {
    k = mod(k, N);
    let r = null;
    let c = p;
    while (k > 0n) {
      if (k & 1n) r = ptAdd(r, c);
      c = ptDouble(c);
      k >>= 1n;
    }
    return r;
  }

  // --- keys / addresses ------------------------------------------------------
  const pubFromSecret = (secret) => ptMul(secret, G);
  function sec(point, compressed = true) {
    const x = bigIntToBytes(point.x, 32);
    if (!compressed)
      return concatBytes(Uint8Array.of(0x04), x, bigIntToBytes(point.y, 32));
    const prefix = point.y % 2n === 0n ? 0x02 : 0x03;
    return concatBytes(Uint8Array.of(prefix), x);
  }
  // recover a point from its SEC bytes (compressed needs a modular sqrt; the
  // field prime is ≡ 3 mod 4, so the root is a single exponentiation)
  function secDecode(b) {
    if (b[0] === 4)
      return { x: bytesToBigInt(b.slice(1, 33)), y: bytesToBigInt(b.slice(33, 65)) };
    const x = bytesToBigInt(b.slice(1, 33));
    const alpha = mod(x * x * x + B, P);
    const beta = modPow(alpha, (P + 1n) / 4n, P);
    const evenBeta = beta % 2n === 0n ? beta : P - beta;
    return { x, y: b[0] === 2 ? evenBeta : P - evenBeta };
  }
  function address(point, compressed = true, testnet = false) {
    const version = Uint8Array.of(testnet ? 0x6f : 0x00);
    return b58checkEncode(concatBytes(version, hash160(sec(point, compressed))));
  }
  function wif(secret, compressed = true, testnet = false) {
    let payload = concatBytes(
      Uint8Array.of(testnet ? 0xef : 0x80),
      bigIntToBytes(secret, 32)
    );
    if (compressed) payload = concatBytes(payload, Uint8Array.of(0x01));
    return b58checkEncode(payload);
  }

  // --- bech32 / native SegWit addresses (BIP-173 / BIP-350) ------------------
  const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  function bech32Polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
  }
  function bech32HrpExpand(hrp) {
    const hi = [], lo = [];
    for (const c of hrp) { hi.push(c.charCodeAt(0) >> 5); lo.push(c.charCodeAt(0) & 31); }
    return hi.concat([0], lo);
  }
  function bech32Checksum(hrp, data, spec) {
    const C = spec === "bech32m" ? 0x2bc830a3 : 1;
    const mod = bech32Polymod(bech32HrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0])) ^ C;
    const ret = [];
    for (let i = 0; i < 6; i++) ret.push((mod >> (5 * (5 - i))) & 31);
    return ret;
  }
  function bech32Encode(hrp, data, spec) {
    const combined = data.concat(bech32Checksum(hrp, data, spec));
    return hrp + "1" + combined.map((d) => BECH32_CHARSET[d]).join("");
  }
  // regroup an 8-bit byte array into 5-bit groups (or back), per BIP-173
  function convertBits(data, fromBits, toBits, pad) {
    let acc = 0, bits = 0;
    const ret = [], maxv = (1 << toBits) - 1, maxAcc = (1 << (fromBits + toBits - 1)) - 1;
    for (const value of data) {
      if (value < 0 || value >> fromBits) return null;
      acc = ((acc << fromBits) | value) & maxAcc;
      bits += fromBits;
      while (bits >= toBits) { bits -= toBits; ret.push((acc >> bits) & maxv); }
    }
    if (pad) { if (bits) ret.push((acc << (toBits - bits)) & maxv); }
    else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) return null;
    return ret;
  }
  function encodeSegwit(hrp, witver, witprog) {
    const spec = witver === 0 ? "bech32" : "bech32m";
    return bech32Encode(hrp, [witver].concat(convertBits(Array.from(witprog), 8, 5, true)), spec);
  }
  // native SegWit P2WPKH address (always from the compressed pubkey)
  function p2wpkhAddress(point, testnet = false) {
    return encodeSegwit(testnet ? "tb" : "bc", 0, hash160(sec(point, true)));
  }

  // --- P2WSH multisig (the witness-script form treasuries use) ---------------
  function encodeVarint(i) {
    if (i > 0xffffffff) throw new Error("varint > 4 bytes not supported here"); // 32-bit shifts below
    if (i < 0xfd) return Uint8Array.of(i);
    if (i <= 0xffff) return Uint8Array.of(0xfd, i & 0xff, i >> 8);
    return Uint8Array.of(0xfe, i & 0xff, (i >> 8) & 0xff, (i >> 16) & 0xff, (i >> 24) & 0xff);
  }
  // push a data item the way Script does (length byte, then bytes; <76 only here)
  function pushData(b) { return concatBytes(Uint8Array.of(b.length), b); }
  // m-of-n witnessScript: OP_m <pub1..pubn> OP_n OP_CHECKMULTISIG
  function multisigScript(m, points) {
    const parts = [Uint8Array.of(0x50 + m)];
    for (const p of points) parts.push(pushData(sec(p, true)));
    parts.push(Uint8Array.of(0x50 + points.length), Uint8Array.of(0xae)); // OP_n, OP_CHECKMULTISIG
    return concatBytes(...parts);
  }
  function p2wshAddress(witnessScript, testnet = false) {
    return encodeSegwit(testnet ? "tb" : "bc", 0, sha256(witnessScript));
  }
  // u64 little-endian (amounts / values), via two 32-bit halves to dodge BigInt-bit ops
  function u64le(n) {
    const b = new Uint8Array(8);
    let v = BigInt(n);
    for (let i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
    return b;
  }
  function u32le(n) { return Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff); }
  // BIP-143 SIGHASH_ALL digest for a single-input witness spend (what the demo signs).
  // prevout = {txid: hex, index, sequence}, output = {amount, scriptPubKey: bytes}
  function sigHashBip143(prevout, scriptCode, amount, output, version = 2, locktime = 0) {
    const txidLE = hexToBytes(prevout.txid).reverse();
    const outpoint = concatBytes(txidLE, u32le(prevout.index));
    const hashPrevouts = doubleSha256(outpoint);
    const hashSequence = doubleSha256(u32le(prevout.sequence));
    const out = concatBytes(u64le(output.amount), encodeVarint(output.scriptPubKey.length), output.scriptPubKey);
    const hashOutputs = doubleSha256(out);
    const preimage = concatBytes(
      u32le(version), hashPrevouts, hashSequence, outpoint,
      encodeVarint(scriptCode.length), scriptCode,
      u64le(amount), u32le(prevout.sequence), hashOutputs, u32le(locktime),
      u32le(1) // SIGHASH_ALL
    );
    return bytesToBigInt(doubleSha256(preimage));
  }

  // --- ECDSA -----------------------------------------------------------------
  function randScalar() {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    return (mod(bytesToBigInt(b), N - 1n)) + 1n;
  }
  // HMAC-SHA256 (RFC 2104), built on the from-scratch sha256 above.
  function hmacSha256(key, msg) {
    if (key.length > 64) key = sha256(key);
    const k = new Uint8Array(64);
    k.set(key);
    const ipad = new Uint8Array(64), opad = new Uint8Array(64);
    for (let i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    return sha256(concatBytes(opad, sha256(concatBytes(ipad, msg))));
  }
  // RFC 6979: derive the signing nonce deterministically from (secret, z) so a
  // signature is reproducible and no RNG can leak the key via a repeated nonce.
  function rfc6979K(secret, z) {
    const x = bigIntToBytes(secret, 32);
    const h1 = bigIntToBytes(mod(z, N), 32);
    let v = new Uint8Array(32).fill(1);
    let k = new Uint8Array(32).fill(0);
    k = hmacSha256(k, concatBytes(v, Uint8Array.of(0x00), x, h1));
    v = hmacSha256(k, v);
    k = hmacSha256(k, concatBytes(v, Uint8Array.of(0x01), x, h1));
    v = hmacSha256(k, v);
    while (true) {
      v = hmacSha256(k, v);
      const cand = bytesToBigInt(v);
      if (cand >= 1n && cand < N) return cand;
      k = hmacSha256(k, concatBytes(v, Uint8Array.of(0x00)));
      v = hmacSha256(k, v);
    }
  }
  function sign(secret, z, k = null, lowS = true) {
    if (k === null) k = rfc6979K(secret, z);
    const r = mod(ptMul(k, G).x, N);
    if (r === 0n) throw new Error("bad nonce produced r == 0; choose another k");
    let s = mod(modInv(k, N) * (z + r * secret), N);
    if (s === 0n) throw new Error("bad nonce produced s == 0; choose another k");
    if (lowS && s > N / 2n) s = N - s;
    return { r, s };
  }
  function verify(point, z, sig) {
    if (!(sig.r >= 1n && sig.r < N && sig.s >= 1n && sig.s < N)) return false;
    const sInv = modInv(sig.s, N);
    const u = mod(z * sInv, N);
    const v = mod(sig.r * sInv, N);
    const R = ptAdd(ptMul(u, G), ptMul(v, point));
    return R !== null && mod(R.x, N) === sig.r;
  }
  function recoverNonceReuse(z1, sig1, z2, sig2) {
    if (sig1.r !== sig2.r) throw new Error("signatures do not share a nonce");
    const r = sig1.r;
    const k = mod((z1 - z2) * modInv(mod(sig1.s - sig2.s, N), N), N);
    return mod((sig1.s * k - z1) * modInv(r, N), N);
  }

  // --- Schnorr signatures (BIP-340) -------------------------------------------
  // The Taproot signature scheme: same curve, cleaner equation (s = k + e·d,
  // no inverses), x-only 32-byte pubkeys with an implied even Y, and every
  // hash domain-separated by a tag.
  function taggedHash(tag, msg) {
    const t = sha256(utf8(tag));
    return sha256(concatBytes(t, t, msg));
  }
  // the point with this x and even y, or null if x isn't on the curve
  function liftX(x) {
    if (x <= 0n || x >= P) return null;
    const c = mod(x * x * x + B, P);
    const y = modPow(c, (P + 1n) / 4n, P);
    if (mod(y * y, P) !== c) return null;
    return { x, y: y % 2n === 0n ? y : P - y };
  }
  const schnorrPubkey = (secret) => bigIntToBytes(ptMul(secret, G).x, 32);
  function schnorrSign(secret, msg, auxRand = new Uint8Array(32)) {
    const pt = ptMul(secret, G);
    const d = pt.y % 2n === 0n ? secret : N - secret;   // even-Y convention
    const px = bigIntToBytes(pt.x, 32);
    const aux = taggedHash("BIP0340/aux", auxRand);
    const t = bigIntToBytes(d, 32).map((b, i) => b ^ aux[i]);
    const k0 = mod(bytesToBigInt(taggedHash("BIP0340/nonce", concatBytes(t, px, msg))), N);
    if (k0 === 0n) throw new Error("bad nonce: k == 0");
    const R = ptMul(k0, G);
    const k = R.y % 2n === 0n ? k0 : N - k0;            // even-Y for R too
    const rx = bigIntToBytes(R.x, 32);
    const e = mod(bytesToBigInt(taggedHash("BIP0340/challenge", concatBytes(rx, px, msg))), N);
    return concatBytes(rx, bigIntToBytes(mod(k + e * d, N), 32));
  }
  function schnorrVerify(pubkey, msg, sig) {
    if (pubkey.length !== 32 || sig.length !== 64) return false;
    const pt = liftX(bytesToBigInt(pubkey));
    if (!pt) return false;
    const r = bytesToBigInt(sig.slice(0, 32));
    const s = bytesToBigInt(sig.slice(32));
    if (r >= P || s >= N) return false;
    const e = mod(bytesToBigInt(taggedHash("BIP0340/challenge", concatBytes(sig.slice(0, 32), pubkey, msg))), N);
    const R = ptAdd(ptMul(s, G), ptMul(e, { x: pt.x, y: P - pt.y })); // s·G - e·P
    return R !== null && R.y % 2n === 0n && R.x === r;
  }

  // --- Taproot (BIP-341, key path) --------------------------------------------
  // Q = P + t·G with t = taggedHash("TapTweak", P.x); the address is witness
  // v1 + Q.x in bech32m (bc1p…).
  const tapTweak = (internalKey) => mod(bytesToBigInt(taggedHash("TapTweak", internalKey)), N);
  function taprootOutputKey(internalKey) {
    const pt = liftX(bytesToBigInt(internalKey));
    if (!pt) throw new Error("internal key is not on the curve");
    const Q = ptAdd(pt, ptMul(tapTweak(internalKey), G));
    return bigIntToBytes(Q.x, 32);
  }
  const p2trAddress = (internalKey, testnet = false) =>
    encodeSegwit(testnet ? "tb" : "bc", 1, taprootOutputKey(internalKey));
  // the secret that key-path-spends the tweaked output
  function taprootTweakSecret(secret) {
    const pt = ptMul(secret, G);
    const d = pt.y % 2n === 0n ? secret : N - secret;
    return mod(d + tapTweak(bigIntToBytes(pt.x, 32)), N);
  }

  // --- Merkle trees + inclusion proofs (SPV) ---------------------------------
  const bytesEqual = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const merkleParent = (l, r) => doubleSha256(concatBytes(l, r));
  function merkleParentLevel(hashes) {
    if (hashes.length === 1) return hashes;
    if (hashes.length % 2 === 1) hashes = hashes.concat([hashes[hashes.length - 1]]);
    const out = [];
    for (let i = 0; i < hashes.length; i += 2) out.push(merkleParent(hashes[i], hashes[i + 1]));
    return out;
  }
  function merkleLevels(hashes) {
    const levels = [hashes.slice()];
    while (levels[levels.length - 1].length > 1) levels.push(merkleParentLevel(levels[levels.length - 1]));
    return levels;
  }
  const merkleRoot = (hashes) => merkleLevels(hashes).slice(-1)[0][0];
  // proof for leaf `index`: [{hash, left}] siblings up to the root (left = sibling on the left)
  function merkleProof(hashes, index) {
    const proof = [];
    let level = hashes.slice(), i = index;
    while (level.length > 1) {
      if (level.length % 2 === 1) level = level.concat([level[level.length - 1]]);
      proof.push(i % 2 === 0 ? { hash: level[i + 1], left: false } : { hash: level[i - 1], left: true });
      level = merkleParentLevel(level);
      i = Math.floor(i / 2);
    }
    return proof;
  }
  function verifyMerkleProof(leaf, proof, root) {
    let h = leaf;
    for (const { hash, left } of proof) h = left ? merkleParent(hash, h) : merkleParent(h, hash);
    return bytesEqual(h, root);
  }

  // --- MuSig2 key aggregation (BIP-327) ---------------------------------------
  // Schnorr's linearity, weaponized: n cosigners aggregate their pubkeys into
  // ONE x-only key (each blinded by a coefficient so nobody can rogue-key the
  // sum), swap nonce PAIRS (round 1), swap partial sigs (round 2) — and the sum
  // is a plain 64-byte BIP-340 signature. Mirrors hermes/musig.py.
  const musigCbytes = (pt) => sec(pt, true);
  const musigCbytesExt = (pt) => (pt === null ? new Uint8Array(33) : sec(pt, true));
  function musigCpoint(b) {
    if (b.length !== 33 || (b[0] !== 2 && b[0] !== 3)) throw new Error("invalid compressed point");
    const pt = liftX(bytesToBigInt(b.slice(1)));
    if (!pt) throw new Error("invalid compressed point");
    return b[0] === 2 ? pt : { x: pt.x, y: P - pt.y };
  }
  function musigCpointExt(b) {
    if (b.every((v) => v === 0)) return null;
    return musigCpoint(b);
  }
  const musigPlainPubkey = (secret) => sec(ptMul(secret, G), true);
  const musigKeySort = (pubkeys) =>
    pubkeys.slice().sort((a, b) => {
      for (let i = 0; i < 33; i++) if (a[i] !== b[i]) return a[i] - b[i];
      return 0;
    });
  // the first key that differs from keys[0] gets coefficient 1 (spec optimization)
  function musigSecondKey(pubkeys) {
    for (const pk of pubkeys.slice(1)) if (!bytesEqual(pk, pubkeys[0])) return pk;
    return new Uint8Array(33);
  }
  function musigKeyAggCoeff(pubkeys, pk) {
    if (bytesEqual(pk, musigSecondKey(pubkeys))) return 1n;
    const L = taggedHash("KeyAgg list", concatBytes(...pubkeys));
    return mod(bytesToBigInt(taggedHash("KeyAgg coefficient", concatBytes(L, pk))), N);
  }
  // Q = Σ a_i·P_i, plus the accumulators tweaking maintains (gacc: parity
  // flips, tacc: summed tweaks) so signers can shift their shares to match
  function musigKeyAgg(pubkeys) {
    let Q = null;
    for (const pk of pubkeys)
      Q = ptAdd(Q, ptMul(musigKeyAggCoeff(pubkeys, pk), musigCpoint(pk)));
    return { Q, gacc: 1n, tacc: 0n };
  }
  const musigXonly = (ctx) => bigIntToBytes(ctx.Q.x, 32);
  // Q' = g·Q + t·G; an x-only tweak (Taproot's TapTweak) negates odd-Y Q first
  function musigApplyTweak(ctx, tweak, isXonly) {
    const g = isXonly && ctx.Q.y % 2n === 1n ? N - 1n : 1n;
    const t = bytesToBigInt(tweak);
    if (t >= N) throw new Error("tweak out of range");
    const Q = ptAdd(ptMul(g, ctx.Q), ptMul(t, G));
    if (!Q) throw new Error("tweaked key is infinity");
    return { Q, gacc: mod(g * ctx.gacc, N), tacc: mod(t + g * ctx.tacc, N) };
  }
  function musigKeyAggAndTweak(pubkeys, tweaks = [], isXonly = []) {
    let ctx = musigKeyAgg(pubkeys);
    tweaks.forEach((tw, i) => { ctx = musigApplyTweak(ctx, tw, isXonly[i]); });
    return ctx;
  }
  // round 1: each signer's nonce PAIR (two nonces kill the Wagner/rogue-nonce
  // attack — the binding coefficient b isn't known until every nonce is fixed)
  function musigNonceHash(rand, pk, aggpk, i, msgPrefixed, extraIn) {
    const buf = concatBytes(
      rand, Uint8Array.of(pk.length), pk, Uint8Array.of(aggpk.length), aggpk,
      msgPrefixed, bigIntToBytes(BigInt(extraIn.length), 4), extraIn, Uint8Array.of(i));
    return bytesToBigInt(taggedHash("MuSig/nonce", buf));
  }
  function musigNonceGenInternal(rand, skBytes, pk, aggpk, msg, extraIn) {
    if (skBytes) {
      const aux = taggedHash("MuSig/aux", rand);
      rand = skBytes.map((b, i) => b ^ aux[i]);
    }
    if (!aggpk) aggpk = new Uint8Array(0);
    if (!extraIn) extraIn = new Uint8Array(0);
    const msgPrefixed = msg === null || msg === undefined
      ? Uint8Array.of(0)
      : concatBytes(Uint8Array.of(1), bigIntToBytes(BigInt(msg.length), 8), msg);
    const k1 = mod(musigNonceHash(rand, pk, aggpk, 0, msgPrefixed, extraIn), N);
    const k2 = mod(musigNonceHash(rand, pk, aggpk, 1, msgPrefixed, extraIn), N);
    const pubnonce = concatBytes(musigCbytes(ptMul(k1, G)), musigCbytes(ptMul(k2, G)));
    // secnonce records WHOSE nonce this is; partialSign refuses a mismatch
    const secnonce = concatBytes(bigIntToBytes(k1, 32), bigIntToBytes(k2, 32), pk);
    return { secnonce, pubnonce };
  }
  function musigNonceGen(secret, pk, aggpk = null, msg = null, extraIn = null) {
    const rand = new Uint8Array(32);
    crypto.getRandomValues(rand);
    const skBytes = secret === null ? null : bigIntToBytes(secret, 32);
    return musigNonceGenInternal(rand, skBytes, pk, aggpk, msg, extraIn);
  }
  // sum everyone's pubnonces slot-wise; a slot may cancel to infinity (zeros)
  function musigNonceAgg(pubnonces) {
    const parts = [];
    for (const j of [0, 1]) {
      let R = null;
      for (const pn of pubnonces) R = ptAdd(R, musigCpoint(pn.slice(j * 33, (j + 1) * 33)));
      parts.push(musigCbytesExt(R));
    }
    return concatBytes(...parts);
  }
  // session = {aggnonce, pubkeys, tweaks, isXonly, msg}; everything shared:
  // the tweaked aggregate Q, binding coefficient b, effective nonce R, challenge e
  function musigSessionValues(session) {
    const { Q, gacc, tacc } = musigKeyAggAndTweak(session.pubkeys, session.tweaks, session.isXonly);
    const b = mod(bytesToBigInt(taggedHash("MuSig/noncecoef",
      concatBytes(session.aggnonce, bigIntToBytes(Q.x, 32), session.msg))), N);
    const R_ = ptAdd(musigCpointExt(session.aggnonce.slice(0, 33)),
      ptMul(b, musigCpointExt(session.aggnonce.slice(33, 66))));
    const R = R_ === null ? G : R_;  // canceled nonces: substitute G
    const e = mod(bytesToBigInt(taggedHash("BIP0340/challenge",
      concatBytes(bigIntToBytes(R.x, 32), bigIntToBytes(Q.x, 32), session.msg))), N);
    return { Q, gacc, tacc, b, R, e };
  }
  // round 2: this signer's share s_i = k1 + b·k2 + e·a_i·d_i. Zeroizes the
  // secnonce first — reuse must be impossible, not just discouraged.
  function musigPartialSign(secnonce, secret, session) {
    const { Q, gacc, b, R, e } = musigSessionValues(session);
    const k1_ = bytesToBigInt(secnonce.slice(0, 32));
    const k2_ = bytesToBigInt(secnonce.slice(32, 64));
    const myPk = secnonce.slice(64, 97);
    secnonce.fill(0, 0, 64);                       // single-use, enforced
    if (k1_ <= 0n || k1_ >= N || k2_ <= 0n || k2_ >= N)
      throw new Error("secnonce out of range (already used?)");
    const k1 = R.y % 2n === 0n ? k1_ : N - k1_;
    const k2 = R.y % 2n === 0n ? k2_ : N - k2_;
    if (!bytesEqual(musigPlainPubkey(secret), myPk))
      throw new Error("secret does not match the secnonce's pubkey");
    const a = musigKeyAggCoeff(session.pubkeys, myPk);
    const g = Q.y % 2n === 0n ? 1n : N - 1n;
    const d = mod(g * gacc * secret, N);
    return bigIntToBytes(mod(k1 + b * k2 + e * a * d, N), 32);
  }
  // check signer i's share BEFORE aggregating — accountability
  function musigPartialSigVerify(psig, pubnonces, pubkeys, tweaks, isXonly, msg, i) {
    const session = { aggnonce: musigNonceAgg(pubnonces), pubkeys, tweaks, isXonly, msg };
    const { Q, gacc, b, R, e } = musigSessionValues(session);
    const s = bytesToBigInt(psig);
    if (s >= N) return false;
    let Rs = ptAdd(musigCpoint(pubnonces[i].slice(0, 33)),
      ptMul(b, musigCpoint(pubnonces[i].slice(33, 66))));
    if (R.y % 2n === 1n) Rs = Rs === null ? null : { x: Rs.x, y: P - Rs.y };
    const a = musigKeyAggCoeff(pubkeys, pubkeys[i]);
    const g = Q.y % 2n === 0n ? 1n : N - 1n;
    const lhs = ptMul(s, G);
    const rhs = ptAdd(Rs, ptMul(mod(e * a * mod(g * gacc, N), N), musigCpoint(pubkeys[i])));
    return lhs !== null && rhs !== null && lhs.x === rhs.x && lhs.y === rhs.y;
  }
  // combine: s = Σ s_i + e·g·tacc → R.x ‖ s, a standard BIP-340 signature
  function musigPartialSigAgg(psigs, session) {
    const { Q, tacc, R, e } = musigSessionValues(session);
    let s = 0n;
    for (const psig of psigs) {
      const si = bytesToBigInt(psig);
      if (si >= N) throw new Error("partial signature out of range");
      s = mod(s + si, N);
    }
    const g = Q.y % 2n === 0n ? 1n : N - 1n;
    s = mod(s + e * g * tacc, N);
    return concatBytes(bigIntToBytes(R.x, 32), bigIntToBytes(s, 32));
  }

  // --- Lightning payment channels (BOLT-3) -----------------------------------
  // BOLT-3 hashes are over the 33-byte compressed SEC points.
  const lnHashInt = (...parts) => bytesToBigInt(sha256(concatBytes(...parts)));
  const cmpBytes = (a, b) => {                        // lexicographic byte compare
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
  };

  // per-commitment public key: basepoint + SHA256(ppc || basepoint)·G
  function lnDerivePubkey(basepoint, perCommitmentPoint) {
    const h = lnHashInt(sec(perCommitmentPoint), sec(basepoint));
    return ptAdd(basepoint, ptMul(h, G));
  }
  function lnDerivePrivkey(basepointSecret, perCommitmentPoint) {
    const h = lnHashInt(sec(perCommitmentPoint), sec(pubFromSecret(basepointSecret)));
    return mod(basepointSecret + h, N);
  }
  // the blinded revocation key mixes one point from each party
  function lnDeriveRevocationPubkey(revocationBasepoint, perCommitmentPoint) {
    const h1 = lnHashInt(sec(revocationBasepoint), sec(perCommitmentPoint));
    const h2 = lnHashInt(sec(perCommitmentPoint), sec(revocationBasepoint));
    return ptAdd(ptMul(h1, revocationBasepoint), ptMul(h2, perCommitmentPoint));
  }
  // the matching private key — assemblable only once BOTH secrets are known
  function lnDeriveRevocationPrivkey(revocationBasepointSecret, perCommitmentSecret) {
    const revBase = pubFromSecret(revocationBasepointSecret);
    const ppc = pubFromSecret(perCommitmentSecret);
    const h1 = lnHashInt(sec(revBase), sec(ppc));
    const h2 = lnHashInt(sec(ppc), sec(revBase));
    return mod(revocationBasepointSecret * h1 + perCommitmentSecret * h2, N);
  }
  // BOLT-3 Appendix D generate_from_seed: bit-flip + SHA256 cascade
  function lnPerCommitmentSecret(seed, index) {
    let p = Uint8Array.from(seed);
    const I = BigInt(index);
    for (let b = 47; b >= 0; b--) {
      if ((I >> BigInt(b)) & 1n) {
        p = Uint8Array.from(p);
        p[b >> 3] ^= 1 << (b & 7);                   // flip bit (b%8) of byte (b//8)
        p = sha256(p);
      }
    }
    return p;
  }
  // minimal script-number push (for to_self_delay)
  function lnScriptNum(n) {
    if (n === 0) return new Uint8Array();
    const out = []; let a = Math.abs(n);
    while (a) { out.push(a & 0xff); a = Math.floor(a / 256); }
    if (out[out.length - 1] & 0x80) out.push(0);
    return Uint8Array.from(out);
  }
  // the funding output: a 2-of-2 multisig with lexicographically sorted keys
  function lnFundingScript(pubA, pubB) {
    const sorted = [sec(pubA), sec(pubB)].sort(cmpBytes);
    const parts = [Uint8Array.of(0x52)];             // OP_2
    for (const p of sorted) parts.push(pushData(p));
    parts.push(Uint8Array.of(0x52), Uint8Array.of(0xae)); // OP_2, OP_CHECKMULTISIG
    return concatBytes(...parts);
  }
  const lnFundingAddress = (pubA, pubB, testnet = false) =>
    p2wshAddress(lnFundingScript(pubA, pubB), testnet);
  // the to_local witnessScript: OP_IF <rev> OP_ELSE <delay> OP_CSV OP_DROP <delayed> OP_ENDIF OP_CHECKSIG
  function lnToLocalScript(revocationPubkey, toSelfDelay, localDelayedPubkey) {
    const d = lnScriptNum(toSelfDelay);
    return concatBytes(
      Uint8Array.of(0x63),                           // OP_IF
      pushData(revocationPubkey),
      Uint8Array.of(0x67),                           // OP_ELSE
      pushData(d), Uint8Array.of(0xb2, 0x75),        // OP_CHECKSEQUENCEVERIFY OP_DROP
      pushData(localDelayedPubkey),
      Uint8Array.of(0x68, 0xac));                    // OP_ENDIF OP_CHECKSIG
  }
  const lnPaymentHash = (preimage) => sha256(preimage);
  // BOLT-3 offered HTLC witnessScript (revocation / preimage / timeout branches)
  function lnHtlcOfferedScript(revocationPubkey, remoteHtlcpubkey, localHtlcpubkey, paymentHash) {
    return concatBytes(
      Uint8Array.of(0x76, 0xa9), pushData(hash160(revocationPubkey)), Uint8Array.of(0x87),
      Uint8Array.of(0x63, 0xac, 0x67),               // OP_IF OP_CHECKSIG OP_ELSE
      pushData(remoteHtlcpubkey), Uint8Array.of(0x7c, 0x82), pushData(lnScriptNum(32)), Uint8Array.of(0x87),
      Uint8Array.of(0x64, 0x75, 0x52, 0x7c), pushData(localHtlcpubkey), Uint8Array.of(0x52, 0xae),
      Uint8Array.of(0x67, 0xa9), pushData(ripemd160(paymentHash)), Uint8Array.of(0x88, 0xac),
      Uint8Array.of(0x68, 0x68));
  }
  // BOLT-3 received (accepted) HTLC witnessScript
  function lnHtlcReceivedScript(revocationPubkey, remoteHtlcpubkey, localHtlcpubkey, paymentHash, cltvExpiry) {
    return concatBytes(
      Uint8Array.of(0x76, 0xa9), pushData(hash160(revocationPubkey)), Uint8Array.of(0x87),
      Uint8Array.of(0x63, 0xac, 0x67),
      pushData(remoteHtlcpubkey), Uint8Array.of(0x7c, 0x82), pushData(lnScriptNum(32)), Uint8Array.of(0x87),
      Uint8Array.of(0x63, 0xa9), pushData(ripemd160(paymentHash)), Uint8Array.of(0x88),
      Uint8Array.of(0x52, 0x7c), pushData(localHtlcpubkey), Uint8Array.of(0x52, 0xae),
      Uint8Array.of(0x67, 0x75), pushData(lnScriptNum(cltvExpiry)), Uint8Array.of(0xb1, 0x75, 0xac),
      Uint8Array.of(0x68, 0x68));
  }
  // the canonical hashlock-or-timeout HTLC the routing demo walks through
  function lnHtlcScript(paymentHash, receiverPubkey, senderPubkey, cltvExpiry) {
    return concatBytes(
      Uint8Array.of(0x63, 0xa9), pushData(ripemd160(paymentHash)), Uint8Array.of(0x88),  // OP_IF OP_HASH160 <20> OP_EQUALVERIFY
      pushData(receiverPubkey), Uint8Array.of(0xac, 0x67),                               // <receiver> OP_CHECKSIG OP_ELSE
      pushData(lnScriptNum(cltvExpiry)), Uint8Array.of(0xb1, 0x75),                      // <cltv> OP_CLTV OP_DROP
      pushData(senderPubkey), Uint8Array.of(0xac, 0x68));                                // <sender> OP_CHECKSIG OP_ENDIF
  }

  // --- FROST threshold Schnorr (RFC 9591, secp256k1/SHA-256) -----------------
  const FROST_CTX = utf8("FROST-secp256k1-SHA256-v1");
  const serScalar = (s) => bigIntToBytes(mod(s, N), 32);
  // RFC 9380 expand_message_xmd with SHA-256
  function expandMessageXmd(msg, dst, length) {
    const bIn = 32, sIn = 64, ell = Math.ceil(length / bIn);
    const dstPrime = concatBytes(dst, Uint8Array.of(dst.length));
    const msgPrime = concatBytes(new Uint8Array(sIn), msg,
      Uint8Array.of((length >> 8) & 0xff, length & 0xff), Uint8Array.of(0), dstPrime);
    const b0 = sha256(msgPrime);
    const blocks = [sha256(concatBytes(b0, Uint8Array.of(1), dstPrime))];
    for (let i = 2; i <= ell; i++) {
      const xored = b0.map((v, j) => v ^ blocks[blocks.length - 1][j]);
      blocks.push(sha256(concatBytes(xored, Uint8Array.of(i), dstPrime)));
    }
    return concatBytes(...blocks).slice(0, length);
  }
  const frostScalarHash = (msg, suffix) =>
    mod(bytesToBigInt(expandMessageXmd(msg, concatBytes(FROST_CTX, utf8(suffix)), 48)), N);
  const frostH1 = (m) => frostScalarHash(m, "rho");
  const frostH2 = (m) => frostScalarHash(m, "chal");
  const frostH3 = (m) => frostScalarHash(m, "nonce");
  const frostH4 = (m) => sha256(concatBytes(FROST_CTX, utf8("msg"), m));
  const frostH5 = (m) => sha256(concatBytes(FROST_CTX, utf8("com"), m));

  function frostPolyEval(x, coeffs) {          // Horner, constant term first
    let v = 0n;
    for (let i = coeffs.length - 1; i >= 0; i--) v = mod(v * x + coeffs[i], N);
    return v;
  }
  function frostKeygen(secret, coefficients, maxParticipants) {
    const poly = [secret, ...coefficients], shares = [];
    for (let i = 1; i <= maxParticipants; i++) shares.push([BigInt(i), frostPolyEval(BigInt(i), poly)]);
    return { shares, groupPubkey: ptMul(secret, G) };
  }
  function frostLagrange(ids, xi) {            // Lagrange coefficient λ_i
    let num = 1n, den = 1n;
    for (const xj of ids) { if (xj === xi) continue; num = mod(num * xj, N); den = mod(den * (xj - xi), N); }
    return mod(num * modInv(den, N), N);
  }
  const frostNonceGenerate = (secret, randomness) => frostH3(concatBytes(randomness, serScalar(secret)));
  function frostCommit(secret, hidingRand, bindingRand) {
    const hn = frostNonceGenerate(secret, hidingRand), bn = frostNonceGenerate(secret, bindingRand);
    return { nonces: [hn, bn], commits: [ptMul(hn, G), ptMul(bn, G)] };
  }
  const frostEncodeCommitments = (list) =>
    concatBytes(...list.flatMap(([id, h, b]) => [serScalar(id), sec(h, true), sec(b, true)]));
  function frostBindingFactors(groupPub, list, msg) {
    const prefix = concatBytes(sec(groupPub, true), frostH4(msg), frostH5(frostEncodeCommitments(list)));
    return list.map(([id]) => [id, frostH1(concatBytes(prefix, serScalar(id)))]);
  }
  function frostGroupCommitment(list, bfl) {
    const bf = new Map(bfl); let R = null;
    for (const [id, h, b] of list) {
      const term = ptAdd(h, ptMul(bf.get(id), b));
      R = R === null ? term : ptAdd(R, term);
    }
    return R;
  }
  const frostChallenge = (R, groupPub, msg) =>
    frostH2(concatBytes(sec(R, true), sec(groupPub, true), msg));
  function frostSign(id, share, groupPub, nonces, msg, list) {
    const bfl = frostBindingFactors(groupPub, list, msg);
    const bf = new Map(bfl).get(id);
    const R = frostGroupCommitment(list, bfl);
    const lam = frostLagrange(list.map(([i]) => i), id);
    const c = frostChallenge(R, groupPub, msg);
    const [hn, bn] = nonces;
    return mod(hn + bn * bf + lam * share * c, N);
  }
  function frostAggregate(list, msg, groupPub, sigShares) {
    const R = frostGroupCommitment(list, frostBindingFactors(groupPub, list, msg));
    let z = 0n; for (const s of sigShares) z = mod(z + s, N);
    return { R, z };
  }
  function frostVerify(msg, sig, groupPub) {
    const c = frostChallenge(sig.R, groupPub, msg);
    const lhs = ptMul(sig.z, G), rhs = ptAdd(sig.R, ptMul(c, groupPub));
    return lhs.x === rhs.x && lhs.y === rhs.y;
  }
  const frostSerializeSig = (sig) => concatBytes(sec(sig.R, true), serScalar(sig.z));

  // --- Schnorr adaptor signatures (PTLCs) ------------------------------------
  const adaptorXonly = (P) => bigIntToBytes(P.x, 32);
  const adaptorEven = (P) => (P.y % 2n) === 0n;
  const adaptorNeg = (P) => ptMul(N - 1n, P);
  const adaptorChallenge = (R, P, msg) => mod(bytesToBigInt(
    taggedHash("BIP0340/challenge", concatBytes(adaptorXonly(R), adaptorXonly(P), msg))), N);
  const adaptorPoint = (t) => ptMul(t, G);
  function adaptorNonce(d, px, msg, T) {
    const k = mod(bytesToBigInt(taggedHash("HermesAdaptor/nonce",
      concatBytes(bigIntToBytes(d, 32), px, msg, adaptorXonly(T)))), N);
    return k === 0n ? 1n : k;
  }
  function adaptorPresign(secret, msg, T, k) {
    const d = adaptorEven(ptMul(secret, G)) ? secret : N - secret;   // even-Y key
    const P = ptMul(d, G), px = adaptorXonly(P);
    if (k === undefined || k === null) k = adaptorNonce(d, px, msg, T);
    const r0 = ptMul(k, G), eff = ptAdd(r0, T);
    const e = adaptorChallenge(eff, P, msg);
    const sPrime = mod((adaptorEven(eff) ? k : -k) + e * d, N);       // flip k if R odd
    return { r0, sPrime };
  }
  function adaptorPresigVerify(pubkeyXonly, msg, T, presig) {
    const P = liftX(bytesToBigInt(pubkeyXonly));
    const eff = ptAdd(presig.r0, T);
    const e = adaptorChallenge(eff, P, msg);
    const expected = ptAdd(adaptorEven(eff) ? presig.r0 : adaptorNeg(presig.r0), ptMul(e, P));
    const lhs = ptMul(presig.sPrime, G);
    return lhs.x === expected.x && lhs.y === expected.y;
  }
  function adaptorAdapt(presig, t) {
    const eff = ptAdd(presig.r0, ptMul(t, G));
    const s = mod(presig.sPrime + (adaptorEven(eff) ? t : -t), N);
    return concatBytes(adaptorXonly(eff), bigIntToBytes(s, 32));
  }
  function adaptorExtract(presig, sig, T) {
    const s = bytesToBigInt(sig.slice(32, 64));
    const eff = ptAdd(presig.r0, T);
    return mod(adaptorEven(eff) ? (s - presig.sPrime) : (presig.sPrime - s), N);
  }

  // --- BIP-340 / Taproot FROST (threshold sig that spends a bc1p vault) -------
  const ftXonly = (P) => bigIntToBytes(P.x, 32);
  const ftSign = (P) => (P.y % 2n === 0n ? 1n : -1n);          // even-y => +1
  const ftChallenge = (R, pubkeyXonly, msg) => mod(bytesToBigInt(
    taggedHash("BIP0340/challenge", concatBytes(ftXonly(R), pubkeyXonly, msg))), N);
  function frostBip340Sign(id, share, groupPub, nonces, msg, list) {          // verifies under group key
    const bfl = frostBindingFactors(groupPub, list, msg), bf = new Map(bfl).get(id);
    const R = frostGroupCommitment(list, bfl);
    const lam = frostLagrange(list.map(([i]) => i), id);
    const c = ftChallenge(R, ftXonly(groupPub), msg);
    const [hn, bn] = nonces;
    return mod(ftSign(R) * (hn + bn * bf) + ftSign(groupPub) * lam * share * c, N);
  }
  function frostBip340Aggregate(list, msg, groupPub, sigShares) {
    const R = frostGroupCommitment(list, frostBindingFactors(groupPub, list, msg));
    let z = 0n; for (const s of sigShares) z = mod(z + s, N);
    return concatBytes(ftXonly(R), bigIntToBytes(z, 32));
  }
  function ftTweak(groupPub) {                                 // TapTweak context
    const internal = ftXonly(groupPub), t = tapTweak(internal);
    return { t, Q: ptAdd(liftX(bytesToBigInt(internal)), ptMul(t, G)) };
  }
  function frostTaprootSign(id, share, groupPub, nonces, msg, list) {         // key-path spend of the vault
    const { Q } = ftTweak(groupPub);
    const bfl = frostBindingFactors(groupPub, list, msg), bf = new Map(bfl).get(id);
    const R = frostGroupCommitment(list, bfl);
    const lam = frostLagrange(list.map(([i]) => i), id);
    const c = ftChallenge(R, ftXonly(Q), msg);
    const [hn, bn] = nonces;
    return mod(ftSign(R) * (hn + bn * bf) + c * ftSign(Q) * ftSign(groupPub) * lam * share, N);
  }
  function frostTaprootAggregate(list, msg, groupPub, sigShares) {
    const { t, Q } = ftTweak(groupPub);
    const R = frostGroupCommitment(list, frostBindingFactors(groupPub, list, msg));
    const c = ftChallenge(R, ftXonly(Q), msg);
    let z = 0n; for (const s of sigShares) z = mod(z + s, N);
    return concatBytes(ftXonly(R), bigIntToBytes(mod(z + c * ftSign(Q) * t, N), 32));
  }
  const frostVaultAddress = (groupPub, testnet = false) => p2trAddress(ftXonly(groupPub), testnet);
  const frostOutputXonly = (groupPub) => taprootOutputKey(ftXonly(groupPub));

  // hash of a message string, as the integer z that ECDSA signs
  const messageHash = (str) => bytesToBigInt(doubleSha256(utf8(str)));

  window.Hermes = {
    // bytes
    utf8, hexToBytes, bytesToHex, bytesToBigInt, bigIntToBytes, concatBytes,
    // hashes
    sha256, doubleSha256, ripemd160, hash160,
    // base58
    b58encode, b58decode, b58checkEncode, b58checkDecode,
    // curve
    P, A, B, N, G, INFINITY, mod, modInv, ptAdd, ptDouble, ptMul,
    // keys
    pubFromSecret, sec, secDecode, address, wif,
    // bech32 / segwit
    encodeSegwit, p2wpkhAddress, convertBits,
    // p2wsh multisig
    multisigScript, p2wshAddress, sigHashBip143, encodeVarint,
    // schnorr / taproot
    taggedHash, liftX, schnorrPubkey, schnorrSign, schnorrVerify,
    tapTweak, taprootOutputKey, p2trAddress, taprootTweakSecret,
    // merkle / spv
    merkleRoot, merkleProof, merkleLevels, verifyMerkleProof,
    // musig2 (BIP-327)
    musigPlainPubkey, musigKeySort, musigKeyAgg, musigKeyAggAndTweak, musigXonly,
    musigApplyTweak, musigKeyAggCoeff, musigNonceGen, musigNonceGenInternal,
    musigNonceAgg, musigSessionValues, musigPartialSign, musigPartialSigVerify,
    musigPartialSigAgg,
    // lightning (BOLT-3)
    lnDerivePubkey, lnDerivePrivkey, lnDeriveRevocationPubkey, lnDeriveRevocationPrivkey,
    lnPerCommitmentSecret, lnFundingScript, lnFundingAddress, lnToLocalScript, lnScriptNum,
    lnPaymentHash, lnHtlcOfferedScript, lnHtlcReceivedScript, lnHtlcScript,
    // frost (RFC 9591)
    frostH1, frostH2, frostH3, frostKeygen, frostLagrange, frostNonceGenerate,
    frostCommit, frostBindingFactors, frostGroupCommitment, frostSign, frostAggregate,
    frostVerify, frostSerializeSig,
    // adaptor signatures / PTLC
    adaptorPoint, adaptorPresign, adaptorPresigVerify, adaptorAdapt, adaptorExtract, adaptorXonly,
    // BIP-340 / Taproot FROST
    frostBip340Sign, frostBip340Aggregate, frostTaprootSign, frostTaprootAggregate,
    frostVaultAddress, frostOutputXonly,
    // ecdsa
    sign, verify, recoverNonceReuse, randScalar, hmacSha256, rfc6979K, messageHash,
  };
})();
