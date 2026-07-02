// Hermes — HD wallet primitives (BIP-39 / BIP-32) for the browser.
//
// SHA-512 (via BigInt), HMAC-SHA512, PBKDF2, mnemonic <-> seed, and BIP-32 key
// derivation. Mirrors hermes/sha512.py, bip39.py, bip32.py and must agree with
// the same official test vectors. Depends on btc.js (window.Hermes).
(function () {
  "use strict";
  const H = window.Hermes;
  const MASK = (1n << 64n) - 1n;

  // --- SHA-512 ---------------------------------------------------------------
  const K = [
    0x428a2f98d728ae22n,0x7137449123ef65cdn,0xb5c0fbcfec4d3b2fn,0xe9b5dba58189dbbcn,
    0x3956c25bf348b538n,0x59f111f1b605d019n,0x923f82a4af194f9bn,0xab1c5ed5da6d8118n,
    0xd807aa98a3030242n,0x12835b0145706fben,0x243185be4ee4b28cn,0x550c7dc3d5ffb4e2n,
    0x72be5d74f27b896fn,0x80deb1fe3b1696b1n,0x9bdc06a725c71235n,0xc19bf174cf692694n,
    0xe49b69c19ef14ad2n,0xefbe4786384f25e3n,0x0fc19dc68b8cd5b5n,0x240ca1cc77ac9c65n,
    0x2de92c6f592b0275n,0x4a7484aa6ea6e483n,0x5cb0a9dcbd41fbd4n,0x76f988da831153b5n,
    0x983e5152ee66dfabn,0xa831c66d2db43210n,0xb00327c898fb213fn,0xbf597fc7beef0ee4n,
    0xc6e00bf33da88fc2n,0xd5a79147930aa725n,0x06ca6351e003826fn,0x142929670a0e6e70n,
    0x27b70a8546d22ffcn,0x2e1b21385c26c926n,0x4d2c6dfc5ac42aedn,0x53380d139d95b3dfn,
    0x650a73548baf63den,0x766a0abb3c77b2a8n,0x81c2c92e47edaee6n,0x92722c851482353bn,
    0xa2bfe8a14cf10364n,0xa81a664bbc423001n,0xc24b8b70d0f89791n,0xc76c51a30654be30n,
    0xd192e819d6ef5218n,0xd69906245565a910n,0xf40e35855771202an,0x106aa07032bbd1b8n,
    0x19a4c116b8d2d0c8n,0x1e376c085141ab53n,0x2748774cdf8eeb99n,0x34b0bcb5e19b48a8n,
    0x391c0cb3c5c95a63n,0x4ed8aa4ae3418acbn,0x5b9cca4f7763e373n,0x682e6ff3d6b2b8a3n,
    0x748f82ee5defb2fcn,0x78a5636f43172f60n,0x84c87814a1f0ab72n,0x8cc702081a6439ecn,
    0x90befffa23631e28n,0xa4506cebde82bde9n,0xbef9a3f7b2c67915n,0xc67178f2e372532bn,
    0xca273eceea26619cn,0xd186b8c721c0c207n,0xeada7dd6cde0eb1en,0xf57d4f7fee6ed178n,
    0x06f067aa72176fban,0x0a637dc5a2c898a6n,0x113f9804bef90daen,0x1b710b35131c471bn,
    0x28db77f523047d84n,0x32caab7b40c72493n,0x3c9ebe0a15c9bebcn,0x431d67c49c100d4cn,
    0x4cc5d4becb3e42b6n,0x597f299cfc657e2an,0x5fcb6fab3ad6faecn,0x6c44198c4a475817n,
  ];
  const H0 = [
    0x6a09e667f3bcc908n,0xbb67ae8584caa73bn,0x3c6ef372fe94f82bn,0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n,0x9b05688c2b3e6c1fn,0x1f83d9abfb41bd6bn,0x5be0cd19137e2179n,
  ];
  const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & MASK;

  function sha512(msg) {
    const ml = BigInt(msg.length) * 8n;
    let len = msg.length + 1;
    len += (112 - (len % 128) + 128) % 128;
    const m = new Uint8Array(len + 16);
    m.set(msg, 0); m[msg.length] = 0x80;
    // 128-bit big-endian length (top 8 bytes are 0 for our sizes)
    const dv = new DataView(m.buffer);
    dv.setBigUint64(m.length - 8, ml & 0xffffffffffffffffn, false);

    const h = H0.slice();
    const w = new Array(80);
    for (let off = 0; off < m.length; off += 128) {
      for (let i = 0; i < 16; i++) w[i] = dv.getBigUint64(off + i * 8, false);
      for (let i = 16; i < 80; i++) {
        const s0 = rotr(w[i-15],1n) ^ rotr(w[i-15],8n) ^ (w[i-15] >> 7n);
        const s1 = rotr(w[i-2],19n) ^ rotr(w[i-2],61n) ^ (w[i-2] >> 6n);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & MASK;
      }
      let [a,b,c,d,e,f,g,hh] = h;
      for (let i = 0; i < 80; i++) {
        const S1 = rotr(e,14n) ^ rotr(e,18n) ^ rotr(e,41n);
        const ch = (e & f) ^ (~e & MASK & g);
        const t1 = (hh + S1 + ch + K[i] + w[i]) & MASK;
        const S0 = rotr(a,28n) ^ rotr(a,34n) ^ rotr(a,39n);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) & MASK;
        hh=g; g=f; f=e; e=(d+t1)&MASK; d=c; c=b; b=a; a=(t1+t2)&MASK;
      }
      const v = [a,b,c,d,e,f,g,hh];
      for (let i = 0; i < 8; i++) h[i] = (h[i] + v[i]) & MASK;
    }
    const out = new Uint8Array(64);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setBigUint64(i * 8, h[i], false);
    return out;
  }

  const BLK = 128;
  function hmac512(key, msg) {
    if (key.length > BLK) key = sha512(key);
    const k = new Uint8Array(BLK); k.set(key, 0);
    const ip = new Uint8Array(BLK), op = new Uint8Array(BLK);
    for (let i = 0; i < BLK; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
    return sha512(H.concatBytes(op, sha512(H.concatBytes(ip, msg))));
  }
  function pbkdf2_512(pw, salt, iters, dklen) {
    const out = [];
    let bi = 1;
    while (out.length < dklen) {
      const ctr = new Uint8Array([bi>>>24, bi>>>16, bi>>>8, bi]);
      let u = hmac512(pw, H.concatBytes(salt, ctr));
      const t = u.slice();
      for (let i = 1; i < iters; i++) { u = hmac512(pw, u); for (let j = 0; j < t.length; j++) t[j] ^= u[j]; }
      out.push(...t); bi++;
    }
    return Uint8Array.from(out.slice(0, dklen));
  }

  // --- BIP-39 ----------------------------------------------------------------
  const utf8nfkd = (s) => new TextEncoder().encode(s.normalize("NFKD"));
  function entropyToMnemonic(entropy, words) {
    const ENT = entropy.length * 8, CS = ENT / 32;
    const checksum = H.sha256(entropy)[0] >> (8 - CS);
    let bits = (H.bytesToBigInt(entropy) << BigInt(CS)) | BigInt(checksum);
    const total = ENT + CS, out = [];
    for (let i = 0; i < total / 11; i++) {
      const shift = BigInt(total - 11 * (i + 1));
      out.push(words[Number((bits >> shift) & 0x7ffn)]);
    }
    return out.join(" ");
  }
  function mnemonicValid(mnemonic, words) {
    const idx = Object.fromEntries(words.map((w,i)=>[w,i]));
    const parts = mnemonic.trim().split(/\s+/);
    if (![12,15,18,21,24].includes(parts.length)) return false;
    let bits = 0n;
    for (const w of parts) { if (!(w in idx)) return false; bits = (bits << 11n) | BigInt(idx[w]); }
    const total = parts.length * 11, CS = total / 33, ENT = total - CS;
    const entropy = H.bigIntToBytes(bits >> BigInt(CS), ENT / 8);
    return (H.sha256(entropy)[0] >> (8 - CS)) === Number(bits & ((1n << BigInt(CS)) - 1n));
  }
  const mnemonicToSeed = (mnemonic, passphrase = "") =>
    pbkdf2_512(utf8nfkd(mnemonic), utf8nfkd("mnemonic" + passphrase), 2048, 64);

  // --- BIP-32 ----------------------------------------------------------------
  const HARDENED = 0x80000000;
  const ser32 = (i) => new Uint8Array([(i>>>24)&255,(i>>>16)&255,(i>>>8)&255,i&255]);
  function fromSeed(seed) {
    const I = hmac512(new TextEncoder().encode("Bitcoin seed"), seed);
    return { secret: H.bytesToBigInt(I.slice(0,32)), chain: I.slice(32),
      depth: 0, parentFp: new Uint8Array(4), childNum: 0 };
  }
  const pubSec = (k) => H.sec(H.pubFromSecret(k.secret), true);
  const fingerprint = (k) => H.hash160(pubSec(k)).slice(0, 4);
  function child(k, index) {
    const data = index >= HARDENED
      ? H.concatBytes(new Uint8Array(1), H.bigIntToBytes(k.secret, 32), ser32(index))
      : H.concatBytes(pubSec(k), ser32(index));
    const I = hmac512(k.chain, data);
    const IL = H.bytesToBigInt(I.slice(0,32));
    const secret = (IL + k.secret) % H.N;
    if (IL >= H.N || secret === 0n) // ~2^-128; BIP-32 says skip to the next index
      throw new Error(`invalid child key at index ${index}; use the next index`);
    return { secret, chain: I.slice(32), depth: k.depth+1, parentFp: fingerprint(k), childNum: index };
  }
  function derivePath(k, path) {
    for (const part of path.split("/")) {
      if (part === "m" || part === "") continue;
      const hard = part.endsWith("'") || part.endsWith("h");
      const index = parseInt(part) + (hard ? HARDENED : 0);
      k = child(k, index);
    }
    return k;
  }
  const address = (k, testnet=false) => H.address(H.pubFromSecret(k.secret), true, testnet);
  function serialize(k, version, keydata) {
    const payload = H.concatBytes(H.hexToBytes(version), new Uint8Array([k.depth]),
      k.parentFp, ser32(k.childNum), k.chain, keydata);
    return H.b58checkEncode(payload);
  }
  const xprv = (k) => serialize(k, "0488ade4", H.concatBytes(new Uint8Array(1), H.bigIntToBytes(k.secret,32)));
  const xpub = (k) => serialize(k, "0488b21e", pubSec(k));

  window.HermesWallet = {
    sha512, hmac512, pbkdf2_512,
    entropyToMnemonic, mnemonicValid, mnemonicToSeed,
    fromSeed, child, derivePath, address, xprv, xpub, fingerprint, HARDENED,
  };
})();
