// demo-capture.js — records web/demo.gif, the README montage of six demos.
//
// Drives the local dev server through seven beats (landing → Curve → Mine →
// Network → Taproot → Lightning → HTLC Second-Stage) with Playwright + the system Chrome, records
// one continuous .webm, and prints its filename. A second ffmpeg pass turns the
// .webm into an optimised, palette-based GIF (see the bottom of this file / HANDOFF.md).
//
//   # 1. dev server (serves web/ on :8011) — see projects/.claude/launch.json
//   cd web && python3 -m http.server 8011
//
//   # 2. record the webm  (needs: npm i playwright  +  Google Chrome installed)
//   node demo-capture.js                       # writes ./cap-<hash>.webm
//
//   # 3. webm -> gif  (needs ffmpeg)
//   V=$(ls -t cap-*.webm | head -1)
//   ffmpeg -i "$V" -vf "setpts=PTS/1.25,fps=15,scale=760:-1:flags=lanczos,palettegen=stats_mode=diff" -y palette.png
//   ffmpeg -i "$V" -i palette.png -lavfi "setpts=PTS/1.25,fps=15,scale=760:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle" -y web/demo.gif
//
// The GIF goes stale like og.png does when a demo is added — re-record to refresh.

const { chromium } = require('playwright');

const BASE = process.env.BASE || 'http://localhost:8011';
const W = 860, H = 720;
const OUT = process.env.OUT_DIR || '.';

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Animate a range input from min→max→min, dispatching input events so the demo redraws.
async function sweepRange(page, sel, ms) {
  await page.evaluate(async ({ sel, ms }) => {
    const el = document.querySelector(sel);
    if (!el) return;
    const min = parseFloat(el.min || '0'), max = parseFloat(el.max || '100');
    const start = performance.now();
    return new Promise(res => {
      function frame(now) {
        let t = (now - start) / ms;
        if (t >= 1) t = 1;
        const tri = t < 0.5 ? t * 2 : (1 - t) * 2;      // up then down
        el.value = String(min + (max - min) * tri);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        if (t < 1) requestAnimationFrame(frame); else res();
      }
      requestAnimationFrame(frame);
    });
  }, { sel, ms });
}

async function goto(page, path) {
  await page.goto(BASE + path, { waitUntil: 'load' });
  await sleep(350);
}

(async () => {
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext({
    viewport: { width: W, height: H },
    deviceScaleFactor: 2,
    recordVideo: { dir: OUT, size: { width: W, height: H } },
  });
  const page = await context.newPage();

  // 0 — Landing hero
  await goto(page, '/');
  await sleep(1600);

  // 1 — The Curve: sweep Point P, the chord-and-tangent construction moves
  await goto(page, '/curve/');
  await sleep(400);
  await sweepRange(page, '#px', 3000);
  await sleep(300);

  // 2 — Mine & Chain: grind the nonce
  await goto(page, '/mine/');
  await page.click('#mineBtn');
  await sleep(3200);

  // 3 — Network & 51%: the canvas is a tall 900x520 with the chain at only 40% height,
  // so it frames with a big empty void. Shrink it to a compact strip and reset (empty),
  // linger on the intro, then fast-forward Step so the chain fills the width block-by-block.
  await goto(page, '/network/');
  await page.evaluate(() => {
    document.querySelector('#tree').height = 300;   // 520 -> compact 3:1 strip, no void
    document.querySelector('#resetC').click();      // cStep=0, redraw empty at new height
  });
  await sleep(1800);                                 // let the "Network & the 51% Attack" intro read
  for (let i = 0; i < 42; i++) { await page.click('#stepBtn'); await sleep(85); }
  await sleep(1200);

  // 4 — Taproot & Schnorr: sign (VALID), then scroll to the "signatures add" beat
  await goto(page, '/taproot/');
  await page.click('#signBtn');
  await sleep(1100);
  await page.locator('#jointSign').scrollIntoViewIfNeeded();
  await sleep(400);
  await page.click('#jointSign');
  await sleep(1600);

  // 5 — Lightning: pay off-chain, the balance bar slides to Bob
  await goto(page, '/lightning/');
  for (let i = 0; i < 5; i++) { await page.click('#payAB'); await sleep(420); }
  await sleep(900);

  // 6 — HTLC Second-Stage: the offered->received toggle flips the flow diagram's
  // middle box from HTLC-timeout (2-of-2, timelocked) to HTLC-success (2-of-2 + preimage).
  await goto(page, '/second-stage/');
  await sleep(1800);                                 // offered / HTLC-timeout, let the intro read
  await page.click('#tabRec');                       // -> received / HTLC-success
  await sleep(1800);

  await context.close(); // finalizes the video
  await browser.close();

  const fs = require('fs');
  const vids = fs.readdirSync(OUT).filter(f => f.endsWith('.webm'));
  console.log('VIDEO:', vids.join(', '));
})();
