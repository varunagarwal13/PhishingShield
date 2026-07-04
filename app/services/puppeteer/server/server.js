/**
 * PHISHING SHIELD — puppeteer/server.js
 * Node.js screenshot microservice.
 * Keeps 3 warm Puppeteer browser instances ready.
 * Python server calls POST /screenshot to get screenshot + DOM analysis.
 */

const express = require('express');
const puppeteer = require('puppeteer');

const app = express();
app.use(express.json());

const POOL_SIZE = 3;
const pool = [];
let poolReady = false;

// ─────────────────────────────────────────────
// BROWSER POOL — warm 3 instances at startup
// ─────────────────────────────────────────────
async function initPool() {
  console.log(`[Puppeteer] Warming up ${POOL_SIZE} browser instances...`);
  for (let i = 0; i < POOL_SIZE; i++) {
    const browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-setuid-sandbox',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
      ]
    });
    pool.push({ browser, busy: false, id: i });
    console.log(`[Puppeteer] Browser ${i} ready`);
  }
  poolReady = true;
  console.log('[Puppeteer] Pool ready. Listening on :3001');
}

function getFreeBrowser() {
  return pool.find(b => !b.busy) || null;
}

// ─────────────────────────────────────────────
// SCREENSHOT ENDPOINT
// ─────────────────────────────────────────────
app.post('/screenshot', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });

  const slot = getFreeBrowser();
  if (!slot) {
    return res.status(503).json({ error: 'all browsers busy, retry in 1s' });
  }

  slot.busy = true;
  let page = null;

  try {
    page = await slot.browser.newPage();

    // Block non-essential resources to speed up load
    await page.setRequestInterception(true);
    page.on('request', (req) => {
      const type = req.resourceType();
      if (['font', 'media', 'websocket'].includes(type)) {
        req.abort();
      } else {
        req.continue();
      }
    });

    // Set user agent to look like a real browser
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    );

    // Set viewport to capture top 600px
    await page.setViewport({ width: 1280, height: 800 });

    // Navigate with timeout
    await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: 4000
    });

    // Small delay for JS-rendered content
    await new Promise(r => setTimeout(r, 300));

    // ── Screenshot (top 600px — logos and login forms live here) ──
    const screenshot = await page.screenshot({
      encoding: 'base64',
      clip: { x: 0, y: 0, width: 1280, height: 600 }
    });

    // ── DOM Analysis ──
    const domSignals = await page.evaluate(() => {
      const hostname = window.location.hostname;

      // Check for password/login fields
      const hasPasswordField = !!document.querySelector('input[type="password"]');

      // Check form action mismatch (form submits to different domain)
      const forms = Array.from(document.forms);
      const formActionMismatch = forms.some(f => {
        if (!f.action) return false;
        try {
          const actionHost = new URL(f.action).hostname;
          return actionHost && actionHost !== hostname;
        } catch { return false; }
      });

      // Cross-origin iframes
      const iframeAbuse = Array.from(document.querySelectorAll('iframe')).some(f => {
        try {
          if (!f.src) return false;
          return new URL(f.src).hostname !== hostname;
        } catch { return false; }
      });

      // Anti-inspection techniques
      const rightClickDisabled = typeof document.oncontextmenu === 'function';

      // DevTools detection attempts in scripts
      const scripts = Array.from(document.scripts)
        .map(s => s.textContent || '')
        .join(' ');
      const devtoolsBlocked = /debugger|devtools|firebug/i.test(scripts);

      // Clipboard hijack
      const clipboardHijack = typeof document.oncopy === 'function' ||
                               typeof document.onpaste === 'function';

      return {
        hasPasswordField,
        formActionMismatch,
        iframeAbuse,
        rightClickDisabled,
        devtoolsBlocked,
        clipboardHijack,
      };
    });

    // ── Page Text (for NLP module) ──
    const pageText = await page.evaluate(() =>
      (document.body?.innerText || '').slice(0, 5000) // cap at 5KB
    );

    await page.close();
    slot.busy = false;

    return res.json({ screenshot, domSignals, pageText });

  } catch (err) {
    console.error(`[Puppeteer] Error for ${url}: ${err.message}`);
    if (page) {
      try { await page.close(); } catch (_) {}
    }
    slot.busy = false;

    // Return empty result (don't crash the Python pipeline)
    return res.json({
      screenshot: null,
      domSignals: {},
      pageText: '',
      error: err.message
    });
  }
});

// ─────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────
app.get('/health', (req, res) => {
  const free = pool.filter(b => !b.busy).length;
  res.json({
    ready: poolReady,
    pool_size: POOL_SIZE,
    free_slots: free,
    busy_slots: POOL_SIZE - free
  });
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
initPool().then(() => {
  app.listen(3001, '127.0.0.1', () => {
    console.log('[Puppeteer] Server listening on 127.0.0.1:3001');
  });
}).catch(err => {
  console.error('[Puppeteer] Failed to init pool:', err);
  process.exit(1);
});
