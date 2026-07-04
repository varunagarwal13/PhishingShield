/**
 * PHISHING SHIELD — background.js
 * Service Worker: intercepts every navigation, calls the local analysis server,
 * and acts on the verdict (block / warn / allow).
 */

const SERVER_URL = 'http://127.0.0.1:8000/analyse';
const TIMEOUT_MS = 5000;

// Deduplication map: "tabId:url" → timestamp
// Prevents double-fire on redirects within 800ms
const recentRequests = new Map();

// ─────────────────────────────────────────────
// MAIN NAVIGATION INTERCEPTOR
// ─────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only handle main frame (frameId 0), not iframes
  if (details.frameId !== 0) return;

  const url = details.url;
  const tabId = details.tabId;

  // Skip non-web URLs
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;

  // Skip our own block page
  if (url.includes(chrome.runtime.id)) return;

  // Deduplication: skip if same tab+url seen within 800ms
  const dedupKey = `${tabId}:${url}`;
  const now = Date.now();
  if (recentRequests.has(dedupKey) && now - recentRequests.get(dedupKey) < 800) return;
  recentRequests.set(dedupKey, now);

  // Clean up old dedup entries (keep map small)
  if (recentRequests.size > 200) {
    const cutoff = now - 5000;
    for (const [k, t] of recentRequests) {
      if (t < cutoff) recentRequests.delete(k);
    }
  }

  // Call analysis server
  let verdict;
  try {
    verdict = await analyseURL(url);
  } catch (e) {
    // Fail open — never block user due to server error
    return;
  }

  if (!verdict) return;

  // ── ACT ON VERDICT ──
  if (verdict.action === 'block') {
    const blockURL = chrome.runtime.getURL('block.html') +
      '?url=' + encodeURIComponent(url) +
      '&score=' + verdict.score +
      '&signals=' + encodeURIComponent(JSON.stringify(verdict.signals || []));

    chrome.tabs.update(tabId, { url: blockURL });

  } else if (verdict.action === 'warn') {
    // Page loads — inject warning banner after DOM is ready
    chrome.tabs.onUpdated.addListener(function listener(updatedTabId, changeInfo) {
      if (updatedTabId === tabId && changeInfo.status === 'complete') {
        chrome.tabs.onUpdated.removeListener(listener);
        chrome.scripting.executeScript({
          target: { tabId },
          func: injectWarningBanner,
          args: [verdict]
        }).catch(() => {}); // ignore if page navigated away
      }
    });
  }
  // 'allow' → do nothing, page loads normally
});

// ─────────────────────────────────────────────
// SERVER CALL
// ─────────────────────────────────────────────
async function analyseURL(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(SERVER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!response.ok) return null;
    return await response.json();
  } catch {
    clearTimeout(timer);
    return null; // server down or timeout → fail open
  }
}

// ─────────────────────────────────────────────
// WARNING BANNER INJECTOR (runs in page context)
// ─────────────────────────────────────────────
function injectWarningBanner(verdict) {
  // Don't inject twice
  if (document.getElementById('ps-warn-banner')) return;

  const signals = (verdict.signals || []).slice(0, 2).join(' · ') || 'Suspicious activity detected';
  const score = verdict.score || 0;

  const banner = document.createElement('div');
  banner.id = 'ps-warn-banner';
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: #1a1a2e; border-bottom: 3px solid #f39c12;
    padding: 0; margin: 0; font-family: -apple-system, system-ui, sans-serif;
    box-shadow: 0 4px 24px rgba(0,0,0,0.4);
  `;

  banner.innerHTML = `
    <div style="display:flex;align-items:center;gap:16px;padding:12px 20px;flex-wrap:wrap;">
      <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:200px;">
        <div style="background:#f39c12;color:#000;font-weight:700;font-size:11px;
          padding:4px 10px;border-radius:3px;white-space:nowrap;letter-spacing:1px;">
          ⚠ RISK ${score}/100
        </div>
        <span style="color:#e0e0e0;font-size:13px;line-height:1.4;">${signals}</span>
      </div>
      <div style="display:flex;gap:8px;flex-shrink:0;">
        <button id="ps-go-back" style="background:transparent;border:1px solid #555;
          color:#ccc;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;">
          ← Go back
        </button>
        <button id="ps-proceed" style="background:#f39c12;border:none;
          color:#000;padding:6px 14px;border-radius:4px;cursor:pointer;
          font-size:12px;font-weight:600;">
          Proceed anyway
        </button>
        <button id="ps-close" style="background:transparent;border:none;
          color:#666;padding:6px 10px;border-radius:4px;cursor:pointer;font-size:16px;">
          ✕
        </button>
      </div>
    </div>
  `;

  document.body.prepend(banner);

  // Add top padding to body so page content isn't hidden under banner
  document.body.style.paddingTop =
    (parseInt(document.body.style.paddingTop || '0') + banner.offsetHeight) + 'px';

  document.getElementById('ps-go-back').onclick = () => history.back();
  document.getElementById('ps-close').onclick = () => banner.remove();
  document.getElementById('ps-proceed').onclick = () => {
    // Log the proceed action
    chrome.runtime.sendMessage({ type: 'USER_PROCEEDED', url: window.location.href, score: verdict.score });
    banner.remove();
  };
}

// ─────────────────────────────────────────────
// MESSAGE HANDLER (from content.js / block.html)
// ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'USER_PROCEEDED') {
    // Log to server that user bypassed warning
    fetch('http://127.0.0.1:8000/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: msg.url, action: 'proceeded', score: msg.score })
    }).catch(() => {});
  }

  if (msg.type === 'FALSE_POSITIVE') {
    fetch('http://127.0.0.1:8000/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: msg.url, action: 'false_positive', score: msg.score })
    }).catch(() => {});
  }

  if (msg.type === 'PIN_OVERRIDE') {
    // Clear the block cache for this URL so it won't be blocked again
    fetch('http://127.0.0.1:8000/cache/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: msg.url })
    }).catch(() => {});
    sendResponse({ ok: true });
  }
});
