/**
 * PHISHING SHIELD — content.js
 * Injected into every page at document_start.
 * Listens for messages from background.js to inject the warning banner.
 * Also handles "proceed anyway" user action logging.
 */

// Listen for direct script execution from background.js
// (background uses chrome.scripting.executeScript → injectWarningBanner)
// This file is also used for relaying messages.

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'INJECT_WARN') {
    injectWarningBanner(msg.verdict);
  }
});

function injectWarningBanner(verdict) {
  if (document.getElementById('ps-warn-banner')) return;

  const signals = (verdict.signals || []).slice(0, 2).join(' · ') || 'Suspicious content detected';
  const score = verdict.score || 0;

  const banner = document.createElement('div');
  banner.id = 'ps-warn-banner';
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: #1a1a2e; border-bottom: 3px solid #f39c12;
    font-family: -apple-system, system-ui, sans-serif;
    box-shadow: 0 4px 24px rgba(0,0,0,0.5);
    animation: ps-slide-down 0.25s ease;
  `;

  // Inject keyframes once
  if (!document.getElementById('ps-styles')) {
    const style = document.createElement('style');
    style.id = 'ps-styles';
    style.textContent = `
      @keyframes ps-slide-down {
        from { transform: translateY(-100%); opacity: 0; }
        to   { transform: translateY(0);    opacity: 1; }
      }
    `;
    document.head.appendChild(style);
  }

  banner.innerHTML = `
    <div style="display:flex;align-items:center;gap:14px;padding:11px 20px;flex-wrap:wrap;">
      <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:180px;">
        <span style="background:#f39c12;color:#000;font-weight:800;font-size:10px;
          padding:3px 9px;border-radius:2px;letter-spacing:1.5px;white-space:nowrap;">
          ⚠ ${score}/100
        </span>
        <span style="color:#ccc;font-size:12px;line-height:1.5;">${signals}</span>
      </div>
      <div style="display:flex;gap:8px;">
        <button id="ps-back-btn"
          style="background:transparent;border:1px solid #444;color:#bbb;
          padding:5px 13px;border-radius:4px;cursor:pointer;font-size:12px;
          transition:border-color 0.15s;">
          ← Back
        </button>
        <button id="ps-proceed-btn"
          style="background:#f39c12;border:none;color:#000;font-weight:700;
          padding:5px 13px;border-radius:4px;cursor:pointer;font-size:12px;">
          Proceed
        </button>
        <button id="ps-dismiss-btn"
          style="background:transparent;border:none;color:#555;
          padding:5px 8px;cursor:pointer;font-size:15px;line-height:1;">
          ✕
        </button>
      </div>
    </div>
  `;

  document.body.insertBefore(banner, document.body.firstChild);

  document.getElementById('ps-back-btn').onclick = () => history.back();
  document.getElementById('ps-dismiss-btn').onclick = () => banner.remove();
  document.getElementById('ps-proceed-btn').onclick = () => {
    chrome.runtime.sendMessage({
      type: 'USER_PROCEEDED',
      url: window.location.href,
      score: verdict.score
    });
    banner.remove();
  };
}
