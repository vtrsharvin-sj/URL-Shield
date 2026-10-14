// URL Shield popup — plain JavaScript, no external libraries.
// Shows the verdict for the active tab. Full protection runs automatically
// in the background service worker; this popup is just a status view plus an
// on-demand full re-scan.

const BACKEND = 'http://localhost:8000';

// Each verdict maps to a message and colour.
const VERDICTS = {
  SAFE: { text: '\u2714 Safe to browse', color: '#0c9d58' },
  PHISHING: { text: '\u26A0 Phishing / suspicious site', color: '#d60000' },
  MALICIOUS: { text: '\u2620 Malicious (Google Safe Browsing)', color: '#d60000' },
  BLACKLISTED: { text: '\u26D4 Blacklisted site (blocked)', color: '#d60000' },
  SSL_FAILED: { text: '\u{1F513} SSL certificate failed', color: '#e67700' }
};

const siteEl = document.getElementById('site');
const resultEl = document.getElementById('result');
const recheckBtn = document.getElementById('recheck');

function setResult(verdict) {
  const info = VERDICTS[verdict] || { text: verdict, color: '#555' };
  resultEl.textContent = info.text;
  resultEl.style.color = info.color;
}

function setStatus(message, color) {
  resultEl.textContent = message;
  resultEl.style.color = color || '#555';
}

function shortUrl(url) {
  return url && url.length > 40 ? url.slice(0, 40) + '\u2026' : url || '';
}

// Query the backend. fast=1 is the quick scan; fast=0 runs the full ML check.
function checkUrl(url, fast) {
  const body = 'fast=' + (fast ? '1' : '0') + '&url=' + encodeURIComponent(url);
  return fetch(BACKEND, {
    method: 'POST',
    headers: { 'Content-type': 'application/x-www-form-urlencoded' },
    body
  }).then((resp) => resp.text()).then((text) => text.trim());
}

function getActiveTab() {
  return new Promise((resolve) => {
    if (!chrome.tabs || !chrome.tabs.query) {
      resolve(null);
      return;
    }
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs && tabs[0] ? tabs[0] : null);
    });
  });
}

async function run(fast) {
  const tab = await getActiveTab();
  if (!tab || !tab.url || !/^https?:\/\//i.test(tab.url)) {
    siteEl.textContent = tab && tab.url ? shortUrl(tab.url) : '\u2014';
    setStatus('Not a web page', '#888');
    return;
  }
  siteEl.textContent = shortUrl(tab.url);
  setStatus(fast ? 'Checking\u2026' : 'Running full scan\u2026');
  try {
    const verdict = await checkUrl(tab.url, fast);
    setResult(verdict);
  } catch (e) {
    setStatus('Backend not reachable', '#e67700');
  }
}

recheckBtn.addEventListener('click', () => run(false));
document.addEventListener('DOMContentLoaded', () => run(true));
