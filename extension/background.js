// URL Shield background service worker.
// Runs automatically on every page navigation (no popup click needed):
//   1. Classifies each URL via the local backend.
//   2. Redirects dangerous pages to a local block page.
//   3. Tracks which hosts are trusted (verdict SAFE) so the content script
//      can block camera/mic/location requests on untrusted sites.
//   4. Cancels risky file downloads from untrusted sites.

const BACKEND = 'http://localhost:8000';

// Verdicts that block the whole page (SAFE is allowed; the rest redirect).
const BLOCK_VERDICTS = new Set([
  'PHISHING',
  'MALICIOUS',
  'BLACKLISTED',
  'SSL_FAILED'
]);

// File extensions considered dangerous to download from an untrusted site.
const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'bat', 'cmd', 'com', 'scr', 'pif', 'msi', 'msp', 'hta', 'cpl',
  'jar', 'js', 'jse', 'vbs', 'vbe', 'ws', 'wsf', 'wsh', 'ps1', 'psm1',
  'reg', 'dll', 'apk', 'app', 'dmg', 'iso', 'img', 'ade', 'adp'
]);

// Short-lived verdict cache (keyed by full URL) and a per-host trust map
// (keyed by hostname) so lookups from the content script are instant.
const cache = new Map();
const hostVerdict = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return '';
  }
}

function isWebUrl(url) {
  return /^https?:\/\//i.test(url);
}

async function classify(url) {
  const cached = cache.get(url);
  if (cached && Date.now() - cached.time < CACHE_TTL_MS) {
    return cached.verdict;
  }
  const body = 'fast=1&url=' + encodeURIComponent(url);
  const resp = await fetch(BACKEND, {
    method: 'POST',
    headers: { 'Content-type': 'application/x-www-form-urlencoded' },
    body
  });
  const verdict = (await resp.text()).trim();
  cache.set(url, { verdict, time: Date.now() });
  const host = hostOf(url);
  if (host) {
    hostVerdict.set(host, verdict);
  }
  return verdict;
}

// A host is "trusted" only when it was explicitly classified SAFE.
// Unknown or flagged hosts are untrusted (fail-closed for permissions).
function isHostTrusted(host) {
  return hostVerdict.get(host) === 'SAFE';
}

function blockedPageUrl(originalUrl, verdict) {
  return (
    chrome.runtime.getURL('blocked.html') +
    '?verdict=' + encodeURIComponent(verdict) +
    '&url=' + encodeURIComponent(originalUrl)
  );
}

async function checkAndMaybeBlock(tabId, url) {
  if (!isWebUrl(url)) {
    return;
  }
  if (url.startsWith(chrome.runtime.getURL(''))) {
    return; // never re-check our own block page
  }
  try {
    const verdict = await classify(url);
    updateBadge(tabId, verdict);
    if (BLOCK_VERDICTS.has(verdict)) {
      chrome.tabs.update(tabId, { url: blockedPageUrl(url, verdict) });
    }
  } catch (e) {
    updateBadge(tabId, 'OFFLINE');
  }
}

function updateBadge(tabId, verdict) {
  const map = {
    SAFE: { text: 'OK', color: '#00AA55' },
    PHISHING: { text: '!', color: '#D60000' },
    MALICIOUS: { text: 'X', color: '#D60000' },
    BLACKLISTED: { text: 'X', color: '#D60000' },
    SSL_FAILED: { text: 'SSL', color: '#E67700' },
    OFFLINE: { text: '--', color: '#888888' }
  };
  const info = map[verdict] || { text: '', color: '#888888' };
  try {
    chrome.action.setBadgeBackgroundColor({ tabId, color: info.color });
    chrome.action.setBadgeText({ tabId, text: info.text });
  } catch (e) {
    // tab may be gone
  }
}

// ------------------------------------------------------------------ //
// Navigation listeners
// ------------------------------------------------------------------ //
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) {
    checkAndMaybeBlock(details.tabId, details.url);
  }
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId === 0) {
    checkAndMaybeBlock(details.tabId, details.url);
  }
});

// ------------------------------------------------------------------ //
// Content-script trust queries (camera / mic / location guard)
// ------------------------------------------------------------------ //
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === 'URLSHIELD_IS_TRUSTED') {
    const host = hostOf(msg.url || (sender.tab && sender.tab.url) || '');
    // If we already have a verdict, answer immediately; otherwise classify.
    if (hostVerdict.has(host)) {
      sendResponse({ trusted: isHostTrusted(host) });
      return true;
    }
    classify(msg.url || (sender.tab && sender.tab.url))
      .then(() => sendResponse({ trusted: isHostTrusted(host) }))
      .catch(() => sendResponse({ trusted: false })); // fail-closed
    return true; // keep the message channel open for the async response
  }
  return false;
});

// ------------------------------------------------------------------ //
// Dangerous download blocking
// ------------------------------------------------------------------ //
function extensionOf(name) {
  const clean = (name || '').split(/[?#]/)[0];
  const dot = clean.lastIndexOf('.');
  return dot >= 0 ? clean.slice(dot + 1).toLowerCase() : '';
}

chrome.downloads.onCreated.addListener((item) => {
  const ext = extensionOf(item.filename || item.finalUrl || item.url);
  if (!DANGEROUS_EXTENSIONS.has(ext)) {
    return; // not a risky file type
  }
  const sourceHost = hostOf(item.referrer || item.finalUrl || item.url);
  if (sourceHost && isHostTrusted(sourceHost)) {
    return; // allow downloads from sites verified SAFE
  }
  // Cancel + erase the download and notify the user.
  chrome.downloads.cancel(item.id, () => {
    chrome.downloads.erase({ id: item.id });
    notifyBlockedDownload(ext, sourceHost || 'an untrusted site');
  });
});

function notifyBlockedDownload(ext, host) {
  try {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icon.png',
      title: 'URL Shield blocked a download',
      message: `Blocked a .${ext} file from ${host}. Downloads of this type ` +
        `are only allowed from trusted sites.`
    });
  } catch (e) {
    // notifications permission missing or API unavailable
  }
}
