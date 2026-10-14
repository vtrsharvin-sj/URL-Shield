// Fills in the block page with the reason for the verdict.
const REASONS = {
  MALICIOUS: 'Google Safe Browsing flagged this site as malicious (malware or phishing).',
  BLACKLISTED: 'This site is on the blacklist of known-bad sites.',
  SSL_FAILED: 'This site has an invalid or expired SSL certificate and is not secure.',
  PHISHING: 'This site looks like a phishing / suspicious site.'
};

const params = new URLSearchParams(location.search);
const verdict = (params.get('verdict') || '').toUpperCase();
const original = params.get('url') || '';

document.getElementById('reason').textContent =
  REASONS[verdict] || 'This site did not pass a safety check.';
document.getElementById('url').textContent = original;

document.getElementById('back').addEventListener('click', () => {
  // Try to leave the blocked site rather than going back onto it.
  if (history.length > 1) {
    history.back();
  } else {
    location.href = 'https://www.google.com';
  }
});
