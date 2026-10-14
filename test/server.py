"""URL Shield backend.

A small, dependency-light HTTP server that classifies a URL as SAFE or one of
several threat categories. It is called by the browser extension on
http://localhost:8000.

Flow per request:
  1. Read the POSTed "url" field (and optional "fast" flag).
  2. Run the security checks in priority order (see run_prediction).
  3. Return a single verdict string.
"""

import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs

import requests

import security_checks as sec

HERE = os.path.dirname(os.path.abspath(__file__))
MARKUP_PATH = os.path.join(HERE, "markup.txt")
PORT = 8000


def fetch_html(url):
    try:
        resp = requests.get(
            url,
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (URL Shield)"},
        )
        return resp.content
    except Exception as exc:  # noqa: BLE001
        print(f"[server] could not fetch {url}: {exc}", file=sys.stderr)
        return b""


def run_ml_model(url):
    """Run the pretrained MLP model via test.py. Returns 'SAFE' or 'PHISHING'."""
    try:
        result = subprocess.run(
            [sys.executable, "test.py", url],
            cwd=HERE,
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        print(f"[server] ML prediction timed out for {url}", file=sys.stderr)
        output = ""
    decision = "PHISHING"
    for line in output.splitlines():
        token = line.strip().upper()
        if token in ("SAFE", "PHISHING"):
            decision = token
    return decision


def run_prediction(url, fast=False):
    """Run every security check in priority order and return a verdict string.

    Priority (first failure wins):
      1. BLACKLISTED  - already known-bad from a previous check
      2. MALICIOUS    - Google Safe Browsing flagged it (also blacklisted)
      3. SSL_FAILED   - HTTPS cert missing / invalid / expired
      4. PHISHING     - pretrained ML model's verdict (skipped when fast=True)
      5. SAFE         - passed everything

    fast=True is used for automatic, in-browser checks on every navigation:
    it skips the slow ML model (WHOIS + Google search) and the heavy page
    fetch, so the browser isn't held up. The popup uses fast=False for a full,
    thorough check including the ML model.
    """
    # 1. Blacklist (fast, no network).
    if sec.is_blacklisted(url):
        sec.log(url, "BLACKLISTED", "matched blacklist")
        return "BLACKLISTED"

    # 2. Google Safe Browsing (fast network call).
    threat, threat_type = sec.safe_browsing_lookup(url)
    if threat:
        sec.log(url, "MALICIOUS", f"Safe Browsing: {threat_type}")
        sec.add_to_blacklist(url, f"safe-browsing {threat_type}")
        return "MALICIOUS"

    # 3. SSL certificate verification (only meaningful for HTTPS).
    ok, ssl_detail = sec.check_ssl(url)
    if not ok and ssl_detail != "NO_HTTPS":
        sec.log(url, "SSL_FAILED", ssl_detail)
        return "SSL_FAILED"

    # 4. Pretrained ML model (slow: skipped in fast mode).
    #    The model reads markup.txt, so fetch the page first in full mode.
    if not fast:
        html = fetch_html(url)
        with open(MARKUP_PATH, "wb") as fh:
            fh.write(html)
        ml_verdict = run_ml_model(url)
        if ml_verdict == "PHISHING":
            sec.log(url, "PHISHING", "ML model (MLPClassifier)")
            sec.add_to_blacklist(url, "ml phishing")
            return "PHISHING"

    # 5. Clean on every check.
    mode = "fast" if fast else "full"
    sec.log(url, "SAFE", f"[{mode}] ssl={ssl_detail}, safe-browsing=clean")
    return "SAFE"


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        fields = parse_qs(body)
        url = (fields.get("url", [""])[0]).strip()
        # fast=1 -> quick automatic check (background worker); default is full.
        fast = (fields.get("fast", ["0"])[0]).strip() in ("1", "true", "True")

        if not url:
            self.send_response(400)
            self._cors()
            self.end_headers()
            self.wfile.write(b"NO URL")
            return

        decision = run_prediction(url, fast=fast)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self._cors()
        self.end_headers()
        self.wfile.write(decision.encode("utf-8"))

    def log_message(self, *args):
        pass  # keep console clean; we print our own lines


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    print(f"URL Shield backend running on http://127.0.0.1:{PORT}")
    print("Model: MLPClassifier (loaded from models/mlp_model.pkl)")
    print("Checks: blacklist > Safe Browsing > SSL > ML model")
    sys.stdout.flush()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
