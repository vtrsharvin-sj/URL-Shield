"""Security layer for URL Shield.

Provides the individual checks the backend runs on each URL:
  - logging (every check and its outcome goes to url_shield.log)
  - blacklist read / add (spam & malicious sites are remembered)
  - Google Safe Browsing lookup (malware / phishing / unwanted software)
  - SSL certificate verification

Each verdict is a short upper-case string so the browser popup can map it to
a distinct message and colour:
  SAFE, BLACKLISTED, MALICIOUS, SSL_FAILED, PHISHING
"""

import datetime
import os
import socket
import ssl
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, "..", ".env"))

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
BLACKLIST_PATH = os.path.join(HERE, os.getenv("BLACKLIST_PATH", "blacklist.txt"))
LOG_PATH = os.path.join(HERE, os.getenv("LOG_PATH", "url_shield.log"))

SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + API_KEY
)


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def log(url, verdict, detail=""):
    """Append one line to the log file and echo it to stdout."""
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {verdict:<11} {url}"
    if detail:
        line += f"  ::  {detail}"
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    print(line)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def get_hostname(url):
    parsed = urlparse(url if "//" in url else "http://" + url)
    return parsed.hostname or ""


def _read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [
            ln.strip().lower()
            for ln in fh
            if ln.strip() and not ln.strip().startswith("#")
        ]


# --------------------------------------------------------------------------- #
# Blacklist
# --------------------------------------------------------------------------- #
def is_blacklisted(url):
    host = get_hostname(url).lower()
    for entry in _read_lines(BLACKLIST_PATH):
        if entry and (entry == host or entry in url.lower()):
            return True
    return False


def add_to_blacklist(url, reason=""):
    host = get_hostname(url).lower()
    if not host or is_blacklisted(url):
        return
    try:
        with open(BLACKLIST_PATH, "a", encoding="utf-8") as fh:
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            fh.write(f"{host}  # {reason} ({stamp})\n")
        log(url, "BLACKLIST+", f"added {host}: {reason}")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Google Safe Browsing
# --------------------------------------------------------------------------- #
def safe_browsing_lookup(url):
    """Return (is_threat, threat_type). Fails open (not a threat) on API error."""
    if not API_KEY:
        return False, "NO_API_KEY"

    body = {
        "client": {"clientId": "url-shield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(SAFE_BROWSING_ENDPOINT, json=body, timeout=15)
        if resp.status_code != 200:
            return False, f"API_HTTP_{resp.status_code}"
        data = resp.json()
        matches = data.get("matches")
        if matches:
            return True, matches[0].get("threatType", "THREAT")
        return False, "CLEAN"
    except requests.RequestException as exc:
        return False, f"API_ERROR:{exc}"


# --------------------------------------------------------------------------- #
# SSL certificate verification
# --------------------------------------------------------------------------- #
def check_ssl(url):
    """Return (ok, detail). Only HTTPS URLs are verified; HTTP has no cert."""
    parsed = urlparse(url if "//" in url else "http://" + url)
    if parsed.scheme != "https":
        return False, "NO_HTTPS"

    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        # Verify expiry explicitly for a clearer message.
        not_after = cert.get("notAfter")
        if not_after:
            expires = datetime.datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z"
            )
            if expires < datetime.datetime.utcnow():
                return False, f"EXPIRED:{not_after}"
        return True, "VALID"
    except ssl.SSLCertVerificationError as exc:
        return False, f"CERT_INVALID:{exc.verify_message}"
    except (ssl.SSLError, socket.timeout, socket.gaierror, OSError) as exc:
        return False, f"SSL_ERROR:{exc}"
