"""
Centralized configuration for DNS Security Auditor.

All settings loaded from environment variables with sensible defaults.
"""

import os
import re


# ============================================================
# Environment
# ============================================================

ENVIRONMENT = os.getenv("ENVIRONMENT", "production")

# ============================================================
# Logging
# ============================================================

LOG_DIR = os.getenv("LOG_DIR", "./logs")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# ============================================================
# Cache
# ============================================================

CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))          # seconds
CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "500"))

# ============================================================
# Rate limiting
# ============================================================

RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "10"))       # max requests
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60")) # per N seconds
RATE_LIMIT_MAX_IPS = int(os.getenv("RATE_LIMIT_MAX_IPS", "10000"))

# ============================================================
# Concurrency
# ============================================================

MAX_CONCURRENT_AUDITS = int(os.getenv("MAX_CONCURRENT_AUDITS", "8"))

# ============================================================
# Reverse proxy trust
# ============================================================

# Only trust the X-Real-IP header when the direct TCP peer is one of these
# addresses. Behind nginx (dns-auditor.service) that's loopback, so this
# defaults to loopback. Someone running uvicorn on 0.0.0.0 directly exposes
# it to clients that could set X-Real-IP themselves and rotate it to dodge
# the per-IP rate limit -- so the header must not be trusted unless it
# actually came through a known proxy.
_trusted_proxies_raw = os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1,::1")
TRUSTED_PROXY_IPS = {ip.strip() for ip in _trusted_proxies_raw.split(",") if ip.strip()}

# ============================================================
# CORS
# ============================================================

_cors_raw = os.getenv("CORS_ORIGINS", "https://dns-audit.com,https://www.dns-audit.com")
CORS_ORIGINS = [o.strip() for o in _cors_raw.split(",") if o.strip()]

# ============================================================
# API
# ============================================================

API_BASE_URL = os.getenv("API_BASE_URL", "/api")

# ============================================================
# Validation patterns
# ============================================================

DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z][A-Za-z0-9-]{1,62}(?<!-)$"
)

# RFC 6376: DKIM selectors are DNS labels -- alphanumeric and hyphens only
SELECTOR_PATTERN = re.compile(r'^[A-Za-z0-9-]{1,63}$')

# ============================================================
# Build identity
# ============================================================

def _read_build_sha() -> str:
    """Short commit SHA of the running checkout, exposed by /api/health.

    The deploy is a git pull plus a systemctl restart, so the checkout is the
    only thing that knows which commit is live. Static asset URLs cannot
    answer it: the cache-busting step rewrites ?v= only when something under
    static/ changes, so a Python-only commit leaves every asset pinned to an
    older build and looks identical from outside. That is exactly the case
    where a skipped restart is invisible.

    Read .git directly instead of shelling out to git. This runs at import in
    the same process that serves requests, and a subprocess per start buys
    nothing. BUILD_SHA overrides it for a deploy that ships without a working
    tree.
    """
    override = os.getenv("BUILD_SHA", "").strip()
    if override:
        return override[:40]

    git_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".git")
    try:
        with open(os.path.join(git_dir, "HEAD"), encoding="utf-8") as fh:
            head = fh.read().strip()
    except OSError:
        return "unknown"

    if not head.startswith("ref:"):
        # Detached HEAD stores the commit id itself. Hex length is 40 for a
        # SHA-1 repository and 64 for a SHA-256 one.
        return head[:7] if re.fullmatch(r"[0-9a-f]{40,64}", head) else "unknown"

    ref = head[4:].strip()
    if not ref.startswith("refs/") or ".." in ref:
        return "unknown"

    try:
        with open(os.path.join(git_dir, *ref.split("/")), encoding="utf-8") as fh:
            return fh.read().strip()[:7]
    except OSError:
        pass

    # A ref that has been packed has no loose file under .git/refs.
    try:
        with open(os.path.join(git_dir, "packed-refs"), encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(("#", "^")):
                    continue
                sha, _, name = line.strip().partition(" ")
                if name == ref:
                    return sha[:7]
    except OSError:
        pass

    return "unknown"


BUILD_SHA = _read_build_sha()
