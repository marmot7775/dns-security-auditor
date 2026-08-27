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
# defaults to loopback. But the Procfile runs uvicorn on 0.0.0.0 directly,
# where a client that connects straight to it could set X-Real-IP itself
# and rotate it to dodge the per-IP rate limit -- so the header must not
# be trusted unless it actually came through a known proxy.
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
