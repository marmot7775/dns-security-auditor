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
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z][A-Za-z0-9-]{1,62}$"
)

# RFC 6376: DKIM selectors are DNS labels -- alphanumeric and hyphens only
SELECTOR_PATTERN = re.compile(r'^[A-Za-z0-9-]{1,63}$')
