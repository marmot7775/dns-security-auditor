"""
DNS Security Auditor - FastAPI Server
======================================
GET  /api/audit?domain=example.com  -- run full audit
GET  /api/health                     -- health check
GET  /docs                           -- interactive API docs
GET  /                               -- serve frontend
GET  /static/*                       -- serve static assets

Usage:
    uvicorn server:app --host 0.0.0.0 --port 8000
"""

import logging
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from audit_engine import run_full_audit


# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("dns-auditor")


# ============================================================
# App
# ============================================================

app = FastAPI(
    title="DNS Security Auditor",
    description=(
        "Comprehensive DNS and email security auditing API. "
        "Checks DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, and Nameservers."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://dns-audit.com",
        "https://www.dns-audit.com",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ============================================================
# Security headers middleware
# ============================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

app.add_middleware(SecurityHeadersMiddleware)


# ============================================================
# Rate limiting (in-memory, per-IP)
# ============================================================

_rate_limits: dict = defaultdict(list)
RATE_LIMIT_MAX = 10       # max requests
RATE_LIMIT_WINDOW = 60    # per 60 seconds


def _check_rate_limit(client_ip: str) -> bool:
    """Return True if the request is allowed, False if rate-limited."""
    now = time.time()
    # Prune old timestamps
    _rate_limits[client_ip] = [
        ts for ts in _rate_limits[client_ip]
        if now - ts < RATE_LIMIT_WINDOW
    ]
    if len(_rate_limits[client_ip]) >= RATE_LIMIT_MAX:
        return False
    _rate_limits[client_ip].append(now)
    # Prevent unbounded memory growth: prune stale IPs periodically
    if len(_rate_limits) > 10000:
        cutoff = now - RATE_LIMIT_WINDOW
        stale = [ip for ip, ts in _rate_limits.items() if not ts or ts[-1] < cutoff]
        for ip in stale:
            del _rate_limits[ip]
    return True


# ============================================================
# Simple in-memory cache (TTL-based)
# ============================================================

_cache: dict = {}
CACHE_TTL = 300  # 5 minutes
CACHE_MAX_SIZE = 500


def _get_cached(domain: str) -> Optional[dict]:
    entry = _cache.get(domain)
    if entry and (time.time() - entry["ts"]) < CACHE_TTL:
        return entry["data"]
    # Expired — clean up
    if entry:
        del _cache[domain]
    return None


def _set_cached(domain: str, data: dict):
    _cache[domain] = {"data": data, "ts": time.time()}
    # Evict oldest entries if cache grows too large
    if len(_cache) > CACHE_MAX_SIZE:
        oldest = sorted(_cache.items(), key=lambda x: x[1]["ts"])[:100]
        for key, _ in oldest:
            _cache.pop(key, None)


# ============================================================
# Domain validation
# ============================================================

DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def _validate_domain(domain: str) -> str:
    """Normalize and validate a domain string."""
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")

    # Normalize
    d = domain.strip().lower()
    if "@" in d:
        d = d.split("@")[-1]
    d = d.replace("http://", "").replace("https://", "").replace("www.", "")
    d = d.split("/")[0].split("?")[0].rstrip(".")

    if not d:
        raise HTTPException(status_code=400, detail="Invalid domain")

    if not DOMAIN_PATTERN.match(d):
        raise HTTPException(
            status_code=400,
            detail=f"'{d}' does not look like a valid domain name",
        )

    if len(d) > 253:
        raise HTTPException(status_code=400, detail="Domain name too long")

    return d


# ============================================================
# API Endpoint
# ============================================================

@app.get("/api/audit", tags=["Audit"])
async def audit_domain(
    request: Request,
    domain: str = Query(..., description="Domain to audit (e.g., example.com)"),
    selector: Optional[str] = Query(None, description="DKIM selector (e.g., google, s1)"),
    scope: Optional[str] = Query(None, description="Audit scope: complete, email_full, dmarc, transport, dns_infra, security_scan"),
    nocache: bool = Query(False, description="Bypass cache"),
):
    """
    Run a comprehensive DNS and email security audit.

    Returns:
    - Security grade (A-F) with numeric score
    - Individual check results (DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC)
    - Priority fixes
    - Detected email vendors
    """
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please wait a minute before trying again."},
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
        )

    domain = _validate_domain(domain)
    log.info("Audit requested: %s (scope=%s, ip=%s)", domain, scope or "complete", client_ip)

    # Check cache
    if not nocache:
        cached = _get_cached(domain)
        if cached:
            log.info("Cache hit: %s", domain)
            return JSONResponse(content=cached)

    # Run audit
    start = time.time()
    try:
        result = run_full_audit(domain, dkim_selector=selector)
    except Exception as e:
        log.error("Audit failed for %s: %s", domain, str(e)[:200])
        raise HTTPException(
            status_code=500,
            detail=f"Audit failed: {str(e)[:200]}",
        )

    elapsed = round(time.time() - start, 2)
    log.info("Audit complete: %s — %.2fs, grade=%s", domain, elapsed, result.get("score", {}).get("grade", "?"))

    # Cache result
    _set_cached(domain, result)

    return JSONResponse(content=result)


# ============================================================
# Health check
# ============================================================

@app.get("/api/health", tags=["System"])
async def health():
    """Health check endpoint for monitoring."""
    return {
        "status": "ok",
        "version": "2.0.0",
        "cache_size": len(_cache),
        "checks": [
            "DMARC", "SPF", "DKIM", "MX", "MTA-STS",
            "TLS-RPT", "BIMI", "DNSSEC", "CAA", "Nameservers",
        ],
    }


# ============================================================
# Static files & frontend
# ============================================================

STATIC_DIR = Path(__file__).parent / "static"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    async def index():
        return FileResponse(str(STATIC_DIR / "index.html"))
else:
    @app.get("/")
    async def index():
        return {"message": "DNS Security Auditor API. Put static files in ./static/"}

