"""
DNS Security Auditor - FastAPI Server
======================================
GET  /api/audit?domain=example.com  -- run full audit
GET  /                               -- serve frontend
GET  /static/*                       -- serve static assets

Usage:
    uvicorn server:app --host 0.0.0.0 --port 8000
"""

import re
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from audit_engine import run_full_audit


# ============================================================
# App
# ============================================================

app = FastAPI(
    title="DNS Security Auditor",
    description="Comprehensive DNS and email security auditing",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ============================================================
# Simple in-memory cache (TTL-based)
# ============================================================

_cache: dict = {}
CACHE_TTL = 300  # 5 minutes


def _get_cached(domain: str) -> Optional[dict]:
    entry = _cache.get(domain)
    if entry and (time.time() - entry["ts"]) < CACHE_TTL:
        return entry["data"]
    return None


def _set_cached(domain: str, data: dict):
    _cache[domain] = {"data": data, "ts": time.time()}
    # Evict old entries if cache grows too large
    if len(_cache) > 500:
        oldest = sorted(_cache.items(), key=lambda x: x[1]["ts"])[:100]
        for key, _ in oldest:
            del _cache[key]


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

@app.get("/api/audit")
async def audit_domain(
    domain: str = Query(..., description="Domain to audit (e.g., example.com)"),
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
    domain = _validate_domain(domain)

    # Check cache
    if not nocache:
        cached = _get_cached(domain)
        if cached:
            return JSONResponse(content=cached)

    # Run audit
    try:
        result = run_full_audit(domain)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Audit failed: {str(e)[:200]}",
        )

    # Cache result
    _set_cached(domain, result)

    return JSONResponse(content=result)


# ============================================================
# Health check
# ============================================================

@app.get("/api/health")
async def health():
    return {"status": "ok", "cache_size": len(_cache)}


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
