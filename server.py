"""
DNS Security Auditor - FastAPI Server
======================================
GET  /api/audit?domain=example.com  -- run full audit
GET  /api/audit/pdf?domain=...      -- download PDF report
GET  /api/health                     -- health check
GET  /docs                           -- interactive API docs
GET  /                               -- serve frontend
GET  /static/*                       -- serve static assets

Usage:
    uvicorn server:app --host 0.0.0.0 --port 8000
"""

import asyncio
import json
import logging
import queue
import re
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from audit_engine import run_full_audit
from pdf_report import generate_audit_pdf


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
# Audit log (GDPR-safe -- no IP, no geolocation)
# ============================================================

AUDIT_LOG_PATH = Path(__file__).parent / "audit.log"
_audit_log_lock = threading.Lock()


def _log_audit(request: Request, domain: str, scope: str, grade: str,
               duration: float, checks: int, source: str = "web"):
    """Write a GDPR-safe JSON-lines audit log entry.

    Logged: domain, timestamp, scope, grade, duration, check count,
            user-agent (browser/OS only), source (web/sse/pdf).
    NOT logged: IP address, geolocation, cookies, personal data.
    """
    ua = request.headers.get("User-Agent", "unknown")
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domain": domain,
        "scope": scope or "complete",
        "grade": grade,
        "duration_s": duration,
        "checks": checks,
        "ua": ua[:200],
        "source": source,
    }
    try:
        with _audit_log_lock:
            with open(AUDIT_LOG_PATH, "a") as f:
                f.write(json.dumps(entry) + "\n")
    except Exception as e:
        log.warning("Audit log write failed: %s", e)


# ============================================================
# App
# ============================================================

app = FastAPI(
    title="DNS Security Auditor",
    description=(
        "Comprehensive DNS and email security auditing API. "
        "Checks DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, DANE, Nameservers, Certificate Transparency, and Blocklist."
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
    allow_headers=["Content-Type", "Accept"],
)


# ============================================================
# Security headers middleware
# ============================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    CSP = (
        "default-src 'self'; "
        "font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "style-src 'self' https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = self.CSP
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path in ("/", "/index.html"):
            # Don't let Cloudflare cache the HTML -- cache-bust params need to reach the browser
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response

app.add_middleware(SecurityHeadersMiddleware)


# ============================================================
# Rate limiting (in-memory, per-IP)
# ============================================================

_rate_limits: dict = defaultdict(list)
_rate_lock = threading.Lock()
RATE_LIMIT_MAX = 10       # max requests
RATE_LIMIT_WINDOW = 60    # per 60 seconds

# DKIM selector validation (DNS label characters only)
SELECTOR_PATTERN = re.compile(r'^[A-Za-z0-9._-]{1,63}$')


def _get_client_ip(request: Request) -> str:
    """Get real client IP behind Cloudflare/reverse proxy."""
    # Cloudflare sets CF-Connecting-IP to the real visitor IP
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    # Standard proxy header (first IP in chain is the client)
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(client_ip: str) -> bool:
    """Return True if the request is allowed, False if rate-limited."""
    now = time.time()
    with _rate_lock:
        # Prune old timestamps
        timestamps = [
            ts for ts in _rate_limits[client_ip]
            if now - ts < RATE_LIMIT_WINDOW
        ]
        if not timestamps:
            # Clean up empty entries instead of keeping them
            _rate_limits.pop(client_ip, None)
            _rate_limits[client_ip] = [now]
            return True
        if len(timestamps) >= RATE_LIMIT_MAX:
            _rate_limits[client_ip] = timestamps
            return False
        timestamps.append(now)
        _rate_limits[client_ip] = timestamps
    return True


# ============================================================
# Simple in-memory cache (TTL-based)
# ============================================================

_cache: dict = {}
_cache_lock = threading.Lock()
CACHE_TTL = 300  # 5 minutes
CACHE_MAX_SIZE = 500


def _get_cached(cache_key: str) -> Optional[dict]:
    with _cache_lock:
        entry = _cache.get(cache_key)
        if entry and (time.time() - entry["ts"]) < CACHE_TTL:
            return entry["data"]
        # Expired -- clean up
        if entry:
            del _cache[cache_key]
    return None


def _set_cached(cache_key: str, data: dict):
    with _cache_lock:
        _cache[cache_key] = {"data": data, "ts": time.time()}
        # Evict oldest entries if cache grows too large
        if len(_cache) > CACHE_MAX_SIZE:
            oldest = sorted(_cache.items(), key=lambda x: x[1]["ts"])[:100]
            for key, _ in oldest:
                _cache.pop(key, None)


# ============================================================
# Domain validation
# ============================================================

DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
)


def _validate_domain(domain: str) -> str:
    """Normalize and validate a domain string."""
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")

    # Normalize
    d = domain.strip().lower()
    if "@" in d:
        d = d.split("@")[-1]
    d = d.removeprefix("http://").removeprefix("https://").removeprefix("www.")
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


_VALID_SCOPES = {"complete", "email_full", "dmarc", "transport", "dns_infra", "security_scan"}


def _validate_scope(scope: Optional[str]) -> Optional[str]:
    """Validate scope parameter. Returns None for default (complete)."""
    if not scope:
        return None
    s = scope.strip().lower()
    if s not in _VALID_SCOPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scope '{scope}'. Valid scopes: {', '.join(sorted(_VALID_SCOPES))}",
        )
    return s


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
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please wait a minute before trying again."},
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
        )

    domain = _validate_domain(domain)
    scope = _validate_scope(scope)
    if selector and not SELECTOR_PATTERN.match(selector.strip()):
        raise HTTPException(status_code=400, detail="Invalid DKIM selector")
    log.info("Audit requested: %s (scope=%s, ip=%s)", domain, scope or "complete", client_ip)

    cache_key = f"{domain}:{selector or ''}:{scope or 'complete'}"

    # Check cache
    if not nocache:
        cached = _get_cached(cache_key)
        if cached:
            log.info("Cache hit: %s", domain)
            return JSONResponse(content=cached)

    # Run audit
    start = time.time()
    try:
        result = run_full_audit(domain, dkim_selector=selector, scope=scope)
    except Exception as e:
        log.error("Audit failed for %s: %s", domain, str(e)[:200], exc_info=True)
        # Return a minimal error result instead of a 500 so the frontend can show something
        result = {
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": {"total": 0, "grade": "?"},
            "checks": [],
            "priority_fixes": [],
            "vendors": [],
            "error": "Audit could not complete. Please try again or check that the domain exists.",
        }

    elapsed = round(time.time() - start, 2)
    log.info("Audit complete: %s -- %.2fs, grade=%s", domain, elapsed, result.get("score", {}).get("grade", "?"))

    # Audit log (GDPR-safe)
    _log_audit(request, domain, scope,
               result.get("score", {}).get("grade", "?"),
               elapsed, len(result.get("checks", [])), source="web")

    # Cache result (skip caching errors -- they may be transient)
    if "error" not in result:
        _set_cached(cache_key, result)

    return JSONResponse(content=result)


# ============================================================
# SSE Streaming Endpoint
# ============================================================

@app.get("/api/audit/stream", tags=["Audit"])
async def audit_stream(
    request: Request,
    domain: str = Query(..., description="Domain to audit"),
    selector: Optional[str] = Query(None, description="DKIM selector"),
    scope: Optional[str] = Query(None, description="Audit scope"),
    nocache: bool = Query(False, description="Bypass cache"),
):
    """Stream audit progress via Server-Sent Events."""
    # Rate limiting
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        # SSE can't return 429 cleanly, so stream an error event
        async def _rate_error():
            yield f"data: {json.dumps({'error': 'Rate limit exceeded. Please wait a minute before trying again.'})}\n\n"
        return StreamingResponse(_rate_error(), media_type="text/event-stream")

    domain = _validate_domain(domain)
    scope = _validate_scope(scope)
    if selector and not SELECTOR_PATTERN.match(selector.strip()):
        raise HTTPException(status_code=400, detail="Invalid DKIM selector")
    log.info("SSE audit requested: %s (scope=%s, ip=%s)", domain, scope or "complete", client_ip)

    cache_key = f"{domain}:{selector or ''}:{scope or 'complete'}"

    # Check cache -- if cached, send result immediately
    if not nocache:
        cached = _get_cached(cache_key)
        if cached:
            log.info("SSE cache hit: %s", domain)
            async def _cached_stream():
                yield f"data: {json.dumps({'done': True, 'result': cached, 'cached': True})}\n\n"
            return StreamingResponse(_cached_stream(), media_type="text/event-stream")

    # Run audit in a background thread, streaming progress via a queue
    progress_q: queue.Queue = queue.Queue()

    def _progress_callback(step_name, completed, total):
        progress_pct = int((completed / total) * 100) if total else 0
        progress_q.put({
            "step": step_name,
            "progress": progress_pct,
            "total_checks": total,
            "completed": completed,
        })

    def _run_audit():
        try:
            result = run_full_audit(domain, dkim_selector=selector, scope=scope,
                                    progress_callback=_progress_callback)
            progress_q.put({"_done": True, "_result": result})
        except Exception as e:
            log.error("SSE audit failed for %s: %s", domain, str(e)[:200], exc_info=True)
            error_result = {
                "domain": domain,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "score": {"total": 0, "grade": "?"},
                "checks": [],
                "priority_fixes": [],
                "vendors": [],
                "error": "Audit could not complete. Please try again or check that the domain exists.",
            }
            progress_q.put({"_done": True, "_result": error_result})

    sse_start_time = time.time()
    audit_thread = threading.Thread(target=_run_audit, daemon=True)
    audit_thread.start()

    async def _event_stream():
        loop = asyncio.get_running_loop()
        while True:
            try:
                msg = await loop.run_in_executor(None, lambda: progress_q.get(timeout=0.2))
            except queue.Empty:
                # Check if client disconnected
                if await request.is_disconnected():
                    log.info("SSE client disconnected: %s", domain)
                    return
                continue

            if "_done" in msg:
                result = msg["_result"]
                # Skip caching errors -- they may be transient
                if "error" not in result:
                    _set_cached(cache_key, result)
                elapsed = round(time.time() - sse_start_time, 2)
                log.info("SSE audit complete: %s -- %.2fs, grade=%s",
                         domain, elapsed, result.get("score", {}).get("grade", "?"))
                # Audit log (GDPR-safe)
                _log_audit(request, domain, scope,
                           result.get("score", {}).get("grade", "?"),
                           elapsed, len(result.get("checks", [])), source="sse")
                yield f"data: {json.dumps({'done': True, 'result': result})}\n\n"
                return
            else:
                yield f"data: {json.dumps(msg)}\n\n"

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ============================================================
# PDF Report Endpoint
# ============================================================

@app.get("/api/audit/pdf", tags=["Audit"])
async def audit_pdf(
    request: Request,
    domain: str = Query(..., description="Domain to generate PDF report for"),
    selector: Optional[str] = Query(None, description="DKIM selector"),
):
    """
    Download a professional PDF audit report.

    Reuses cached audit data when available; otherwise runs a fresh audit.
    """
    # Rate limiting (shared with /api/audit)
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please wait a minute before trying again."},
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
        )

    domain = _validate_domain(domain)
    if selector and not SELECTOR_PATTERN.match(selector.strip()):
        raise HTTPException(status_code=400, detail="Invalid DKIM selector")
    log.info("PDF requested: %s (ip=%s)", domain, client_ip)

    cache_key = f"{domain}:{selector or ''}:complete"

    # Reuse cached audit data if available
    cached = _get_cached(cache_key)
    if cached:
        data = cached
        log.info("PDF using cached data: %s", domain)
    else:
        # Run fresh audit (always complete scope for PDF)
        start = time.time()
        try:
            data = run_full_audit(domain, dkim_selector=selector, scope="complete")
        except Exception as e:
            log.error("PDF audit failed for %s: %s", domain, str(e)[:200], exc_info=True)
            raise HTTPException(status_code=500, detail="Audit failed -- cannot generate PDF")
        elapsed = round(time.time() - start, 2)
        log.info("PDF audit complete: %s -- %.2fs", domain, elapsed)
        _set_cached(cache_key, data)

    # Generate PDF
    try:
        pdf_bytes = generate_audit_pdf(data)
    except Exception as e:
        log.error("PDF generation failed for %s: %s", domain, str(e)[:200], exc_info=True)
        raise HTTPException(status_code=500, detail="PDF generation failed")

    filename = f"dns-audit-{domain}.pdf"
    return Response(
        content=bytes(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}",
            "Cache-Control": "no-store",
        },
    )


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
# SEO: robots.txt & sitemap.xml
# ============================================================

@app.get("/robots.txt", response_class=PlainTextResponse, tags=["SEO"])
async def robots_txt():
    return (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /api/\n"
        "Disallow: /docs\n"
        "Disallow: /redoc\n"
        "\n"
        "Sitemap: https://dns-audit.com/sitemap.xml\n"
    )


@app.get("/sitemap.xml", tags=["SEO"])
async def sitemap_xml():
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "  <url>\n"
        "    <loc>https://dns-audit.com/</loc>\n"
        "    <changefreq>weekly</changefreq>\n"
        "    <priority>1.0</priority>\n"
        "  </url>\n"
        "  <url>\n"
        "    <loc>https://dns-audit.com/privacy</loc>\n"
        "    <changefreq>monthly</changefreq>\n"
        "    <priority>0.3</priority>\n"
        "  </url>\n"
        "</urlset>\n"
    )
    return Response(content=xml, media_type="application/xml")


# ============================================================
# 404 handler
# ============================================================

@app.exception_handler(404)
async def not_found(request: Request, exc):
    """Redirect unknown non-API routes to homepage."""
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=404,
            content={"detail": "Endpoint not found"},
        )
    from starlette.responses import RedirectResponse
    return RedirectResponse(url="/")


# ============================================================
# Static files & frontend
# ============================================================

STATIC_DIR = Path(__file__).parent / "static"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    async def index():
        return FileResponse(str(STATIC_DIR / "index.html"))

    @app.get("/privacy", tags=["Pages"])
    async def privacy():
        return FileResponse(str(STATIC_DIR / "privacy.html"))

    @app.get("/methodology", tags=["Pages"])
    async def methodology():
        return FileResponse(str(STATIC_DIR / "methodology.html"))
else:
    @app.get("/")
    async def index():
        return {"message": "DNS Security Auditor API. Put static files in ./static/"}

