"""
DNS Security Auditor - FastAPI Server
======================================
GET  /api/audit?domain=example.com  -- run full audit
GET  /api/audit/pdf?domain=...      -- download PDF report
POST /api/analyze-headers            -- analyze email headers
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
from typing import Dict, Optional

from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

import dns.resolver
import dns.exception

from audit_engine import run_full_audit
from header_analyzer import analyze_headers, get_sample_headers
try:
    from pdf_report import generate_pdf
except ImportError:
    generate_pdf = None


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
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
)


# ============================================================
# Security headers middleware
# ============================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    CSP = (
        "default-src 'self'; "
        "font-src 'self'; "
        "style-src 'self'; "
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
    """Normalize and validate a domain string.

    Handles URLs, email addresses, trailing dots, ports, and IDN domains.
    """
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")

    # Normalize
    d = domain.strip().lower()
    if "@" in d:
        d = d.split("@")[-1]
    d = d.removeprefix("http://").removeprefix("https://")
    d = d.split("/")[0].split("?")[0].split("#")[0]
    # Strip port (e.g. example.com:443)
    if ":" in d:
        d = d.rsplit(":", 1)[0]
    d = d.rstrip(".")

    if not d:
        raise HTTPException(status_code=400, detail="Invalid domain")

    # Handle internationalized domain names (IDN) -- convert to punycode
    try:
        d = d.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        # If IDNA encoding fails, try encoding each label individually
        try:
            labels = d.split(".")
            d = ".".join(
                label.encode("idna").decode("ascii") for label in labels
            )
        except (UnicodeError, UnicodeDecodeError):
            pass  # Fall through to regex validation below

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


def _preflight_dns_check(domain: str) -> Optional[Dict]:
    """Quick DNS existence check before running the full audit.

    Returns an error dict if the domain is clearly unreachable,
    or None if it looks OK (or ambiguous) and the audit should proceed.
    """
    _err_base = {
        "domain": domain,
        "checks": [],
        "priority_fixes": [],
        "score": {"total": 0, "grade": "?"},
    }
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        try:
            resolver.resolve(domain, "SOA")
        except dns.resolver.NoAnswer:
            resolver.resolve(domain, "NS")
    except dns.resolver.NXDOMAIN:
        return {
            **_err_base,
            "error": "domain_not_found",
            "error_message": "This domain does not exist in DNS. Verify the spelling and try again.",
        }
    except dns.resolver.NoNameservers:
        return {
            **_err_base,
            "error": "dns_broken",
            "error_message": (
                f"The DNS servers for '{domain}' returned an error (SERVFAIL or REFUSED). "
                "The nameservers may be misconfigured or temporarily unreachable. "
                "Try again in a few minutes."
            ),
        }
    except dns.exception.Timeout:
        return {
            **_err_base,
            "error": "timeout",
            "error_message": (
                f"DNS queries for '{domain}' timed out. The nameservers may be "
                "slow or unreachable. Try again in a few minutes."
            ),
        }
    except dns.exception.DNSException:
        pass  # Ambiguous, let the full audit try
    return None


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
    - Individual check results (DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, DANE, Nameservers, CT, Blocklist)
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

    # Pre-flight DNS check
    preflight_err = _preflight_dns_check(domain)
    if preflight_err:
        log.info("Preflight failed for %s: %s", domain, preflight_err.get("error"))
        return JSONResponse(content=preflight_err)

    # Run audit
    start = time.time()
    try:
        result = run_full_audit(domain, dkim_selector=selector, scope=scope)
    except Exception as e:
        log.error("Audit failed for %s: %s", domain, str(e)[:200], exc_info=True)
        result = {
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": {"total": 0, "grade": "?"},
            "checks": [],
            "priority_fixes": [],
            "vendors": [],
            "error": "server_error",
            "error_message": "Audit could not complete. Please try again.",
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

    # Pre-flight DNS check
    preflight_err = _preflight_dns_check(domain)
    if preflight_err:
        log.info("SSE preflight failed for %s: %s", domain, preflight_err.get("error"))
        async def _preflight_error():
            yield f"data: {json.dumps({'done': True, 'result': preflight_err})}\n\n"
        return StreamingResponse(_preflight_error(), media_type="text/event-stream")

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
                "error": "server_error",
                "error_message": "Audit could not complete. Please try again.",
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

@app.get("/api/audit/{domain}/pdf", tags=["Audit"])
async def audit_pdf(
    request: Request,
    domain: str,
    scope: Optional[str] = Query("complete", description="Audit scope"),
    selector: Optional[str] = Query(None, description="DKIM selector"),
):
    """
    Download a professional PDF audit report.

    Reuses cached audit data when available; otherwise runs a fresh audit.
    """
    if generate_pdf is None:
        raise HTTPException(status_code=503, detail="PDF generation unavailable (reportlab not installed)")

    # Rate limiting (shared with /api/audit)
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
    log.info("PDF requested: %s (scope=%s, ip=%s)", domain, scope or "complete", client_ip)

    cache_key = f"{domain}:{selector or ''}:{scope or 'complete'}"

    # Reuse cached audit data if available
    cached = _get_cached(cache_key)
    if cached:
        data = cached
        log.info("PDF using cached data: %s", domain)
    else:
        start = time.time()
        try:
            data = run_full_audit(domain, dkim_selector=selector, scope=scope)
        except Exception as e:
            log.error("PDF audit failed for %s: %s", domain, str(e)[:200], exc_info=True)
            raise HTTPException(status_code=500, detail="Audit failed -- cannot generate PDF")
        elapsed = round(time.time() - start, 2)
        log.info("PDF audit complete: %s -- %.2fs", domain, elapsed)
        _set_cached(cache_key, data)

    # Check for audit errors
    if data.get("error"):
        return Response(
            content=data.get("error_message", "Audit failed"),
            status_code=400,
            media_type="text/plain",
        )

    # Generate PDF
    try:
        pdf_bytes = generate_pdf(data)
    except Exception as e:
        log.error("PDF generation failed for %s: %s", domain, str(e)[:200], exc_info=True)
        raise HTTPException(status_code=500, detail="PDF generation failed")

    safe_domain = re.sub(r'[^a-zA-Z0-9._-]', '', domain)
    filename = f"dns-audit-{safe_domain}.pdf"
    return Response(
        content=bytes(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


# ============================================================
# Email Header Analyzer
# ============================================================

@app.post("/api/analyze-headers", tags=["Headers"])
async def analyze_email_headers(request: Request):
    """
    Analyze raw email headers for authentication, deliverability, and security.

    Accepts raw email header text as the POST body.
    Returns structured analysis including authentication results,
    mail journey, identity checks, and deliverability diagnosis.
    """
    # Rate limiting
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please wait a minute before trying again."},
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
        )

    try:
        body = await request.body()
        raw_headers = body.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read request body")

    if not raw_headers.strip():
        raise HTTPException(status_code=400, detail="No headers provided")

    if len(raw_headers) > 200_000:
        raise HTTPException(status_code=400, detail="Input too large (max 200KB)")

    try:
        result = analyze_headers(raw_headers)
    except Exception as e:
        log.error("Header analysis failed: %s", str(e)[:200], exc_info=True)
        raise HTTPException(status_code=500, detail="Header analysis failed")

    return JSONResponse(content=result)


@app.get("/api/sample-headers", tags=["Headers"])
async def sample_headers():
    """Return sample email headers for the try-it-out feature."""
    return PlainTextResponse(content=get_sample_headers())


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
            "TLS-RPT", "BIMI", "DNSSEC", "CAA", "DANE",
            "Nameservers", "Certificate Transparency", "Blocklist",
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
        "    <loc>https://dns-audit.com/dmarcbis</loc>\n"
        "    <changefreq>monthly</changefreq>\n"
        "    <priority>0.8</priority>\n"
        "  </url>\n"
        "  <url>\n"
        "    <loc>https://dns-audit.com/privacy</loc>\n"
        "    <changefreq>monthly</changefreq>\n"
        "    <priority>0.3</priority>\n"
        "  </url>\n"
        "  <url>\n"
        "    <loc>https://dns-audit.com/headers</loc>\n"
        "    <changefreq>monthly</changefreq>\n"
        "    <priority>0.7</priority>\n"
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

    @app.get("/dmarcbis", tags=["Pages"])
    async def dmarcbis():
        return FileResponse(str(STATIC_DIR / "dmarcbis.html"))

    @app.get("/methodology", tags=["Pages"])
    async def methodology():
        return FileResponse(str(STATIC_DIR / "methodology.html"))

    @app.get("/headers", tags=["Pages"])
    async def headers_page():
        return FileResponse(str(STATIC_DIR / "index.html"))
else:
    @app.get("/")
    async def index():
        return {"message": "DNS Security Auditor API. Put static files in ./static/"}

