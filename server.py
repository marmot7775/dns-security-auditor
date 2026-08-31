"""
DNS Security Auditor - FastAPI Server
======================================
GET  /api/audit?domain=example.com   -- run full audit (JSON)
GET  /api/audit/stream?domain=...    -- audit progress (SSE)
GET  /api/audit/{domain}/pdf         -- download PDF report
GET  /api/health                     -- health check (verifies DNS resolution)
GET  /                               -- serve frontend
GET  /static/*                       -- serve static assets

Usage:
    uvicorn server:app --host 0.0.0.0 --port 8000
"""

import asyncio
import functools
import hashlib
import json
import logging
import logging.handlers
import queue
import re
import secrets
import threading
import time
import uuid

import anyio.to_thread
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

import dns.resolver
import dns.exception

from audit_engine import run_full_audit
from config import (
    LOG_DIR, LOG_LEVEL, CACHE_TTL, CACHE_MAX_SIZE,
    RATE_LIMIT_MAX, RATE_LIMIT_WINDOW, RATE_LIMIT_MAX_IPS,
    MAX_CONCURRENT_AUDITS, CORS_ORIGINS,
    DOMAIN_PATTERN, SELECTOR_PATTERN,
    TRUSTED_PROXY_IPS,
)
from dns_tools import normalize_domain
try:
    from pdf_report import generate_pdf
except ImportError:
    generate_pdf = None


# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("dns-auditor")

# Rotating error log -- directory is configurable via LOG_DIR env var
_log_dir = Path(LOG_DIR)

# Audit logger (GDPR-safe -- no raw IP, no geolocation). Configured below once
# the log directory is known to exist.
audit_logger = logging.getLogger("dns-auditor.audit")
audit_logger.propagate = False  # don't double-log to root
audit_logger.setLevel(logging.INFO)

try:
    _log_dir.mkdir(parents=True, exist_ok=True)
    error_file_handler = logging.handlers.RotatingFileHandler(
        str(_log_dir / "errors.log"),
        maxBytes=10_000_000,  # 10MB
        backupCount=5,
    )
    error_file_handler.setLevel(logging.ERROR)
    error_file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(message)s'
    ))
    log.addHandler(error_file_handler)

    # Audit log: rotating, JSON-lines. Uses the logger's internal lock for
    # thread safety. Note: with multiple uvicorn workers, RotatingFileHandler
    # can still race during rotation (both processes may rename). Acceptable
    # at this scale; use ConcurrentLogHandler if strict correctness is needed.
    audit_handler = logging.handlers.RotatingFileHandler(
        str(_log_dir / "audit.log"),
        maxBytes=10_000_000,
        backupCount=10,
    )
    audit_handler.setLevel(logging.INFO)
    audit_handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(audit_handler)
except PermissionError:
    log.warning("Cannot create log directory %s -- file logging disabled", _log_dir)


# ============================================================
# Audit log (GDPR-safe -- no raw IP, no geolocation)
# ============================================================

# Per-process salt for the visitor id. Generated fresh at start-up and never
# written anywhere, so nobody holding the log can brute-force a hash back to
# an IP -- the salt does not outlive the process.
_VID_SALT = secrets.token_bytes(32)


def _vid_day() -> str:
    """UTC date the visitor id is bucketed into."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _visitor_id(request: Request, day: Optional[str] = None) -> str:
    """Daily-rotating, salted, non-reversible visitor id.

    sha256(process salt | UTC date | client IP | user agent), truncated to
    12 hex chars. The IP is read here, hashed, and dropped: it is never
    written to the log and never held anywhere else. The date in the hashed
    material means the same visitor hashes to something different tomorrow,
    so the log can tell one heavy user from twenty light ones within a day
    without following anyone across days.
    """
    ip = _get_client_ip(request)
    ua = request.headers.get("User-Agent", "")
    material = b"|".join([
        _VID_SALT,
        (day or _vid_day()).encode("utf-8"),
        ip.encode("utf-8", "replace"),
        ua.encode("utf-8", "replace"),
    ])
    return hashlib.sha256(material).hexdigest()[:12]


def _referer_host(request: Request) -> Optional[str]:
    """Host of the Referer header, or None if there is not one.

    Only the host is kept: a full referer URL can carry private path and
    query data. Absent header means the field is omitted entirely rather
    than written as null.
    """
    ref = request.headers.get("Referer")
    if not ref:
        return None
    try:
        host = urlsplit(ref.strip()).hostname
    except ValueError:
        return None
    return host[:100] if host else None


# Result error codes that mean something other than "the audit broke".
_STATUS_BY_ERROR = {"timeout": "timeout", "cancelled": "abandoned"}


def _audit_status(result):
    """Map an audit result onto its (status, error code) pair."""
    err = result.get("error") if isinstance(result, dict) else None
    if not err:
        return "ok", None
    return _STATUS_BY_ERROR.get(err, "error"), err


def _log_audit(request: Request, domain: str, scope: str,
               duration: float, checks: int, source: str = "web",
               status: str = "ok", error: Optional[str] = None):
    """Write a GDPR-safe JSON-lines audit log entry.

    Logged: domain, timestamp, scope, duration, check count, outcome
            (status, plus an error code when the outcome is not "ok"),
            user-agent (browser/OS only), source (web/sse/pdf), a
            daily-rotating visitor hash, and the referring host if one
            was sent.
    NOT logged: IP address, geolocation, cookies, referring URL path,
            personal data.

    Fields are only ever added, never renamed or removed: the existing log
    holds entries with none of status/error/vid/ref, so no reader may
    assume any of them is present.
    """
    ua = request.headers.get("User-Agent", "unknown")
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domain": domain,
        "scope": scope or "complete",
        "duration_s": duration,
        "checks": checks,
        "ua": ua[:200],
        "source": source,
        "status": status,
        "vid": _visitor_id(request),
    }
    if status != "ok" and error:
        entry["error"] = error
    ref = _referer_host(request)
    if ref:
        entry["ref"] = ref
    try:
        audit_logger.info(json.dumps(entry))
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
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
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
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = self.CSP
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        path = request.url.path
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        elif any(path.endswith(ext) for ext in ('.css', '.js', '.png', '.jpg', '.svg', '.woff2', '.woff', '.ico')):
            response.headers["Cache-Control"] = "public, max-age=14400"  # 4 hours
        elif path in ('/', '/dmarcbis', '/dnssec', '/about'):
            response.headers["Cache-Control"] = "public, max-age=300"  # 5 minutes for HTML
        return response

app.add_middleware(SecurityHeadersMiddleware)


# ============================================================
# Rate limiting (in-memory, per-IP)
# ============================================================

_rate_limits: dict = defaultdict(list)
_rate_lock = threading.Lock()
_RATE_LIMIT_MAX_IPS = RATE_LIMIT_MAX_IPS

_active_audits = 0
_active_audits_lock = threading.Lock()
_MAX_CONCURRENT_AUDITS = MAX_CONCURRENT_AUDITS


def _get_client_ip(request: Request) -> str:
    """Get real client IP behind nginx reverse proxy.

    Trust chain: Client -> Cloudflare -> nginx -> uvicorn
    nginx sets X-Real-IP from the connecting Cloudflare edge IP's
    CF-Connecting-IP header. That's trustworthy when nginx (a configured
    TRUSTED_PROXY_IPS peer) is the direct TCP peer -- but uvicorn can also
    be reached directly (Procfile: --host 0.0.0.0), where the header
    comes straight from whoever connects and rotating it would bypass the
    rate limit entirely. Only honor X-Real-IP when the direct peer is a
    trusted proxy; otherwise use the peer address itself.
    Client-sent headers like CF-Connecting-IP and X-Forwarded-For
    are NOT trusted directly (trivially spoofable for rate limit bypass).
    """
    peer_ip = request.client.host if request.client else None
    real_ip = request.headers.get("X-Real-IP")
    if real_ip and peer_ip in TRUSTED_PROXY_IPS:
        return real_ip.strip()
    return peer_ip or "unknown"


def _check_rate_limit(client_ip: str) -> bool:
    """Return True if the request is allowed, False if rate-limited."""
    now = time.time()
    with _rate_lock:
        # Evict stale entries if dict grows too large
        if len(_rate_limits) > _RATE_LIMIT_MAX_IPS:
            stale = [
                ip for ip, ts_list in _rate_limits.items()
                if not ts_list or now - ts_list[-1] > RATE_LIMIT_WINDOW
            ]
            for ip in stale:
                _rate_limits.pop(ip, None)
            # If still too large, drop the half with the oldest last-seen timestamps
            if len(_rate_limits) > _RATE_LIMIT_MAX_IPS:
                sorted_ips = sorted(
                    _rate_limits.items(),
                    key=lambda kv: max(kv[1]) if kv[1] else 0,
                )
                drop_count = len(_rate_limits) // 2
                for ip, _ in sorted_ips[:drop_count]:
                    _rate_limits.pop(ip, None)

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
            oldest_keys = sorted(_cache, key=lambda k: _cache[k]["ts"])[:100]
            for key in oldest_keys:
                _cache.pop(key, None)


# ============================================================
# Domain validation
# ============================================================





def _validate_domain(domain: str) -> str:
    """Normalize and validate a domain string.

    Handles URLs, email addresses, trailing dots, ports, and IDN domains.
    """
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")

    d = normalize_domain(domain)

    if not d:
        raise HTTPException(status_code=400, detail="Invalid domain")

    # Length check before regex: caps regex CPU on pathological-length input.
    if len(d) > 253:
        raise HTTPException(status_code=400, detail="Domain name too long")

    if not DOMAIN_PATTERN.match(d):
        raise HTTPException(
            status_code=400,
            detail=f"'{d}' does not look like a valid domain name",
        )

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
):
    """
    Run a comprehensive DNS and email security audit.

    Returns:
    - Per-check pass/warn/fail status with priority fixes
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
        raise HTTPException(status_code=400, detail="Invalid DKIM selector (RFC 6376: alphanumeric and hyphens only)")
    request_id = str(uuid.uuid4())
    log.info("Audit requested: %s (scope=%s, ip=%s, rid=%s)", domain, scope or "complete", client_ip, request_id)

    cache_key = f"{domain}:{selector or ''}:{scope or 'complete'}"

    # Check cache (always; nocache removed from public API to prevent abuse)
    cached = _get_cached(cache_key)
    if cached:
        log.info("Cache hit: %s (rid=%s)", domain, request_id)
        cached_with_rid = {**cached, "request_id": request_id, "cached": True}
        return JSONResponse(content=cached_with_rid)

    # Pre-flight DNS check (offloaded -- this does blocking socket I/O)
    preflight_err = await anyio.to_thread.run_sync(_preflight_dns_check, domain)
    if preflight_err:
        log.info("Preflight failed for %s: %s", domain, preflight_err.get("error"))
        return JSONResponse(content=preflight_err)

    # Reserve a concurrent-audit slot atomically (DoS protection).
    # Shared with /api/audit/stream: both endpoints invoke the same
    # expensive run_full_audit(), so they draw from one global budget
    # rather than /api/audit being unbounded.
    global _active_audits
    with _active_audits_lock:
        if _active_audits >= _MAX_CONCURRENT_AUDITS:
            return JSONResponse(
                status_code=503,
                content={"detail": "Server is busy. Please try again in a moment."},
                headers={"Retry-After": "5"},
            )
        _active_audits += 1

    # Run audit (offloaded -- this is fully synchronous and would otherwise
    # block the event loop, stalling every other request on this worker).
    start = time.time()
    try:
        try:
            result = await anyio.to_thread.run_sync(
                functools.partial(run_full_audit, domain, dkim_selector=selector, scope=scope)
            )
        except Exception as e:
            log.error("Audit failed for %s: %s", domain, str(e)[:200], exc_info=True)
            result = {
                "domain": domain,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "checks": [],
                "priority_fixes": [],
                "vendors": [],
                "error": "server_error",
                "error_message": "Audit could not complete. Please try again.",
            }
    finally:
        with _active_audits_lock:
            _active_audits -= 1

    elapsed = round(time.time() - start, 2)
    log.info("Audit complete: %s -- %.2fs (rid=%s)", domain, elapsed, request_id)

    # Audit log (GDPR-safe). A failed audit must not read as ordinary
    # healthy usage: the outcome is carried on the entry itself.
    log_status, log_error = _audit_status(result)
    _log_audit(request, domain, scope,
               elapsed, len(result.get("checks", [])), source="web",
               status=log_status, error=log_error)

    # Cache result (skip caching errors -- they may be transient)
    if "error" not in result:
        _set_cached(cache_key, result)

    result["request_id"] = request_id
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
):
    """Stream audit progress via Server-Sent Events."""
    global _active_audits
    client_ip = _get_client_ip(request)

    # Capacity peek BEFORE rate-limit check: if the server is at the concurrent
    # cap, reject without consuming a per-IP rate-limit slot. Otherwise an
    # attacker who pins the cap can drain rate-limit slots faster than honest
    # users. The actual reservation is still atomic below.
    if _active_audits >= _MAX_CONCURRENT_AUDITS:
        async def _busy_error():
            yield f"data: {json.dumps({'error': 'Server is busy. Please try again in a moment.'})}\n\n"
        return StreamingResponse(_busy_error(), media_type="text/event-stream")

    if not _check_rate_limit(client_ip):
        async def _rate_error():
            yield f"data: {json.dumps({'error': 'Rate limit exceeded. Please wait a minute before trying again.'})}\n\n"
        return StreamingResponse(_rate_error(), media_type="text/event-stream")

    domain = _validate_domain(domain)
    scope = _validate_scope(scope)
    if selector and not SELECTOR_PATTERN.match(selector.strip()):
        raise HTTPException(status_code=400, detail="Invalid DKIM selector (RFC 6376: alphanumeric and hyphens only)")
    request_id = str(uuid.uuid4())
    log.info("SSE audit requested: %s (scope=%s, ip=%s, rid=%s)", domain, scope or "complete", client_ip, request_id)

    cache_key = f"{domain}:{selector or ''}:{scope or 'complete'}"

    # Check cache -- if cached, send result immediately
    cached = _get_cached(cache_key)
    if cached:
        log.info("SSE cache hit: %s (rid=%s)", domain, request_id)
        async def _cached_stream():
            cached_result = {**cached, "request_id": request_id}
            yield f"data: {json.dumps({'done': True, 'result': cached_result, 'cached': True, 'request_id': request_id})}\n\n"
        return StreamingResponse(_cached_stream(), media_type="text/event-stream")

    # Pre-flight DNS check (offloaded -- this does blocking socket I/O)
    preflight_err = await anyio.to_thread.run_sync(_preflight_dns_check, domain)
    if preflight_err:
        log.info("SSE preflight failed for %s: %s", domain, preflight_err.get("error"))
        async def _preflight_error():
            yield f"data: {json.dumps({'done': True, 'result': preflight_err})}\n\n"
        return StreamingResponse(_preflight_error(), media_type="text/event-stream")

    # Reserve a concurrent-audit slot atomically (DoS protection)
    with _active_audits_lock:
        if _active_audits >= _MAX_CONCURRENT_AUDITS:
            async def _busy_error():
                yield f"data: {json.dumps({'error': 'Server is busy. Please try again in a moment.'})}\n\n"
            return StreamingResponse(_busy_error(), media_type="text/event-stream")
        _active_audits += 1

    # Run audit in a background thread, streaming progress via a queue
    progress_q: queue.Queue = queue.Queue()
    cancel_event = threading.Event()

    def _progress_callback(step_name, completed, total):
        if cancel_event.is_set():
            raise InterruptedError("Audit cancelled: client disconnected")
        progress_pct = int((completed / total) * 100) if total else 0
        msg = {
            "step": step_name,
            "progress": progress_pct,
            "total_checks": total,
            "completed": completed,
        }
        # DKIM sub-progress: step_name like "DKIM:5" means 5 selectors found
        if ":" in str(step_name) and step_name.startswith("DKIM:"):
            count = step_name.split(":", 1)[1]
            msg["step"] = "DKIM"
            msg["detail"] = f"{count} found so far"
        progress_q.put(msg)

    def _run_audit():
        # Note: the concurrency slot reserved above is released in
        # _event_stream's finally, not here. This thread can keep running
        # after the client disconnects (e.g. stuck in one slow blocking DNS
        # call with no progress_callback checkpoint in between), so tying
        # the release to this thread's completion would hold the slot open
        # long after the stream itself has closed.
        try:
            result = run_full_audit(domain, dkim_selector=selector, scope=scope,
                                    progress_callback=_progress_callback)
            progress_q.put({"_done": True, "_result": result})
        except InterruptedError:
            log.info("SSE audit cancelled (client disconnect): %s", domain)
            progress_q.put({"_done": True, "_result": {"error": "cancelled"}})
        except Exception as e:
            log.error("SSE audit failed for %s: %s", domain, str(e)[:200], exc_info=True)
            error_result = {
                "domain": domain,
                "timestamp": datetime.now(timezone.utc).isoformat(),
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
        global _active_audits
        loop = asyncio.get_running_loop()
        outcome_logged = False
        try:
            while True:
                if time.time() - sse_start_time > 120:
                    log.warning("SSE stream exceeded 120s limit: %s", domain)
                    cancel_event.set()
                    timeout_result = {
                        "domain": domain,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "checks": [],
                        "priority_fixes": [],
                        "vendors": [],
                        "error": "timeout",
                        "error_message": "Audit exceeded the 120 second time limit. Please try again.",
                    }
                    _log_audit(request, domain, scope, 120.0, 0, source="sse",
                               status="timeout", error="timeout")
                    outcome_logged = True
                    yield f"data: {json.dumps({'done': True, 'result': timeout_result})}\n\n"
                    return
                try:
                    msg = await loop.run_in_executor(None, lambda: progress_q.get(timeout=0.2))
                except queue.Empty:
                    # Check if client disconnected
                    if await request.is_disconnected():
                        log.info("SSE client disconnected: %s", domain)
                        cancel_event.set()  # Signal audit thread to stop
                        # Log the abandonment. Without an entry here, a user
                        # who starts an audit and gives up looks exactly like
                        # a user who never visited at all.
                        _log_audit(request, domain, scope,
                                   round(time.time() - sse_start_time, 2), 0,
                                   source="sse", status="abandoned")
                        outcome_logged = True
                        return
                    continue

                if "_done" in msg:
                    result = msg["_result"]
                    # Skip caching errors -- they may be transient
                    if "error" not in result:
                        _set_cached(cache_key, result)
                    elapsed = round(time.time() - sse_start_time, 2)
                    log.info("SSE audit complete: %s -- %.2fs",
                             domain, elapsed)
                    # Audit log (GDPR-safe)
                    log_status, log_error = _audit_status(result)
                    _log_audit(request, domain, scope,
                               elapsed, len(result.get("checks", [])), source="sse",
                               status=log_status, error=log_error)
                    outcome_logged = True
                    result["request_id"] = request_id
                    yield f"data: {json.dumps({'done': True, 'result': result, 'request_id': request_id})}\n\n"
                    return
                else:
                    yield f"data: {json.dumps(msg)}\n\n"
        finally:
            cancel_event.set()  # Ensure thread stops if generator exits for any reason
            if not outcome_logged:
                # The disconnect poll above is not the only way a stream ends
                # early: uvicorn cancels the response task the moment the
                # client goes away, which closes this generator without that
                # poll ever running again. Logging the abandonment here too is
                # what makes "user gave up" countable rather than invisible.
                _log_audit(request, domain, scope,
                           round(time.time() - sse_start_time, 2), 0,
                           source="sse", status="abandoned")
            # Release the concurrency slot here, not when the background
            # thread finishes -- the stream ending (disconnect, completion,
            # or timeout) is what should free capacity for new clients.
            with _active_audits_lock:
                _active_audits -= 1

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
        raise HTTPException(status_code=400, detail="Invalid DKIM selector (RFC 6376: alphanumeric and hyphens only)")
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
            data = await anyio.to_thread.run_sync(
                functools.partial(run_full_audit, domain, dkim_selector=selector, scope=scope)
            )
        except Exception as e:
            log.error("PDF audit failed for %s: %s", domain, str(e)[:200], exc_info=True)
            raise HTTPException(status_code=500, detail="Audit failed: cannot generate PDF")
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

    # Generate PDF (offloaded -- rendering is CPU-bound synchronous work)
    try:
        pdf_bytes = await anyio.to_thread.run_sync(generate_pdf, data)
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
# Health check
# ============================================================

@app.get("/api/health", tags=["System"])
async def health():
    """
    Health check endpoint for monitoring and load balancers.
    Returns 200 if the application and DNS resolution are functional.
    """
    try:
        dns.resolver.resolve("example.com", "A", lifetime=2)
        return {"status": "ok", "dns_resolution": "working"}
    except Exception as e:
        log.error("Health check DNS resolution failed: %s", str(e)[:200])
        return JSONResponse(
            content={"status": "error"},
            status_code=500,
        )


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


# ============================================================
# 404 handler
# ============================================================

@app.exception_handler(404)
async def not_found(request: Request, exc):
    """Serve a proper 404 page for non-API routes; JSON for API routes."""
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=404,
            content={"detail": "Endpoint not found"},
        )
    not_found_path = STATIC_DIR / "404.html"
    if not_found_path.exists():
        return FileResponse(str(not_found_path), status_code=404)
    return PlainTextResponse(
        "Page not found. Return to https://dns-audit.com/",
        status_code=404,
    )


# ============================================================
# Static files & frontend
# ============================================================

STATIC_DIR = Path(__file__).parent / "static"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    async def index():
        return FileResponse(str(STATIC_DIR / "index.html"))

    @app.get("/articles", tags=["Pages"])
    @app.get("/articles/", tags=["Pages"])
    async def articles_index():
        return FileResponse(str(STATIC_DIR / "articles" / "index.html"))

    @app.get("/articles/dmarcbis", tags=["Pages"])
    async def articles_dmarcbis():
        return FileResponse(str(STATIC_DIR / "articles" / "dmarcbis.html"))

    @app.get("/articles/dnssec", tags=["Pages"])
    async def articles_dnssec():
        return FileResponse(str(STATIC_DIR / "articles" / "dnssec.html"))

    @app.get("/articles/dane", tags=["Pages"])
    async def articles_dane():
        return FileResponse(str(STATIC_DIR / "articles" / "dane.html"))

    @app.get("/dmarcbis", tags=["Pages"])
    async def dmarcbis_redirect():
        return RedirectResponse(url="/articles/dmarcbis", status_code=301)

    @app.get("/dnssec", tags=["Pages"])
    async def dnssec_redirect():
        return RedirectResponse(url="/articles/dnssec", status_code=301)

    @app.get("/dane", tags=["Pages"])
    async def dane_redirect():
        return RedirectResponse(url="/articles/dane", status_code=301)

    @app.get("/blog/dmarc-running-on-a-text-file", tags=["Pages"])
    async def dmarc_running_on_a_text_file():
        return RedirectResponse(url="/articles/dmarcbis", status_code=301)

    @app.get("/blog/dnssec-stopped-being-hard", tags=["Pages"])
    async def dnssec_stopped_being_hard():
        return RedirectResponse(url="/articles/dnssec", status_code=301)

    @app.get("/methodology", tags=["Pages"])
    async def methodology_redirect():
        return RedirectResponse(url="/about", status_code=301)

    @app.get("/about", tags=["Pages"])
    async def about():
        return FileResponse(str(STATIC_DIR / "about.html"))

    @app.get("/security", response_class=PlainTextResponse, tags=["Pages"])
    async def security_policy():
        security_path = Path(__file__).parent / "SECURITY.md"
        if security_path.exists():
            return security_path.read_text(encoding="utf-8")
        return "Security policy not available."

else:
    @app.get("/")
    async def index():
        return {"message": "DNS Security Auditor API. Put static files in ./static/"}


@app.get("/sitemap.xml")
async def sitemap():
    """Generate a simple sitemap for search engines."""
    base = "https://dns-audit.com"
    pages = [
        {"loc": "/", "changefreq": "weekly", "priority": "1.0"},
        {"loc": "/articles/", "changefreq": "weekly", "priority": "0.8"},
        {"loc": "/articles/dmarcbis", "changefreq": "monthly", "priority": "0.8"},
        {"loc": "/articles/dnssec", "changefreq": "monthly", "priority": "0.8"},
        {"loc": "/articles/dane", "changefreq": "monthly", "priority": "0.8"},
        {"loc": "/about", "changefreq": "monthly", "priority": "0.5"},
    ]
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for p in pages:
        xml += "  <url>\n"
        xml += f"    <loc>{base}{p['loc']}</loc>\n"
        xml += f"    <changefreq>{p['changefreq']}</changefreq>\n"
        xml += f"    <priority>{p['priority']}</priority>\n"
        xml += "  </url>\n"
    xml += '</urlset>'
    return Response(content=xml, media_type="application/xml")

