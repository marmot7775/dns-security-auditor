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
    uvicorn server:app --host 127.0.0.1 --port 8000

    One worker only. nginx terminates TLS in front of this and proxies to
    loopback. See the "Single worker guard" section below before adding
    --workers or WEB_CONCURRENCY.
"""

import asyncio
import functools
import hashlib
import json
import logging
import logging.handlers
import os
import re
import secrets
import sys
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
from ua_classify import is_bot, ua_summary
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
# Single worker guard
# ============================================================

# This app is single worker by design, and it has to stay that way. Every
# piece of coordination state in this module is a plain module-level global,
# private to one process:
#
#   _rate_limits    (line 398)   per-IP rate limit table
#   _active_audits  (line 402)   concurrency budget
#   _inflight       (line 415)   single-flight audit registry
#   _cache          (line 532)   audit result cache
#   _health_cache   (line 1202)  health probe memo
#
# A second worker gets its own copy of all five, so none of them are global
# any more: the per-IP limit multiplies by the worker count, so does the
# concurrency cap, the same audit runs once per worker because neither can
# see the other's _inflight dict, and the health probe stops deduplicating
# its DNS lookup. Nothing raises and nothing logs at request time, so the
# start-up check below is the only signal anyone gets. Scaling out means
# moving all five to shared storage first. See CLAUDE.md, "Single worker by
# design", and the comment above ExecStart in dns-auditor.service.

def _parse_worker_flag(argv) -> Optional[int]:
    """Pull a worker count out of a uvicorn or gunicorn argv, or return None."""
    for i, arg in enumerate(argv):
        if arg in ("--workers", "-w") and i + 1 < len(argv):
            try:
                return int(argv[i + 1])
            except ValueError:
                return None
        if arg.startswith("--workers="):
            try:
                return int(arg.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _detect_worker_count():
    """Return (count, source) for the configured worker count, else (None, "").

    Three places the number can come from: this process's own argv, the
    supervisor's argv (uvicorn and gunicorn respawn workers with a rewritten
    command line, so under spawn the flag only survives in the parent), and
    WEB_CONCURRENCY, which both servers honour without any flag at all.
    """
    count = _parse_worker_flag(sys.argv)
    if count is not None:
        return count, "workers flag on the command line"

    try:
        with open("/proc/%d/cmdline" % os.getppid(), "rb") as fh:
            parent_argv = fh.read().decode("utf-8", "replace").split("\0")
        count = _parse_worker_flag(parent_argv)
        if count is not None:
            return count, "workers flag on the supervising process"
    except OSError:
        pass

    raw = os.getenv("WEB_CONCURRENCY")
    if raw:
        try:
            return int(raw), "WEB_CONCURRENCY"
        except ValueError:
            return None, ""
    return None, ""


def _warn_if_multiple_workers() -> None:
    """Shout at start-up if this process is one of several workers."""
    count, source = _detect_worker_count()
    if count is None or count <= 1:
        return
    log.error(
        "MULTI WORKER START DETECTED (%s: %s). This app is single worker by "
        "design and its limits are no longer being enforced. The rate limit "
        "table, the concurrency budget, the single flight audit registry, "
        "the result cache and the health cache are all per process globals, "
        "so every worker keeps a private copy. Each IP now gets %s times the "
        "intended requests per window, %s times MAX_CONCURRENT_AUDITS can "
        "run at once, identical audits run side by side instead of sharing "
        "one result, and the health probe stops deduplicating its DNS "
        "lookup. Nothing else will report any of this. Run one worker, or "
        "move all five to shared storage first. See CLAUDE.md, section "
        "Single worker by design.",
        source, count, count, count,
    )


_warn_if_multiple_workers()


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
            browser and OS family, whether the caller is a bot, source
            (web/sse/pdf), a daily-rotating visitor hash, and the
            referring host if one was sent.
    NOT logged: the raw user-agent string, IP address, geolocation,
            cookies, referring URL path, personal data.

    The bot flag is derived from the full user agent before ua_summary()
    reduces it to coarse labels. That order is load-bearing: the labels do
    not carry enough to tell a crawler from a person, so deriving the flag
    afterwards would classify every future audit as a bot.

    Fields are only ever added, never renamed or removed: the existing log
    holds entries with none of status/error/vid/ref/bot, so no reader may
    assume any of them is present. The ua field is an exception in value
    only, not in name: entries written before this change hold a truncated
    raw string, entries written after hold "<browser> / <OS>".
    """
    ua_raw = request.headers.get("User-Agent", "")
    bot = is_bot(ua_raw)
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domain": domain,
        "scope": scope or "complete",
        "duration_s": duration,
        "checks": checks,
        "ua": ua_summary(ua_raw),
        "bot": bot,
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
    """Headers this app owns.

    X-Frame-Options and Referrer-Policy are deliberately not here: nginx sets
    both, at server level and again inside the /static/ block, so it covers
    every route including the static files that are served straight from disk
    and never reach this process. Setting them here as well only put each one
    on the wire twice. Framing is still blocked from this side by the CSP's
    frame-ancestors 'none'.

    Strict-Transport-Security is not here either. It used to be gated on
    request.url.scheme == "https", which can never be true: uvicorn runs
    without --proxy-headers (see _get_client_ip for why that matters), so
    behind nginx the scheme is always http and the branch was dead. The HSTS
    header users actually receive comes from the edge. If this app ever needs
    to send its own, gate it on a config value, not on the scheme.
    """

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
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = self.CSP
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

# Audits currently running, keyed on cache_key, each holding an asyncio.Future
# that resolves to the audit result. Share a link and five people can click
# inside the twenty seconds before the first audit populates the cache: all
# five used to miss, reserve a slot, and run the same 13 checks against the
# same nameservers. Now the first arrival runs it and the rest await the same
# future. Guarded by _active_audits_lock; no await happens while it is held.
# /api/audit and the PDF endpoint share this registry because they key on the
# same audit, so a PDF request can join a JSON audit already in flight.
# /api/audit/stream stays out: each client needs its own progress stream.
_inflight: Dict[str, "asyncio.Future"] = {}


def _join_or_lead(cache_key: str):
    """Return (future, is_leader) for this cache key.

    The leader must resolve the future exactly once, in a finally, and pop the
    key. Anything else leaves every follower waiting forever.
    """
    with _active_audits_lock:
        existing = _inflight.get(cache_key)
        if existing is not None:
            return existing, False
        future = asyncio.get_running_loop().create_future()
        _inflight[cache_key] = future
        return future, True


def _release_inflight(cache_key: str, future, payload: Optional[Dict]) -> None:
    """Hand the result to the followers and clear the key.

    Called from the leader's finally, so it also runs when the leader is
    cancelled mid-request or returns 503. A payload of None means the leader
    produced nothing usable, and the followers get a plain error rather than
    waiting on a future that will never resolve.
    """
    with _active_audits_lock:
        if _inflight.get(cache_key) is future:
            del _inflight[cache_key]
    if future.done():
        return
    if payload is None:
        payload = {
            "checks": [],
            "priority_fixes": [],
            "vendors": [],
            "error": "server_error",
            "error_message": "Audit could not complete. Please try again.",
        }
    future.set_result(payload)


def _get_client_ip(request: Request) -> str:
    """Get real client IP behind nginx reverse proxy.

    Trust chain: Client -> Cloudflare -> nginx -> uvicorn
    nginx sets X-Real-IP from the connecting Cloudflare edge IP's
    CF-Connecting-IP header. That's trustworthy when nginx (a configured
    TRUSTED_PROXY_IPS peer) is the direct TCP peer -- but uvicorn can also
    be started bound to 0.0.0.0, where the header comes straight from
    whoever connects and rotating it would bypass the rate limit entirely.
    Only honor X-Real-IP when the direct peer is a trusted proxy; otherwise
    use the peer address itself.
    Client-sent headers like CF-Connecting-IP and X-Forwarded-For
    are NOT trusted directly (trivially spoofable for rate limit bypass).

    DO NOT add --proxy-headers to the uvicorn command line. This whole
    check depends on it being absent. With the flag off, request.client.host
    is nginx's loopback address, which is exactly the "is the direct peer a
    trusted proxy" test above. With the flag on, uvicorn rewrites
    request.client.host from X-Forwarded-For before this function ever runs,
    so peer_ip becomes an attacker-supplied value, it stops matching
    TRUSTED_PROXY_IPS, and the rate limiter's trust model is gone. The one
    thing the flag looks like it would fix, request.url.scheme being http
    behind nginx, is not worth that: see SecurityHeadersMiddleware.
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


# Preflight resolver, built once. dns.resolver.Resolver() re-reads
# /etc/resolv.conf from disk on every construction, and this configuration
# never changes between calls.
try:
    _preflight_resolver = dns.resolver.Resolver()
except dns.exception.DNSException:
    # No resolver configuration at import time. An unconfigured resolver still
    # raises through _preflight_dns_check's own handling rather than taking the
    # whole module down on import.
    _preflight_resolver = dns.resolver.Resolver(configure=False)
_preflight_resolver.timeout = 5
_preflight_resolver.lifetime = 3


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
        try:
            _preflight_resolver.resolve(domain, "SOA")
        except dns.resolver.NoAnswer:
            _preflight_resolver.resolve(domain, "NS")
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
    # Normalize before validating. Validating the trimmed value while caching
    # and resolving the raw one lets "%20google" pass, poison its own cache
    # key, and look up " google._domainkey.example.com".
    selector = selector.strip() if selector else None
    if selector and not SELECTOR_PATTERN.match(selector):
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

    # Join an identical audit already running, rather than starting a second
    # one. A follower does no work, so it takes no concurrency slot.
    _audit_future, _is_leader = _join_or_lead(cache_key)
    if not _is_leader:
        log.info("Coalesced onto in-flight audit: %s (rid=%s)", domain, request_id)
        # shield: awaiting a Future directly propagates the awaiting task's
        # cancellation into the Future itself, so one follower giving up would
        # otherwise cancel the shared result for the leader and every other
        # follower.
        shared = await asyncio.shield(_audit_future)
        return JSONResponse(content={**shared, "request_id": request_id, "coalesced": True})

    # Reserve a concurrent-audit slot atomically (DoS protection).
    # Shared with /api/audit/stream: both endpoints invoke the same
    # expensive run_full_audit(), so they draw from one global budget
    # rather than /api/audit being unbounded.
    global _active_audits
    _payload = None
    try:
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
            # Pre-flight DNS check (offloaded -- this does blocking socket I/O).
            # It runs inside the reservation so a domain whose nameservers
            # blackhole traffic is bounded by the audit budget instead of tying
            # up an anyio thread that plain page loads draw from too.
            preflight_err = await anyio.to_thread.run_sync(_preflight_dns_check, domain)
            if preflight_err:
                log.info("Preflight failed for %s: %s", domain, preflight_err.get("error"))
                _payload = preflight_err
                return JSONResponse(content=preflight_err)

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
        _payload = result
        return JSONResponse(content=result)
    finally:
        # Runs on every path out, including the 503 and a cancelled request,
        # so a follower is never left waiting on a future nobody resolves.
        _release_inflight(cache_key, _audit_future, _payload)


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
    # Normalize before validating. Validating the trimmed value while caching
    # and resolving the raw one lets "%20google" pass, poison its own cache
    # key, and look up " google._domainkey.example.com".
    selector = selector.strip() if selector else None
    if selector and not SELECTOR_PATTERN.match(selector):
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

    # Reserve a concurrent-audit slot atomically (DoS protection)
    with _active_audits_lock:
        if _active_audits >= _MAX_CONCURRENT_AUDITS:
            async def _busy_error():
                yield f"data: {json.dumps({'error': 'Server is busy. Please try again in a moment.'})}\n\n"
            return StreamingResponse(_busy_error(), media_type="text/event-stream")
        _active_audits += 1

    # Everything from here to the StreamingResponse return has to release the
    # slot on failure. The normal release lives in _event_stream's finally,
    # which only runs once the generator is actually consumed, so any failure
    # before that point leaks the slot permanently. Thread.start raising
    # RuntimeError under thread exhaustion is the case that actually happens,
    # and eight of those leave every user with "Server is busy" until the
    # service is restarted.
    slot_held = True
    try:
        # Pre-flight DNS check (offloaded -- this does blocking socket I/O).
        # It runs inside the reservation so a domain whose nameservers
        # blackhole traffic is bounded by the audit budget instead of tying up
        # an anyio thread that plain page loads draw from too.
        preflight_err = await anyio.to_thread.run_sync(_preflight_dns_check, domain)
        if preflight_err:
            log.info("SSE preflight failed for %s: %s", domain, preflight_err.get("error"))
            with _active_audits_lock:
                _active_audits -= 1
            slot_held = False

            async def _preflight_error():
                yield f"data: {json.dumps({'done': True, 'result': preflight_err})}\n\n"

            return StreamingResponse(_preflight_error(), media_type="text/event-stream")

        # Run audit in a background thread, streaming progress over an
        # asyncio.Queue. The old queue.Queue had to be polled from a worker
        # thread, so every open stream held one of the default executor's
        # threads (6 on a 2 vCPU box) to watch a queue that is empty almost
        # all the time.
        loop = asyncio.get_running_loop()
        progress_q: asyncio.Queue = asyncio.Queue()
        cancel_event = threading.Event()

        def _emit(msg):
            # Called from the audit thread. The stream's loop can already be
            # gone (client disconnected, worker shutting down); dropping the
            # message is right then, there is nobody left to receive it.
            try:
                loop.call_soon_threadsafe(progress_q.put_nowait, msg)
            except RuntimeError:
                pass

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
            _emit(msg)

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
                _emit({"_done": True, "_result": result})
            except InterruptedError:
                log.info("SSE audit cancelled (client disconnect): %s", domain)
                _emit({"_done": True, "_result": {"error": "cancelled"}})
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
                _emit({"_done": True, "_result": error_result})

        sse_start_time = time.time()
        audit_thread = threading.Thread(target=_run_audit, daemon=True)
        audit_thread.start()

        async def _event_stream():
            global _active_audits
            outcome_logged = False
            # Nothing has been written to the socket yet, so the keepalive
            # clock starts with the stream itself.
            last_yield = time.time()
            try:
                while True:
                    if time.time() - sse_start_time > 90:
                        log.warning("SSE stream exceeded 90s limit: %s", domain)
                        cancel_event.set()
                        timeout_result = {
                            "domain": domain,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "checks": [],
                            "priority_fixes": [],
                            "vendors": [],
                            "error": "timeout",
                            "error_message": "Audit exceeded the 90 second time limit. Please try again.",
                        }
                        _log_audit(request, domain, scope, 90.0, 0, source="sse",
                                   status="timeout", error="timeout")
                        outcome_logged = True
                        yield f"data: {json.dumps({'done': True, 'result': timeout_result})}\n\n"
                        return
                    try:
                        msg = await asyncio.wait_for(progress_q.get(), timeout=0.2)
                    except asyncio.TimeoutError:
                        # Between checks the stream would otherwise write
                        # nothing at all. Cloudflare closes a proxied
                        # connection that goes quiet, well before the 90s cap
                        # above can produce a graceful result, and the client's
                        # idle watchdog cannot tell a slow check from a dead
                        # socket. An SSE comment line fixes both: browsers
                        # ignore any line starting with a colon. Only when the
                        # stream has actually been silent, not on every 200ms
                        # poll.
                        if time.time() - last_yield > 10:
                            last_yield = time.time()
                            yield ": keepalive\n\n"

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
                        last_yield = time.time()
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
    except Exception as e:
        if slot_held:
            with _active_audits_lock:
                _active_audits -= 1
        log.error("SSE audit setup failed for %s: %s", domain, str(e)[:200], exc_info=True)

        async def _setup_error():
            yield f"data: {json.dumps({'error': 'Audit could not start. Please try again in a moment.'})}\n\n"

        return StreamingResponse(_setup_error(), media_type="text/event-stream")


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
    # Normalize before validating. Validating the trimmed value while caching
    # and resolving the raw one lets "%20google" pass, poison its own cache
    # key, and look up " google._domainkey.example.com".
    selector = selector.strip() if selector else None
    if selector and not SELECTOR_PATTERN.match(selector):
        raise HTTPException(status_code=400, detail="Invalid DKIM selector (RFC 6376: alphanumeric and hyphens only)")
    log.info("PDF requested: %s (scope=%s, ip=%s)", domain, scope or "complete", client_ip)

    cache_key = f"{domain}:{selector or ''}:{scope or 'complete'}"

    # Reserve a concurrent-audit slot atomically, the same budget /api/audit
    # and /api/audit/stream draw from. Without this the endpoint was bounded
    # only by the per-IP rate limit, and both the audit and the PDF render run
    # on anyio's default thread limiter (40 tokens) that Starlette also uses
    # for FileResponse. A handful of IPs, or one crawler following PDF links,
    # could exhaust that limiter and leave /, /about, /privacy and the article
    # pages queued behind full DNS audits with no audit at the cap at all.
    # The render is reserved too, not just the audit: a cached PDF still burns
    # a limiter token for CPU-bound rendering.
    global _active_audits
    with _active_audits_lock:
        if _active_audits >= _MAX_CONCURRENT_AUDITS:
            return JSONResponse(
                status_code=503,
                content={"detail": "Server is busy. Please try again in a moment."},
                headers={"Retry-After": "5"},
            )
        _active_audits += 1

    _pdf_future = None
    _pdf_payload = None
    try:
        # Reuse cached audit data if available
        cached = _get_cached(cache_key)
        if cached:
            data = cached
            log.info("PDF using cached data: %s", domain)
        else:
            # Join an identical audit already in flight rather than running a
            # second one. Unlike /api/audit a follower here keeps its slot: it
            # still has a PDF to render, which is the CPU-bound half. The
            # registry is joined after the reservation on purpose, so the
            # leader always already holds a slot and cannot end up waiting on
            # followers that hold them all.
            _pdf_future, _is_leader = _join_or_lead(cache_key)
            if not _is_leader:
                log.info("PDF coalesced onto in-flight audit: %s", domain)
                data = await asyncio.shield(_pdf_future)
                _pdf_future = None  # a follower must not resolve or pop it
                if data.get("error"):
                    return Response(
                        content=data.get("error_message", "Audit failed"),
                        status_code=400,
                        media_type="text/plain",
                    )
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
                _pdf_payload = data

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
    finally:
        if _pdf_future is not None:
            _release_inflight(cache_key, _pdf_future, _pdf_payload)
        with _active_audits_lock:
            _active_audits -= 1

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

# The health probe's DNS lookup is a real network round trip. Memoizing it
# keeps an uptime monitor on a 30 second interval from generating live DNS
# traffic on every hit.
_HEALTH_TTL = 30
_health_cache = {"ok": None, "expires": 0.0}
_health_cache_lock = threading.Lock()


@app.get("/api/health", tags=["System"])
async def health():
    """
    Health check endpoint for monitoring and load balancers.
    Returns 200 if the application and DNS resolution are functional.
    """
    with _health_cache_lock:
        verdict = _health_cache["ok"] if time.time() < _health_cache["expires"] else None

    if verdict is None:
        try:
            # Offloaded: this is a blocking socket call, and the service runs a
            # single uvicorn worker, so running it inline froze the event loop
            # for the whole round trip and stalled every request in flight.
            await anyio.to_thread.run_sync(
                functools.partial(dns.resolver.resolve, "example.com", "A", lifetime=2)
            )
            verdict = True
        except Exception as e:
            log.error("Health check DNS resolution failed: %s", str(e)[:200])
            verdict = False
        with _health_cache_lock:
            _health_cache["ok"] = verdict
            _health_cache["expires"] = time.time() + _HEALTH_TTL

    if verdict:
        return {"status": "ok", "dns_resolution": "working"}
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

    # Third of the three /blog/ slugs. It had no route and 404'd while the
    # other two redirected. The markdown that declared these canonicals is
    # gone now, and nginx logs show no real traffic to any of the three, but
    # the log window is two weeks and a 301 is cheaper than a dead link in
    # someone's old message.
    @app.get("/blog/the-dnssec-story-nobody-tells", tags=["Pages"])
    async def the_dnssec_story_nobody_tells():
        return RedirectResponse(url="/articles/dnssec", status_code=301)

    @app.get("/methodology", tags=["Pages"])
    async def methodology_redirect():
        return RedirectResponse(url="/about", status_code=301)

    @app.get("/about", tags=["Pages"])
    async def about():
        return FileResponse(str(STATIC_DIR / "about.html"))

    @app.get("/privacy", tags=["Pages"])
    async def privacy():
        return FileResponse(str(STATIC_DIR / "privacy.html"))

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
        {"loc": "/privacy", "changefreq": "yearly", "priority": "0.3"},
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

