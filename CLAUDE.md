# dns-security-auditor

## Stack
- **Backend:** Python, FastAPI (server.py), uvicorn
- **Frontend:** Vanilla HTML/CSS/JS (static/)
- **Server:** Ubuntu on DigitalOcean (159.223.201.90), Cloudflare DNS
- **Domain:** dns-audit.com

## Key files
- `server.py` -- FastAPI app, SSE streaming, caching, rate limiting
- `audit_engine.py` -- orchestrates all 13 security checks
- `result_transformer.py` -- transforms raw results into frontend card format
- `static/app.js` -- frontend logic, SSE client, result rendering
- `static/style.css` -- all styles, 5 responsive breakpoints
- `static/index.html` -- single-page app shell
- `comprehensive_selectors.py` -- DKIM selector list for auto-discovery
- `dns_tools.py` -- domain normalization, audit entry point

## Rules
- NEVER use em-dashes (—) or double-hyphens ( -- ) in user-facing text. Rewrite the sentence instead.
- Fail color is #ef4444 (clear red). Dark theme default, light mode via prefers-color-scheme.
- All touch targets must be 44px minimum on mobile
- Text contrast must pass WCAG AA (4.5:1 ratio)
- No personal data in logs (GDPR-safe)

## Architecture
- API: /api/audit (JSON), /api/audit/stream (SSE), /api/audit/pdf
- 6 audit scopes: complete, email_full, dmarc, transport, dns_infra, security_scan
- Server-side scope filtering skips unneeded checks
- Cache key format: "domain:selector:scope" (5 min TTL)
- Audit log: audit.log (JSON-lines, GDPR-safe)

## Deploy
git push && ssh marmot7@159.223.201.90 "cd dns-security-auditor && git pull && sudo systemctl restart dns-auditor"

## Cache-busting
After any change to `static/style.css` or `static/app.js`, run this command before committing, OR include it as the final step of your commit. It handles any alphanumeric version string and rewrites both CSS and JS references across every static HTML page:

```bash
NEW=$(git rev-parse --short HEAD) && for f in static/*.html; do
  sed -i -E "s|(style\.css\|app\.js)\?v=[a-zA-Z0-9]+|\1?v=$NEW|g" "$f"
done
```

The older pattern `grep -oP 'v=\K[a-f0-9]+'` is broken: it only matches hex characters, so version strings containing non-hex letters (e.g. `ds17`, `sec9`) produce a partial or empty match and sed silently no-ops. Do not use the old pattern.

## Testing
python3 -m pytest tests/ -v
python3 -c "import ast; ast.parse(open('server.py').read()); print('OK')"
curl -s https://dns-audit.com/api/health | python3 -m json.tool
