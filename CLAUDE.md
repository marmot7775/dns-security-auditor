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
- `config.py` -- DKIM selectors list
- `dns_tools.py` -- domain normalization, audit entry point

## Rules
- NEVER use em-dashes anywhere. Use " -- " instead.
- Fail color is burnt red (#9b4040), not blue-gray
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

## Testing
python3 -m pytest tests/ -v
python3 -c "import ast; ast.parse(open('server.py').read()); print('OK')"
curl -s https://dns-audit.com/api/health | python3 -m json.tool
