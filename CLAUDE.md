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
- When editing static/privacy.html body content, update the "Last updated" date in the same commit.

## Architecture
- API: /api/audit (JSON), /api/audit/stream (SSE), /api/audit/{domain}/pdf
- 6 audit scopes: complete, email_full, dmarc, transport, dns_infra, security_scan
- Server-side scope filtering skips unneeded checks
- Cache key format: "domain:selector:scope" (5 min TTL)
- Audit log: audit.log (JSON-lines, GDPR-safe). Fields: ts, domain, scope,
  duration_s, checks, ua, bot, source, status, vid, plus error when status is
  not "ok" and ref when a Referer was sent. Fields are added, never renamed or
  removed, so older entries carry fewer of them.
  - `ua` is coarse labels only, "<browser family> / <OS family>", never a raw
    user-agent string and never a version number. Browser families: Chrome,
    Firefox, Safari, Edge, other, bot/tool, unknown. OS families: Windows,
    macOS, Linux, iOS, Android, other, unknown.
  - `bot` is a boolean derived in `ua_classify.is_bot()` from the full user
    agent, and it has to be computed before `ua_summary()` reduces the string.
    The labels do not carry enough to tell a crawler from a person, so any
    reader that tries to re-derive bot status from `ua` gets nothing. Read the
    `bot` field.
  - `rewrite_audit_log_ua.py` applies the same transformation to stored history
    (audit.log and audit.log.N). It backs up originals, leaves entries that
    already have a bot flag alone, and prints before and after line counts.

## Deploy
git push && ssh marmot7@159.223.201.90 "cd dns-security-auditor && git pull && ~/.venv/bin/pip install -r requirements.txt && sudo systemctl restart dns-auditor"

The pip install step matters: the server's venv is not kept in sync with
requirements.txt automatically, so a new or bumped dependency (e.g.
cryptography, added for DNSSEC/RSA key generation) installs fine in a
fresh CI venv but crash-loops the live service if this step is skipped.

## Cache-busting
After any change to `static/style.css` or `static/app.js`, run this command before committing, OR include it as the final step of your commit. It handles any alphanumeric version string and rewrites both CSS and JS references across every static HTML page:

```bash
NEW=$(git rev-parse --short HEAD) && for f in static/*.html static/articles/*.html; do
  sed -i -E "s|(style\.css\|app\.js\|articles\.js)\?v=[a-zA-Z0-9]+|\1?v=$NEW|g" "$f"
done
```

The glob must include `static/articles/`. `static/*.html` does not match
nested paths, so an earlier version of this loop updated only the four
top-level pages and left the four article pages pinned to an older build.
`articles.js` is in the pattern for the same reason: it is a real asset that
needs busting and only `static/articles/index.html` references it.

The older pattern `grep -oP 'v=\K[a-f0-9]+'` is broken: it only matches hex characters, so version strings containing non-hex letters (e.g. `ds17`, `sec9`) produce a partial or empty match and sed silently no-ops. Do not use the old pattern.

## Testing
Any module a test imports that is not in requirements.txt goes in requirements-dev.txt, never in the workflow file.

python3 -m pytest tests/ -v
python3 -c "import ast; ast.parse(open('server.py').read()); print('OK')"
curl -s https://dns-audit.com/api/health | python3 -m json.tool
