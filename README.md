# DNS Security Auditor - Web Application

FastAPI backend + vanilla HTML/CSS/JS frontend for dns-audit.com.

Replaces the Streamlit app with a professional, single-page security audit tool.

## Project Structure

```
dns-security-auditor/
    server.py               # FastAPI app - serves API + static files
    audit_engine.py         # Orchestrates all checks, builds response
    result_transformer.py   # Converts raw module output to frontend format
    requirements.txt        # Python dependencies
    Procfile                # Deployment (Render/Railway)
    static/
        index.html          # Frontend - single page
        style.css           # Styles
        app.js              # Frontend logic, API calls, rendering
    # --- Your existing modules (unchanged) ---
    checks_extra.py         # MTA-STS, TLS-RPT, BIMI
    mx_check.py             # MX analysis
    spf_intelligence.py     # SPF-based DKIM discovery
    advanced_fingerprinting.py
    security_scoring.py
    dkim_formatter.py
    dkim_key_age.py
    dkim_tag_analyzer.py
    comprehensive_selectors.py
    config.py
```

## Setup

```bash
# Clone your repo
git clone https://github.com/marmot7775/dns-security-auditor.git
cd dns-security-auditor

# Copy the new files into the repo root
# (server.py, audit_engine.py, result_transformer.py, Procfile)
# Copy static/ directory into repo root

# Install dependencies
pip install -r requirements.txt

# Run locally
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

Open http://localhost:8000 in your browser.

## Integration Steps

1. Copy these new files into your existing repo root:
   - `server.py`
   - `audit_engine.py`
   - `result_transformer.py`
   - `Procfile`
   - `static/` directory (index.html, style.css, app.js)

2. Update `requirements.txt` to include FastAPI and uvicorn (see the new one).

3. Your existing modules stay exactly where they are. No changes needed to:
   - checks_extra.py
   - mx_check.py
   - spf_intelligence.py
   - advanced_fingerprinting.py
   - security_scoring.py
   - dkim_formatter.py
   - dkim_key_age.py
   - dkim_tag_analyzer.py
   - comprehensive_selectors.py
   - config.py

4. The old `app.py` (Streamlit) and `dns_tools.py` are no longer needed.
   You can keep them for reference or remove them.

## API

```
GET /api/audit?domain=example.com
GET /api/audit?domain=example.com&nocache=true
GET /api/health
```

Response shape:

```json
{
  "domain": "example.com",
  "timestamp": "2026-02-13T22:45:00",
  "elapsed_seconds": 4.2,
  "score": { "total": 72, "grade": "B" },
  "checks": [
    {
      "name": "DMARC",
      "status": "pass|warn|fail",
      "pill_label": "optional override",
      "verdict": "one-line summary",
      "record": "raw DNS record",
      "explanation": "HTML plain-English explanation",
      "details": [
        { "type": "good|warning|error|info", "text": "..." }
      ],
      "fix": "HTML recommended action"
    }
  ],
  "priority_fixes": ["Fix 1", "Fix 2"],
  "vendors": [
    { "name": "Google Workspace", "confidence": 95 }
  ]
}
```

## Deployment

### Render

1. Connect your GitHub repo
2. Build command: `pip install -r requirements.txt`
3. Start command: `uvicorn server:app --host 0.0.0.0 --port $PORT`

### Railway

1. Connect your GitHub repo
2. It auto-detects the Procfile

### VPS

```bash
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8000
```

Use nginx as a reverse proxy for production. Add SSL via Let's Encrypt.
