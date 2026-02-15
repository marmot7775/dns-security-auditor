"""
DMARCbis Tree Walk - Animated Visualization Card
=================================================
Generates self-contained HTML/CSS/JS pages for the tree walk
presentation. Used by server.py to serve /treewalk.
"""

import html as html_lib
import json
from typing import Any, Dict


def render_landing_page() -> str:
    """Landing page with domain input form."""
    return """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DMARCbis Tree Walk Visualizer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: #0a0e1a;
    color: #f1f5f9;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .landing { text-align: center; max-width: 600px; padding: 40px; }
  .landing h1 {
    font-size: 42px; font-weight: 800; letter-spacing: -1px;
    background: linear-gradient(135deg, #f1f5f9 0%, #60a5fa 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text; margin-bottom: 12px;
  }
  .landing p { color: #94a3b8; font-size: 16px; line-height: 1.6; margin-bottom: 32px; }
  .landing form { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
  .landing input {
    padding: 14px 20px; background: #1e293b;
    border: 1.5px solid rgba(99,130,191,0.2); border-radius: 12px;
    color: #f1f5f9; font-family: 'JetBrains Mono', monospace;
    font-size: 15px; width: 320px; outline: none; transition: border-color 0.2s ease;
  }
  .landing input:focus { border-color: #60a5fa; }
  .landing input::placeholder { color: #64748b; }
  .landing button {
    padding: 14px 28px; background: rgba(96,165,250,0.15);
    border: 1.5px solid rgba(96,165,250,0.3); border-radius: 12px;
    color: #60a5fa; font-family: 'Inter', sans-serif;
    font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s ease;
  }
  .landing button:hover { background: rgba(96,165,250,0.25); }
  .badge {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 14px; background: rgba(96,165,250,0.1);
    border: 1px solid rgba(96,165,250,0.2); border-radius: 100px;
    font-size: 11px; font-weight: 600; color: #60a5fa;
    letter-spacing: 0.5px; text-transform: uppercase; margin-bottom: 20px;
  }
  .badge .dot {
    width: 6px; height: 6px; border-radius: 50%; background: #60a5fa;
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 0.5; transform: scale(0.8); }
    50% { opacity: 1; transform: scale(1.2); }
  }
  .examples { margin-top: 24px; font-size: 13px; color: #64748b; }
  .examples a {
    color: #60a5fa; text-decoration: none;
    font-family: 'JetBrains Mono', monospace; font-size: 12px;
  }
  .examples a:hover { text-decoration: underline; }
</style>
</head>
<body>
  <div class="landing">
    <div class="badge"><span class="dot"></span> DMARCbis &middot; Standards Track</div>
    <h1>DNS Tree Walk</h1>
    <p>Visualize how email receivers discover DMARC policies by walking up the DNS hierarchy per
    <a href="https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/" target="_blank" rel="noopener" style="color:#60a5fa;text-decoration:none;">draft-ietf-dmarc-dmarcbis</a>,
    Section 4.10. The Tree Walk offers a DNS-native alternative to Public Suffix Lists, giving domain owners direct control over organizational boundaries.</p>
    <form action="/treewalk" method="get">
      <input type="text" name="domain" placeholder="mail.example.com" required autofocus>
      <button type="submit">🌳 Visualize</button>
    </form>
    <div class="examples">
      Try: <a href="/treewalk?domain=mail.google.com">mail.google.com</a> &middot;
      <a href="/treewalk?domain=subdomain.github.io">subdomain.github.io</a> &middot;
      <a href="/treewalk?domain=mx.microsoft.com">mx.microsoft.com</a>
    </div>
  </div>
  <footer style="text-align:center;padding:2rem 0 1rem;color:#888;font-size:0.85rem;">
    <a href="/" style="color:#60a5fa;text-decoration:none;">dns-audit.com</a> &middot;
    Built by <a href="https://www.linkedin.com/in/neilanuskiewicz/" target="_blank" rel="noopener" style="color:#60a5fa;text-decoration:none;">Neil Anuskiewicz</a> &middot;
    Email &amp; DNS Security Consultant
  </footer>
</body>
</html>"""


def render_tree_walk_page(tw_result: Dict[str, Any]) -> str:
    """Generate the full-page animated tree walk visualization."""
    author_domain = html_lib.escape(tw_result.get("domain", ""))
    author_domain_js = json.dumps(tw_result.get("domain", ""))

    # Build steps with educational narration
    raw_steps = tw_result.get("steps", [])
    steps = []
    for i, s in enumerate(raw_steps):
        step_domain = s.get("domain", "")
        query_name = s.get("query", f"_dmarc.{step_domain}")
        is_found = s.get("found", False)
        is_first = i == 0
        is_terminal = is_found and step_domain == tw_result.get("policy_source")

        # Build educational narration
        if is_first:
            if is_found:
                narration = f"Starting at the author domain. Query {query_name} — Found a DMARC record! This subdomain has its own policy."
            else:
                narration = f"Starting at the author domain. Query {query_name} — No DMARC record found here. The tree walk begins by removing the leftmost label and moving up the DNS hierarchy."
        else:
            if is_found:
                if is_terminal:
                    policy = tw_result.get("effective_policy", "none")
                    tag = tw_result.get("applied_tag", "p")
                    narration = f"Query {query_name} — DMARC record found! The effective policy is {tag}={policy}. This is the organizational domain. Walk complete."
                else:
                    narration = f"Query {query_name} — DMARC record found. Checking for organizational boundary markers (psd tag)..."
            else:
                narration = f"Query {query_name} — No record found. Continuing to walk up by removing the leftmost label..."

        steps.append({
            "step_number": i + 1,
            "query_name": query_name,
            "domain_queried": step_domain,
            "response_type": "FOUND" if is_found else "NXDOMAIN",
            "record_text": s.get("record"),
            "narration": narration,
            "is_terminal": is_terminal,
        })

    steps_json = json.dumps(steps, default=str)
    total_queries = len(steps)

    result_obj = {
        "organizational_domain": tw_result.get("policy_source") or tw_result.get("org_domain"),
        "policy": tw_result.get("effective_policy"),
        "determination_method": _determination_method(tw_result),
    }
    result_json = json.dumps(result_obj, default=str)

    # Unique domains in step order (reversed for top-down tree)
    seen = set()
    domains = []
    for s in steps:
        d = s["domain_queried"]
        if d not in seen:
            seen.add(d)
            domains.append(d)
    domains.reverse()  # Show tree top-down (TLD at top)
    domains_json = json.dumps(domains)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tree Walk: {author_domain}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  :root {{
    --bg-primary: #0a0e1a; --bg-card: #111827; --bg-node: #1e293b;
    --bg-node-active: #1a2744; --border-subtle: rgba(99,130,191,0.15);
    --border-active: rgba(96,165,250,0.5); --text-primary: #f1f5f9;
    --text-secondary: #94a3b8; --text-muted: #64748b;
    --accent-blue: #60a5fa; --accent-cyan: #22d3ee; --accent-green: #34d399;
    --accent-red: #f87171; --accent-amber: #fbbf24; --accent-purple: #a78bfa;
    --glow-blue: rgba(96,165,250,0.3); --glow-green: rgba(52,211,153,0.3);
  }}
  body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg-primary); color: var(--text-primary);
    overflow-x: hidden; min-height: 100vh; padding: 12px 20px;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .back-link {{
    display: inline-flex; align-items: center; gap: 6px;
    color: var(--text-muted); text-decoration: none; font-size: 13px;
    font-weight: 500; margin-bottom: 16px; transition: color 0.2s;
  }}
  .back-link:hover {{ color: var(--accent-blue); }}

  /* Header with controls at top */
  .header {{
    background: var(--bg-card);
    border-radius: 16px; border: 1px solid var(--border-subtle);
    padding: 16px 24px; margin-bottom: 12px;
    box-shadow: 0 0 0 1px rgba(255,255,255,0.03), 0 10px 30px -10px rgba(0,0,0,0.3);
  }}
  .header-top {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; margin-bottom: 10px; }}
  .title-section {{ flex: 1; min-width: 280px; }}
  .badge {{
    display: inline-flex; align-items: center; gap: 6px;
    padding: 3px 12px; background: rgba(96,165,250,0.1);
    border: 1px solid rgba(96,165,250,0.2); border-radius: 100px;
    font-size: 10px; font-weight: 600; color: var(--accent-blue);
    letter-spacing: 0.5px; text-transform: uppercase; margin-bottom: 8px;
  }}
  .badge .dot {{
    width: 5px; height: 5px; border-radius: 50%; background: var(--accent-blue);
    animation: pulse-dot 2s ease-in-out infinite;
  }}
  @keyframes pulse-dot {{
    0%, 100% {{ opacity: 0.5; transform: scale(0.8); }}
    50% {{ opacity: 1; transform: scale(1.2); }}
  }}
  .title {{
    font-size: 20px; font-weight: 800; letter-spacing: -0.5px;
    background: linear-gradient(135deg, var(--text-primary) 0%, var(--accent-blue) 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text; margin-bottom: 4px;
  }}
  .subtitle {{ font-size: 12px; color: var(--text-secondary); line-height: 1.5; max-width: 600px; }}

  /* Controls at top - immediately visible */
  .controls {{
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  }}
  .btn {{
    padding: 10px 20px; border: 1px solid var(--border-subtle);
    border-radius: 10px; background: var(--bg-node); color: var(--text-secondary);
    font-family: 'Inter', sans-serif; font-size: 13px; font-weight: 600;
    cursor: pointer; transition: all 0.2s ease; display: flex;
    align-items: center; gap: 8px; white-space: nowrap;
  }}
  .btn:hover {{ background: var(--bg-node-active); border-color: var(--border-active); color: var(--text-primary); }}
  .btn:disabled {{ opacity: 0.4; cursor: not-allowed; }}
  .btn-primary {{
    background: linear-gradient(135deg, rgba(96,165,250,0.2) 0%, rgba(96,165,250,0.1) 100%);
    border-color: rgba(96,165,250,0.4); color: var(--accent-blue);
    box-shadow: 0 0 20px -10px var(--glow-blue);
  }}
  .btn-primary:hover {{ background: linear-gradient(135deg, rgba(96,165,250,0.3) 0%, rgba(96,165,250,0.15) 100%); }}
  .speed-controls {{ display: flex; gap: 8px; }}
  .speed-btn {{
    padding: 8px 14px; font-size: 12px; min-width: 50px; justify-content: center;
  }}
  .speed-btn.active {{
    background: rgba(96,165,250,0.2); border-color: var(--accent-blue);
    color: var(--accent-blue);
  }}
  .progress-text {{ font-size: 12px; color: var(--text-muted); font-weight: 500; padding: 0 8px; }}

  .domain-display {{
    display: inline-flex; align-items: center; gap: 10px;
    padding: 8px 16px; background: rgba(0,0,0,0.3);
    border: 1px solid var(--border-subtle); border-radius: 8px;
    font-family: 'JetBrains Mono', monospace; font-size: 14px;
    font-weight: 500; color: var(--accent-cyan);
  }}
  .domain-display .label {{
    font-family: 'Inter', sans-serif; font-size: 10px; font-weight: 600;
    color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;
  }}

  /* Main content: 2-column layout */
  .main-content {{
    display: grid; grid-template-columns: 1.2fr 1fr; gap: 20px;
    min-height: 540px; max-height: 65vh;
  }}
  @media (max-width: 1100px) {{
    .main-content {{ grid-template-columns: 1fr; max-height: none; }}
  }}

  /* Left panel: Narration */
  .narration-panel {{
    background: var(--bg-card); border-radius: 16px;
    border: 1px solid var(--border-subtle); padding: 28px;
    box-shadow: 0 0 0 1px rgba(255,255,255,0.03), 0 10px 30px -10px rgba(0,0,0,0.3);
    overflow-y: auto;
  }}
  .panel-title {{
    font-size: 11px; font-weight: 700; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 1px; margin-bottom: 20px;
    display: flex; align-items: center; gap: 8px;
  }}
  .narration-item {{
    margin-bottom: 20px; padding: 16px 18px;
    background: var(--bg-node); border: 1.5px solid transparent;
    border-radius: 12px; opacity: 0; transform: translateY(10px);
    transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  }}
  .narration-item.visible {{ opacity: 1; transform: translateY(0); }}
  .narration-item.active {{
    border-color: var(--accent-blue);
    background: linear-gradient(135deg, rgba(96,165,250,0.08) 0%, rgba(96,165,250,0.04) 100%);
    box-shadow: 0 0 25px -8px var(--glow-blue);
    transform: scale(1.02);
  }}
  .narration-header {{
    display: flex; align-items: flex-start; gap: 12px; margin-bottom: 10px;
  }}
  .step-badge {{
    width: 28px; height: 28px; display: flex; align-items: center; justify-content: center;
    border-radius: 8px; font-size: 13px; font-weight: 700;
    background: rgba(96,165,250,0.15); color: var(--accent-blue);
    flex-shrink: 0;
  }}
  .narration-query {{
    font-family: 'JetBrains Mono', monospace; font-size: 13px;
    font-weight: 600; color: var(--text-primary); word-break: break-all;
    flex: 1;
  }}
  .narration-text {{
    font-size: 14px; color: var(--text-secondary); line-height: 1.6;
    margin-left: 40px;
  }}
  .response-badge {{
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 6px; font-size: 11px;
    font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
    margin: 8px 0 0 40px;
  }}
  .response-found {{ background: rgba(52,211,153,0.15); color: var(--accent-green); }}
  .response-not-found {{ background: rgba(248,113,113,0.15); color: var(--accent-red); }}
  .record-display {{
    margin: 10px 0 0 40px; padding: 10px 14px;
    background: rgba(0,0,0,0.4); border-radius: 8px;
    font-family: 'JetBrains Mono', monospace; font-size: 11px;
    color: var(--accent-cyan); word-break: break-all; line-height: 1.6;
    opacity: 0; transition: opacity 0.3s ease;
  }}
  .record-display.visible {{ opacity: 1; }}

  /* Right panel: DNS Tree */
  .tree-panel {{
    background: var(--bg-card); border-radius: 16px;
    border: 1px solid var(--border-subtle); padding: 28px;
    box-shadow: 0 0 0 1px rgba(255,255,255,0.03), 0 10px 30px -10px rgba(0,0,0,0.3);
    display: flex; flex-direction: column; position: relative; overflow: hidden;
  }}
  .tree-panel::before {{
    content: ''; position: absolute; width: 250px; height: 250px;
    background: radial-gradient(circle, rgba(96,165,250,0.05) 0%, transparent 70%);
    top: 50%; left: 50%; transform: translate(-50%, -50%); pointer-events: none;
    animation: tree-glow 4s ease-in-out infinite;
  }}
  @keyframes tree-glow {{
    0%, 100% {{ opacity: 0.3; transform: translate(-50%, -50%) scale(1); }}
    50% {{ opacity: 0.6; transform: translate(-50%, -50%) scale(1.1); }}
  }}
  .tree-container {{
    flex: 1; display: flex; flex-direction: column; justify-content: center;
    gap: 0; width: 100%; max-width: 400px; margin: 0 auto;
    position: relative; z-index: 1;
  }}
  .tree-node {{
    padding: 14px 18px; background: var(--bg-node);
    border: 2px solid var(--border-subtle); border-radius: 12px;
    opacity: 0; transform: scale(0.92); position: relative;
    transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1);
  }}
  .tree-node.visible {{ opacity: 1; transform: scale(1); }}
  .tree-node.querying {{
    border-color: var(--accent-blue);
    background: linear-gradient(135deg, rgba(96,165,250,0.12) 0%, rgba(96,165,250,0.06) 100%);
    box-shadow: 0 0 0 2px rgba(96,165,250,0.3), 0 0 30px -8px var(--glow-blue),
      inset 0 0 30px -10px var(--glow-blue);
    animation: query-pulse 1.2s ease-in-out infinite;
  }}
  @keyframes query-pulse {{
    0%, 100% {{ box-shadow: 0 0 0 2px rgba(96,165,250,0.3), 0 0 30px -8px var(--glow-blue); }}
    50% {{ box-shadow: 0 0 0 3px rgba(96,165,250,0.5), 0 0 45px -5px var(--glow-blue), 0 0 70px -15px var(--glow-blue); }}
  }}
  .tree-node.found {{
    border-color: var(--accent-green);
    box-shadow: 0 0 0 2px var(--accent-green), 0 0 30px -8px var(--glow-green);
  }}
  .tree-node.not-found {{ border-color: rgba(248,113,113,0.25); opacity: 0.5; }}
  .tree-node.org-domain {{
    border-color: var(--accent-green);
    background: linear-gradient(135deg, rgba(52,211,153,0.15) 0%, rgba(34,211,238,0.08) 100%);
    box-shadow: 0 0 0 3px var(--accent-green), 0 0 50px -10px var(--glow-green),
      0 0 90px -20px var(--glow-green);
    animation: org-glow 2.5s ease-in-out infinite;
  }}
  @keyframes org-glow {{
    0%, 100% {{ box-shadow: 0 0 0 3px var(--accent-green), 0 0 50px -10px var(--glow-green); }}
    50% {{ box-shadow: 0 0 0 3px var(--accent-green), 0 0 70px -8px var(--glow-green), 0 0 120px -25px rgba(52,211,153,0.2); }}
  }}
  .node-domain {{
    font-family: 'JetBrains Mono', monospace; font-size: 14px;
    font-weight: 600; color: var(--text-primary);
  }}
  .node-status {{
    position: absolute; top: 10px; right: 12px; font-size: 20px;
    opacity: 0; transform: scale(0);
    transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
  }}
  .node-status.visible {{ opacity: 1; transform: scale(1); }}
  .node-label {{
    margin-top: 8px; display: inline-flex; align-items: center; gap: 5px;
    padding: 4px 10px; border-radius: 6px; font-size: 10px;
    font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
    opacity: 0; transition: opacity 0.4s ease;
  }}
  .node-label.visible {{ opacity: 1; }}
  .node-label.org {{
    background: rgba(52,211,153,0.2); color: var(--accent-green);
  }}
  .tree-connector {{
    width: 3px; height: 24px; background: var(--border-subtle);
    margin: 0 auto; position: relative; opacity: 0;
    transition: all 0.4s ease;
  }}
  .tree-connector.visible {{ opacity: 1; }}
  .tree-connector.active {{
    background: linear-gradient(180deg, var(--accent-blue) 0%, rgba(96,165,250,0.6) 100%);
    box-shadow: 0 0 12px var(--glow-blue);
  }}
  .tree-connector.traversed {{ background: var(--text-muted); }}
  .tree-connector .pulse {{
    position: absolute; top: -6px; left: 50%; transform: translateX(-50%);
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--accent-blue);
    box-shadow: 0 0 15px var(--accent-blue), 0 0 30px var(--glow-blue);
    opacity: 0;
  }}
  .tree-connector .pulse.animate {{
    animation: pulse-travel 0.6s ease-in-out forwards;
  }}
  @keyframes pulse-travel {{
    0% {{ top: -6px; opacity: 1; }}
    100% {{ top: calc(100% - 4px); opacity: 1; }}
  }}

  /* Result banner */
  .result-banner {{
    margin-top: 20px; padding: 24px 32px;
    background: linear-gradient(135deg, rgba(52,211,153,0.08) 0%, rgba(96,165,250,0.06) 100%);
    border: 1px solid var(--border-subtle); border-radius: 16px;
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 20px; opacity: 0; transform: translateY(15px);
    transition: all 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: 0 0 0 1px rgba(255,255,255,0.03), 0 10px 30px -10px rgba(0,0,0,0.3);
  }}
  .result-banner.visible {{ opacity: 1; transform: translateY(0); }}
  .result-left {{ display: flex; align-items: center; gap: 16px; }}
  .result-icon {{
    width: 48px; height: 48px; display: flex; align-items: center;
    justify-content: center; border-radius: 12px; font-size: 24px;
  }}
  .result-icon.success {{ background: rgba(52,211,153,0.2); }}
  .result-icon.fail {{ background: rgba(248,113,113,0.2); }}
  .result-label {{
    font-size: 11px; font-weight: 600; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 0.5px;
  }}
  .result-value {{
    font-family: 'JetBrains Mono', monospace; font-size: 18px;
    font-weight: 700; color: var(--accent-green); margin-top: 3px;
  }}
  .result-value.none {{ color: var(--accent-red); }}
  .result-meta {{ text-align: right; }}
  .result-queries {{ font-size: 13px; color: var(--text-secondary); }}
  .result-method {{ font-size: 11px; color: var(--text-muted); margin-top: 4px; }}
  .result-policy {{
    margin-top: 6px; display: inline-flex; padding: 4px 12px;
    border-radius: 6px; font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.5px;
  }}
  .policy-reject {{ background: rgba(52,211,153,0.2); color: var(--accent-green); }}
  .policy-quarantine {{ background: rgba(251,191,36,0.2); color: var(--accent-amber); }}
  .policy-none {{ background: rgba(248,113,113,0.2); color: var(--accent-red); }}

  footer {{
    text-align: center; padding: 2rem 0 1rem; color: #888; font-size: 0.85rem;
  }}
  footer a {{ color: #60a5fa; text-decoration: none; }}
  footer a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>

<div class="container">
  <a href="/treewalk" class="back-link">← Try another domain</a>

  <!-- Header with controls at the TOP -->
  <div class="header">
    <div class="header-top">
      <div class="title-section">
        <div class="badge"><span class="dot"></span> DMARCbis &middot; Standards Track</div>
        <div class="title">DNS Tree Walk</div>
        <div class="subtitle">
          Watch how email receivers discover which DMARC policy applies to
          <strong>{author_domain}</strong> by walking up the DNS hierarchy, per
          <a href="https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/" target="_blank" rel="noopener" style="color:var(--accent-blue);text-decoration:none;">draft-ietf-dmarc-dmarcbis</a> &sect;4.10.
        </div>
      </div>

      <!-- CONTROLS AT TOP - immediately visible -->
      <div class="controls">
        <button class="btn btn-primary" id="btn-play" onclick="startAnimation()">▶ Auto-Play</button>
        <button class="btn" id="btn-step" onclick="stepForward()">Step ▶</button>
        <div class="speed-controls">
          <button class="btn speed-btn active" data-speed="1" onclick="setSpeed(1)">1x</button>
          <button class="btn speed-btn" data-speed="2" onclick="setSpeed(2)">2x</button>
          <button class="btn speed-btn" data-speed="0" onclick="setSpeed(0)">Manual</button>
        </div>
        <span class="progress-text" id="progress">Ready</span>
      </div>
    </div>

    <div class="domain-display">
      <span class="label">Query Target</span>
      {author_domain}
    </div>
  </div>

  <!-- Main content: narration + tree -->
  <div class="main-content">
    <div class="narration-panel">
      <div class="panel-title">📖 Step-by-Step Explanation</div>
      <div id="narration-log"></div>
    </div>

    <div class="tree-panel">
      <div class="panel-title" style="margin-bottom:16px;">🌲 DNS Hierarchy</div>
      <div class="tree-container" id="tree-container"></div>
    </div>
  </div>

  <!-- Result banner -->
  <div class="result-banner" id="result-banner">
    <div class="result-left">
      <div class="result-icon" id="result-icon">✅</div>
      <div>
        <div class="result-label">Organizational Domain</div>
        <div class="result-value" id="result-domain"></div>
      </div>
    </div>
    <div class="result-meta">
      <div class="result-queries" id="result-queries"></div>
      <div class="result-method" id="result-method"></div>
      <div class="result-policy" id="result-policy"></div>
    </div>
  </div>
</div>

<footer>
  <a href="/">dns-audit.com</a> &middot;
  Built by <a href="https://www.linkedin.com/in/neilanuskiewicz/" target="_blank" rel="noopener">Neil Anuskiewicz</a> &middot;
  Email &amp; DNS Security Consultant
</footer>

<script>
  const steps = {steps_json};
  const result = {result_json};
  const totalQueries = {total_queries};

  // Build domain list from steps (bottom-up, then reverse for top-down display)
  const domainSet = new Set();
  const domainOrder = [];
  steps.forEach(s => {{
    if (!domainSet.has(s.domain_queried)) {{
      domainSet.add(s.domain_queried);
      domainOrder.push(s.domain_queried);
    }}
  }});
  const domains = domainOrder.reverse();

  let currentStep = -1;
  let animating = false;
  let speed = 1; // 1x, 2x, or 0 (manual)

  function esc(text) {{
    const d = document.createElement('div');
    d.textContent = text;
    return d.innerHTML;
  }}

  function setSpeed(newSpeed) {{
    speed = newSpeed;
    document.querySelectorAll('.speed-btn').forEach(btn => {{
      btn.classList.toggle('active', parseInt(btn.dataset.speed) === newSpeed);
    }});
  }}

  function buildTree() {{
    const container = document.getElementById('tree-container');
    container.innerHTML = '';

    domains.forEach((domain, i) => {{
      if (i > 0) {{
        const conn = document.createElement('div');
        conn.className = 'tree-connector';
        conn.id = 'conn-' + i;
        conn.innerHTML = '<div class="pulse" id="pulse-' + i + '"></div>';
        container.appendChild(conn);
      }}

      const node = document.createElement('div');
      node.className = 'tree-node';
      node.id = 'node-' + i;
      node.innerHTML = '<div class="node-domain">' + esc(domain) + '</div>'
        + '<div class="node-status" id="status-' + i + '"></div>'
        + '<div class="node-label" id="label-' + i + '"></div>';
      container.appendChild(node);
    }});

    // Stagger tree appearance
    domains.forEach((_, i) => {{
      setTimeout(() => {{
        const n = document.getElementById('node-' + i);
        if (n) n.classList.add('visible');
        if (i > 0) {{
          const c = document.getElementById('conn-' + i);
          if (c) c.classList.add('visible');
        }}
      }}, 80 * i);
    }});
  }}

  function renderNarration(step, index) {{
    const log = document.getElementById('narration-log');
    const item = document.createElement('div');
    item.className = 'narration-item';
    item.id = 'narr-' + index;

    const isFound = step.response_type === 'FOUND';
    const badgeClass = isFound ? 'response-found' : 'response-not-found';
    const badgeText = isFound ? '✓ Found' : '✗ Not Found';

    let recordHtml = '';
    if (step.record_text) {{
      recordHtml = '<div class="record-display" id="record-' + index + '">' + esc(step.record_text) + '</div>';
    }}

    item.innerHTML = '<div class="narration-header">'
      + '<div class="step-badge">' + step.step_number + '</div>'
      + '<div class="narration-query">' + esc(step.query_name) + '</div>'
      + '</div>'
      + '<div class="narration-text">' + esc(step.narration) + '</div>'
      + '<div class="response-badge ' + badgeClass + '">' + badgeText + '</div>'
      + recordHtml;

    log.appendChild(item);
    return item;
  }}

  async function animateStep(index) {{
    const baseDelay = speed === 2 ? 400 : 800;
    const step = steps[index];
    const nodeIndex = domains.indexOf(step.domain_queried);

    return new Promise(resolve => {{
      // Animate connector/pulse if not first node
      if (nodeIndex > 0 && index > 0) {{
        const conn = document.getElementById('conn-' + nodeIndex);
        const pulse = document.getElementById('pulse-' + nodeIndex);
        if (conn) conn.classList.add('active');
        if (pulse) {{
          pulse.classList.add('animate');
          setTimeout(() => pulse.classList.remove('animate'), 600);
        }}
      }}

      setTimeout(() => {{
        // Remove scanning from all nodes
        domains.forEach((_, i) => {{
          const n = document.getElementById('node-' + i);
          if (n) n.classList.remove('querying');
        }});

        // Mark current node as querying
        if (nodeIndex >= 0) {{
          const node = document.getElementById('node-' + nodeIndex);
          if (node) node.classList.add('querying');
        }}

        // Add narration
        const narrItem = renderNarration(step, index);
        setTimeout(() => {{
          narrItem.classList.add('visible');
          narrItem.classList.add('active');

          // Remove active from previous narrations
          for (let j = 0; j < index; j++) {{
            const prev = document.getElementById('narr-' + j);
            if (prev) prev.classList.remove('active');
          }}

          setTimeout(() => {{
            if (nodeIndex >= 0) {{
              const node = document.getElementById('node-' + nodeIndex);
              const statusEl = document.getElementById('status-' + nodeIndex);

              if (node) node.classList.remove('querying');

              if (step.response_type === 'FOUND') {{
                if (statusEl) statusEl.textContent = '✅';
                if (node) node.classList.add('found');

                const rec = document.getElementById('record-' + index);
                if (rec) setTimeout(() => rec.classList.add('visible'), 200);

                // Mark as org domain if terminal
                if (step.is_terminal || result.organizational_domain === step.domain_queried) {{
                  setTimeout(() => {{
                    if (node) {{
                      node.classList.remove('found');
                      node.classList.add('org-domain');
                    }}
                    const label = document.getElementById('label-' + nodeIndex);
                    if (label) {{
                      label.innerHTML = '🏢 Organizational Domain';
                      label.className = 'node-label org visible';
                    }}
                  }}, 400);
                }}
              }} else {{
                if (statusEl) statusEl.textContent = '❌';
                if (node) node.classList.add('not-found');
              }}

              if (statusEl) statusEl.classList.add('visible');

              // Mark connector as traversed
              if (nodeIndex > 0) {{
                const c = document.getElementById('conn-' + nodeIndex);
                if (c) {{
                  c.classList.remove('active');
                  c.classList.add('traversed');
                }}
              }}
            }}

            document.getElementById('progress').textContent = 'Step ' + (index + 1) + ' of ' + steps.length;
            setTimeout(resolve, 250);
          }}, baseDelay);
        }}, 100);
      }}, nodeIndex > 0 && index > 0 ? 500 : 100);
    }});
  }}

  function showResult() {{
    const banner = document.getElementById('result-banner');
    const domainEl = document.getElementById('result-domain');
    const iconEl = document.getElementById('result-icon');

    if (result.organizational_domain) {{
      domainEl.textContent = result.organizational_domain;
      iconEl.textContent = '✅';
      iconEl.className = 'result-icon success';
    }} else {{
      domainEl.textContent = 'No DMARC policy found';
      domainEl.classList.add('none');
      iconEl.textContent = '⚠️';
      iconEl.className = 'result-icon fail';
    }}

    document.getElementById('result-queries').textContent = totalQueries + ' DNS quer' + (totalQueries === 1 ? 'y' : 'ies');
    document.getElementById('result-method').textContent = 'Determined by: ' + result.determination_method;

    if (result.policy) {{
      const pe = document.getElementById('result-policy');
      const policyClass = {{'reject': 'policy-reject', 'quarantine': 'policy-quarantine', 'none': 'policy-none'}}[result.policy] || 'policy-none';
      pe.className = 'result-policy ' + policyClass;
      pe.textContent = 'p=' + result.policy;
    }}

    banner.classList.add('visible');
    document.getElementById('btn-play').innerHTML = '↻ Replay';
    document.getElementById('progress').textContent = 'Complete ✓';
    animating = false;
  }}

  function resetState() {{
    document.getElementById('narration-log').innerHTML = '';
    document.getElementById('result-banner').classList.remove('visible');
    domains.forEach((_, i) => {{
      const n = document.getElementById('node-' + i);
      if (n) n.className = 'tree-node visible';
      const s = document.getElementById('status-' + i);
      if (s) {{ s.className = 'node-status'; s.textContent = ''; }}
      const l = document.getElementById('label-' + i);
      if (l) l.className = 'node-label';
      if (i > 0) {{
        const c = document.getElementById('conn-' + i);
        if (c) c.className = 'tree-connector visible';
      }}
    }});
  }}

  async function startAnimation() {{
    if (animating) return;
    if (speed === 0) {{
      alert('Manual mode selected. Use "Step ▶" button to advance.');
      return;
    }}

    animating = true;
    currentStep = -1;
    resetState();

    document.getElementById('btn-play').innerHTML = '⏸ Playing...';
    document.getElementById('btn-play').disabled = true;
    document.getElementById('btn-step').disabled = true;

    const stepDelay = speed === 2 ? 300 : 650;

    for (let i = 0; i < steps.length; i++) {{
      currentStep = i;
      await animateStep(i);
      if (i < steps.length - 1) await new Promise(r => setTimeout(r, stepDelay));
    }}

    document.getElementById('btn-play').disabled = false;
    document.getElementById('btn-step').disabled = false;
    setTimeout(showResult, 500);
  }}

  async function stepForward() {{
    if (animating) return;
    if (currentStep < 0) resetState();
    currentStep++;
    if (currentStep < steps.length) {{
      animating = true;
      await animateStep(currentStep);
      animating = false;
      if (currentStep === steps.length - 1) setTimeout(showResult, 500);
    }}
  }}

  // Initialize
  buildTree();

  // AUTO-PLAY after 1.5s delay
  setTimeout(() => {{
    if (speed !== 0) startAnimation();
  }}, 1500);
</script>

</body>
</html>"""


def _build_decision_text(step: dict, tw_result: dict) -> str:
    """Build plain-English decision text for a tree walk step."""
    if step.get("found"):
        domain = step.get("domain", "")
        if domain == tw_result.get("policy_source"):
            policy = tw_result.get("effective_policy", "none")
            tag = tw_result.get("applied_tag", "p")
            return f"DMARC record found! Policy {tag}={policy} applies. Walk complete."
        return f"DMARC record found at {domain}. Checking for policy boundaries..."
    return f"No DMARC record at _dmarc.{step.get('domain', '')}. Remove leftmost label, continue walking up."


def _determination_method(tw_result: dict) -> str:
    """Describe how the organizational domain was determined."""
    if tw_result.get("psd_flag") == "n":
        return "psd=n boundary tag"
    if tw_result.get("psd_flag") == "y":
        return "psd=y (public suffix)"
    if tw_result.get("policy_source"):
        if tw_result.get("is_subdomain"):
            return "inherited from parent domain"
        return "direct author domain match"
    return "no policy found"
