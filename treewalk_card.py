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
    <div class="badge"><span class="dot"></span> DMARCbis Draft Standard</div>
    <h1>DNS Tree Walk</h1>
    <p>Visualize how email receivers discover DMARC policies by walking up the DNS hierarchy &mdash; the new algorithm replacing Public Suffix Lists.</p>
    <form action="/treewalk" method="get">
      <input type="text" name="domain" placeholder="mail.example.com" required autofocus>
      <button type="submit">\U0001f333 Visualize</button>
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
    # The existing dmarc_tree_walk module returns a different structure
    # than what we built on master. Adapt to both formats.
    author_domain = html_lib.escape(tw_result.get("domain", ""))
    author_domain_js = json.dumps(tw_result.get("domain", ""))

    # Build steps in the format the JS animation expects
    raw_steps = tw_result.get("steps", [])
    steps = []
    for i, s in enumerate(raw_steps):
        steps.append({
            "step_number": i + 1,
            "query_name": s.get("query", f"_dmarc.{s.get('domain', '')}"),
            "domain_queried": s.get("domain", ""),
            "response_type": "FOUND" if s.get("found") else "NXDOMAIN",
            "record_text": s.get("record"),
            "psd_tag": None,
            "decision": _build_decision_text(s, tw_result),
            "is_terminal": s.get("found", False) and s.get("domain") == tw_result.get("policy_source"),
        })

    steps_json = json.dumps(steps, default=str)
    total_queries = len(steps)

    result_obj = {
        "organizational_domain": tw_result.get("policy_source") or tw_result.get("org_domain"),
        "policy": tw_result.get("effective_policy"),
        "determination_method": _determination_method(tw_result),
    }
    result_json = json.dumps(result_obj, default=str)

    # Unique domains in step order
    seen = set()
    domains = []
    for s in steps:
        d = s["domain_queried"]
        if d not in seen:
            seen.add(d)
            domains.append(d)
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
    overflow-x: hidden; min-height: 100vh; padding: 24px;
  }}
  .back-link {{
    display: inline-flex; align-items: center; gap: 6px;
    color: var(--text-muted); text-decoration: none; font-size: 13px;
    font-weight: 500; margin-bottom: 20px; transition: color 0.2s;
  }}
  .back-link:hover {{ color: var(--accent-blue); }}
  .card {{
    max-width: 1200px; margin: 0 auto; background: var(--bg-card);
    border-radius: 20px; border: 1px solid var(--border-subtle); overflow: hidden;
    box-shadow: 0 0 0 1px rgba(255,255,255,0.03), 0 20px 60px -15px rgba(0,0,0,0.5),
      0 0 100px -30px rgba(96,165,250,0.08);
  }}
  .card-header {{
    padding: 32px 40px 24px;
    background: linear-gradient(135deg, rgba(96,165,250,0.08) 0%, rgba(34,211,238,0.04) 100%);
    border-bottom: 1px solid var(--border-subtle); position: relative; overflow: hidden;
  }}
  .card-header::before {{
    content: ''; position: absolute; top: -50%; right: -20%;
    width: 400px; height: 400px;
    background: radial-gradient(circle, rgba(96,165,250,0.06) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-badge {{
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 12px; background: rgba(96,165,250,0.1);
    border: 1px solid rgba(96,165,250,0.2); border-radius: 100px;
    font-size: 11px; font-weight: 600; color: var(--accent-blue);
    letter-spacing: 0.5px; text-transform: uppercase; margin-bottom: 12px;
  }}
  .header-badge .dot {{
    width: 6px; height: 6px; border-radius: 50%; background: var(--accent-blue);
    animation: pulse-dot 2s ease-in-out infinite;
  }}
  @keyframes pulse-dot {{
    0%, 100% {{ opacity: 0.5; transform: scale(0.8); }}
    50% {{ opacity: 1; transform: scale(1.2); }}
  }}
  .card-title {{
    font-size: 28px; font-weight: 800; letter-spacing: -0.5px;
    background: linear-gradient(135deg, var(--text-primary) 0%, var(--accent-blue) 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text; margin-bottom: 8px;
  }}
  .card-subtitle {{ font-size: 15px; color: var(--text-secondary); line-height: 1.5; }}
  .domain-display {{
    margin-top: 16px; display: inline-flex; align-items: center; gap: 10px;
    padding: 10px 18px; background: rgba(0,0,0,0.3);
    border: 1px solid var(--border-subtle); border-radius: 10px;
    font-family: 'JetBrains Mono', monospace; font-size: 15px;
    font-weight: 500; color: var(--accent-cyan);
  }}
  .domain-display .label {{
    font-family: 'Inter', sans-serif; font-size: 11px; font-weight: 600;
    color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;
  }}
  .card-body {{ display: grid; grid-template-columns: 1fr 1fr; min-height: 400px; }}
  @media (max-width: 800px) {{
    .card-body {{ grid-template-columns: 1fr; }}
    .panel-left {{ border-right: none !important; border-bottom: 1px solid var(--border-subtle); }}
    .comparison {{ grid-template-columns: 1fr !important; }}
    .comparison-arrow {{ display: none !important; }}
  }}
  .panel-left {{
    padding: 28px 32px; border-right: 1px solid var(--border-subtle);
    overflow-y: auto; max-height: 600px;
  }}
  .panel-right {{
    padding: 28px 32px; display: flex; flex-direction: column;
    align-items: center; position: relative; overflow: hidden;
  }}
  .panel-right::before {{
    content: ''; position: absolute; width: 300px; height: 300px;
    background: radial-gradient(circle, rgba(96,165,250,0.04) 0%, transparent 70%);
    top: 50%; left: 50%; transform: translate(-50%, -50%); pointer-events: none;
  }}
  .panel-title {{
    font-size: 12px; font-weight: 700; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 1px; margin-bottom: 20px;
    display: flex; align-items: center; gap: 8px;
  }}
  .panel-title .icon {{ font-size: 14px; }}
  .tree-container {{
    flex: 1; display: flex; flex-direction: column; justify-content: center;
    gap: 0; width: 100%; max-width: 420px; position: relative; z-index: 1;
  }}
  .tree-connector {{
    width: 2px; height: 28px; background: var(--border-subtle);
    margin: 0 auto; position: relative; opacity: 0; transition: opacity 0.3s ease;
  }}
  .tree-connector.visible {{ opacity: 1; }}
  .tree-connector.active {{ background: var(--accent-blue); box-shadow: 0 0 8px var(--glow-blue); }}
  .tree-connector.traversed {{ background: var(--text-muted); }}
  .tree-connector .packet {{
    position: absolute; top: -4px; left: 50%; transform: translateX(-50%);
    width: 8px; height: 8px; border-radius: 50%; background: var(--accent-blue);
    box-shadow: 0 0 12px var(--accent-blue), 0 0 24px var(--glow-blue); opacity: 0;
  }}
  .tree-connector .packet.animate {{ opacity: 1; animation: packet-travel 0.5s ease-in-out forwards; }}
  @keyframes packet-travel {{ 0% {{ top: -4px; opacity: 1; }} 100% {{ top: calc(100% - 4px); opacity: 1; }} }}
  .tree-node {{
    padding: 16px 20px; background: var(--bg-node);
    border: 1.5px solid var(--border-subtle); border-radius: 14px;
    opacity: 0; transform: scale(0.9);
    transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1); position: relative;
  }}
  .tree-node.visible {{ opacity: 1; transform: scale(1); }}
  .tree-node.scanning {{
    border-color: var(--accent-blue);
    box-shadow: 0 0 0 1px var(--accent-blue), 0 0 20px -5px var(--glow-blue), inset 0 0 20px -10px var(--glow-blue);
    animation: scan-pulse 1.5s ease-in-out infinite;
  }}
  @keyframes scan-pulse {{
    0%, 100% {{ box-shadow: 0 0 0 1px var(--accent-blue), 0 0 20px -5px var(--glow-blue); }}
    50% {{ box-shadow: 0 0 0 2px var(--accent-blue), 0 0 30px -5px var(--glow-blue), 0 0 60px -15px var(--glow-blue); }}
  }}
  .tree-node.found {{
    border-color: var(--accent-green);
    box-shadow: 0 0 0 1px var(--accent-green), 0 0 25px -5px var(--glow-green);
  }}
  .tree-node.not-found {{ border-color: rgba(248,113,113,0.3); opacity: 0.6; }}
  .tree-node.org-domain {{
    border-color: var(--accent-green);
    background: linear-gradient(135deg, rgba(52,211,153,0.08) 0%, rgba(34,211,238,0.04) 100%);
    box-shadow: 0 0 0 2px var(--accent-green), 0 0 40px -10px var(--glow-green), 0 0 80px -20px var(--glow-green);
    animation: org-glow 2s ease-in-out infinite;
  }}
  @keyframes org-glow {{
    0%, 100% {{ box-shadow: 0 0 0 2px var(--accent-green), 0 0 40px -10px var(--glow-green); }}
    50% {{ box-shadow: 0 0 0 2px var(--accent-green), 0 0 60px -10px var(--glow-green), 0 0 100px -25px rgba(52,211,153,0.15); }}
  }}
  .node-domain {{ font-family: 'JetBrains Mono', monospace; font-size: 15px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px; }}
  .node-query {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-muted); opacity: 0; transition: opacity 0.3s ease; }}
  .node-query.visible {{ opacity: 1; }}
  .node-status {{ position: absolute; top: 12px; right: 14px; font-size: 18px; opacity: 0; transform: scale(0); transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1); }}
  .node-status.visible {{ opacity: 1; transform: scale(1); }}
  .node-label {{ margin-top: 8px; display: inline-flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 6px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0; transition: opacity 0.4s ease; }}
  .node-label.visible {{ opacity: 1; }}
  .node-label.org {{ background: rgba(52,211,153,0.15); color: var(--accent-green); }}
  .node-label.psd {{ background: rgba(167,139,250,0.15); color: var(--accent-purple); }}
  .step-entry {{ margin-bottom: 16px; padding: 14px 16px; background: var(--bg-node); border: 1px solid transparent; border-radius: 12px; opacity: 0; transform: translateX(-20px); transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1); }}
  .step-entry.visible {{ opacity: 1; transform: translateX(0); }}
  .step-entry.active {{ border-color: var(--border-active); background: var(--bg-node-active); box-shadow: 0 0 20px -5px var(--glow-blue); }}
  .step-entry.found {{ border-color: rgba(52,211,153,0.4); box-shadow: 0 0 20px -5px var(--glow-green); }}
  .step-entry.nxdomain {{ border-color: rgba(248,113,113,0.2); }}
  .step-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .step-number {{ width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; border-radius: 50%; font-size: 12px; font-weight: 700; background: rgba(96,165,250,0.15); color: var(--accent-blue); flex-shrink: 0; }}
  .step-query {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 500; color: var(--text-primary); word-break: break-all; }}
  .step-response {{ display: flex; align-items: center; gap: 6px; margin: 6px 0 0 34px; font-size: 12px; font-weight: 500; }}
  .step-response .badge {{ padding: 2px 8px; border-radius: 6px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }}
  .badge-nxdomain {{ background: rgba(248,113,113,0.15); color: var(--accent-red); }}
  .badge-norecord {{ background: rgba(251,191,36,0.15); color: var(--accent-amber); }}
  .badge-found {{ background: rgba(52,211,153,0.15); color: var(--accent-green); }}
  .step-decision {{ margin: 8px 0 0 34px; font-size: 12px; color: var(--text-secondary); line-height: 1.5; }}
  .step-record {{ margin: 8px 0 0 34px; padding: 8px 12px; background: rgba(0,0,0,0.3); border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--accent-cyan); word-break: break-all; line-height: 1.6; opacity: 0; transition: opacity 0.4s ease; }}
  .step-record.visible {{ opacity: 1; }}
  .result-banner {{ padding: 20px 40px; background: linear-gradient(135deg, rgba(52,211,153,0.06) 0%, rgba(96,165,250,0.04) 100%); border-top: 1px solid var(--border-subtle); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px; opacity: 0; transform: translateY(10px); transition: all 0.6s cubic-bezier(0.4, 0, 0.2, 1); }}
  .result-banner.visible {{ opacity: 1; transform: translateY(0); }}
  .result-left {{ display: flex; align-items: center; gap: 16px; }}
  .result-icon {{ width: 44px; height: 44px; display: flex; align-items: center; justify-content: center; border-radius: 12px; font-size: 22px; }}
  .result-icon.success {{ background: rgba(52,211,153,0.15); }}
  .result-icon.fail {{ background: rgba(248,113,113,0.15); }}
  .result-label {{ font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
  .result-value {{ font-family: 'JetBrains Mono', monospace; font-size: 18px; font-weight: 700; color: var(--accent-green); margin-top: 2px; }}
  .result-value.none {{ color: var(--accent-red); }}
  .result-meta {{ text-align: right; }}
  .result-queries {{ font-size: 13px; color: var(--text-secondary); }}
  .result-method {{ font-size: 11px; color: var(--text-muted); margin-top: 4px; }}
  .result-policy {{ margin-top: 4px; display: inline-flex; padding: 3px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }}
  .policy-reject {{ background: rgba(52,211,153,0.15); color: var(--accent-green); }}
  .policy-quarantine {{ background: rgba(251,191,36,0.15); color: var(--accent-amber); }}
  .policy-none {{ background: rgba(248,113,113,0.15); color: var(--accent-red); }}
  .controls {{ padding: 16px 40px; border-top: 1px solid var(--border-subtle); display: flex; align-items: center; justify-content: center; gap: 16px; }}
  .btn {{ padding: 8px 20px; border: 1px solid var(--border-subtle); border-radius: 8px; background: var(--bg-node); color: var(--text-secondary); font-family: 'Inter', sans-serif; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.2s ease; display: flex; align-items: center; gap: 6px; }}
  .btn:hover {{ background: var(--bg-node-active); border-color: var(--border-active); color: var(--text-primary); }}
  .btn-primary {{ background: rgba(96,165,250,0.15); border-color: rgba(96,165,250,0.3); color: var(--accent-blue); }}
  .btn-primary:hover {{ background: rgba(96,165,250,0.25); }}
  .progress-text {{ font-size: 12px; color: var(--text-muted); font-weight: 500; }}
  .explainer {{ padding: 24px 40px; border-top: 1px solid var(--border-subtle); background: rgba(0,0,0,0.15); }}
  .explainer-title {{ font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }}
  .explainer-text {{ font-size: 13px; color: var(--text-secondary); line-height: 1.7; max-width: 800px; }}
  .explainer-text strong {{ color: var(--text-primary); font-weight: 600; }}
  .explainer-text code {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; background: rgba(96,165,250,0.1); padding: 1px 6px; border-radius: 4px; color: var(--accent-blue); }}
  .comparison {{ padding: 24px 40px; border-top: 1px solid var(--border-subtle); display: grid; grid-template-columns: 1fr 40px 1fr; gap: 0; align-items: start; }}
  .comparison-col {{ padding: 16px; border-radius: 12px; }}
  .comparison-col.old {{ background: rgba(248,113,113,0.04); border: 1px solid rgba(248,113,113,0.1); }}
  .comparison-col.new {{ background: rgba(52,211,153,0.04); border: 1px solid rgba(52,211,153,0.1); }}
  .comparison-label {{ font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
  .comparison-col.old .comparison-label {{ color: var(--accent-red); }}
  .comparison-col.new .comparison-label {{ color: var(--accent-green); }}
  .comparison-text {{ font-size: 12px; color: var(--text-secondary); line-height: 1.6; }}
  .comparison-arrow {{ display: flex; align-items: center; justify-content: center; font-size: 20px; color: var(--text-muted); padding-top: 30px; }}
</style>
</head>
<body>

<a href="/treewalk" class="back-link">\u2190 Try another domain</a>

<div class="card">
  <div class="card-header">
    <div class="header-badge"><span class="dot"></span> DMARCbis Draft Standard</div>
    <div class="card-title">DNS Tree Walk</div>
    <div class="card-subtitle">How email receivers discover your DMARC policy by walking up the DNS hierarchy</div>
    <div class="domain-display">
      <span class="label">Author Domain</span>
      {author_domain}
    </div>
  </div>

  <div class="card-body">
    <div class="panel-left">
      <div class="panel-title"><span class="icon">\U0001f4dd</span> Query Log</div>
      <div id="step-log"></div>
    </div>
    <div class="panel-right">
      <div class="panel-title" style="align-self:flex-start;width:100%"><span class="icon">\U0001f332</span> DNS Hierarchy</div>
      <div class="tree-container" id="tree-container"></div>
    </div>
  </div>

  <div class="result-banner" id="result-banner">
    <div class="result-left">
      <div class="result-icon" id="result-icon">\u2705</div>
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

  <div class="controls">
    <button class="btn btn-primary" id="btn-play" onclick="startAnimation()">\u25b6 Play Animation</button>
    <button class="btn" id="btn-step" onclick="stepForward()">Step \u25b6\ufe0f</button>
    <span class="progress-text" id="progress">Ready</span>
  </div>

  <div class="explainer">
    <div class="explainer-title">What is the DNS Tree Walk?</div>
    <div class="explainer-text">
      <strong>DMARCbis</strong> (the upcoming DMARC standard) replaces the old Public Suffix List (PSL) approach with a
      <strong>DNS Tree Walk</strong>. Instead of relying on an external list to find the organizational domain,
      the receiver walks up the DNS hierarchy query by query, checking <code>_dmarc.&lt;domain&gt;</code> at each level.
      The walk stops when it finds a record with a <code>psd</code> (Public Suffix Domain) boundary tag, or when labels run out.
      This puts <strong>domain owners in control</strong> of their own organizational boundaries, with no third-party list dependency.
    </div>
  </div>

  <div class="comparison">
    <div class="comparison-col old">
      <div class="comparison-label">\u274c Old Way (RFC 7489)</div>
      <div class="comparison-text">
        Download a Public Suffix List from a third party.
        Look up the organizational domain in that list.
        Only 2 queries: the author domain, then the org domain.
        Different receivers may use different PSL versions \u2192 inconsistent results.
      </div>
    </div>
    <div class="comparison-arrow">\u2192</div>
    <div class="comparison-col new">
      <div class="comparison-label">\u2705 New Way (DMARCbis)</div>
      <div class="comparison-text">
        Walk up the DNS tree, checking for DMARC records at each level.
        The <code>psd</code> tag marks organizational boundaries directly in DNS.
        No external dependency. Domain owners control their own boundaries.
        Consistent results for all receivers. Max 8 queries.
      </div>
    </div>
  </div>
</div>

<script>
  const steps = {steps_json};
  const result = {result_json};
  const domains = {domains_json};
  const totalQueries = {total_queries};

  let currentStep = -1;
  let animating = false;

  function esc(text) {{
    const d = document.createElement('div');
    d.textContent = text;
    return d.innerHTML;
  }}

  function buildTree() {{
    const container = document.getElementById('tree-container');
    container.innerHTML = '';
    domains.forEach((domain, i) => {{
      if (i > 0) {{
        const conn = document.createElement('div');
        conn.className = 'tree-connector'; conn.id = 'conn-' + i;
        conn.innerHTML = '<div class="packet" id="packet-' + i + '"></div>';
        container.appendChild(conn);
      }}
      const node = document.createElement('div');
      node.className = 'tree-node'; node.id = 'node-' + i;
      node.innerHTML = '<div class="node-domain">' + esc(domain) + '</div>'
        + '<div class="node-query" id="query-' + i + '">_dmarc.' + esc(domain) + '</div>'
        + '<div class="node-status" id="status-' + i + '"></div>'
        + '<div class="node-label" id="label-' + i + '"></div>';
      container.appendChild(node);
    }});
    domains.forEach((_, i) => {{
      setTimeout(() => {{
        const n = document.getElementById('node-' + i);
        if (n) n.classList.add('visible');
        if (i > 0) {{ const c = document.getElementById('conn-' + i); if (c) c.classList.add('visible'); }}
      }}, 150 * i);
    }});
  }}

  function renderStepLog(step, index) {{
    const log = document.getElementById('step-log');
    const entry = document.createElement('div');
    entry.className = 'step-entry'; entry.id = 'log-' + index;
    let badgeClass = 'badge-nxdomain', badgeText = step.response_type;
    if (step.response_type === 'FOUND') {{ badgeClass = 'badge-found'; badgeText = 'FOUND'; }}
    else if (step.response_type === 'NOERROR_NO_DMARC') {{ badgeClass = 'badge-norecord'; badgeText = 'NO RECORD'; }}
    let recordHtml = '';
    if (step.record_text) recordHtml = '<div class="step-record" id="record-' + index + '">' + esc(step.record_text) + '</div>';
    entry.innerHTML = '<div class="step-header"><div class="step-number">' + step.step_number + '</div>'
      + '<div class="step-query">' + esc(step.query_name) + '</div></div>'
      + '<div class="step-response"><span class="badge ' + badgeClass + '">' + esc(badgeText) + '</span></div>'
      + recordHtml
      + '<div class="step-decision">' + esc(step.decision) + '</div>';
    log.appendChild(entry);
    return entry;
  }}

  function animateStep(index) {{
    return new Promise(resolve => {{
      const step = steps[index];
      const nodeIndex = domains.indexOf(step.domain_queried);
      if (nodeIndex > 0 && index > 0) {{
        const conn = document.getElementById('conn-' + nodeIndex);
        const packet = document.getElementById('packet-' + nodeIndex);
        if (conn) conn.classList.add('active');
        if (packet) {{ packet.classList.add('animate'); setTimeout(() => packet.classList.remove('animate'), 600); }}
      }}
      setTimeout(() => {{
        domains.forEach((_, i) => {{ const n = document.getElementById('node-' + i); if (n) n.classList.remove('scanning'); }});
        if (nodeIndex >= 0) {{
          const node = document.getElementById('node-' + nodeIndex);
          if (node) node.classList.add('scanning');
          const q = document.getElementById('query-' + nodeIndex);
          if (q) q.classList.add('visible');
        }}
        const entry = renderStepLog(step, index);
        setTimeout(() => {{
          entry.classList.add('visible'); entry.classList.add('active');
          for (let j = 0; j < index; j++) {{ const p = document.getElementById('log-' + j); if (p) p.classList.remove('active'); }}
          setTimeout(() => {{
            if (nodeIndex >= 0) {{
              const statusEl = document.getElementById('status-' + nodeIndex);
              const node = document.getElementById('node-' + nodeIndex);
              if (node) node.classList.remove('scanning');
              if (step.response_type === 'FOUND') {{
                if (statusEl) statusEl.textContent = '\u2705';
                if (node) node.classList.add('found');
                entry.classList.add('found');
                const rec = document.getElementById('record-' + index);
                if (rec) setTimeout(() => rec.classList.add('visible'), 200);
                if (step.is_terminal || result.organizational_domain === step.domain_queried) {{
                  setTimeout(() => {{
                    if (node) {{ node.classList.remove('found'); node.classList.add('org-domain'); }}
                    const label = document.getElementById('label-' + nodeIndex);
                    if (label) {{ label.innerHTML = '\U0001f3e2 Organizational Domain'; label.className = 'node-label org visible'; }}
                  }}, 400);
                }}
              }} else {{
                if (statusEl) statusEl.textContent = '\u274c';
                if (node) node.classList.add('not-found');
                entry.classList.add('nxdomain');
              }}
              if (statusEl) statusEl.classList.add('visible');
              if (nodeIndex > 0) {{ const c = document.getElementById('conn-' + nodeIndex); if (c) {{ c.classList.remove('active'); c.classList.add('traversed'); }} }}
            }}
            document.getElementById('progress').textContent = 'Step ' + (index + 1) + ' of ' + steps.length;
            setTimeout(resolve, 300);
          }}, 800);
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
      iconEl.textContent = '\u2705'; iconEl.className = 'result-icon success';
    }} else {{
      domainEl.textContent = 'No DMARC policy found';
      domainEl.classList.add('none'); iconEl.textContent = '\u26a0\ufe0f'; iconEl.className = 'result-icon fail';
    }}
    document.getElementById('result-queries').textContent = totalQueries + ' DNS quer' + (totalQueries === 1 ? 'y' : 'ies');
    document.getElementById('result-method').textContent = 'Determined by: ' + result.determination_method;
    if (result.policy) {{
      const pe = document.getElementById('result-policy');
      const pc = {{'reject':'policy-reject','quarantine':'policy-quarantine','none':'policy-none'}}[result.policy] || 'policy-none';
      pe.className = 'result-policy ' + pc; pe.textContent = 'p=' + result.policy;
    }}
    banner.classList.add('visible');
    document.getElementById('btn-play').innerHTML = '\u21bb Replay';
    document.getElementById('progress').textContent = 'Complete';
    animating = false;
  }}

  function resetState() {{
    document.getElementById('step-log').innerHTML = '';
    document.getElementById('result-banner').classList.remove('visible');
    domains.forEach((_, i) => {{
      const n = document.getElementById('node-' + i); if (n) n.className = 'tree-node visible';
      const s = document.getElementById('status-' + i); if (s) {{ s.className = 'node-status'; s.textContent = ''; }}
      const q = document.getElementById('query-' + i); if (q) q.className = 'node-query';
      const l = document.getElementById('label-' + i); if (l) l.className = 'node-label';
      if (i > 0) {{ const c = document.getElementById('conn-' + i); if (c) c.className = 'tree-connector visible'; }}
    }});
  }}

  async function startAnimation() {{
    if (animating) return;
    animating = true; currentStep = -1; resetState();
    document.getElementById('btn-play').innerHTML = '\u23f8 Playing...';
    document.getElementById('btn-play').disabled = true;
    document.getElementById('btn-step').disabled = true;
    for (let i = 0; i < steps.length; i++) {{
      currentStep = i; await animateStep(i);
      if (i < steps.length - 1) await new Promise(r => setTimeout(r, 600));
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
      animating = true; await animateStep(currentStep); animating = false;
      if (currentStep === steps.length - 1) setTimeout(showResult, 500);
    }}
  }}

  buildTree();
</script>
<footer style="text-align:center;padding:2rem 0 1rem;color:#888;font-size:0.85rem;">
  <a href="/" style="color:#60a5fa;text-decoration:none;">dns-audit.com</a> &middot;
  Built by <a href="https://www.linkedin.com/in/neilanuskiewicz/" target="_blank" rel="noopener" style="color:#60a5fa;text-decoration:none;">Neil Anuskiewicz</a> &middot;
  Email &amp; DNS Security Consultant
</footer>
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
