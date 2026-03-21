"""
PDF Report Generator for dns-audit.com

Generates a professional, branded PDF audit report from the same JSON
structure the frontend uses.

Usage:
    from pdf_report import generate_pdf
    pdf_bytes = generate_pdf(audit_result_dict)

Wire into server.py:
    @app.get("/api/audit/{domain}/pdf")
    async def audit_pdf(domain: str, scope: str = "complete", selector: str = None):
        result = audit_dns_security(domain, scope=scope,
                    dkim_selectors=[selector] if selector else None)
        pdf = generate_pdf(result)
        return Response(content=pdf, media_type="application/pdf",
                        headers={"Content-Disposition":
                            f'attachment; filename="dns-audit-{domain}.pdf"'})
"""

import io
import re
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    KeepTogether, HRFlowable,
)

# -- Brand colors --
NAVY        = colors.HexColor("#0a3d6b")
PASS_CLR    = colors.HexColor("#1a8a6a")
PASS_BG     = colors.HexColor("#edf8f4")
WARN_CLR    = colors.HexColor("#7a6a1e")
WARN_BG     = colors.HexColor("#f9f7ec")
FAIL_CLR    = colors.HexColor("#9b4040")
FAIL_BG     = colors.HexColor("#fdf3f3")
FIX_BG      = colors.HexColor("#edf4f0")
FIX_BORDER  = colors.HexColor("#1a8a6a")
RECORD_BG   = colors.HexColor("#1b1e24")
RECORD_FG   = colors.HexColor("#dfe3eb")
TEXT_PRI    = colors.HexColor("#1a1a1a")
TEXT_SEC    = colors.HexColor("#4d4d4d")
TEXT_TER    = colors.HexColor("#6b6b6b")
BORDER      = colors.HexColor("#dce1e6")

GRADE_COLORS = {
    "A": colors.HexColor("#10b981"), "B": colors.HexColor("#3b82f6"),
    "C": colors.HexColor("#f59e0b"), "D": colors.HexColor("#f97316"),
    "F": colors.HexColor("#ef4444"),
}
STATUS_CLR = {"pass": PASS_CLR, "warn": WARN_CLR, "fail": FAIL_CLR}
STATUS_BG  = {"pass": PASS_BG,  "warn": WARN_BG,  "fail": FAIL_BG}
STATUS_LBL = {"pass": "PASS",   "warn": "WARNING", "fail": "FAIL"}
DETAIL_ICON = {"good": "\u2713", "error": "\u2717", "warning": "\u26A0", "info": "\u2022"}


def _strip_html(t):
    if not t: return ""
    t = re.sub(r"<br\s*/?>", "\n", t, flags=re.IGNORECASE)
    t = re.sub(r"<[^>]+>", "", t)
    for old, new in [("&amp;","&"),("&lt;","<"),("&gt;",">"),("&quot;",'"'),("&#39;","'")]:
        t = t.replace(old, new)
    return t.strip()

def _safe(t):
    if not t: return ""
    return str(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def _sev(c):
    return {"fail":0,"warn":1,"pass":2}.get(c.get("status","pass"),3)


def _styles():
    s = {}
    s["title"]       = ParagraphStyle("T",  fontName="Helvetica-Bold",    fontSize=24, textColor=colors.white,     leading=30)
    s["title_sub"]   = ParagraphStyle("TS", fontName="Helvetica",         fontSize=12, textColor=colors.HexColor("#b0c8e0"), leading=16)
    s["heading"]     = ParagraphStyle("H",  fontName="Helvetica-Bold",    fontSize=15, textColor=TEXT_PRI, leading=21, spaceBefore=16, spaceAfter=5)
    s["subheading"]  = ParagraphStyle("SH", fontName="Helvetica-Bold",    fontSize=11, textColor=NAVY,    leading=15, spaceBefore=10, spaceAfter=3)
    s["body"]        = ParagraphStyle("B",  fontName="Helvetica",         fontSize=10.5,textColor=TEXT_SEC, leading=15, spaceBefore=2,  spaceAfter=2)
    s["body_small"]  = ParagraphStyle("BS", fontName="Helvetica",         fontSize=9.5,textColor=TEXT_TER, leading=13, spaceBefore=1,  spaceAfter=1)
    s["verdict"]     = ParagraphStyle("V",  fontName="Helvetica-Oblique", fontSize=10, textColor=TEXT_TER, leading=14, spaceAfter=4)
    s["record"]      = ParagraphStyle("R",  fontName="Courier",           fontSize=8.5,textColor=RECORD_FG,leading=12.5)
    s["fix_label"]   = ParagraphStyle("FL", fontName="Helvetica-Bold",    fontSize=8.5,textColor=PASS_CLR, leading=11, spaceAfter=2)
    s["fix_text"]    = ParagraphStyle("FT", fontName="Helvetica",         fontSize=10.5,textColor=TEXT_PRI, leading=15)
    s["pfix_num"]    = ParagraphStyle("PN", fontName="Helvetica-Bold",    fontSize=10.5,textColor=FAIL_CLR, leading=15)
    s["pfix_txt"]    = ParagraphStyle("PT", fontName="Helvetica",         fontSize=10.5,textColor=TEXT_PRI, leading=15)
    for k, clr in [("good",PASS_CLR),("warning",WARN_CLR),("error",FAIL_CLR),("info",TEXT_SEC)]:
        s[f"d_{k}"] = ParagraphStyle(f"D{k}", fontName="Helvetica", fontSize=10, textColor=clr, leading=14, spaceBefore=1, spaceAfter=1, leftIndent=12)
    return s


class _PageTpl:
    def __init__(self, domain, grade, score, ts):
        self.domain, self.grade, self.score, self.ts = domain, grade, score, ts

    def first(self, c, doc):
        w, h = letter
        c.setFillColor(NAVY); c.rect(0, h-100, w, 100, fill=1, stroke=0)
        c.setFillColor(colors.white); c.setFont("Helvetica-Bold", 22)
        c.drawString(54, h-40, "DNS Security Audit Report")
        c.setFont("Helvetica", 12); c.setFillColor(colors.HexColor("#b0c8e0"))
        c.drawString(54, h-60, self.domain)
        c.setFont("Helvetica", 9.5); c.drawString(54, h-78, f"Generated {self.ts}")
        c.setFont("Helvetica", 8.5); c.setFillColor(colors.HexColor("#6b91b5"))
        c.drawRightString(w-54, h-78, "dns-audit.com")
        gc = GRADE_COLORS.get(self.grade, NAVY)
        cx, cy = w-100, h-50
        c.setFillColor(gc); c.circle(cx, cy, 22, fill=1, stroke=0)
        c.setFillColor(colors.white); c.setFont("Helvetica-Bold", 24)
        c.drawCentredString(cx, cy-8, self.grade)
        c.setFillColor(colors.HexColor("#b0c8e0")); c.setFont("Helvetica", 10)
        c.drawCentredString(cx, cy-30, f"{self.score}/100")
        self._foot(c, doc)

    def later(self, c, doc):
        self._foot(c, doc)

    def _foot(self, c, doc):
        w, _ = letter
        c.setFont("Helvetica", 8); c.setFillColor(TEXT_TER)
        c.drawString(54, 30, f"dns-audit.com  |  {self.domain}")
        c.drawRightString(w-54, 30, f"Page {doc.page}")


def _summary_table(data, S):
    checks = data.get("checks", [])
    pc = sum(1 for c in checks if c.get("status")=="pass")
    wc = sum(1 for c in checks if c.get("status")=="warn")
    fc = sum(1 for c in checks if c.get("status")=="fail")
    def _c(label, val, clr):
        return [Paragraph(f'<font color="{clr.hexval()}" size="20"><b>{val}</b></font>', S["body"]),
                Paragraph(f'<font color="#6b6b6b" size="9">{label}</font>', S["body_small"])]
    t = Table([[_c("Passing",str(pc),PASS_CLR), _c("Warnings",str(wc),WARN_CLR), _c("Issues",str(fc),FAIL_CLR)]],
              colWidths=[2.1*inch]*3)
    t.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"TOP"),("TOPPADDING",(0,0),(-1,-1),10),
        ("BOTTOMPADDING",(0,0),(-1,-1),10),("LEFTPADDING",(0,0),(-1,-1),12),
        ("LINEAFTER",(0,0),(1,0),0.5,BORDER)]))
    return [t, Spacer(1,12)]


def _priority_fixes(data, S):
    fixes = data.get("priority_fixes", [])
    if not fixes: return []
    els = [Paragraph("Priority Fixes", S["subheading"])]
    for i, fix in enumerate(fixes, 1):
        r = Table([[Paragraph(f"<b>{i}</b>",S["pfix_num"]), Paragraph(_safe(fix),S["pfix_txt"])]],
                  colWidths=[0.3*inch, 6.2*inch])
        r.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"TOP"),("TOPPADDING",(0,0),(-1,-1),4),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),("BACKGROUND",(0,0),(-1,-1),FAIL_BG),
            ("ROUNDEDCORNERS",[3,3,3,3])]))
        els += [r, Spacer(1,4)]
    els.append(Spacer(1,8))
    return els


def _check_section(check, S):
    name   = check.get("name","Unknown")
    status = check.get("status","pass")
    verdict = check.get("verdict","")
    record = check.get("record","")
    details = check.get("details",[])
    fix    = check.get("fix","")
    s_clr  = STATUS_CLR.get(status, TEXT_SEC)
    s_lbl  = STATUS_LBL.get(status, "INFO")
    els = []

    # Header: name + pill
    hdr = Table([[Paragraph(f"<b>{_safe(name)}</b>", S["heading"]),
                  Paragraph(f'<font color="{s_clr.hexval()}" size="9"><b> {s_lbl} </b></font>', S["body"])]],
                colWidths=[5.5*inch, 1.5*inch])
    hdr.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(1,0),(1,0),"RIGHT"),
        ("TOPPADDING",(0,0),(-1,-1),0),("BOTTOMPADDING",(0,0),(-1,-1),0)]))
    els.append(hdr)

    if verdict:
        els.append(Paragraph(_safe(verdict), S["verdict"]))

    # Record block
    if record:
        rec = _safe(record)
        rt = Table([[Paragraph(rec, S["record"])]], colWidths=[6.7*inch])
        rt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),RECORD_BG),
            ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8),
            ("LEFTPADDING",(0,0),(-1,-1),10),("RIGHTPADDING",(0,0),(-1,-1),10),
            ("ROUNDEDCORNERS",[4,4,4,4])]))
        els += [Spacer(1,4), rt, Spacer(1,4)]

    # Details
    for d in details:
        dt = d.get("type","info")
        icon = DETAIL_ICON.get(dt, "\u2022")
        sk = f"d_{dt}" if f"d_{dt}" in S else "d_info"
        els.append(Paragraph(f"{icon}  {_safe(d.get('text',''))}", S[sk]))

    # Fix block
    if fix and status in ("warn","fail"):
        fp = _strip_html(fix)
        fs = _safe(fp).replace("\n","<br/>")
        fc = [Paragraph("<b>RECOMMENDED FIX</b>", S["fix_label"]),
              Paragraph(fs, S["fix_text"])]
        ft = Table([[fc]], colWidths=[6.7*inch])
        ft.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),FIX_BG),
            ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8),
            ("LEFTPADDING",(0,0),(-1,-1),10),("RIGHTPADDING",(0,0),(-1,-1),10),
            ("LINEBEFORE",(0,0),(0,-1),2.5,FIX_BORDER),
            ("ROUNDEDCORNERS",[0,4,4,0])]))
        els += [Spacer(1,6), ft]

    els += [Spacer(1,8), HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=8)]
    return [KeepTogether(els)]


def _vendors(data, S):
    vs = data.get("vendors", [])
    if not vs: return []
    els = [Paragraph("Detected Email Services", S["subheading"])]
    rows = [[Paragraph(f"<b>{_safe(v.get('name',''))}</b>",S["body"]),
             Paragraph(f"{v.get('confidence',0)}%",S["body_small"])] for v in vs]
    if rows:
        t = Table(rows, colWidths=[5.0*inch, 1.5*inch])
        t.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("LINEBELOW",(0,0),(-1,-2),0.3,BORDER),("ALIGN",(1,0),(1,-1),"RIGHT")]))
        els.append(t)
    els.append(Spacer(1,12))
    return els


def _methodology(S):
    inner = [Spacer(1,16), HRFlowable(width="100%",thickness=0.5,color=BORDER,spaceAfter=12),
           Paragraph("Methodology", S["subheading"]),
           Paragraph(
        "This report was generated by dns-audit.com using live DNS queries against "
        "published DNS records. All checks use RFC-compliant evaluation logic. "
        "DMARC policy discovery implements the DNS Tree Walk algorithm per DMARCbis "
        "(draft-ietf-dmarc-dmarcbis-41, Section 4.10). SPF evaluation tracks lookup "
        "counts against the RFC 7208 10-lookup limit including void lookup detection. "
        "DANE validation checks TLSA records per RFC 7672 with DNSSEC dependency "
        "verification.", S["body_small"]),
           Spacer(1,6),
           Paragraph(
        "Scores are based on authentication configuration (DMARC 25, SPF 20, DKIM 25), "
        "key security (15), vendor intelligence (10), and best practices (5). "
        "Infrastructure checks (DNSSEC, CAA, DANE, Nameservers) are evaluated but "
        "not scored, as their absence may be intentional.", S["body_small"])]
    return [KeepTogether(inner)]


def generate_audit_pdf(audit_result: dict) -> bytes:
    domain = audit_result.get("domain", "unknown")
    sc = audit_result.get("score", {})
    grade = sc.get("grade", "?")
    total = int(sc.get("total", 0))
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")

    buf = io.BytesIO()
    S = _styles()
    tpl = _PageTpl(domain, grade, total, now)

    doc = SimpleDocTemplate(buf, pagesize=letter,
        topMargin=1.4*inch, bottomMargin=0.65*inch,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        title=f"DNS Security Audit - {domain}",
        author="dns-audit.com",
        subject=f"Security audit report for {domain}")

    story = []
    story.extend(_summary_table(audit_result, S))
    story.extend(_priority_fixes(audit_result, S))
    story.append(Paragraph("Detailed Results", S["subheading"]))
    story.append(Spacer(1,6))
    for check in sorted(audit_result.get("checks",[]), key=_sev):
        story.extend(_check_section(check, S))
    story.extend(_vendors(audit_result, S))
    story.extend(_methodology(S))

    doc.build(story, onFirstPage=tpl.first, onLaterPages=tpl.later)
    return buf.getvalue()


if __name__ == "__main__":
    sample = {
        "domain": "example.com",
        "score": {"grade": "B", "total": 72},
        "priority_fixes": [
            "Upgrade DMARC policy from p=none to p=reject",
            "Add MTA-STS policy for transport encryption",
        ],
        "checks": [
            {"name":"DMARC","status":"warn","verdict":"DMARC record found with p=none (monitoring only)",
             "record":"v=DMARC1; p=none; rua=mailto:dmarc@example.com",
             "details":[{"type":"good","text":"DMARC record published"},
                        {"type":"warning","text":"Policy is p=none -- no enforcement"},
                        {"type":"good","text":"Aggregate reporting configured"}],
             "fix":"Upgrade to p=reject once monitoring confirms all legitimate sources pass."},
            {"name":"SPF","status":"pass","verdict":"Valid SPF record with hardfail (-all)",
             "record":"v=spf1 include:_spf.google.com -all",
             "details":[{"type":"good","text":"SPF record is valid"},
                        {"type":"good","text":"Uses -all (hardfail)"},
                        {"type":"info","text":"3 of 10 DNS lookups used"}],
             "fix":None},
            {"name":"MTA-STS","status":"fail","verdict":"No MTA-STS policy found",
             "record":None,
             "details":[{"type":"error","text":"No _mta-sts TXT record found"},
                        {"type":"error","text":"No policy file at /.well-known/mta-sts.txt"}],
             "fix":"Add MTA-STS to enforce TLS. Create _mta-sts.example.com TXT record with v=STSv1; id=20260320."},
            {"name":"DKIM","status":"pass","verdict":"Valid 2048-bit key found (selector: google)",
             "record":"v=DKIM1; k=rsa; p=MIIBIjANBgkqhki...",
             "details":[{"type":"good","text":"2048-bit RSA key"},
                        {"type":"good","text":"Selector: google"}],
             "fix":None},
            {"name":"DNSSEC","status":"warn","verdict":"DNSSEC not enabled",
             "record":None,
             "details":[{"type":"warning","text":"No DNSKEY records found"},
                        {"type":"info","text":"DNSSEC prevents DNS spoofing and cache poisoning"}],
             "fix":"Enable DNSSEC through your domain registrar or DNS hosting provider."},
        ],
        "vendors": [
            {"name": "Google Workspace", "confidence": 95},
            {"name": "SendGrid", "confidence": 60},
        ],
    }
    pdf = generate_audit_pdf(sample)
    with open("/tmp/dns-audit-sample.pdf", "wb") as f:
        f.write(pdf)
    print(f"Written /tmp/dns-audit-sample.pdf ({len(pdf):,} bytes)")
