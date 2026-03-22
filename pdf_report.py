


"""
PDF Report Generator for dns-audit.com

Generates a comprehensive, multi-page branded PDF audit report from the same
JSON structure the frontend uses.  Designed to be a standalone document an IT
admin can hand to their CISO or management to justify security changes.

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
from typing import Dict, List, Optional, Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    KeepTogether, HRFlowable, PageBreak, CondPageBreak,
)
from reportlab.graphics.shapes import Drawing, Wedge, Circle, String, Group
from reportlab.graphics import renderPDF

# ================================================================
# Brand colors
# ================================================================

NAVY        = colors.HexColor("#0a3d6b")
NAVY_LIGHT  = colors.HexColor("#1a5a8a")
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
BORDER_LIGHT = colors.HexColor("#e8ecf0")
BLUE_ACCENT = colors.HexColor("#3b82f6")
TEAL_ACCENT = colors.HexColor("#2dd4bf")
SURFACE_BG  = colors.HexColor("#f8fafc")
LIGHT_BLUE_BG = colors.HexColor("#eff6ff")

GRADE_COLORS = {
    "A+": colors.HexColor("#10b981"), "A": colors.HexColor("#10b981"),
    "B": colors.HexColor("#3b82f6"),
    "C": colors.HexColor("#f59e0b"), "D": colors.HexColor("#f97316"),
    "F": colors.HexColor("#ef4444"),
}
STATUS_CLR = {"pass": PASS_CLR, "warn": WARN_CLR, "fail": FAIL_CLR}
STATUS_BG  = {"pass": PASS_BG,  "warn": WARN_BG,  "fail": FAIL_BG}
STATUS_LBL = {"pass": "PASS",   "warn": "WARNING", "fail": "FAIL"}
DETAIL_ICON = {"good": "\u2713", "error": "\u2717", "warning": "\u26A0", "info": "\u2022"}

PRIORITY_CLR = {
    "critical": FAIL_CLR,
    "high": colors.HexColor("#f97316"),
    "medium": WARN_CLR,
    "low": BLUE_ACCENT,
}
PRIORITY_BG = {
    "critical": FAIL_BG,
    "high": colors.HexColor("#fff7ed"),
    "medium": WARN_BG,
    "low": LIGHT_BLUE_BG,
}

METRIC_COLORS = {
    "green": PASS_CLR,
    "amber": WARN_CLR,
    "red": FAIL_CLR,
    "blue": BLUE_ACCENT,
}


# ================================================================
# Utilities
# ================================================================

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

def _get_check(data, name):
    for c in data.get("checks", []):
        if c.get("name") == name:
            return c
    return {}

def _clr(color_name):
    return METRIC_COLORS.get(color_name, TEXT_SEC)


def _alt_rows(cmds, row_count):
    """Add alternating row backgrounds to table style commands (skip header)."""
    shaded = colors.HexColor("#f0f4f8")
    for i in range(1, row_count):
        if i % 2 == 0:
            cmds.append(("BACKGROUND", (0, i), (-1, i), shaded))
    return cmds


def _score_gauge(score, grade, grade_color):
    """Build a circular donut gauge showing score/grade.

    Returns a Drawing flowable: filled arc for the score percentage,
    light gray track for the remainder, grade letter centered inside.
    """
    size = 120
    cx, cy = size / 2, size / 2
    outer_r = 52
    inner_r = 36
    track_clr = colors.HexColor("#e2e8f0")

    pct = max(0, min(score, 100)) / 100.0
    score_angle = pct * 360

    d = Drawing(size, size)

    # Background track (full circle)
    d.add(Wedge(cx, cy, outer_r, 0, 360, radius1=inner_r,
                fillColor=track_clr, strokeColor=None, strokeWidth=0))

    # Score arc (counter-clockwise from 12 o'clock = 90 degrees)
    if score_angle > 0:
        start = 90
        end = 90 - score_angle
        if end < -270:
            end = -270
        d.add(Wedge(cx, cy, outer_r, end, start, radius1=inner_r,
                     fillColor=grade_color, strokeColor=None, strokeWidth=0))

    # Inner white circle for clean donut hole
    d.add(Circle(cx, cy, inner_r - 0.5,
                 fillColor=SURFACE_BG, strokeColor=None, strokeWidth=0))

    # Grade letter centered
    d.add(String(cx, cy - 10, grade,
                 fontSize=26, fontName="Helvetica-Bold",
                 fillColor=grade_color, textAnchor="middle"))

    # Score underneath
    d.add(String(cx, cy - 24, f"{score}/100",
                 fontSize=9, fontName="Helvetica",
                 fillColor=TEXT_TER, textAnchor="middle"))

    return d


# ================================================================
# Styles
# ================================================================

def _styles():
    s = {}
    s["title"]       = ParagraphStyle("T",  fontName="Helvetica-Bold",    fontSize=28, textColor=colors.white, leading=34)
    s["title_sub"]   = ParagraphStyle("TS", fontName="Helvetica",         fontSize=14, textColor=colors.HexColor("#b0c8e0"), leading=18)
    s["heading"]     = ParagraphStyle("H",  fontName="Helvetica-Bold",    fontSize=16, textColor=TEXT_PRI, leading=22, spaceBefore=16, spaceAfter=5)
    s["heading2"]    = ParagraphStyle("H2", fontName="Helvetica-Bold",    fontSize=14, textColor=NAVY, leading=19, spaceBefore=14, spaceAfter=4)
    s["subheading"]  = ParagraphStyle("SH", fontName="Helvetica-Bold",    fontSize=13, textColor=NAVY, leading=17, spaceBefore=12, spaceAfter=3)
    s["body"]        = ParagraphStyle("B",  fontName="Helvetica",         fontSize=11, textColor=TEXT_SEC, leading=16, spaceBefore=2, spaceAfter=2)
    s["body_large"]  = ParagraphStyle("BL", fontName="Helvetica",         fontSize=12, textColor=TEXT_PRI, leading=17, spaceBefore=2, spaceAfter=2)
    s["body_small"]  = ParagraphStyle("BS", fontName="Helvetica",         fontSize=10, textColor=TEXT_TER, leading=14, spaceBefore=1, spaceAfter=1)
    s["body_tiny"]   = ParagraphStyle("BT", fontName="Helvetica",         fontSize=9,  textColor=TEXT_TER, leading=12)
    s["verdict"]     = ParagraphStyle("V",  fontName="Helvetica-Oblique", fontSize=11, textColor=TEXT_TER, leading=16, spaceAfter=5)
    s["record"]      = ParagraphStyle("R",  fontName="Courier",           fontSize=9.5, textColor=RECORD_FG, leading=13)
    s["record_sm"]   = ParagraphStyle("RS", fontName="Courier",           fontSize=8.5, textColor=RECORD_FG, leading=12)
    s["fix_label"]   = ParagraphStyle("FL", fontName="Helvetica-Bold",    fontSize=10, textColor=PASS_CLR, leading=13, spaceAfter=3)
    s["fix_text"]    = ParagraphStyle("FT", fontName="Helvetica",         fontSize=11, textColor=TEXT_PRI, leading=16)
    s["pfix_num"]    = ParagraphStyle("PN", fontName="Helvetica-Bold",    fontSize=11, textColor=FAIL_CLR, leading=16)
    s["pfix_txt"]    = ParagraphStyle("PT", fontName="Helvetica",         fontSize=11, textColor=TEXT_PRI, leading=16)
    s["toc"]         = ParagraphStyle("TOC", fontName="Helvetica",        fontSize=11, textColor=NAVY, leading=18)
    s["callout"]     = ParagraphStyle("CO", fontName="Helvetica-Bold",    fontSize=11, textColor=FAIL_CLR, leading=16)
    s["callout_body"]= ParagraphStyle("CB", fontName="Helvetica",         fontSize=11, textColor=TEXT_PRI, leading=16)
    s["metric_label"]= ParagraphStyle("ML", fontName="Helvetica",         fontSize=9,  textColor=TEXT_TER, leading=12, alignment=TA_CENTER)
    s["metric_value"]= ParagraphStyle("MV", fontName="Helvetica-Bold",    fontSize=14, textColor=TEXT_PRI, leading=18, alignment=TA_CENTER)
    s["section_num"] = ParagraphStyle("SN", fontName="Helvetica-Bold",    fontSize=10, textColor=colors.white, leading=14)
    s["page_title"]  = ParagraphStyle("PG", fontName="Helvetica-Bold",    fontSize=20, textColor=NAVY, leading=26, spaceBefore=4, spaceAfter=8)
    for k, clr in [("good",PASS_CLR),("warning",WARN_CLR),("error",FAIL_CLR),("info",TEXT_SEC)]:
        s[f"d_{k}"] = ParagraphStyle(f"D{k}", fontName="Helvetica", fontSize=10.5, textColor=clr, leading=15, spaceBefore=1, spaceAfter=1, leftIndent=12)
    return s


# ================================================================
# Page template with header/footer
# ================================================================

class _PageTpl:
    def __init__(self, domain, grade, score, ts):
        self.domain = domain
        self.grade = grade
        self.score = score
        self.ts = ts
        self._page_count = 0

    def on_page(self, c, doc):
        self._page_count += 1
        w, h = letter
        # Footer on every page
        c.setFont("Helvetica", 8)
        c.setFillColor(TEXT_TER)
        c.drawString(54, 28, f"dns-audit.com  |  {self.domain}  |  {self.ts}")
        c.drawRightString(w - 54, 28, f"Page {doc.page}")
        # Thin top line (not on cover page)
        if doc.page > 1:
            c.setStrokeColor(BORDER)
            c.setLineWidth(0.5)
            c.line(54, h - 40, w - 54, h - 40)


# ================================================================
# Cover page (Page 1)
# ================================================================

def _cover_page(data, S):
    """Build cover page elements."""
    domain = data.get("domain", "unknown")
    sc = data.get("score", {})
    grade = sc.get("grade", "?")
    total = int(sc.get("total", 0))
    es = data.get("executive_summary", {})
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")

    els = []

    # Navy header block via table
    gc = GRADE_COLORS.get(grade, NAVY)

    # Title block
    title_content = [
        [Paragraph("DNS Security Audit Report", S["title"])],
    ]
    title_tbl = Table(title_content, colWidths=[6.5*inch])
    title_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), NAVY),
        ("TOPPADDING", (0,0), (-1,-1), 16),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 16),
        ("ROUNDEDCORNERS", [6,6,0,0]),
    ]))
    els.append(title_tbl)

    # Domain + date row under title
    sub_content = [
        [Paragraph(f"<b>{_safe(domain)}</b>", S["title_sub"]),
         Paragraph(f"dns-audit.com", S["title_sub"])],
    ]
    sub_tbl = Table(sub_content, colWidths=[4.5*inch, 2.0*inch])
    sub_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), NAVY),
        ("TOPPADDING", (0,0), (-1,-1), 2),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14),
        ("LEFTPADDING", (0,0), (-1,-1), 16),
        ("ALIGN", (1,0), (1,0), "RIGHT"),
        ("RIGHTPADDING", (1,0), (1,0), 16),
        ("ROUNDEDCORNERS", [0,0,6,6]),
    ]))
    els.append(sub_tbl)
    els.append(Spacer(1, 16))

    # Grade + Score gauge (donut chart)
    gauge = _score_gauge(total, grade, gc)

    verdict_text = es.get("verdict", "")
    verdict_cell = [
        Paragraph("Overall Security Grade", S["subheading"]),
        Spacer(1, 4),
        Paragraph(_safe(verdict_text), S["body_large"]),
    ]

    grade_row = Table([[gauge, verdict_cell]], colWidths=[1.8*inch, 4.7*inch])
    grade_row.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND", (0,0), (-1,-1), SURFACE_BG),
        ("BOX", (0,0), (-1,-1), 0.5, BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 14),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14),
        ("LEFTPADDING", (0,0), (-1,-1), 12),
        ("RIGHTPADDING", (0,0), (-1,-1), 12),
        ("ROUNDEDCORNERS", [6,6,6,6]),
    ]))
    els.append(grade_row)
    els.append(Spacer(1, 16))

    # Three key metrics
    sp = es.get("spoofing_protection", {})
    dr = es.get("dmarcbis_readiness", {})
    pc = es.get("protocol_coverage", {})

    def _metric_cell(label, value, color_name):
        clr = _clr(color_name)
        return [
            Paragraph(f'<font color="{clr.hexval()}" size="16"><b>{_safe(str(value))}</b></font>',
                      ParagraphStyle("MV2", alignment=TA_CENTER, leading=22)),
            Paragraph(f'<font color="#6b6b6b" size="9">{_safe(label)}</font>',
                      ParagraphStyle("ML2", alignment=TA_CENTER, leading=13)),
        ]

    sp_val = sp.get("label", "Unknown")
    sp_detail = sp.get("detail", "")
    dr_val = dr.get("label", "Unknown")
    pc_conf = pc.get("configured", 0)
    pc_total = pc.get("total", 9)

    metrics = Table([
        [_metric_cell(f"Spoofing Protection\n{sp_detail}", sp_val, sp.get("color", "red")),
         _metric_cell("DMARCbis Readiness", dr_val, dr.get("color", "red")),
         _metric_cell("Protocol Coverage", f"{pc_conf}/{pc_total}", pc.get("color", "red"))],
    ], colWidths=[2.17*inch]*3)
    metrics.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("TOPPADDING", (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("BACKGROUND", (0,0), (-1,-1), colors.white),
        ("BOX", (0,0), (-1,-1), 0.5, BORDER),
        ("LINEAFTER", (0,0), (1,0), 0.5, BORDER),
        ("ROUNDEDCORNERS", [6,6,6,6]),
    ]))
    els.append(metrics)
    els.append(Spacer(1, 20))

    # Table of contents
    els.append(Paragraph("Table of Contents", S["subheading"]))
    els.append(Spacer(1, 4))
    toc_items = [
        "1. Executive Summary",
        "2. Email Security Roadmap",
        "3. DMARC Deep Dive",
        "4. Attack Surface Analysis",
        "5. Protocol Details (SPF, DKIM, MTA-STS, TLS-RPT, DANE, DNSSEC, CAA, MX)",
        "6. Migration Path",
        "7. About This Report",
    ]
    for item in toc_items:
        els.append(Paragraph(item, S["toc"]))
    els.append(Spacer(1, 12))

    # Audit date line
    els.append(Paragraph(f"Audit performed: {now}", S["body_small"]))

    return els


# ================================================================
# Section header helper
# ================================================================

def _section_header(number, title, S):
    """Consistent section header with number badge."""
    badge = Table(
        [[Paragraph(f"<b>{number}</b>", S["section_num"])]],
        colWidths=[0.3*inch], rowHeights=[0.25*inch]
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), NAVY),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 2),
        ("BOTTOMPADDING", (0,0), (-1,-1), 2),
        ("ROUNDEDCORNERS", [4,4,4,4]),
    ]))
    row = Table([[badge, Paragraph(title, S["page_title"])]], colWidths=[0.45*inch, 6.05*inch])
    row.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
    ]))
    return [row, HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=10)]


# ================================================================
# Page 2: Executive Summary
# ================================================================

def _executive_summary_page(data, S):
    """Build the executive summary page."""
    es = data.get("executive_summary", {})
    els = [PageBreak()]
    els.extend(_section_header("1", "Executive Summary", S))

    # Verdict
    verdict = es.get("verdict", "")
    if verdict:
        vt = Table([[Paragraph(_safe(verdict), S["body_large"])]], colWidths=[6.5*inch])
        vt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), SURFACE_BG),
            ("BOX", (0,0), (-1,-1), 0.5, BORDER),
            ("TOPPADDING", (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
            ("LEFTPADDING", (0,0), (-1,-1), 12),
            ("RIGHTPADDING", (0,0), (-1,-1), 12),
            ("ROUNDEDCORNERS", [4,4,4,4]),
        ]))
        els.append(vt)
        els.append(Spacer(1, 12))

    # Biggest risk callout
    biggest_risk = es.get("biggest_risk", "")
    if biggest_risk:
        risk_content = [
            [Paragraph("\u26A0  YOUR BIGGEST RISK RIGHT NOW", S["callout"]),],
            [Paragraph(_safe(biggest_risk), S["callout_body"])],
        ]
        rt = Table(risk_content, colWidths=[6.5*inch])
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), FAIL_BG),
            ("LINEBEFORE", (0,0), (0,-1), 3, FAIL_CLR),
            ("TOPPADDING", (0,0), (-1,0), 10),
            ("TOPPADDING", (0,1), (-1,1), 2),
            ("BOTTOMPADDING", (0,-1), (-1,-1), 10),
            ("LEFTPADDING", (0,0), (-1,-1), 12),
            ("RIGHTPADDING", (0,0), (-1,-1), 12),
            ("ROUNDEDCORNERS", [0,4,4,0]),
        ]))
        els.append(rt)
        els.append(Spacer(1, 14))

    # Summary table: pass/warn/fail counts
    checks = data.get("checks", [])
    pc = sum(1 for c in checks if c.get("status") == "pass")
    wc = sum(1 for c in checks if c.get("status") == "warn")
    fc = sum(1 for c in checks if c.get("status") == "fail")
    def _count_cell(label, val, clr):
        return [
            Paragraph(f'<font color="{clr.hexval()}" size="20"><b>{val}</b></font>',
                      ParagraphStyle("CC", alignment=TA_CENTER, leading=26)),
            Paragraph(f'<font color="#6b6b6b" size="9">{label}</font>',
                      ParagraphStyle("CL", alignment=TA_CENTER, leading=13)),
        ]
    count_tbl = Table([
        [_count_cell("Passing", str(pc), PASS_CLR),
         _count_cell("Warnings", str(wc), WARN_CLR),
         _count_cell("Issues", str(fc), FAIL_CLR)],
    ], colWidths=[2.17*inch]*3)
    count_tbl.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LINEAFTER", (0,0), (1,0), 0.5, BORDER),
    ]))
    els.append(count_tbl)
    els.append(Spacer(1, 14))

    # Attack surface overview
    dmarc = _get_check(data, "DMARC")
    attack_surface = dmarc.get("attack_surface")
    if attack_surface:
        els.append(Paragraph("Attack Surface Overview", S["heading2"]))
        vectors = attack_surface.get("vectors", [])
        if vectors:
            header = [
                Paragraph("<b>Attack Vector</b>", S["body_small"]),
                Paragraph("<b>Status</b>", S["body_small"]),
                Paragraph("<b>Summary</b>", S["body_small"]),
            ]
            rows = [header]
            for v in vectors:
                status = v.get("status", "")
                s_clr = {"protected": PASS_CLR, "partial": WARN_CLR, "exposed": FAIL_CLR}.get(status, TEXT_SEC)
                s_lbl = {"protected": "Protected", "partial": "Partial", "exposed": "Exposed"}.get(status, status)
                rows.append([
                    Paragraph(_safe(v.get("name", "")), S["body"]),
                    Paragraph(f'<font color="{s_clr.hexval()}"><b>{s_lbl}</b></font>', S["body"]),
                    Paragraph(_safe(v.get("summary", "")), S["body_small"]),
                ])
            vt = Table(rows, colWidths=[1.7*inch, 1.0*inch, 3.8*inch])
            cmds = [
                ("VALIGN", (0,0), (-1,-1), "TOP"),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LINEBELOW", (0,0), (-1,0), 0.5, NAVY),
                ("LINEBELOW", (0,1), (-1,-2), 0.3, BORDER),
                ("BACKGROUND", (0,0), (-1,0), SURFACE_BG),
            ]
            _alt_rows(cmds, len(rows))
            vt.setStyle(TableStyle(cmds))
            els.append(vt)
        els.append(Spacer(1, 14))

    # Comparison intelligence
    tb = dmarc.get("tag_breakdown", {})
    ci = (tb or {}).get("comparison_intelligence") or dmarc.get("comparison_intelligence")
    if ci:
        els.append(Paragraph("Your Domain vs. the Top 1,000", S["heading2"]))
        pos_stmt = ci.get("position_statement", "")
        if pos_stmt:
            els.append(Paragraph(_safe(pos_stmt), S["body"]))
        pct = ci.get("position_pct", 0)
        els.append(Paragraph(f"Adoption position: top {pct}%", S["body"]))

        # Adoption stats
        stats = ci.get("adoption_stats", [])
        if isinstance(stats, list) and stats:
            stat_rows = []
            for stat in stats:
                if isinstance(stat, dict):
                    stat_rows.append([
                        Paragraph(_safe(stat.get("label", "")), S["body_small"]),
                        Paragraph(f"{stat.get('adoption_pct', 0)}%", S["body_small"]),
                    ])
            if stat_rows:
                st = Table(stat_rows, colWidths=[3.5*inch, 1.5*inch])
                st.setStyle(TableStyle([
                    ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
                    ("TOPPADDING", (0,0), (-1,-1), 3),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                    ("LINEBELOW", (0,0), (-1,-2), 0.3, BORDER),
                    ("ALIGN", (1,0), (1,-1), "RIGHT"),
                ]))
                els.append(Spacer(1, 4))
                els.append(st)
        elif isinstance(stats, dict):
            stat_rows = []
            for k, v in stats.items():
                stat_rows.append([
                    Paragraph(_safe(k.replace("_", " ").title()), S["body_small"]),
                    Paragraph(f"{v}%", S["body_small"]),
                ])
            if stat_rows:
                st = Table(stat_rows, colWidths=[3.5*inch, 1.5*inch])
                st.setStyle(TableStyle([
                    ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
                    ("TOPPADDING", (0,0), (-1,-1), 3),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                    ("LINEBELOW", (0,0), (-1,-2), 0.3, BORDER),
                    ("ALIGN", (1,0), (1,-1), "RIGHT"),
                ]))
                els.append(Spacer(1, 4))
                els.append(st)

        tagline = ci.get("adoption_tagline", "")
        if tagline:
            els.append(Spacer(1, 4))
            els.append(Paragraph(f"<i>{_safe(tagline)}</i>", S["body_small"]))

    return els


# ================================================================
# Page 3: Email Security Roadmap
# ================================================================

def _roadmap_page(data, S):
    """Build the email security roadmap page."""
    roadmap = data.get("security_roadmap", {})
    items = roadmap.get("items", [])
    els = [CondPageBreak(4*inch)]
    els.extend(_section_header("2", "Email Security Roadmap", S))

    # Summary
    summary = roadmap.get("summary", "")
    if summary:
        els.append(Paragraph(_safe(summary), S["body"]))
        els.append(Spacer(1, 8))

    # Tier summary bar
    tiers = roadmap.get("tiers", {})
    tier_cells = []
    for tier_name in ["critical", "high", "medium", "low"]:
        count = tiers.get(tier_name, 0)
        t_clr = PRIORITY_CLR.get(tier_name, TEXT_SEC)
        tier_cells.append([
            Paragraph(f'<font color="{t_clr.hexval()}" size="14"><b>{count}</b></font>',
                      ParagraphStyle("TC", alignment=TA_CENTER, leading=18)),
            Paragraph(f'<font color="#6b6b6b" size="8">{tier_name.upper()}</font>',
                      ParagraphStyle("TL", alignment=TA_CENTER, leading=12)),
        ])
    if any(tiers.values()):
        tier_bar = Table([tier_cells], colWidths=[1.625*inch]*4)
        tier_bar.setStyle(TableStyle([
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LINEAFTER", (0,0), (2,0), 0.5, BORDER),
            ("BACKGROUND", (0,0), (-1,-1), SURFACE_BG),
            ("BOX", (0,0), (-1,-1), 0.5, BORDER),
            ("ROUNDEDCORNERS", [4,4,4,4]),
        ]))
        els.append(tier_bar)
        els.append(Spacer(1, 12))

    # Roadmap items table
    if items:
        header = [
            Paragraph("<b>#</b>", S["body_small"]),
            Paragraph("<b>Priority</b>", S["body_small"]),
            Paragraph("<b>Protocol</b>", S["body_small"]),
            Paragraph("<b>Action</b>", S["body_small"]),
            Paragraph("<b>Business Impact</b>", S["body_small"]),
        ]
        rows = [header]
        for i, item in enumerate(items, 1):
            p = item.get("priority", "low")
            p_clr = PRIORITY_CLR.get(p, TEXT_SEC)
            rows.append([
                Paragraph(str(i), S["body_small"]),
                Paragraph(f'<font color="{p_clr.hexval()}"><b>{p.upper()}</b></font>', S["body_small"]),
                Paragraph(_safe(item.get("protocol", "")), S["body"]),
                Paragraph(_safe(item.get("action", "")), S["body"]),
                Paragraph(_safe(item.get("impact", "")), S["body_small"]),
            ])
        rt = Table(rows, colWidths=[0.3*inch, 0.8*inch, 0.8*inch, 2.1*inch, 2.5*inch])
        cmds = [
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LINEBELOW", (0,0), (-1,0), 0.5, NAVY),
            ("LINEBELOW", (0,1), (-1,-2), 0.3, BORDER),
            ("BACKGROUND", (0,0), (-1,0), SURFACE_BG),
        ]
        _alt_rows(cmds, len(rows))
        rt.setStyle(TableStyle(cmds))
        els.append(rt)
    else:
        els.append(Paragraph("No action items. Your email security meets all current best practices.", S["body"]))

    # Priority fixes (legacy format)
    fixes = data.get("priority_fixes", [])
    if fixes:
        els.append(Spacer(1, 14))
        els.append(Paragraph("Priority Fixes", S["heading2"]))
        for i, fix in enumerate(fixes, 1):
            r = Table(
                [[Paragraph(f"<b>{i}</b>", S["pfix_num"]),
                  Paragraph(_safe(fix), S["pfix_txt"])]],
                colWidths=[0.3*inch, 6.2*inch]
            )
            r.setStyle(TableStyle([
                ("VALIGN", (0,0), (-1,-1), "TOP"),
                ("TOPPADDING", (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("BACKGROUND", (0,0), (-1,-1), FAIL_BG),
                ("ROUNDEDCORNERS", [3,3,3,3]),
            ]))
            els.append(r)
            els.append(Spacer(1, 3))

    return els


# ================================================================
# Pages 4-5: DMARC Deep Dive
# ================================================================

def _dmarc_deep_dive(data, S):
    """Build the DMARC deep dive section."""
    dmarc = _get_check(data, "DMARC")
    if not dmarc:
        return []

    els = [PageBreak()]
    els.extend(_section_header("3", "DMARC Deep Dive", S))

    status = dmarc.get("status", "pass")
    s_clr = STATUS_CLR.get(status, TEXT_SEC)
    s_lbl = STATUS_LBL.get(status, "INFO")

    # Status + verdict
    hdr = Table([
        [Paragraph(f"<b>DMARC</b>", S["heading"]),
         Paragraph(f'<font color="{s_clr.hexval()}" size="10"><b> {s_lbl} </b></font>', S["body"])],
    ], colWidths=[5.5*inch, 1.0*inch])
    hdr.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN", (1,0), (1,0), "RIGHT"),
        ("TOPPADDING", (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
    ]))
    els.append(hdr)

    verdict = dmarc.get("verdict", "")
    if verdict:
        els.append(Paragraph(_safe(verdict), S["verdict"]))

    # Current record
    record = dmarc.get("record", "")
    if record:
        els.append(Paragraph("Current Record", S["subheading"]))
        els.extend(_record_block(record, S))

    # DMARCbis Health Verdict
    tb = dmarc.get("tag_breakdown") or {}
    health = tb.get("health")
    if health:
        els.append(Spacer(1, 8))
        els.append(Paragraph("DMARCbis Health Verdict", S["heading2"]))
        h_clr = _clr(health.get("color", "red"))
        h_label = health.get("label", "")
        h_summary = health.get("summary", "")
        verdict_row = Table([
            [Paragraph(f'<font color="{h_clr.hexval()}" size="13"><b>{_safe(h_label)}</b></font>', S["body"]),
             Paragraph(_safe(h_summary), S["body"])],
        ], colWidths=[2.0*inch, 4.5*inch])
        verdict_row.setStyle(TableStyle([
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("BACKGROUND", (0,0), (-1,-1), SURFACE_BG),
            ("BOX", (0,0), (-1,-1), 0.5, BORDER),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
            ("ROUNDEDCORNERS", [4,4,4,4]),
        ]))
        els.append(verdict_row)

        reasons = health.get("reasons", [])
        for r in reasons:
            els.append(Paragraph(f"\u2022  {_safe(r)}", S["body_small"]))

    # Strict validation results
    sv = dmarc.get("strict_validation")
    if sv:
        els.append(Spacer(1, 10))
        els.append(Paragraph("DMARCbis Strict Validation", S["heading2"]))
        p_count = sv.get("pass_count", 0)
        f_count = sv.get("fail_count", 0)
        w_count = sv.get("warn_count", 0)
        t_count = sv.get("total_count", 0)
        els.append(Paragraph(
            f'<font color="{PASS_CLR.hexval()}">{p_count} pass</font>  |  '
            f'<font color="{WARN_CLR.hexval()}">{w_count} warn</font>  |  '
            f'<font color="{FAIL_CLR.hexval()}">{f_count} fail</font>  |  '
            f'{t_count} total checks', S["body"]
        ))
        els.append(Spacer(1, 4))

        for cat in sv.get("categories", []):
            els.append(Paragraph(f"<b>{_safe(cat.get('label', ''))}</b>", S["body"]))
            for chk in cat.get("checks", []):
                c_status = chk.get("status", "pass")
                icon = {"pass": "\u2713", "fail": "\u2717", "warn": "\u26A0"}.get(c_status, "\u2022")
                c_clr = STATUS_CLR.get(c_status, TEXT_SEC)
                style_key = {"pass": "d_good", "fail": "d_error", "warn": "d_warning"}.get(c_status, "d_info")
                els.append(Paragraph(f"{icon}  {_safe(chk.get('message', ''))}", S[style_key]))

    # Tag-by-tag breakdown
    tags_list = tb.get("tags", [])
    if tags_list:
        els.append(Spacer(1, 10))
        els.append(Paragraph("Tag-by-Tag Breakdown", S["heading2"]))

        header = [
            Paragraph("<b>Tag</b>", S["body_small"]),
            Paragraph("<b>Value</b>", S["body_small"]),
            Paragraph("<b>DMARCbis</b>", S["body_small"]),
            Paragraph("<b>Explanation</b>", S["body_small"]),
        ]
        rows = [header]
        for tag in tags_list:
            tag_name = tag.get("tag", "")
            val = tag.get("value") or "(absent)" if tag.get("is_absent") else (tag.get("value") or "(default)")
            bis_status = tag.get("dmarcbis", "")
            bis_clr = {"current": PASS_CLR, "new": TEAL_ACCENT, "deprecated": FAIL_CLR}.get(bis_status, TEXT_SEC)
            bis_label = {"current": "Current", "new": "New", "deprecated": "Deprecated"}.get(bis_status, bis_status)

            explanation = tag.get("explanation", "")
            bis_note = tag.get("dmarcbis_note", "")
            if bis_note:
                explanation += f" [{bis_note}]"

            # Include warnings
            warnings = tag.get("warnings", [])
            for w in warnings:
                explanation += f" \u26A0 {w.get('text', '')}"

            rows.append([
                Paragraph(f"<b>{_safe(tag_name)}</b>", S["body"]),
                Paragraph(f"<font name='Courier' size='9'>{_safe(str(val))}</font>", S["body"]),
                Paragraph(f'<font color="{bis_clr.hexval()}">{_safe(bis_label)}</font>', S["body_small"]),
                Paragraph(_safe(explanation), S["body_small"]),
            ])

        tt = Table(rows, colWidths=[0.5*inch, 1.3*inch, 0.9*inch, 3.8*inch])
        cmds = [
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LINEBELOW", (0,0), (-1,0), 0.5, NAVY),
            ("LINEBELOW", (0,1), (-1,-2), 0.3, BORDER),
            ("BACKGROUND", (0,0), (-1,0), SURFACE_BG),
        ]
        _alt_rows(cmds, len(rows))
        tt.setStyle(TableStyle(cmds))
        els.append(tt)

    # Dangerous combinations
    config_warnings = tb.get("config_warnings", [])
    if config_warnings:
        els.append(Spacer(1, 10))
        els.append(Paragraph("Configuration Warnings", S["heading2"]))
        for w in config_warnings:
            level = w.get("level", "advisory")
            w_clr = {"critical": FAIL_CLR, "advisory": WARN_CLR}.get(level, TEXT_SEC)
            w_bg = {"critical": FAIL_BG, "advisory": WARN_BG}.get(level, SURFACE_BG)
            title = w.get("title", "")
            text = w.get("text", "")
            tags_involved = ", ".join(w.get("tags", []))

            content = []
            content.append(Paragraph(f'<font color="{w_clr.hexval()}"><b>{_safe(title)}</b></font>', S["body"]))
            content.append(Paragraph(_safe(text), S["body_small"]))
            if tags_involved:
                content.append(Paragraph(f"Tags: {_safe(tags_involved)}", S["body_tiny"]))

            wt = Table([[content]], colWidths=[6.5*inch])
            wt.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), w_bg),
                ("LINEBEFORE", (0,0), (0,-1), 2.5, w_clr),
                ("TOPPADDING", (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING", (0,0), (-1,-1), 10),
                ("RIGHTPADDING", (0,0), (-1,-1), 10),
                ("ROUNDEDCORNERS", [0,4,4,0]),
            ]))
            els.append(wt)
            els.append(Spacer(1, 4))

    # Record Builder: current vs recommended
    rb = tb.get("record_builder") or dmarc.get("record_builder")
    if rb and rb.get("mode") != "ready":
        els.append(Spacer(1, 10))
        els.append(Paragraph("Record Builder: Current vs. Recommended", S["heading2"]))

        current = rb.get("current_record")
        recommended = rb.get("recommended_record")

        if current:
            els.append(Paragraph("Current record:", S["body_small"]))
            els.extend(_record_block(current, S, small=True))

        if recommended:
            els.append(Paragraph("Recommended record:", S["body_small"]))
            els.extend(_record_block(recommended, S, small=True))

        changes = rb.get("changes", [])
        if changes:
            els.append(Spacer(1, 4))
            els.append(Paragraph("Changes:", S["body_small"]))
            for ch in changes:
                action = ch.get("action", "")
                tag = ch.get("tag", "")
                reason = ch.get("reason", "")
                action_icon = {"added": "+", "changed": "\u2192", "removed": "\u2717"}.get(action, "\u2022")
                els.append(Paragraph(
                    f"{action_icon}  <b>{_safe(tag)}</b> ({action}): {_safe(reason)}",
                    S["body_small"]
                ))

    return els


# ================================================================
# Pages 5-6: Attack Surface Analysis
# ================================================================

def _attack_surface_page(data, S):
    """Build the attack surface analysis section."""
    dmarc = _get_check(data, "DMARC")
    attack_surface = dmarc.get("attack_surface")
    if not attack_surface:
        return []

    els = [PageBreak()]
    els.extend(_section_header("4", "Attack Surface Analysis", S))

    # Overall assessment
    overall = attack_surface.get("overall", {})
    level = overall.get("level", "")
    o_clr = _clr(overall.get("color", "red"))
    o_label = overall.get("label", "")
    o_summary = overall.get("summary", "")

    overall_row = Table([
        [Paragraph(f'<font color="{o_clr.hexval()}" size="14"><b>{_safe(o_label)}</b></font>', S["body"]),
         Paragraph(_safe(o_summary), S["body"])],
    ], colWidths=[2.0*inch, 4.5*inch])
    overall_row.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND", (0,0), (-1,-1), SURFACE_BG),
        ("BOX", (0,0), (-1,-1), 0.5, BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING", (0,0), (-1,-1), 12),
        ("ROUNDEDCORNERS", [4,4,4,4]),
    ]))
    els.append(overall_row)
    els.append(Spacer(1, 12))

    # Detailed vectors
    vectors = attack_surface.get("vectors", [])
    for v in vectors:
        v_name = v.get("name", "")
        v_status = v.get("status", "")
        v_color = {"protected": PASS_CLR, "partial": WARN_CLR, "exposed": FAIL_CLR}.get(v_status, TEXT_SEC)
        v_bg = {"protected": PASS_BG, "partial": WARN_BG, "exposed": FAIL_BG}.get(v_status, SURFACE_BG)
        v_label = {"protected": "PROTECTED", "partial": "PARTIAL", "exposed": "EXPOSED"}.get(v_status, v_status.upper())
        v_summary = v.get("summary", "")
        v_detail = v.get("detail", "")

        content = [
            Paragraph(
                f'<b>{_safe(v_name)}</b>  '
                f'<font color="{v_color.hexval()}" size="9"><b>[{v_label}]</b></font>',
                S["body"]
            ),
            Paragraph(_safe(v_summary), S["body_small"]),
        ]
        if v_detail:
            content.append(Paragraph(_safe(v_detail), S["body_small"]))

        vt = Table([[content]], colWidths=[6.5*inch])
        vt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), v_bg),
            ("LINEBEFORE", (0,0), (0,-1), 2.5, v_color),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
            ("RIGHTPADDING", (0,0), (-1,-1), 10),
            ("ROUNDEDCORNERS", [0,4,4,0]),
        ]))
        els.append(vt)
        els.append(Spacer(1, 6))

    # Attacker perspective
    attacker_path = attack_surface.get("attacker_path", "")
    if attacker_path:
        els.append(Spacer(1, 8))
        els.append(Paragraph("Attacker Perspective", S["heading2"]))
        ap = Table([[Paragraph(_safe(attacker_path), S["body"])]], colWidths=[6.5*inch])
        ap.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#fef3cd")),
            ("BOX", (0,0), (-1,-1), 0.5, WARN_CLR),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
            ("RIGHTPADDING", (0,0), (-1,-1), 10),
            ("ROUNDEDCORNERS", [4,4,4,4]),
        ]))
        els.append(ap)

    # Subdomain audit results (tree walk)
    tw = dmarc.get("tree_walk") or data.get("tree_walk")
    if tw:
        steps = tw.get("steps", [])
        if steps and len(steps) > 1:
            els.append(Spacer(1, 12))
            els.append(Paragraph("DMARC DNS Tree Walk (Subdomain Audit)", S["heading2"]))
            header = [
                Paragraph("<b>Domain</b>", S["body_small"]),
                Paragraph("<b>Record Found</b>", S["body_small"]),
                Paragraph("<b>Policy</b>", S["body_small"]),
            ]
            rows = [header]
            for step in steps:
                found = step.get("found", False)
                domain_name = step.get("domain", "")
                policy_val = step.get("policy", "")
                found_icon = "\u2713" if found else "\u2717"
                f_clr = PASS_CLR if found else FAIL_CLR
                rows.append([
                    Paragraph(f"<font name='Courier' size='9'>{_safe(domain_name)}</font>", S["body"]),
                    Paragraph(f'<font color="{f_clr.hexval()}">{found_icon}</font>', S["body"]),
                    Paragraph(_safe(policy_val) if policy_val else "-", S["body_small"]),
                ])
            st = Table(rows, colWidths=[3.0*inch, 1.0*inch, 2.5*inch])
            cmds = [
                ("VALIGN", (0,0), (-1,-1), "TOP"),
                ("TOPPADDING", (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("LINEBELOW", (0,0), (-1,0), 0.5, NAVY),
                ("LINEBELOW", (0,1), (-1,-2), 0.3, BORDER),
                ("BACKGROUND", (0,0), (-1,0), SURFACE_BG),
            ]
            _alt_rows(cmds, len(rows))
            st.setStyle(TableStyle(cmds))
            els.append(st)

    # Subdomain audit results
    sa = data.get("subdomain_audit")
    if sa and sa.get("subdomains"):
        els.append(Spacer(1, 12))
        els.append(Paragraph("Subdomain Security Audit", S["heading2"]))

        # Summary lines
        for line in sa.get("summary_lines", []):
            els.append(Paragraph(_safe(line), S["body"]))

        # Callout
        callout = sa.get("callout")
        if callout:
            ct = Table([[Paragraph(_safe(callout), S["callout_body"])]], colWidths=[6.5*inch])
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), FAIL_BG),
                ("LINEBEFORE", (0,0), (0,-1), 3, FAIL_CLR),
                ("TOPPADDING", (0,0), (-1,-1), 8),
                ("BOTTOMPADDING", (0,0), (-1,-1), 8),
                ("LEFTPADDING", (0,0), (-1,-1), 10),
                ("RIGHTPADDING", (0,0), (-1,-1), 10),
                ("ROUNDEDCORNERS", [0,4,4,0]),
            ]))
            els.append(Spacer(1, 4))
            els.append(ct)

        els.append(Spacer(1, 6))

        # Table
        header = [
            Paragraph("<b>Subdomain</b>", S["body_small"]),
            Paragraph("<b>Exists</b>", S["body_small"]),
            Paragraph("<b>Mail</b>", S["body_small"]),
            Paragraph("<b>Own DMARC</b>", S["body_small"]),
            Paragraph("<b>Effective Policy</b>", S["body_small"]),
            Paragraph("<b>Status</b>", S["body_small"]),
        ]
        rows = [header]
        for sub in sa["subdomains"]:
            s_clr = {"protected": PASS_CLR, "partial": WARN_CLR, "exposed": FAIL_CLR}.get(sub.get("status", ""), TEXT_SEC)
            status_icon = {"protected": "\u2713", "partial": "\u26A0", "exposed": "\u2717"}.get(sub.get("status", ""), "")
            exists_text = "Yes" if sub.get("exists") else "No"
            mail_text = "-"
            if sub.get("exists"):
                mail_text = sub.get("mail_signals", "No") if sub.get("sends_mail") else "No"

            dmarc_text = "-"
            if sub.get("exists"):
                dmarc_text = "Yes" if sub.get("has_own_dmarc") else "No"

            rows.append([
                Paragraph(f"<font name='Courier' size='7.5'>{_safe(sub.get('subdomain', ''))}</font>", S["body_small"]),
                Paragraph(exists_text, S["body_small"]),
                Paragraph(mail_text, S["body_small"]),
                Paragraph(dmarc_text, S["body_small"]),
                Paragraph(f"<font size='8'>{_safe(sub.get('policy_display', ''))}</font>", S["body_small"]),
                Paragraph(f'<font color="{s_clr.hexval()}">{status_icon} {_safe(sub.get("status_label", ""))}</font>', S["body_small"]),
            ])

        st = Table(rows, colWidths=[1.7*inch, 0.5*inch, 0.6*inch, 0.7*inch, 1.5*inch, 1.0*inch])
        cmds = [
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("LINEBELOW", (0,0), (-1,0), 0.5, NAVY),
            ("LINEBELOW", (0,1), (-1,-2), 0.3, BORDER),
            ("BACKGROUND", (0,0), (-1,0), SURFACE_BG),
        ]
        _alt_rows(cmds, len(rows))
        st.setStyle(TableStyle(cmds))
        els.append(st)

    return els


# ================================================================
# Pages 6-7: Protocol Details
# ================================================================

def _protocol_details(data, S):
    """Build protocol detail sections for SPF, DKIM, MTA-STS, etc."""
    els = [PageBreak()]
    els.extend(_section_header("5", "Protocol Details", S))

    # SPF
    spf = _get_check(data, "SPF")
    if spf:
        els.extend(_protocol_card(spf, S))
        spf_deep = spf.get("spf_deep")
        if spf_deep:
            els.extend(_spf_deep_section(spf_deep, S))

    # DKIM
    dkim = _get_check(data, "DKIM")
    if dkim:
        els.extend(_protocol_card(dkim, S))
        dkim_deep = dkim.get("dkim_deep")
        if dkim_deep:
            els.extend(_dkim_deep_section(dkim_deep, S))

    # MTA-STS
    mta_sts = _get_check(data, "MTA-STS")
    if mta_sts:
        els.extend(_protocol_card(mta_sts, S))

    # TLS-RPT
    tls_rpt = _get_check(data, "TLS-RPT")
    if tls_rpt:
        els.extend(_protocol_card(tls_rpt, S))

    # DANE
    dane = _get_check(data, "DANE")
    if dane:
        els.extend(_protocol_card(dane, S))

    # DNSSEC
    dnssec = _get_check(data, "DNSSEC")
    if dnssec:
        els.extend(_protocol_card(dnssec, S))

    # CAA
    caa = _get_check(data, "CAA")
    if caa:
        els.extend(_protocol_card(caa, S))

    # MX Records
    mx = _get_check(data, "MX Records")
    if mx:
        els.extend(_protocol_card(mx, S))

    # Nameservers
    ns = _get_check(data, "Nameservers")
    if ns:
        els.extend(_protocol_card(ns, S))

    # BIMI
    bimi = _get_check(data, "BIMI")
    if bimi:
        els.extend(_protocol_card(bimi, S))

    # Detected vendors
    els.extend(_vendors(data, S))

    return els


def _protocol_card(check, S):
    """Render a single protocol check as a card."""
    name = check.get("name", "Unknown")
    status = check.get("status", "pass")
    verdict = check.get("verdict", "")
    record = check.get("record", "")
    details = check.get("details", [])
    fix = check.get("fix", "")
    s_clr = STATUS_CLR.get(status, TEXT_SEC)
    s_lbl = STATUS_LBL.get(status, "INFO")
    pill_label = check.get("pill_label")
    if pill_label:
        s_lbl = pill_label

    els = []

    # Header: name + pill
    hdr = Table([
        [Paragraph(f"<b>{_safe(name)}</b>", S["heading"]),
         Paragraph(f'<font color="{s_clr.hexval()}" size="10"><b> {_safe(s_lbl)} </b></font>', S["body"])],
    ], colWidths=[5.5*inch, 1.0*inch])
    hdr.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN", (1,0), (1,0), "RIGHT"),
        ("TOPPADDING", (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
    ]))
    els.append(hdr)

    if verdict:
        els.append(Paragraph(_safe(verdict), S["verdict"]))

    # Record block
    if record:
        els.extend(_record_block(record, S))

    # Details
    for d in details:
        dt = d.get("type", "info")
        icon = DETAIL_ICON.get(dt, "\u2022")
        sk = f"d_{dt}" if f"d_{dt}" in S else "d_info"
        els.append(Paragraph(f"{icon}  {_safe(d.get('text', ''))}", S[sk]))

    # Explanation
    explanation = check.get("explanation", "")
    if explanation:
        exp_text = _strip_html(explanation)
        if exp_text and exp_text != verdict:
            els.append(Spacer(1, 2))
            els.append(Paragraph(_safe(exp_text), S["body_small"]))

    # Fix block
    if fix and status in ("warn", "fail"):
        fp = _strip_html(fix)
        fs = _safe(fp).replace("\n", "<br/>")
        fc = [Paragraph("<b>RECOMMENDED FIX</b>", S["fix_label"]),
              Paragraph(fs, S["fix_text"])]
        ft = Table([[fc]], colWidths=[6.5*inch])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), FIX_BG),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
            ("RIGHTPADDING", (0,0), (-1,-1), 10),
            ("LINEBEFORE", (0,0), (0,-1), 2.5, FIX_BORDER),
            ("ROUNDEDCORNERS", [0,4,4,0]),
        ]))
        els.append(Spacer(1, 6))
        els.append(ft)

    # Fix records (copy-paste DNS records)
    fix_records = check.get("fix_records")
    if fix_records:
        els.append(Spacer(1, 4))
        els.append(Paragraph("DNS records to add:", S["body_small"]))
        for fr in fix_records:
            rec_str = f"{fr.get('host','')}  {fr.get('type','')}  {fr.get('value','')}"
            comment = fr.get("comment", "")
            if comment:
                rec_str += f"  ; {comment}"
            els.extend(_record_block(rec_str, S, small=True))

    els.extend([Spacer(1, 6), HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6)])
    return [KeepTogether(els)]


def _record_block(record, S, small=False):
    """Render a DNS record in a dark code block."""
    rec = _safe(record)
    style = S["record_sm"] if small else S["record"]
    rt = Table([[Paragraph(rec, style)]], colWidths=[6.5*inch])
    rt.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), RECORD_BG),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING", (0,0), (-1,-1), 9),
        ("RIGHTPADDING", (0,0), (-1,-1), 9),
        ("ROUNDEDCORNERS", [4,4,4,4]),
    ]))
    return [Spacer(1, 3), rt, Spacer(1, 3)]


def _spf_deep_section(spf_deep, S):
    """Render SPF mechanism breakdown and provider identification."""
    els = []
    mechanisms = spf_deep.get("mechanisms", [])
    if mechanisms:
        els.append(Paragraph("SPF Mechanism Breakdown", S["subheading"]))
        header = [
            Paragraph("<b>Mechanism</b>", S["body_small"]),
            Paragraph("<b>Type</b>", S["body_small"]),
            Paragraph("<b>Provider</b>", S["body_small"]),
            Paragraph("<b>DNS Cost</b>", S["body_small"]),
        ]
        rows = [header]
        for m in mechanisms:
            provider = m.get("provider") or "-"
            rows.append([
                Paragraph(f"<font name='Courier' size='8'>{_safe(m.get('raw', ''))}</font>", S["body_small"]),
                Paragraph(_safe(m.get("type", "")), S["body_small"]),
                Paragraph(_safe(provider), S["body_small"]),
                Paragraph(str(m.get("cost", 0)), S["body_small"]),
            ])
        mt = Table(rows, colWidths=[2.5*inch, 0.8*inch, 1.7*inch, 0.7*inch])
        cmds = [
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("LINEBELOW", (0,0), (-1,0), 0.5, NAVY),
            ("LINEBELOW", (0,1), (-1,-2), 0.3, BORDER),
            ("BACKGROUND", (0,0), (-1,0), SURFACE_BG),
        ]
        _alt_rows(cmds, len(rows))
        mt.setStyle(TableStyle(cmds))
        els.append(mt)

    # Lookup count
    lookup_count = spf_deep.get("lookup_count", 0)
    if lookup_count > 0:
        lc_clr = PASS_CLR if lookup_count <= 7 else (WARN_CLR if lookup_count <= 9 else FAIL_CLR)
        els.append(Paragraph(
            f'DNS lookups: <font color="{lc_clr.hexval()}"><b>{lookup_count}/10</b></font>',
            S["body"]
        ))

    # All mechanism
    all_mech = spf_deep.get("all_mechanism", "")
    all_exp = spf_deep.get("all_explanation", "")
    if all_mech:
        all_sev = spf_deep.get("all_severity", "info")
        a_clr = {"critical": FAIL_CLR, "warning": WARN_CLR, "info": PASS_CLR}.get(all_sev, TEXT_SEC)
        els.append(Paragraph(
            f'All mechanism: <font color="{a_clr.hexval()}"><b>{_safe(all_mech)}</b></font>'
            f' - {_safe(all_exp)}', S["body_small"]
        ))

    # Misconfigs
    misconfigs = spf_deep.get("misconfigs", [])
    for mc in misconfigs:
        mc_clr = {"critical": FAIL_CLR, "warning": WARN_CLR}.get(mc.get("level", ""), TEXT_SEC)
        els.append(Paragraph(
            f'\u26A0  <font color="{mc_clr.hexval()}"><b>{_safe(mc.get("title", ""))}</b></font>: '
            f'{_safe(mc.get("text", ""))}', S["body_small"]
        ))

    els.append(Spacer(1, 6))
    return els


def _dkim_deep_section(dkim_deep, S):
    """Render DKIM key analysis with strength ratings."""
    els = []
    keys = dkim_deep.get("keys", [])
    if keys:
        els.append(Paragraph("DKIM Key Analysis", S["subheading"]))
        header = [
            Paragraph("<b>Selector</b>", S["body_small"]),
            Paragraph("<b>Vendor</b>", S["body_small"]),
            Paragraph("<b>Key Type</b>", S["body_small"]),
            Paragraph("<b>Bits</b>", S["body_small"]),
            Paragraph("<b>Strength</b>", S["body_small"]),
            Paragraph("<b>Rotation</b>", S["body_small"]),
        ]
        rows = [header]
        for k in keys:
            r_clr = {"green": PASS_CLR, "amber": WARN_CLR, "red": FAIL_CLR}.get(k.get("rating", ""), TEXT_SEC)
            rows.append([
                Paragraph(f"<font name='Courier' size='8'>{_safe(k.get('selector', ''))}</font>", S["body_small"]),
                Paragraph(_safe(k.get("vendor") or "-"), S["body_small"]),
                Paragraph(_safe(k.get("key_type", "")), S["body_small"]),
                Paragraph(str(k.get("key_bits", "")), S["body_small"]),
                Paragraph(f'<font color="{r_clr.hexval()}">{_safe(k.get("rating_label", ""))}</font>', S["body_small"]),
                Paragraph(_safe(k.get("rotation_status", "")), S["body_small"]),
            ])
        kt = Table(rows, colWidths=[60, 70, 70, 40, 140, 80])
        cmds = [
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("LINEBELOW", (0,0), (-1,0), 0.5, NAVY),
            ("LINEBELOW", (0,1), (-1,-2), 0.3, BORDER),
            ("BACKGROUND", (0,0), (-1,0), SURFACE_BG),
        ]
        _alt_rows(cmds, len(rows))
        kt.setStyle(TableStyle(cmds))
        els.append(kt)

    # Rotation guidance
    for k in keys:
        guidance = k.get("rotation_guidance", "")
        if guidance:
            els.append(Paragraph(
                f"\u2022  <b>{_safe(k.get('selector', ''))}</b>: {_safe(guidance)}",
                S["body_small"]
            ))

    # Summary + recommendations
    summary = dkim_deep.get("summary", "")
    if summary:
        els.append(Paragraph(_safe(summary), S["body_small"]))

    recs = dkim_deep.get("recommendations", [])
    for rec in recs:
        els.append(Paragraph(f"\u2022  {_safe(rec)}", S["body_small"]))

    els.append(Spacer(1, 6))
    return els


def _vendors(data, S):
    """Render detected email service providers."""
    vs = data.get("vendors", [])
    if not vs:
        return []
    els = [Spacer(1, 8), Paragraph("Detected Email Services", S["heading2"])]
    header = [
        Paragraph("<b>Provider</b>", S["body_small"]),
        Paragraph("<b>Confidence</b>", S["body_small"]),
    ]
    rows = [header]
    for v in vs:
        conf = v.get("confidence", 0)
        c_clr = PASS_CLR if conf >= 80 else (WARN_CLR if conf >= 50 else TEXT_SEC)
        rows.append([
            Paragraph(f"<b>{_safe(v.get('name', ''))}</b>", S["body"]),
            Paragraph(f'<font color="{c_clr.hexval()}">{conf}%</font>', S["body"]),
        ])
    vt = Table(rows, colWidths=[4.5*inch, 2.0*inch])
    cmds = [
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LINEBELOW", (0,0), (-1,0), 0.5, NAVY),
        ("LINEBELOW", (0,1), (-1,-2), 0.3, BORDER),
        ("BACKGROUND", (0,0), (-1,0), SURFACE_BG),
        ("ALIGN", (1,0), (1,-1), "RIGHT"),
    ]
    _alt_rows(cmds, len(rows))
    vt.setStyle(TableStyle(cmds))
    els.append(vt)
    els.append(Spacer(1, 8))
    return els


# ================================================================
# Page 7: Migration Path
# ================================================================

def _migration_page(data, S):
    """Build the migration path section."""
    dmarc = _get_check(data, "DMARC")
    tb = dmarc.get("tag_breakdown") or {}
    migration = tb.get("migration")
    if not migration:
        return []

    els = [CondPageBreak(4*inch)]
    els.extend(_section_header("6", "Migration Path to DMARCbis Ready", S))

    status = migration.get("status", "")
    if status == "ready":
        els.append(Paragraph(
            "\u2713  Your DMARC record is already DMARCbis Ready. No migration needed.",
            S["body_large"]
        ))
        return els

    steps = migration.get("steps", [])
    if not steps:
        return els

    total_steps = migration.get("total_steps", len(steps))
    els.append(Paragraph(f"{total_steps} steps to reach DMARCbis Ready status:", S["body"]))
    els.append(Spacer(1, 8))

    for step in steps:
        step_num = step.get("step", 0)
        action = step.get("action", "")
        why = step.get("why", "")
        record_after = step.get("record_after", "")
        tags_changed = step.get("tags_changed", [])

        # Step header
        step_content = [
            Paragraph(f'<font color="{NAVY.hexval()}" size="12"><b>Step {step_num}: {_safe(action)}</b></font>', S["body"]),
            Paragraph(_safe(why), S["body_small"]),
        ]

        if tags_changed:
            step_content.append(
                Paragraph(f"Tags affected: <b>{', '.join(_safe(t) for t in tags_changed)}</b>", S["body_tiny"])
            )

        st = Table([[step_content]], colWidths=[6.5*inch])
        st.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), LIGHT_BLUE_BG),
            ("LINEBEFORE", (0,0), (0,-1), 2.5, BLUE_ACCENT),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
            ("RIGHTPADDING", (0,0), (-1,-1), 10),
            ("ROUNDEDCORNERS", [0,4,4,0]),
        ]))
        els.append(st)

        # Record after this step
        if record_after:
            els.append(Paragraph("Record after this step:", S["body_tiny"]))
            els.extend(_record_block(record_after, S, small=True))

        els.append(Spacer(1, 4))

    # Target record
    target = migration.get("target_record", "")
    if target:
        els.append(Spacer(1, 8))
        els.append(Paragraph("Target DMARCbis-Ready Record", S["heading2"]))
        els.extend(_record_block(target, S))

    return els


# ================================================================
# Final page: About This Report
# ================================================================

def _about_page(data, S):
    """Build the About This Report final page."""
    domain = data.get("domain", "unknown")
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")

    els = [PageBreak()]
    els.extend(_section_header("7", "About This Report", S))

    # Branding
    brand_content = [
        Paragraph(
            '<font size="14"><b>Generated by dns-audit.com</b></font>',
            ParagraphStyle("BR", alignment=TA_CENTER, leading=20)
        ),
        Spacer(1, 4),
        Paragraph(
            '<font size="10" color="#2dd4bf">The first DMARCbis-aware DNS security audit tool</font>',
            ParagraphStyle("BR2", alignment=TA_CENTER, leading=14)
        ),
    ]
    bt = Table([[brand_content]], colWidths=[6.5*inch])
    bt.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), NAVY),
        ("TOPPADDING", (0,0), (-1,-1), 16),
        ("BOTTOMPADDING", (0,0), (-1,-1), 16),
        ("ROUNDEDCORNERS", [6,6,6,6]),
    ]))
    els.append(bt)
    els.append(Spacer(1, 16))

    # Report details
    els.append(Paragraph("Report Details", S["subheading"]))
    details = [
        ("Domain audited", domain),
        ("Date and time", now),
        ("Audit type", "Comprehensive DNS Security Audit"),
        ("Protocols checked", "DMARC, SPF, DKIM, MTA-STS, TLS-RPT, DANE, DNSSEC, CAA, MX, BIMI, CT, Nameservers, Blocklist"),
    ]
    for label, value in details:
        els.append(Paragraph(f"<b>{_safe(label)}:</b>  {_safe(value)}", S["body"]))
    els.append(Spacer(1, 14))

    # Methodology
    els.append(Paragraph("Methodology", S["subheading"]))
    els.append(Paragraph(
        "This report was generated using live DNS queries against published DNS records. "
        "All checks use RFC-compliant evaluation logic. DMARC policy discovery implements "
        "the DNS Tree Walk algorithm per DMARCbis (draft-ietf-dmarc-dmarcbis, Section 4.10). "
        "SPF evaluation tracks lookup counts against the RFC 7208 10-lookup limit including "
        "void lookup detection. DANE validation checks TLSA records per RFC 7672 with DNSSEC "
        "dependency verification.", S["body_small"]
    ))
    els.append(Spacer(1, 6))
    els.append(Paragraph(
        "Scores are based on authentication configuration (DMARC 25, SPF 20, DKIM 25), "
        "key security (15), vendor intelligence (10), and best practices (5). "
        "Infrastructure checks (DNSSEC, CAA, DANE, Nameservers) are evaluated but "
        "not scored, as their absence may be intentional.", S["body_small"]
    ))
    els.append(Spacer(1, 14))

    # Disclaimer
    els.append(Paragraph("Disclaimer", S["subheading"]))
    els.append(Paragraph(
        "This report reflects publicly available DNS records at the time of the audit. "
        "DNS records can change at any time. For the most current assessment, re-test at "
        "dns-audit.com. This report is provided for informational purposes only and does "
        "not constitute professional security advice. Organizations should validate "
        "findings with their IT security team before making changes.", S["body_small"]
    ))
    els.append(Spacer(1, 14))

    # Re-test link
    retest = Table([
        [Paragraph(
            f"Re-test this domain at <b>https://dns-audit.com/?d={_safe(domain)}</b>",
            ParagraphStyle("RT", fontSize=11, textColor=NAVY, alignment=TA_CENTER, leading=16)
        )],
    ], colWidths=[6.5*inch])
    retest.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), LIGHT_BLUE_BG),
        ("BOX", (0,0), (-1,-1), 0.5, BLUE_ACCENT),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("ROUNDEDCORNERS", [4,4,4,4]),
    ]))
    els.append(retest)

    return els


# ================================================================
# Main entry point
# ================================================================

def generate_pdf(audit_result: dict) -> bytes:
    """Generate a comprehensive multi-page PDF report.

    Returns PDF bytes suitable for streaming to the client.
    """
    domain = re.sub(r'<[^>]+>', '', audit_result.get("domain", "unknown"))
    sc = audit_result.get("score", {})
    grade = sc.get("grade", "?")
    total = int(sc.get("total", 0))
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")

    buf = io.BytesIO()
    S = _styles()
    tpl = _PageTpl(domain, grade, total, now)

    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        topMargin=0.7*inch,
        bottomMargin=0.6*inch,
        leftMargin=0.75*inch,
        rightMargin=0.75*inch,
        title=f"DNS Security Audit - {_strip_html(domain)}",
        author="dns-audit.com",
        subject=f"Comprehensive security audit report for {_strip_html(domain)}",
    )

    story = []

    # Page 1: Cover page
    story.extend(_cover_page(audit_result, S))

    # Page 2: Executive Summary
    story.extend(_executive_summary_page(audit_result, S))

    # Page 3: Email Security Roadmap
    story.extend(_roadmap_page(audit_result, S))

    # Pages 4-5: DMARC Deep Dive
    story.extend(_dmarc_deep_dive(audit_result, S))

    # Pages 5-6: Attack Surface Analysis
    story.extend(_attack_surface_page(audit_result, S))

    # Pages 6-7: Protocol Details
    story.extend(_protocol_details(audit_result, S))

    # Page 7: Migration Path
    story.extend(_migration_page(audit_result, S))

    # Final page: About This Report
    story.extend(_about_page(audit_result, S))

    doc.build(story, onFirstPage=tpl.on_page, onLaterPages=tpl.on_page)
    return buf.getvalue()


if __name__ == "__main__":
    sample = {
        "domain": "example.com",
        "score": {"grade": "B", "total": 72},
        "executive_summary": {
            "verdict": "Your domain has email authentication but attackers can still exploit subdomain spoofing.",
            "spoofing_protection": {"label": "Partial", "color": "amber", "detail": "2/4 vectors protected"},
            "dmarcbis_readiness": {"label": "In Progress", "color": "amber"},
            "protocol_coverage": {"configured": 5, "total": 9, "color": "amber"},
            "biggest_risk": "Domain is in monitoring mode (p=none). Spoofed email is still delivered to recipients.",
            "has_record_builder": True,
        },
        "security_roadmap": {
            "items": [
                {"priority": "critical", "protocol": "DMARC", "action": "Progress from p=none to enforcement",
                 "impact": "Domain is in monitoring mode. Spoofed mail is still delivered."},
                {"priority": "high", "protocol": "DKIM", "action": "Rotate weak DKIM keys to 2048-bit",
                 "impact": "Weak keys can be factored, allowing forged DKIM signatures."},
                {"priority": "medium", "protocol": "MTA-STS", "action": "Configure MTA-STS for TLS enforcement",
                 "impact": "Without MTA-STS, email encryption can be silently stripped."},
                {"priority": "low", "protocol": "BIMI", "action": "Consider adding BIMI for brand visibility",
                 "impact": "BIMI displays your logo in supported email clients."},
            ],
            "tiers": {"critical": 1, "high": 1, "medium": 1, "low": 1},
            "total": 4,
            "summary": "4 recommendations across 4 priority tiers.",
        },
        "priority_fixes": [
            "Upgrade DMARC policy from p=none to p=reject",
            "Add MTA-STS policy for transport encryption",
        ],
        "checks": [
            {"name": "DMARC", "status": "warn",
             "verdict": "DMARC record found with p=none (monitoring only)",
             "record": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
             "details": [
                 {"type": "good", "text": "DMARC record published"},
                 {"type": "warning", "text": "Policy is p=none: no enforcement"},
                 {"type": "good", "text": "Aggregate reporting configured"},
             ],
             "fix": "Upgrade to p=reject once monitoring confirms all legitimate sources pass.",
             "attack_surface": {
                 "overall": {"level": "high", "label": "High Risk", "color": "red",
                             "summary": "Multiple attack vectors are exposed."},
                 "vectors": [
                     {"name": "Direct Domain Spoofing", "status": "exposed", "color": "red",
                      "summary": "Policy p=none does not block spoofed email.",
                      "detail": "An attacker can send email as @example.com and it will be delivered."},
                     {"name": "Subdomain Spoofing", "status": "exposed", "color": "red",
                      "summary": "No subdomain policy enforcement.",
                      "detail": "Attackers can spoof any subdomain."},
                     {"name": "Non-Existent Subdomain Spoofing", "status": "exposed", "color": "red",
                      "summary": "np= tag is absent.",
                      "detail": "Non-existent subdomains fall back to root policy (p=none)."},
                     {"name": "Reporting Intelligence", "status": "protected", "color": "green",
                      "summary": "Aggregate reports configured.",
                      "detail": "Reports will be sent to dmarc@example.com."},
                 ],
                 "attacker_path": "An attacker would directly spoof @example.com since p=none means no mail is rejected.",
             },
             "tag_breakdown": {
                 "health": {
                     "status": "monitoring",
                     "label": "Monitoring Only",
                     "color": "amber",
                     "summary": "Record is functional but not enforcing any policy.",
                     "reasons": ["p=none does not reject or quarantine spoofed mail",
                                 "np= tag is missing (non-existent subdomain gap)"],
                 },
                 "tags": [
                     {"tag": "v", "value": "DMARC1", "is_default": False, "is_absent": False,
                      "label": "Version", "explanation": "DMARC version identifier",
                      "dmarcbis": "current", "warnings": []},
                     {"tag": "p", "value": "none", "is_default": False, "is_absent": False,
                      "label": "Policy", "explanation": "Policy for the organizational domain",
                      "dmarcbis": "current",
                      "warnings": [{"level": "warning", "text": "p=none is monitoring only"}]},
                     {"tag": "np", "value": None, "is_default": True, "is_absent": True,
                      "label": "Non-existent subdomain policy", "explanation": "Policy for non-existent subdomains",
                      "dmarcbis": "new", "dmarcbis_note": "New in DMARCbis",
                      "warnings": [{"level": "warning", "text": "Missing np= tag"}]},
                     {"tag": "rua", "value": "mailto:dmarc@example.com", "is_default": False,
                      "is_absent": False, "label": "Aggregate report URI",
                      "explanation": "Where aggregate reports are sent",
                      "dmarcbis": "current", "warnings": []},
                 ],
                 "config_warnings": [
                     {"level": "advisory", "title": "No enforcement",
                      "text": "p=none does not protect against spoofing. Consider upgrading to p=quarantine or p=reject.",
                      "tags": ["p"]},
                 ],
                 "migration": {
                     "status": "migration",
                     "steps": [
                         {"step": 1, "action": "Review aggregate reports for 2-4 weeks",
                          "why": "Identify all legitimate senders and fix their SPF/DKIM alignment before enforcing.",
                          "tags_changed": []},
                         {"step": 2, "action": "Test quarantine with t=y",
                          "why": "t=y drops the effective policy one level, so p=quarantine with t=y acts like p=none.",
                          "record_after": "v=DMARC1; p=quarantine; t=y; rua=mailto:dmarc@example.com",
                          "tags_changed": ["p", "t"]},
                         {"step": 3, "action": "Enforce reject by removing t=y",
                          "why": "Full protection. Mail failing authentication is blocked.",
                          "record_after": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
                          "tags_changed": ["t"]},
                         {"step": 4, "action": "Add DMARCbis tags: np=reject, sp=reject, psd=n",
                          "why": "These tags close gaps in the old standard and prepare for DMARCbis.",
                          "tags_changed": ["np", "sp", "psd"]},
                     ],
                     "total_steps": 4,
                     "target_record": "v=DMARC1; p=reject; sp=reject; np=reject; psd=n; fo=1; rua=mailto:dmarc@example.com",
                 },
                 "record_builder": {
                     "mode": "fix",
                     "current_record": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                     "recommended_record": "v=DMARC1; p=reject; sp=reject; np=reject; fo=1; psd=n; rua=mailto:dmarc@example.com",
                     "changes": [
                         {"tag": "p", "action": "changed", "old": "none", "value": "reject",
                          "reason": "Enforce reject to block spoofed mail."},
                         {"tag": "sp", "action": "added", "value": "reject",
                          "reason": "Closes subdomain policy gap."},
                         {"tag": "np", "action": "added", "value": "reject",
                          "reason": "Protects non-existent subdomains from spoofing (new in DMARCbis)."},
                     ],
                 },
                 "comparison_intelligence": {
                     "position_statement": "Your domain is behind 68% of the top 1,000 domains in DMARC adoption.",
                     "position_pct": 32,
                     "position_label": "Bottom third",
                     "adoption_stats": [
                         {"label": "p=reject adoption", "adoption_pct": 52},
                         {"label": "np= tag adoption", "adoption_pct": 8},
                     ],
                     "adoption_tagline": "The top 1,000 are moving toward DMARCbis. Your domain should too.",
                 },
             },
             "strict_validation": {
                 "categories": [
                     {"key": "record_structure", "label": "Record Structure",
                      "checks": [
                          {"category": "record_structure", "name": "v= tag", "status": "pass",
                           "message": "v=DMARC1 is correctly placed as the first tag"},
                          {"category": "record_structure", "name": "Record syntax", "status": "pass",
                           "message": "Record syntax is valid"},
                      ]},
                     {"key": "tag_values", "label": "Tag Values",
                      "checks": [
                          {"category": "tag_values", "name": "p= value", "status": "warn",
                           "message": "p=none provides monitoring only, no enforcement"},
                          {"category": "tag_values", "name": "np= tag", "status": "fail",
                           "message": "np= tag is missing (required by DMARCbis)"},
                      ]},
                 ],
                 "pass_count": 2, "fail_count": 1, "warn_count": 1, "total_count": 4,
                 "summary": "2 pass, 1 warning, 1 failure", "has_structural_errors": False,
             },
            },
            {"name": "SPF", "status": "pass",
             "verdict": "Valid SPF record with hardfail (-all)",
             "record": "v=spf1 include:_spf.google.com -all",
             "details": [
                 {"type": "good", "text": "SPF record is valid"},
                 {"type": "good", "text": "Uses -all (hardfail)"},
                 {"type": "info", "text": "3 of 10 DNS lookups used"},
             ],
             "fix": None,
             "spf_deep": {
                 "mechanisms": [
                     {"raw": "include:_spf.google.com", "type": "include", "value": "_spf.google.com",
                      "cost": 1, "provider": "Google Workspace"},
                 ],
                 "all_mechanism": "-all",
                 "all_explanation": "Hardfail: unauthorized servers are rejected",
                 "all_severity": "info",
                 "lookup_count": 3,
                 "misconfigs": [],
                 "optimizations": [],
             },
            },
            {"name": "DKIM", "status": "pass",
             "verdict": "Valid 2048-bit key found (selector: google)",
             "record": "v=DKIM1; k=rsa; p=MIIBIjANBgkqhki...",
             "details": [
                 {"type": "good", "text": "2048-bit RSA key"},
                 {"type": "good", "text": "Selector: google"},
             ],
             "fix": None,
             "dkim_deep": {
                 "keys": [
                     {"selector": "google", "vendor": "Google Workspace", "key_type": "RSA",
                      "key_bits": 2048, "rating": "green", "rating_label": "Strong",
                      "rotation_status": "CURRENT", "rotation_guidance": "Key is current, no rotation needed."},
                 ],
                 "has_weak": False, "has_revoked": False, "all_strong": True,
                 "summary": "All DKIM keys meet current strength requirements.",
                 "recommendations": [],
             },
            },
            {"name": "MTA-STS", "status": "fail", "pill_label": "Not configured",
             "verdict": "No MTA-STS policy found",
             "record": None,
             "details": [
                 {"type": "error", "text": "No _mta-sts TXT record found"},
                 {"type": "error", "text": "No policy file at /.well-known/mta-sts.txt"},
             ],
             "fix": "Add MTA-STS to enforce TLS. Create _mta-sts.example.com TXT record."},
            {"name": "DNSSEC", "status": "warn",
             "verdict": "DNSSEC not enabled",
             "record": None,
             "details": [
                 {"type": "warning", "text": "No DNSKEY records found"},
                 {"type": "info", "text": "DNSSEC prevents DNS spoofing and cache poisoning"},
             ],
             "fix": "Enable DNSSEC through your domain registrar or DNS hosting provider."},
        ],
        "vendors": [
            {"name": "Google Workspace", "confidence": 95},
            {"name": "SendGrid", "confidence": 60},
        ],
    }
    pdf = generate_pdf(sample)
    with open("/tmp/dns-audit-sample.pdf", "wb") as f:
        f.write(pdf)
    print(f"Written /tmp/dns-audit-sample.pdf ({len(pdf):,} bytes)")
