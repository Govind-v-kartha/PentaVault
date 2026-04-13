"""PentaVault - Professional PDF & DOCX report generator.

PDF:  Generated with fpdf2 (professional white-theme, proper alignment).
DOCX: Generated via Node.js 'docx' package for pixel-perfect formatting.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from fpdf import FPDF
    _FPDF_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - environment dependent
    FPDF = object  # type: ignore[assignment,misc]
    _FPDF_IMPORT_ERROR = exc

# ── latin-1 safety ──────────────────────────────────────────────
def _latin1_safe(text: str) -> str:
    _MAP = {
        "\u2014": "--", "\u2013": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"', "\u2022": "-", "\u2026": "...",
        "\u00a9": "(c)", "\u00ae": "(R)", "\u2122": "(TM)", "\u00b7": "-",
        "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u200b": "", "\u00a0": " ",
    }
    for old, new in _MAP.items():
        text = text.replace(old, new)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _strip_html(html: str) -> str:
    text = re.sub(r"<[^>]+>", "", html or "")
    for ent, ch in [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                    ("&quot;", '"'), ("&#39;", "'")]:
        text = text.replace(ent, ch)
    return text.strip()


# ── Colours ─────────────────────────────────────────────────────
CLR_NAVY  = (31, 56, 100)
CLR_BLUE  = (46, 117, 182)
CLR_BODY  = (64, 64, 64)
CLR_GRAY  = (128, 128, 128)
CLR_LGRAY = (204, 204, 204)
CLR_WHITE = (255, 255, 255)
CLR_FIELD = (242, 242, 242)

SEV_CLR = {
    "Critical":      ((192, 0, 0),   (255, 224, 224)),
    "High":          ((255, 0, 0),   (255, 224, 224)),
    "Medium":        ((255, 140, 0), (255, 242, 204)),
    "Low":           ((0, 176, 80),  (226, 239, 218)),
    "Info":          ((68, 114, 196),(222, 234, 241)),
    "Informational": ((68, 114, 196),(222, 234, 241)),
    "None":          ((68, 114, 196),(222, 234, 241)),
}

SEV_PRIORITY = {
    "Critical": "Immediate (0-7 days)",
    "High":     "Immediate (0-7 days)",
    "Medium":   "Short-term (7-30 days)",
    "Low":      "Standard (30-90 days)",
    "Info":     "Observation",
}

SEV_DESCS = {
    "Critical": "Immediate exploitation risk; may lead to full compromise",
    "High":     "Significant risk to data confidentiality and integrity",
    "Medium":   "Moderate risk; exploitable under certain conditions",
    "Low":      "Low impact; informational or defense-in-depth value",
    "Info":     "Observation or best-practice improvement",
}


def _stc(s): return SEV_CLR.get(s, SEV_CLR["Info"])[0]
def _sbg(s): return SEV_CLR.get(s, SEV_CLR["Info"])[1]


def _sev_counts(findings):
    sc = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        s = f.get("severity", "Info")
        if s in ("None", "Informational"):
            s = "Info"
        sc[s] = sc.get(s, 0) + 1
    return sc


# ── Description / Impact / Steps builders ───────────────────────
def _build_description(f):
    title = (f.get("title") or "").lower()
    url = f.get("affected_url") or f.get("url") or "the target"
    param = f.get("parameter") or "the parameter"
    evidence = f.get("evidence") or ""

    if "sql injection" in title and "error" in title:
        return f"The endpoint at {url} fails to sanitize input in '{param}' before SQL queries. Database error messages reveal internal schema. Evidence: {evidence[:120]}"
    if "sql injection" in title and "time" in title:
        return f"The endpoint at {url} is vulnerable to time-based blind SQL injection via '{param}'. Time-delay payloads confirm injectable parameter. Evidence: {evidence[:120]}"
    if "sql injection" in title and "boolean" in title:
        return f"The endpoint at {url} is vulnerable to boolean-based blind SQL injection via '{param}'. Response variations confirm data extraction capability. Evidence: {evidence[:120]}"
    if "sql injection" in title:
        return f"The endpoint at {url} is vulnerable to SQL injection via '{param}'. An attacker can manipulate SQL logic to extract or modify database records. Evidence: {evidence[:120]}"
    if "stored" in title and "xss" in title:
        return f"The application stores and renders user-supplied content at {url} without encoding. Persistent scripts execute for all viewers."
    if "dom" in title and "xss" in title:
        return f"The page at {url} passes user-controllable DOM sources into dangerous execution sinks without sanitization. Evidence: {evidence[:120]}"
    if "xss" in title or "cross-site" in title:
        return f"The endpoint at {url} reflects input from '{param}' without encoding. An attacker can execute JavaScript in victim browsers. Evidence: {evidence[:120]}"
    if "idor" in title or "object" in title:
        return f"The endpoint at {url} does not verify resource ownership. Users can access other users' data by enumerating IDs. Evidence: {evidence[:120]}"
    if "ssrf" in title:
        return f"The parameter '{param}' at {url} accepts URLs the server fetches without validation, enabling access to internal services. Evidence: {evidence[:120]}"
    if "redirect" in title:
        return f"The endpoint at {url} accepts unvalidated redirect destinations via '{param}', enabling phishing. Evidence: {evidence[:120]}"
    if "content-security-policy" in title or "csp" in title:
        return f"The application at {url} lacks a Content-Security-Policy header, leaving no restrictions on script sources."
    if "strict-transport" in title or "hsts" in title:
        return f"The application at {url} lacks HSTS, making users vulnerable to SSL stripping attacks."
    if "x-frame" in title:
        return f"The application at {url} lacks X-Frame-Options, enabling clickjacking attacks."
    if "x-content-type" in title:
        return f"The application at {url} lacks X-Content-Type-Options, allowing MIME-sniffing."
    if "x-xss" in title:
        return f"The application at {url} lacks X-XSS-Protection header for legacy browser defense."
    if "referrer" in title:
        return f"The application at {url} lacks Referrer-Policy, potentially leaking sensitive URL information."
    if "permissions" in title:
        return f"The application at {url} lacks Permissions-Policy, not restricting browser feature access."
    if "server version" in title:
        return f"The application at {url} discloses server software version in headers. Evidence: {evidence[:120]}"
    return f"{f.get('title', 'Vulnerability detected')} at {url}. {evidence[:150] if evidence else ''}"


def _build_impact(severity, title):
    t = title.lower()
    if "sql injection" in t:
        return "Full authentication bypass; unauthorized database access; extraction of credentials and PII."
    if "stored" in t and "xss" in t:
        return "Session hijacking, credential theft, account takeover for all viewers of affected content."
    if "xss" in t or "cross-site" in t:
        return "Session hijacking, credential theft, phishing through the trusted domain."
    if "idor" in t or "object" in t:
        return "Unauthorized access to confidential data belonging to other users."
    if "ssrf" in t:
        return "Access to internal services and cloud metadata; potential credential theft."
    if "redirect" in t:
        return "User redirection to attacker-controlled phishing pages."
    if any(x in t for x in ("header", "csp", "hsts", "x-frame", "server version",
                            "referrer", "permissions", "x-content", "x-xss")):
        return "Increased attack surface; may facilitate exploitation of other vulnerabilities."
    if severity == "Critical":
        return "Immediate exploitation risk with potential for full system compromise."
    if severity == "High":
        return "Significant risk to data confidentiality and integrity."
    if severity == "Medium":
        return "Moderate risk; exploitable under certain conditions."
    return "Low direct impact; defense-in-depth improvement opportunity."


def _build_steps(f):
    url = f.get("affected_url") or f.get("url") or "the target URL"
    param = f.get("parameter") or "the parameter"
    payload = f.get("payload") or "the test payload"
    evidence = f.get("evidence") or ""
    t = (f.get("title") or "").lower()

    if "sql injection" in t:
        return [f"Navigate to {url}", f"Inject payload in '{param}': {payload}",
                f"Observe: {evidence[:100]}" if evidence else "Confirm SQL logic modified"]
    if "xss" in t or "cross-site" in t:
        return [f"Navigate to {url}", f"Insert payload in '{param}': {payload}",
                f"Observe unescaped reflection: {evidence[:100]}" if evidence else "Confirm payload rendered"]
    if "idor" in t or "object" in t:
        return [f"Access resource at {url}", "Modify the ID to access another user's resource",
                f"Observe: {evidence[:100]}" if evidence else "Confirm unauthorized data access"]
    if "ssrf" in t:
        return [f"Navigate to {url}", f"Set '{param}' to internal URL: {payload}",
                f"Observe internal data: {evidence[:100]}" if evidence else "Confirm server-side request"]
    if "redirect" in t:
        return [f"Navigate to {url}", f"Set '{param}' to external URL: {payload}",
                f"Observe redirect: {evidence[:100]}" if evidence else "Confirm 3xx redirect"]
    if any(x in t for x in ("header", "csp", "hsts", "x-frame", "server version",
                            "referrer", "permissions", "x-content", "x-xss")):
        return [f"Send HTTP request to {url}", "Inspect response headers",
                f"Confirm: {evidence[:120]}" if evidence else "Verify missing header"]
    return [f"Navigate to {url}", f"Test '{param}': {payload}",
            f"Observe: {evidence[:100]}" if evidence else "Analyse response"]


# ── Charts ──────────────────────────────────────────────────────
def _generate_charts(findings):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None, None

    sc = _sev_counts(findings)
    labels = [k for k, v in sc.items() if v > 0]
    sizes = [sc[k] for k in labels]
    cm = {"Critical": "#C00000", "High": "#FF0000", "Medium": "#FF8C00",
          "Low": "#00B050", "Info": "#4472C4"}

    pie_bytes = None
    if sizes:
        fig, ax = plt.subplots(figsize=(4.5, 4.5))
        fig.patch.set_facecolor("white")
        _, texts, autotexts = ax.pie(
            sizes, labels=labels,
            colors=[cm.get(l, "#888") for l in labels],
            autopct="%1.0f%%", startangle=90,
            textprops={"fontsize": 10, "color": "#404040"})
        for a in autotexts:
            a.set_color("white"); a.set_fontweight("bold")
        ax.set_title("Severity Distribution", fontsize=14,
                     fontweight="bold", color="#1F3864", pad=16)
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                    facecolor="white")
        plt.close(fig)
        pie_bytes = buf.getvalue()

    owasp = {}
    for f in findings:
        c = f.get("owasp_category", "Unknown")
        owasp[c] = owasp.get(c, 0) + 1
    so = sorted(owasp.items(), key=lambda x: x[1], reverse=True)[:10]

    bar_bytes = None
    if so:
        cats = [x[0][:35] for x in so]
        vals = [x[1] for x in so]
        fig, ax = plt.subplots(figsize=(7, max(3, len(cats)*0.5+1)))
        fig.patch.set_facecolor("white")
        ax.set_facecolor("white")
        bars = ax.barh(cats[::-1], vals[::-1], color="#1F3864",
                       edgecolor="#2E75B6", height=0.6)
        ax.set_xlabel("Findings", fontsize=10, color="#404040")
        ax.set_title("OWASP 2025 Category Breakdown", fontsize=14,
                     fontweight="bold", color="#1F3864")
        ax.tick_params(colors="#404040", labelsize=8)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for s in ("bottom", "left"):
            ax.spines[s].set_color("#CCCCCC")
        for b, v in zip(bars, vals[::-1]):
            ax.text(b.get_width() + 0.2, b.get_y() + b.get_height()/2,
                    str(v), va="center", color="#1F3864", fontsize=9,
                    fontweight="bold")
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                    facecolor="white")
        plt.close(fig)
        bar_bytes = buf.getvalue()

    return pie_bytes, bar_bytes


# ═════════════════════════════════════════════════════════════════
#  PDF CLASS
# ═════════════════════════════════════════════════════════════════
_W = 180  # usable width mm (A4 210 - 15 - 15)
_RH = 7   # standard row height
_HH = 8   # header row height


class PentaVaultPDF(FPDF):

    def __init__(self, target, **kw):
        super().__init__(**kw)
        self._target = target
        self._date = datetime.now().strftime("%B %d, %Y")
        self.set_auto_page_break(auto=True, margin=28)

    def cell(self, *a, **kw):
        if len(a) > 2 and isinstance(a[2], str):
            a = list(a); a[2] = _latin1_safe(a[2])
        for k in ("text", "txt"):
            if k in kw and isinstance(kw[k], str):
                kw[k] = _latin1_safe(kw[k])
        return super().cell(*a, **kw)

    def multi_cell(self, *a, **kw):
        if len(a) > 2 and isinstance(a[2], str):
            a = list(a); a[2] = _latin1_safe(a[2])
        for k in ("text", "txt"):
            if k in kw and isinstance(kw[k], str):
                kw[k] = _latin1_safe(kw[k])
        return super().multi_cell(*a, **kw)

    def header(self):
        if self.page_no() <= 1:
            return
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*CLR_GRAY)
        t = self._target[:40] + "..." if len(self._target) > 40 else self._target
        self.cell(0, 6,
                  f"Vulnerability Assessment Report  |  {t}  |  CONFIDENTIAL",
                  align="R")
        self.set_draw_color(*CLR_BLUE)
        self.line(15, 14, self.w - 15, 14)
        self.ln(8)

    def footer(self):
        if self.page_no() <= 1:
            return
        self.set_y(-20)
        self.set_draw_color(*CLR_LGRAY)
        self.line(15, self.get_y(), self.w - 15, self.get_y())
        self.ln(3)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*CLR_GRAY)
        self.cell(0, 6,
                  f"(c) 2026 Govind V Kartha -- PentaVault  |  Page {self.page_no()}  |  {self._date}",
                  align="C")

    def _draw_shield(self, cx, cy, size=28, alpha=0.08):
        """Draw a shield icon centred at (cx, cy) with given size."""
        c = int(230 + (255 - 230) * (1 - alpha))  # very faint
        self.set_fill_color(c, c, c)
        self.set_draw_color(c, c, c)
        # Shield body (rounded rect approximation)
        w, h = size * 0.8, size
        x0, y0 = cx - w / 2, cy - h * 0.45
        self.rect(x0, y0, w, h * 0.6, "F")
        # Shield bottom triangle
        x1, y1_ = x0, y0 + h * 0.6
        x2, y2 = x0 + w, y0 + h * 0.6
        x3, y3 = cx, cy + h * 0.55
        # Use a series of thin rects to approximate the triangle
        steps = 20
        for i in range(steps):
            frac = i / steps
            lx = x1 + (x3 - x1) * frac
            rx = x2 + (x3 - x2) * frac
            ry = y1_ + (y3 - y1_) * frac
            if rx > lx:
                self.rect(lx, ry, rx - lx, (y3 - y1_) / steps, "F")
        # Checkmark inside shield
        self.set_draw_color(c - 10, c - 10, c - 10)
        self.set_line_width(size * 0.04)
        mx, my = cx - size * 0.1, cy + size * 0.05
        self.line(mx - size * 0.12, my - size * 0.05, mx, my + size * 0.08)
        self.line(mx, my + size * 0.08, mx + size * 0.18, my - size * 0.15)
        self.set_line_width(0.2)

    def wm(self):
        """Draw PentaVault watermark with shield logo and text."""
        cx, cy = self.w / 2, self.h / 2
        # Shield logo
        self._draw_shield(cx, cy - 12, size=32, alpha=0.08)
        # Text
        self.set_font("Helvetica", "B", 52)
        self.set_text_color(235, 235, 235)
        with self.rotation(35, cx, cy):
            self.set_xy(cx - 65, cy)
            self.cell(0, 0, "PENTAVAULT")
        self.set_text_color(*CLR_BODY)

    def new_page(self):
        self.add_page()
        self.wm()

    def need(self, mm=40):
        if self.get_y() > self.h - mm:
            self.new_page()

    # ── Section headings ──
    def h1(self, text):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*CLR_NAVY)
        self.cell(0, 12, text, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*CLR_NAVY)
        self.line(15, self.get_y(), self.w - 15, self.get_y())
        self.ln(6)

    def h2(self, text):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*CLR_BLUE)
        self.cell(0, 10, text, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def h3(self, text):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*CLR_BODY)
        self.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body(self, text, sz=10):
        self.set_font("Helvetica", "", sz)
        self.set_text_color(*CLR_BODY)
        self.multi_cell(0, 5, text)
        self.ln(2)

    def bul(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*CLR_BODY)
        self.cell(8, 5, chr(0x2D), new_x="RIGHT")
        self.multi_cell(_W - 8, 5, text)
        self.ln(1)

    def numbered(self, num, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*CLR_BODY)
        self.cell(8, 5, f"{num}.", new_x="RIGHT")
        self.multi_cell(_W - 8, 5, text)
        self.ln(1)

    # ── Table helpers ──
    def tbl_hdr(self, cols):
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(*CLR_NAVY)
        self.set_text_color(*CLR_WHITE)
        self.set_draw_color(*CLR_LGRAY)
        for txt, w in cols:
            self.cell(w, _HH, txt, border=1, fill=True, align="C")
        self.ln()

    def tbl_cell(self, text, w, h=_RH, bold=False, align="L",
                 fg=CLR_BODY, bg=None):
        self.set_font("Helvetica", "B" if bold else "", 9)
        self.set_text_color(*fg)
        if bg:
            self.set_fill_color(*bg)
            self.cell(w, h, text, border=1, fill=True, align=align)
        else:
            self.cell(w, h, text, border=1, align=align)

    def tbl_sev(self, sev, w, h=_RH):
        self.tbl_cell(sev, w, h, bold=True, align="C",
                      fg=_stc(sev), bg=_sbg(sev))

    def sep(self):
        self.set_draw_color(*CLR_LGRAY)
        self.line(15, self.get_y(), self.w - 15, self.get_y())
        self.ln(4)


# ═════════════════════════════════════════════════════════════════
#  generate_pdf
# ═════════════════════════════════════════════════════════════════
def generate_pdf(
    target: str,
    findings: list[dict[str, Any]],
    scan_data: dict[str, Any],
    mitre_data: dict[str, Any] | None = None,
    ai_summary: str | None = None,
) -> bytes:

    if _FPDF_IMPORT_ERROR is not None:
        raise RuntimeError(
            "PDF export dependency missing: install fpdf2 (pip install fpdf2)."
        ) from _FPDF_IMPORT_ERROR

    pdf = PentaVaultPDF(target, orientation="P", unit="mm", format="A4")
    pdf.set_margins(15, 15, 15)
    now = datetime.now()
    sc = _sev_counts(findings)
    total = len(findings)
    crit_high = sc["Critical"] + sc["High"]
    mode = scan_data.get("mode", "full").title()

    # ── Column width sets (must sum to _W=180) ──
    # Exec summary severity table:  63 + 27 + 90 = 180
    C_SEV = (63, 27, 90)
    # Summary table:  14 + 68 + 14 + 56 + 28 = 180
    C_SUM = (14, 68, 14, 56, 28)
    # Detail meta:  45 + 135 = 180
    C_DET = (45, 135)
    # Roadmap:  14 + 64 + 62 + 40 = 180
    C_REM = (14, 64, 62, 40)
    # Appendix:  40 + 40 + 100 = 180
    C_APP = (40, 40, 100)
    # MITRE breakdown:  22 + 60 + 30 + 22 + 22 = 156  (will use variable)

    # ══════════════  COVER PAGE  ══════════════
    pdf.add_page()
    pdf.ln(22)

    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*CLR_BLUE)
    pdf.cell(0, 12, "PentaVault", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*CLR_GRAY)
    pdf.cell(0, 6, "Automated VAPT Security Suite", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(16)

    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*CLR_NAVY)
    pdf.cell(0, 14, "VULNERABILITY ASSESSMENT", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 14, "REPORT", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_draw_color(*CLR_BLUE)
    pdf.set_line_width(0.5)
    pdf.line(50, pdf.get_y() + 2, 160, pdf.get_y() + 2)
    pdf.ln(8)

    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(*CLR_BLUE)
    pdf.cell(0, 10, "Web Application Security Assessment", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(18)

    # Cover metadata
    lw, vw = 55, 125
    meta = [
        ("Target:", target),
        ("Scan Mode:", mode),
        ("Assessment Date:", now.strftime("%B %d, %Y")),
        ("Report Date:", now.strftime("%B %d, %Y")),
        ("Classification:", "CONFIDENTIAL"),
        ("Prepared By:", "PentaVault -- Automated VAPT Security Suite"),
        ("Version:", "1.0 -- Automated"),
    ]
    for label, val in meta:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*CLR_NAVY)
        pdf.cell(lw, 8, label, align="R")
        is_conf = label == "Classification:"
        pdf.set_font("Helvetica", "B" if is_conf else "", 11)
        pdf.set_text_color(*((192, 0, 0) if is_conf else CLR_BODY))
        v = val if len(val) <= 55 else val[:52] + "..."
        pdf.cell(vw, 8, f"  {v}", new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(-42)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*CLR_GRAY)
    pdf.cell(0, 6, "(c) 2026 Govind V Kartha -- PentaVault", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5,
             "This document contains confidential and proprietary information.",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5,
             "Distribution is restricted to authorized personnel only.",
             align="C")

    # ══════════════  1. EXECUTIVE SUMMARY  ══════════════
    pdf.new_page()
    pdf.h1("1. Executive Summary")

    pdf.body(
        f"PentaVault was engaged to conduct an automated vulnerability "
        f"assessment of {target}. The assessment was performed in '{mode}' "
        f"mode, simulating the perspective of an external threat actor."
    )
    if crit_high > 0:
        pdf.body(
            f"The assessment identified {total} vulnerabilities. "
            f"{crit_high} critical or high-severity vulnerabilities were "
            f"identified that could result in full compromise of the "
            f"application and unauthorized access to data. Immediate "
            f"remediation is strongly recommended."
        )
    else:
        pdf.body(
            f"The assessment identified {total} vulnerabilities. No critical "
            f"or high-severity vulnerabilities were found."
        )

    pdf.ln(2)

    # Severity table
    pdf.tbl_hdr([("Severity", C_SEV[0]), ("Count", C_SEV[1]),
                 ("Risk Description", C_SEV[2])])
    pdf.set_draw_color(*CLR_LGRAY)
    for sev_name in ("Critical", "High", "Medium", "Low", "Info"):
        pdf.tbl_cell(sev_name, C_SEV[0], bold=True,
                     fg=_stc(sev_name), bg=_sbg(sev_name))
        pdf.tbl_cell(str(sc[sev_name]), C_SEV[1], bold=True, align="C",
                     fg=_stc(sev_name), bg=_sbg(sev_name))
        pdf.tbl_cell(SEV_DESCS[sev_name], C_SEV[2])
        pdf.ln()
    # Total
    tot = (213, 232, 240)
    pdf.tbl_cell("Total", C_SEV[0], bold=True, fg=CLR_NAVY, bg=tot)
    pdf.tbl_cell(str(total), C_SEV[1], bold=True, align="C",
                 fg=CLR_NAVY, bg=tot)
    pdf.tbl_cell("", C_SEV[2], bg=tot)
    pdf.ln()

    # AI
    if ai_summary:
        pdf.ln(6)
        pdf.h2("AI-Powered Threat Analysis")
        pdf.body(_strip_html(ai_summary))

    # Charts
    pie_b, bar_b = _generate_charts(findings)
    if pie_b or bar_b:
        pdf.new_page()
        pdf.h2("1.1 Visual Analytics")
        tmp = tempfile.mkdtemp()
        try:
            if pie_b:
                p = os.path.join(tmp, "pie.png")
                with open(p, "wb") as fp:
                    fp.write(pie_b)
                pdf.image(p, x=55, w=100)
                pdf.ln(6)
            if bar_b:
                pdf.need(80)
                p = os.path.join(tmp, "bar.png")
                with open(p, "wb") as fp:
                    fp.write(bar_b)
                pdf.image(p, x=20, w=170)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ══════════════  2. SCOPE AND METHODOLOGY  ══════════════
    pdf.new_page()
    pdf.h1("2. Scope and Methodology")

    pdf.h2("2.1 Scope")
    pdf.body("The following targets were included in the assessment:")
    pdf.bul(f"Web Application: {target}")
    pdf.bul(f"Scan Mode: {mode} (Concurrent threads: {scan_data.get('threads', 5)})")
    cookie = scan_data.get("cookie")
    pdf.bul(f"Authentication: {'Authenticated scan with session cookie' if cookie else 'Unauthenticated scan'}")
    pdf.bul("Out of scope: Physical infrastructure, social engineering, third-party integrations")
    pdf.ln(2)

    pdf.h2("2.2 Methodology")
    pdf.body(
        "The assessment followed automated vulnerability testing methodology "
        "aligned with the OWASP Testing Guide v4.2 and the PTES (Penetration "
        "Testing Execution Standard). Testing phases included:"
    )
    pdf.bul("Reconnaissance and information gathering (DNS, WHOIS, port scanning)")
    pdf.bul("Technology fingerprinting (server, framework, WAF detection, SSL/TLS)")
    pdf.bul("Automated web crawling and endpoint discovery")
    pdf.bul("Vulnerability testing: SQL Injection, XSS, SSRF, IDOR, Open Redirect, Security Headers")
    pdf.bul("CVSS v3.1 severity scoring and risk classification")
    pdf.bul("OWASP 2025 Top 10 and MITRE ATT&CK Enterprise v16.1 mapping")
    pdf.bul("Exploitation proof and evidence collection for confirmed findings")

    # ══════════════  3. FINDINGS SUMMARY  ══════════════
    pdf.new_page()
    pdf.h1("3. Findings Summary")

    if not findings:
        pdf.body("No vulnerabilities were identified during this assessment.")
    else:
        pdf.tbl_hdr([("ID", C_SUM[0]), ("Title", C_SUM[1]),
                     ("CVSS", C_SUM[2]), ("OWASP Category", C_SUM[3]),
                     ("Severity", C_SUM[4])])
        for i, f in enumerate(findings):
            pdf.need(12)
            pdf.set_draw_color(*CLR_LGRAY)
            fid = f.get("id") or f"VULN-{i+1:03d}"
            title = (f.get("title") or "N/A")[:40]
            cvss = f.get("cvss_score")
            cvss_s = f"{cvss:.1f}" if cvss is not None else "-"
            owasp = (f.get("owasp_category") or "N/A")[:32]
            sev = f.get("severity", "Info")

            pdf.tbl_cell(fid, C_SUM[0], align="C")
            pdf.tbl_cell(title, C_SUM[1])
            pdf.tbl_cell(cvss_s, C_SUM[2], align="C")
            pdf.tbl_cell(owasp, C_SUM[3])
            pdf.tbl_sev(sev, C_SUM[4])
            pdf.ln()

    # ══════════════  4. DETAILED FINDINGS  ══════════════
    pdf.new_page()
    pdf.h1("4. Detailed Findings")

    if not findings:
        pdf.body("No vulnerabilities were identified during this assessment.")

    for i, f in enumerate(findings):
        if i > 0:
            pdf.need(70)

        fid = f.get("id") or f"VULN-{i+1:03d}"
        title = f.get("title", "Unknown Vulnerability")
        sev = f.get("severity", "Info")
        cvss = f.get("cvss_score")
        cvss_s = f"{cvss:.1f}" if cvss is not None else "N/A"
        cvss_vec = f.get("cvss_vector", "N/A")
        owasp = f.get("owasp_category", "N/A")
        url = f.get("affected_url") or f.get("url") or "N/A"
        param = f.get("parameter", "N/A")
        remediation = f.get("remediation",
                            "Review and apply security best practices.")

        pdf.h2(f"4.{i+1} {fid} - {title}")

        # Meta table
        pdf.set_draw_color(*CLR_LGRAY)
        pdf.tbl_hdr([("Field", C_DET[0]), ("Details", C_DET[1])])

        # Severity (coloured)
        pdf.tbl_cell("Severity", C_DET[0], bold=True, bg=CLR_FIELD)
        pdf.tbl_sev(sev, C_DET[1])
        pdf.ln()

        rows = [
            ("CVSS Score", cvss_s),
            ("CVSS Vector", cvss_vec),
            ("OWASP Category", owasp),
            ("Affected URL", url[:75] if len(url) > 75 else url),
            ("Parameter", param),
        ]
        for label, val in rows:
            pdf.need(12)
            pdf.set_draw_color(*CLR_LGRAY)
            pdf.tbl_cell(label, C_DET[0], bold=True, bg=CLR_FIELD)
            pdf.tbl_cell(val, C_DET[1])
            pdf.ln()

        pdf.ln(4)

        # Description
        pdf.need(25)
        pdf.h3("Description")
        pdf.body(_build_description(f))

        # Business Impact
        pdf.need(20)
        pdf.h3("Business Impact")
        pdf.body(_build_impact(sev, title))

        # Steps to Reproduce
        pdf.need(25)
        pdf.h3("Steps to Reproduce")
        steps = _build_steps(f)
        for si, step in enumerate(steps, 1):
            pdf.numbered(si, step)

        pdf.ln(2)

        # Recommendation
        pdf.need(20)
        pdf.h3("Recommendation")
        pdf.body(remediation)

        # References
        mitre_techs = f.get("mitre_attack", [])
        refs = []
        if owasp and owasp != "N/A":
            refs.append(owasp)
        if cvss_vec and cvss_vec != "N/A":
            refs.append(f"CVSS v3.1: {cvss_vec}")
        for mt in mitre_techs[:3]:
            refs.append(
                f"MITRE ATT&CK: {mt['technique']} - {mt['name']} ({mt.get('tactic','')})"
            )
        if refs:
            pdf.need(15)
            pdf.h3("References")
            for r in refs:
                pdf.bul(r)

        pdf.ln(2)
        pdf.sep()

    # ══════════════  5. MITRE ATT&CK  ══════════════
    next_sec = 5
    if mitre_data:
        pdf.new_page()
        pdf.h1(f"{next_sec}. MITRE ATT&CK Analysis")

        cov = mitre_data.get("matrix_coverage", {})
        if cov:
            pdf.body(
                f"The scan mapped {cov.get('total_technique_hits',0)} techniques "
                f"across {cov.get('tactics_with_hits',0)}/"
                f"{cov.get('total_tactics',14)} Enterprise ATT&CK tactics "
                f"({cov.get('overall_coverage_pct',0)}% matrix coverage)."
            )

        narr = mitre_data.get("threat_narrative", {})
        if narr and narr.get("narrative"):
            risk = narr.get("risk_level", "Unknown")
            m = {"Critical":"Critical","High":"High","Moderate":"Medium"}
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*_stc(m.get(risk, "Medium")))
            pdf.cell(0, 8, f"Risk Level: {risk}",
                     new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
            pdf.body(_strip_html(narr["narrative"]))

        # MITRE breakdown tables per tactic
        C_MIT = (22, 58, 30, 22, 22)  # = 154, close enough
        for tg in mitre_data.get("mitre_breakdown", []):
            pdf.need(25)
            pdf.h3(f"{tg['tactic']} ({tg['tactic_id']})")
            techs = tg.get("techniques", [])
            if techs:
                pdf.tbl_hdr([("ID", C_MIT[0]), ("Technique", C_MIT[1]),
                             ("Confidence", C_MIT[2]), ("Findings", C_MIT[3]),
                             ("Weight", C_MIT[4])])
                for tech in techs:
                    pdf.need(10)
                    pdf.set_draw_color(*CLR_LGRAY)
                    pdf.tbl_cell(tech.get("technique_id", ""), C_MIT[0])
                    pdf.tbl_cell(tech.get("name", "")[:35], C_MIT[1])
                    pdf.tbl_cell(tech.get("confidence", "medium"), C_MIT[2], align="C")
                    pdf.tbl_cell(str(tech.get("finding_count", 0)), C_MIT[3], align="C")
                    pdf.tbl_cell(str(tech.get("severity_weight", "-")), C_MIT[4], align="C")
                    pdf.ln()
            pdf.ln(2)

        # Attack paths
        paths = mitre_data.get("attack_paths", [])
        if paths:
            pdf.need(30)
            pdf.h2(f"{next_sec}.1 Attack Path Analysis")
            for path in paths:
                pdf.need(20)
                pdf.h3(path.get("name", "Attack Path"))
                if path.get("description"):
                    pdf.body(path["description"])
                for step in path.get("steps", []):
                    if isinstance(step, str):
                        pdf.bul(step)
                    else:
                        pdf.bul(f"{step.get('tactic','')}: {step.get('technique','')} - {step.get('detail','')}")
                pdf.ln(2)

        next_sec += 1

    # ══════════════  REMEDIATION ROADMAP  ══════════════
    pdf.new_page()
    pdf.h1(f"{next_sec}. Remediation Roadmap")
    pdf.body(
        "The following remediation priorities are recommended based on "
        "exploitability and business impact:"
    )
    pdf.ln(2)

    if findings:
        pdf.tbl_hdr([("ID", C_REM[0]), ("Finding", C_REM[1]),
                     ("Recommended Action", C_REM[2]),
                     ("Priority", C_REM[3])])
        for i, f in enumerate(findings):
            pdf.need(12)
            pdf.set_draw_color(*CLR_LGRAY)
            fid = f.get("id") or f"VULN-{i+1:03d}"
            title = (f.get("title") or "N/A")[:38]
            sev = f.get("severity", "Info")
            rec = (f.get("remediation") or "Apply best practices")[:36]
            pri = SEV_PRIORITY.get(sev, "Observation")

            pdf.tbl_cell(fid, C_REM[0], align="C")
            pdf.tbl_cell(title, C_REM[1])
            pdf.tbl_cell(rec, C_REM[2])
            pdf.tbl_cell(pri, C_REM[3], bold=True, align="C",
                         fg=_stc(sev), bg=_sbg(sev))
            pdf.ln()
    next_sec += 1

    # ══════════════  CONCLUSION  ══════════════
    pdf.need(60)
    pdf.ln(4)
    pdf.h1(f"{next_sec}. Conclusion")

    if crit_high > 0:
        pdf.body(
            f"The assessment revealed significant security deficiencies in "
            f"{target}, most notably {sc['Critical']} critical and "
            f"{sc['High']} high-severity vulnerabilities. These represent "
            f"a severe and immediate risk to data confidentiality and "
            f"integrity."
        )
        pdf.body(
            "PentaVault recommends prioritizing remediation of critical and "
            "high-severity findings within 7 days, followed by a "
            "re-assessment to validate all applied fixes."
        )
    elif sc["Medium"] > 0:
        pdf.body(
            f"The assessment identified {sc['Medium']} medium-severity "
            f"vulnerabilities in {target}. These should be addressed within "
            f"30 days to reduce risk exposure."
        )
    else:
        pdf.body(
            f"The assessment of {target} revealed an acceptable security "
            f"posture. {total} findings were identified, primarily "
            f"informational or low-severity in nature."
        )

    # ══════════════  APPENDIX A  ══════════════
    pdf.new_page()
    pdf.h1("Appendix A: CVSS Scoring Criteria")

    pdf.tbl_hdr([("Severity", C_APP[0]), ("CVSS Range", C_APP[1]),
                 ("Description", C_APP[2])])
    criteria = [
        ("Critical", "9.0 -- 10.0",
         "Exploitable with significant impact; requires immediate action"),
        ("High", "7.0 -- 8.9",
         "Significant risk to data or system integrity"),
        ("Medium", "4.0 -- 6.9",
         "Moderate risk; exploitation may require specific conditions"),
        ("Low", "0.1 -- 3.9",
         "Minimal direct impact; useful for defense-in-depth"),
        ("Info", "N/A",
         "Observation or best-practice improvement; no direct security risk"),
    ]
    for sev_name, rng, desc in criteria:
        pdf.set_draw_color(*CLR_LGRAY)
        pdf.tbl_cell(sev_name, C_APP[0], bold=True,
                     fg=_stc(sev_name), bg=_sbg(sev_name))
        pdf.tbl_cell(rng, C_APP[1])
        pdf.tbl_cell(desc, C_APP[2])
        pdf.ln()

    return pdf.output()


# ═════════════════════════════════════════════════════════════════
#  DOCX — delegates to Node.js for pixel-perfect formatting
# ═════════════════════════════════════════════════════════════════
_JS_SCRIPT = Path(__file__).parent / "generate_report.js"


def generate_docx(
    target: str,
    findings: list[dict[str, Any]],
    scan_data: dict[str, Any],
    mitre_data: dict[str, Any] | None = None,
    ai_summary: str | None = None,
) -> bytes:
    """Generate professional DOCX by calling Node.js docx library."""
    payload = {
        "target": target,
        "findings": findings,
        "scan_data": scan_data,
        "mitre_data": mitre_data,
        "ai_summary": ai_summary,
    }
    json_str = json.dumps(payload, default=str)

    if shutil.which("node") is None:
        raise RuntimeError("DOCX generation failed: Node.js runtime not found in PATH")

    result = subprocess.run(
        ["node", str(_JS_SCRIPT)],
        input=json_str.encode("utf-8"),
        capture_output=True,
        timeout=30,
    )

    if result.returncode != 0:
        err = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"DOCX generation failed: {err}")

    return result.stdout
