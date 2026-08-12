/**
 * PentaVault — Professional DOCX Report Generator
 *
 * Reads scan data as JSON from stdin, writes DOCX binary to stdout.
 * Usage:  echo '<json>' | node generate_report.js
 *
 * Styled to match professional vulnerability assessment report standards.
 * © 2026 Govind V Kartha — PentaVault
 */

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, LevelFormat, SimpleField
} = require("docx");

// ─── read stdin ───────────────────────────────────────────────────────────────
let inputChunks = [];
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => inputChunks.push(c));
process.stdin.on("end", async () => {
  const data = JSON.parse(inputChunks.join(""));
  const buf = await buildReport(data);
  process.stdout.write(buf);
});

// ─── BORDER HELPERS ───────────────────────────────────────────────────────────
const border    = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const borders   = { top: border, bottom: border, left: border, right: border };
const noBorder  = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const noBorders = { top: noBorder, bottom: noBorder, left: noBorder, right: noBorder };

// ─── SEVERITY MAPS ───────────────────────────────────────────────────────────
const SEV_COLORS = {
  Critical:      { fg: "C00000", bg: "FFE0E0" },
  High:          { fg: "FF0000", bg: "FFE0E0" },
  Medium:        { fg: "FF8C00", bg: "FFF2CC" },
  Low:           { fg: "00B050", bg: "E2EFDA" },
  Info:          { fg: "4472C4", bg: "DEEAF1" },
  Informational: { fg: "4472C4", bg: "DEEAF1" },
  None:          { fg: "4472C4", bg: "DEEAF1" },
};

const SEV_PRIORITY = {
  Critical: "Immediate (0\u20137 days)",
  High:     "Immediate (0\u20137 days)",
  Medium:   "Short-term (7\u201330 days)",
  Low:      "Standard (30\u201390 days)",
  Info:     "Observation",
};

const SEV_DESCS = {
  Critical: "Immediate exploitation risk; may lead to full system compromise",
  High:     "Significant risk to data confidentiality and integrity",
  Medium:   "Moderate risk; exploitable under certain conditions",
  Low:      "Low impact; informational or defense-in-depth value",
  Info:     "Observation or best-practice improvement; no direct security risk",
};

function sev(s) { return SEV_COLORS[s] || SEV_COLORS.Info; }

// ─── REUSABLE ELEMENT BUILDERS ────────────────────────────────────────────────
function cell(text, opts = {}) {
  const { bg = "FFFFFF", bold = false, color = "000000", width = 2340,
          colspan = 1, align = undefined, size = 20 } = opts;
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: bg, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    verticalAlign: VerticalAlign.CENTER,
    columnSpan: colspan,
    children: [new Paragraph({
      alignment: align,
      children: [new TextRun({ text: String(text), bold, color, font: "Arial", size })]
    })]
  });
}

function hcell(text, width = 2340) {
  return cell(text, { bg: "1F3864", bold: true, color: "FFFFFF", width });
}

function severityCell(text, width = 1872) {
  const s = sev(text);
  return cell(text, { bg: s.bg, bold: true, color: s.fg, width });
}

function fieldCell(text, width = 2340) {
  return cell(text, { bg: "F2F2F2", bold: true, color: "000000", width });
}

function heading1(text, pageBreak = false) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    pageBreakBefore: pageBreak,
    children: [new TextRun({ text, bold: true, size: 32, color: "1F3864", font: "Arial" })],
    spacing: { before: 360, after: 160 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: "1F3864", space: 4 } }
  });
}


function heading2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    children: [new TextRun({ text, bold: true, size: 26, color: "2E75B6", font: "Arial" })],
    spacing: { before: 240, after: 120 }
  });
}

function heading3(text) {
  return new Paragraph({
    children: [new TextRun({ text, bold: true, size: 22, color: "404040", font: "Arial" })],
    spacing: { before: 180, after: 80 }
  });
}

function para(text, opts = {}) {
  const { color = "404040", size = 20, bold = false, spacing = { before: 80, after: 80 } } = opts;
  return new Paragraph({
    spacing,
    children: [new TextRun({ text, color, size, bold, font: "Arial" })]
  });
}

function bullet(text) {
  return new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    spacing: { before: 40, after: 40 },
    children: [new TextRun({ text, font: "Arial", size: 20, color: "404040" })]
  });
}

function numberedItem(text) {
  return new Paragraph({
    numbering: { reference: "steps", level: 0 },
    spacing: { before: 40, after: 40 },
    children: [new TextRun({ text, font: "Arial", size: 20, color: "404040" })]
  });
}

function spacer() {
  return new Paragraph({ children: [new TextRun("")], spacing: { before: 80, after: 80 } });
}

function separator() {
  return new Paragraph({
    children: [new TextRun("")],
    spacing: { before: 240, after: 240 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC", space: 4 } }
  });
}

function stripHtml(html) {
  return (html || "")
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").trim();
}

// ─── severity counting ────────────────────────────────────────────────────────
function sevCounts(findings) {
  const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) {
    let s = f.severity || "Info";
    if (s === "None" || s === "Informational") s = "Info";
    c[s] = (c[s] || 0) + 1;
  }
  return c;
}

// ─── MAIN REPORT BUILDER ─────────────────────────────────────────────────────
async function buildReport(data) {
  const { target, findings = [], scan_data = {}, mitre_data, ai_summary } = data;
  const now = new Date();
  const dateStr = now.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  const monthYear = now.toLocaleDateString("en-US", { year: "numeric", month: "long" });
  const sc = sevCounts(findings);
  const total = findings.length;
  const critHigh = sc.Critical + sc.High;
  const mode = (scan_data.mode || "full").charAt(0).toUpperCase() + (scan_data.mode || "full").slice(1);
  const threads = scan_data.threads || 5;

  const TW = 9360; // total table width in DXA (6.5 inches)

  const pageProps = {
    page: {
      size: { width: 12240, height: 15840 },
      margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 }
    }
  };

  // Branded watermark line for headers
  const watermarkPara = new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 80 },
    children: [
      new TextRun({ text: "\u2726  ", font: "Arial", size: 14, color: "E0E0E0" }),
      new TextRun({ text: "P E N T A V A U L T", font: "Arial", size: 14, bold: true, color: "E0E0E0" }),
      new TextRun({ text: "  \u2726", font: "Arial", size: 14, color: "E0E0E0" }),
    ]
  });

  // ════════════════════════════════════════════════════════════════
  //  BUILD DETAILED FINDINGS
  // ════════════════════════════════════════════════════════════════
  const detailedFindings = [];
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    const fid = f.id || `VULN-${String(i + 1).padStart(3, "0")}`;
    const title = f.title || "Unknown Vulnerability";
    const severity = f.severity || "Info";
    const cvss = f.cvss_score != null ? Number(f.cvss_score).toFixed(1) : "N/A";
    const cvssVec = f.cvss_vector || "N/A";
    const owasp = f.owasp_category || "N/A";
    const url = f.affected_url || f.url || "N/A";
    const param = f.parameter || "N/A";
    const evidence = f.evidence || "";
    const payload = f.payload || "";
    const remediation = f.remediation || "Review and apply security best practices.";
    const mitreTechs = f.mitre_attack || [];

    // Section heading
    detailedFindings.push(heading2(`4.${i + 1} ${fid} \u2013 ${title}`));

    // Metadata table — exactly like the sample
    detailedFindings.push(new Table({
      width: { size: TW, type: WidthType.DXA },
      columnWidths: [2340, 7020],
      rows: [
        new TableRow({ tableHeader: true, children: [hcell("Field", 2340), hcell("Details", 7020)] }),
        new TableRow({ children: [fieldCell("Severity", 2340), severityCell(severity, 7020)] }),
        new TableRow({ children: [fieldCell("CVSS Score", 2340), cell(cvss, { width: 7020 })] }),
        new TableRow({ children: [fieldCell("CVSS Vector", 2340), cell(cvssVec, { width: 7020 })] }),
        new TableRow({ children: [fieldCell("OWASP Category", 2340), cell(owasp, { width: 7020 })] }),
        new TableRow({ children: [fieldCell("Affected URL", 2340), cell(url.length > 70 ? url.slice(0, 67) + "..." : url, { width: 7020 })] }),
        new TableRow({ children: [fieldCell("Parameter", 2340), cell(param, { width: 7020 })] }),
      ]
    }));
    detailedFindings.push(spacer());

    // Description
    detailedFindings.push(heading3("Description"));
    detailedFindings.push(para(_buildDescription(f)));
    detailedFindings.push(spacer());

    // Business Impact
    detailedFindings.push(heading3("Business Impact"));
    detailedFindings.push(para(_buildImpactText(severity, title)));
    detailedFindings.push(spacer());

    // Steps to Reproduce
    detailedFindings.push(heading3("Steps to Reproduce"));
    const steps = _buildSteps(f);
    for (const step of steps) {
      detailedFindings.push(numberedItem(step));
    }
    detailedFindings.push(spacer());

    // Recommendation
    detailedFindings.push(heading3("Recommendation"));
    detailedFindings.push(para(remediation));
    detailedFindings.push(spacer());

    // References
    const refs = [];
    if (owasp && owasp !== "N/A") refs.push(owasp);
    if (cvssVec && cvssVec !== "N/A") refs.push(`CVSS v3.1: ${cvssVec}`);
    for (const mt of mitreTechs.slice(0, 3)) {
      refs.push(`MITRE ATT&CK: ${mt.technique} \u2013 ${mt.name} (${mt.tactic || ""})`);
    }
    if (refs.length > 0) {
      detailedFindings.push(heading3("References"));
      for (const r of refs) detailedFindings.push(bullet(r));
      detailedFindings.push(spacer());
    }

    detailedFindings.push(separator());
    detailedFindings.push(spacer());
  }

  // ════════════════════════════════════════════════════════════════
  //  BUILD MITRE SECTION
  // ════════════════════════════════════════════════════════════════
  const mitreSection = [];
  let nextSec = 5;
  if (mitre_data) {
    const cov = mitre_data.matrix_coverage || {};
    const narr = mitre_data.threat_narrative || {};
    const breakdown = mitre_data.mitre_breakdown || [];

    mitreSection.push(heading1(`${nextSec}. MITRE ATT&CK Analysis`));

    if (cov.total_technique_hits != null) {
      mitreSection.push(para(
        `The scan mapped ${cov.total_technique_hits} techniques across ` +
        `${cov.tactics_with_hits}/${cov.total_tactics || 14} Enterprise ATT&CK tactics ` +
        `(${cov.overall_coverage_pct || 0}% matrix coverage).`
      ));
    }

    if (narr.risk_level) {
      const riskSev = { Critical: "Critical", High: "High", Moderate: "Medium" }[narr.risk_level] || "Medium";
      const sv = sev(riskSev);
      mitreSection.push(para(`Risk Level: ${narr.risk_level}`, { bold: true, color: sv.fg }));
    }
    if (narr.narrative) {
      mitreSection.push(spacer());
      mitreSection.push(para(stripHtml(narr.narrative)));
    }

    mitreSection.push(spacer());

    // Breakdown table per tactic
    for (const tg of breakdown) {
      mitreSection.push(heading3(`${tg.tactic} (${tg.tactic_id})`));
      if (tg.techniques && tg.techniques.length > 0) {
        mitreSection.push(new Table({
          width: { size: TW, type: WidthType.DXA },
          columnWidths: [1400, 3800, 1560, 1300, 1300],
          rows: [
            new TableRow({ tableHeader: true, children: [
              hcell("ID", 1400), hcell("Technique", 3800), hcell("Confidence", 1560),
              hcell("Findings", 1300), hcell("Weight", 1300)
            ]}),
            ...tg.techniques.map(tech => new TableRow({ children: [
              cell(tech.technique_id, { width: 1400, size: 18 }),
              cell(tech.name, { width: 3800, size: 18 }),
              cell(tech.confidence || "medium", { width: 1560, size: 18, align: AlignmentType.CENTER }),
              cell(String(tech.finding_count || 0), { width: 1300, size: 18, align: AlignmentType.CENTER }),
              cell(String(tech.severity_weight || "-"), { width: 1300, size: 18, align: AlignmentType.CENTER })
            ]}))
          ]
        }));
      }
      mitreSection.push(spacer());
    }

    // Attack paths
    if (mitre_data.attack_paths && mitre_data.attack_paths.length > 0) {
      mitreSection.push(heading2(`${nextSec}.1 Attack Path Analysis`));
      for (const path of mitre_data.attack_paths) {
        mitreSection.push(heading3(path.name || "Attack Path"));
        if (path.description) mitreSection.push(para(path.description));
        if (path.steps) {
          for (const step of path.steps) {
            mitreSection.push(bullet(typeof step === "string" ? step : `${step.tactic}: ${step.technique} \u2013 ${step.detail || ""}`));
          }
        }
        mitreSection.push(spacer());
      }
    }

    nextSec++;
  }

  // ════════════════════════════════════════════════════════════════
  //  REMEDIATION ROADMAP
  // ════════════════════════════════════════════════════════════════
  const remRows = findings.map((f, i) => {
    const fid = f.id || `VULN-${String(i + 1).padStart(3, "0")}`;
    const title = (f.title || "N/A").slice(0, 45);
    const severity = f.severity || "Info";
    const rec = (f.remediation || "Apply best practices").slice(0, 40);
    const sv = sev(severity);
    const pri = SEV_PRIORITY[severity] || "Observation";
    return new TableRow({ children: [
      cell(fid, { width: 936 }),
      cell(title, { width: 4092 }),
      cell(rec, { width: 2340 }),
      cell(pri, { bg: sv.bg, bold: true, color: sv.fg, width: 1992 })
    ] });
  });

  // ════════════════════════════════════════════════════════════════
  //  AI SUMMARY SECTION
  // ════════════════════════════════════════════════════════════════
  const aiSection = [];
  if (ai_summary) {
    aiSection.push(heading2("AI-Powered Threat Analysis"));
    const cleanText = stripHtml(ai_summary);
    const paragraphs = cleanText.split(/\n\n+/).filter(p => p.trim());
    for (const p of paragraphs) {
      aiSection.push(para(p.trim()));
    }
    aiSection.push(spacer());
  }

  // ════════════════════════════════════════════════════════════════
  //  CONCLUSION
  // ════════════════════════════════════════════════════════════════
  const conclusionParas = [];
  if (critHigh > 0) {
    conclusionParas.push(para(
      `The assessment revealed significant security deficiencies in ${target}, ` +
      `most notably ${sc.Critical} critical and ${sc.High} high-severity vulnerabilities. ` +
      `These findings represent a severe and immediate risk to the confidentiality ` +
      `and integrity of data.`
    ));
    conclusionParas.push(spacer());
    conclusionParas.push(para(
      `PentaVault recommends prioritizing remediation of critical and ` +
      `high-severity findings within 7 days of receiving this report, ` +
      `followed by a re-assessment to validate all applied fixes.`
    ));
  } else if (sc.Medium > 0) {
    conclusionParas.push(para(
      `The assessment identified ${sc.Medium} medium-severity vulnerabilities ` +
      `in ${target}. While no critical issues were found, these items should ` +
      `be addressed within 30 days to reduce risk exposure.`
    ));
  } else {
    conclusionParas.push(para(
      `The assessment of ${target} revealed a generally acceptable security ` +
      `posture. ${total} findings were identified, primarily informational ` +
      `or low-severity in nature.`
    ));
  }

  // ════════════════════════════════════════════════════════════════
  //  DOCUMENT ASSEMBLY
  // ════════════════════════════════════════════════════════════════
  const doc = new Document({
    numbering: {
      config: [
        {
          reference: "bullets",
          levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } } }]
        },
        {
          reference: "steps",
          levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } } }]
        }
      ]
    },
    styles: {
      default: { document: { run: { font: "Arial", size: 20, color: "404040" } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 32, bold: true, font: "Arial", color: "1F3864" },
          paragraph: { spacing: { before: 360, after: 160 }, outlineLevel: 0 } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 26, bold: true, font: "Arial", color: "2E75B6" },
          paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } }
      ]
    },
    sections: [
      // ── COVER PAGE ──────────────────────────────────────────────────────────
      {
        properties: pageProps,
        headers: { default: new Header({ children: [watermarkPara] }) },
        children: [
          new Paragraph({ spacing: { before: 1440, after: 240 }, children: [] }),
          new Paragraph({
            alignment: AlignmentType.CENTER, spacing: { before: 480, after: 120 },
            children: [new TextRun({ text: "VULNERABILITY ASSESSMENT REPORT", bold: true, size: 52, color: "1F3864", font: "Arial" })]
          }),
          new Paragraph({
            alignment: AlignmentType.CENTER, spacing: { before: 0, after: 480 },
            border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: "2E75B6", space: 4 } },
            children: [new TextRun({ text: "Web Application Security Assessment", size: 32, color: "2E75B6", font: "Arial" })]
          }),
          spacer(),
          // Cover metadata table (no borders)
          new Table({
            width: { size: TW, type: WidthType.DXA },
            rows: [
              ["Target:",            target.length > 55 ? target.slice(0, 52) + "..." : target],
              ["Scan Mode:",         mode],
              ["Assessment Date:",   dateStr],
              ["Report Date:",       dateStr],
              ["Classification:",    "CONFIDENTIAL"],
              ["Prepared By:",       "PentaVault \u2014 Automated VAPT Security Suite"],
              ["Version:",           "1.0 \u2013 Automated"],
            ].map(([label, value]) => new TableRow({ children: [
              new TableCell({ borders: noBorders, width: { size: 3120, type: WidthType.DXA },
                children: [new Paragraph({ children: [new TextRun({ text: label, bold: true, font: "Arial", size: 22, color: "1F3864" })] })] }),
              new TableCell({ borders: noBorders, width: { size: 6240, type: WidthType.DXA },
                children: [new Paragraph({ children: [new TextRun({ text: value, font: "Arial", size: 22, color: label === "Classification:" ? "C00000" : "404040", bold: label === "Classification:" })] })] })
            ] }))
          }),
          new Paragraph({
            spacing: { before: 2880, after: 0 }, alignment: AlignmentType.CENTER,
            children: [new TextRun({ text: "\u00A9 2026 Govind V Kartha. This document contains confidential and proprietary information. Distribution is restricted to authorized personnel only.", size: 16, color: "808080", font: "Arial", italics: true })]
          })
        ]
      },

      // ── MAIN CONTENT ────────────────────────────────────────────────────────
      {
        properties: pageProps,
        headers: {
          default: new Header({ children: [
            watermarkPara,
            new Paragraph({
              alignment: AlignmentType.RIGHT,
              border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: "2E75B6", space: 4 } },
              children: [new TextRun({ text: `Vulnerability Assessment Report  |  ${target.length > 35 ? target.slice(0, 32) + "..." : target}  |  CONFIDENTIAL`, size: 16, color: "808080", font: "Arial" })]
            })
          ] })
        },
        footers: {
          default: new Footer({ children: [
            new Paragraph({
              alignment: AlignmentType.CENTER,
              border: { top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 4 } },
              children: [
                new TextRun({ text: "\u00A9 2026 Govind V Kartha \u2014 PentaVault  |  Page ", size: 16, color: "808080", font: "Arial" }),
                new SimpleField("PAGE"),
                new TextRun({ text: `  |  ${monthYear}`, size: 16, color: "808080", font: "Arial" })
              ]
            })
          ] })
        },
        children: [

          // 1. EXECUTIVE SUMMARY
          heading1("1. Executive Summary"),
          para(`PentaVault was engaged to conduct an automated vulnerability assessment of ${target}. The assessment was performed in '${mode}' mode, simulating the perspective of an external threat actor scanning for common web application vulnerabilities.`),
          spacer(),
          critHigh > 0
            ? para(`The assessment identified ${total} vulnerabilities. ${critHigh} critical or high-severity vulnerabilities were identified that could result in full compromise of the application and unauthorized access to data. Immediate remediation is strongly recommended.`)
            : para(`The assessment identified ${total} vulnerabilities. No critical or high-severity vulnerabilities were found.`),
          spacer(),

          // Severity summary table — exactly like the sample
          new Table({
            width: { size: TW, type: WidthType.DXA },
            columnWidths: [4680, 1872, 2808],
            rows: [
              new TableRow({ tableHeader: true, children: [hcell("Severity", 4680), hcell("Count", 1872), hcell("Risk Description", 2808)] }),
              ...["Critical", "High", "Medium", "Low", "Info"].map(s => {
                const sv = sev(s);
                return new TableRow({ children: [
                  cell(s, { bg: sv.bg, bold: true, color: sv.fg, width: 4680 }),
                  cell(String(sc[s]), { bg: sv.bg, bold: true, color: sv.fg, width: 1872 }),
                  cell(SEV_DESCS[s], { width: 2808 })
                ] });
              }),
              new TableRow({ children: [
                cell("Total", { bg: "D5E8F0", bold: true, color: "1F3864", width: 4680 }),
                cell(String(total), { bg: "D5E8F0", bold: true, color: "1F3864", width: 1872 }),
                cell("", { width: 2808 })
              ] }),
            ]
          }),
          spacer(), spacer(),

          // AI summary (if available)
          ...aiSection,

          // 2. SCOPE & METHODOLOGY
          heading1("2. Scope and Methodology", true),
          heading2("2.1 Scope"),
          para("The following targets were included in the assessment:"),
          bullet(`Web Application: ${target}`),
          bullet(`Scan Mode: ${mode} (Concurrent threads: ${threads})`),
          bullet(`Authentication: ${scan_data.cookie ? "Authenticated scan with session cookie" : "Unauthenticated scan"}`),
          bullet(`Out of scope: Physical infrastructure, social engineering, third-party integrations`),
          spacer(),
          heading2("2.2 Methodology"),
          para("The assessment followed automated vulnerability testing methodology aligned with the OWASP Testing Guide v4.2 and the PTES (Penetration Testing Execution Standard). Testing phases included:"),
          bullet("Reconnaissance and information gathering (DNS, WHOIS, port scanning)"),
          bullet("Technology fingerprinting (server, framework, WAF detection, SSL/TLS analysis)"),
          bullet("Automated web crawling and endpoint discovery"),
          bullet("Vulnerability testing: SQL Injection, Cross-Site Scripting, SSRF, IDOR, Open Redirect, Security Headers"),
          bullet("CVSS v3.1 severity scoring and risk classification"),
          bullet("OWASP 2025 Top 10 and MITRE ATT&CK Enterprise v16.1 mapping"),
          bullet("Exploitation proof and evidence collection for confirmed findings"),
          spacer(), spacer(),

          // 3. FINDINGS SUMMARY
          heading1("3. Findings Summary", true),
          ...(findings.length === 0
            ? [para("No vulnerabilities were identified during this assessment.")]
            : [new Table({
                width: { size: TW, type: WidthType.DXA },
                columnWidths: [936, 4092, 1872, 936, 1524],
                rows: [
                  new TableRow({ tableHeader: true, cantSplit: true, children: [hcell("ID", 936), hcell("Title", 4092), hcell("Component", 1872), hcell("CVSS", 936), hcell("Severity", 1524)] }),
                  ...findings.map((f, i) => {
                    const fid = f.id || `VULN-${String(i + 1).padStart(3, "0")}`;
                    const cvss = f.cvss_score != null ? Number(f.cvss_score).toFixed(1) : "-";
                    const component = _extractComponent(f);
                    return new TableRow({ cantSplit: true, children: [
                      cell(fid, { width: 936 }),
                      cell((f.title || "N/A").slice(0, 50), { width: 4092 }),
                      cell(component, { width: 1872 }),
                      cell(cvss, { width: 936 }),
                      severityCell(f.severity || "Info", 1524)
                    ] });
                  })
                ]
              })
            ]),
          spacer(), spacer(),

          // 4. DETAILED FINDINGS
          heading1("4. Detailed Findings", true),
          ...(findings.length === 0
            ? [para("No vulnerabilities were identified during this assessment.")]
            : detailedFindings),

          // 5. MITRE (conditional)
          ...mitreSection,

          // REMEDIATION ROADMAP
          heading1(`${nextSec}. Remediation Roadmap`, true),
          para("The following remediation priorities are recommended based on exploitability and business impact:"),
          spacer(),
          ...(findings.length > 0
            ? [new Table({
                width: { size: TW, type: WidthType.DXA },
                columnWidths: [936, 4092, 2340, 1992],
                rows: [
                  new TableRow({ tableHeader: true, cantSplit: true, children: [hcell("ID", 936), hcell("Finding", 4092), hcell("Recommended Action", 2340), hcell("Priority", 1992)] }),
                  ...remRows
                ]
              })]
            : [para("No remediation actions required.")]),
          spacer(), spacer(),

          // CONCLUSION
          heading1(`${nextSec + 1}. Conclusion`, true),
          ...conclusionParas,
          spacer(), spacer(),

          // APPENDIX A
          heading1("Appendix A: CVSS Scoring Criteria", true),

          new Table({
            width: { size: TW, type: WidthType.DXA },
            columnWidths: [2340, 2340, 4680],
            rows: [
              new TableRow({ tableHeader: true, children: [hcell("Severity", 2340), hcell("CVSS Score Range", 2340), hcell("Description", 4680)] }),
              ...[
                ["Critical",      "9.0 \u2013 10.0", "Exploitable with significant impact; requires immediate action"],
                ["High",          "7.0 \u2013 8.9",  "Significant risk to data or system integrity"],
                ["Medium",        "4.0 \u2013 6.9",  "Moderate risk; exploitation may require specific conditions"],
                ["Low",           "0.1 \u2013 3.9",  "Minimal direct impact; useful for defense-in-depth"],
                ["Informational", "N/A",              "Observation or best-practice improvement; no direct security risk"]
              ].map(([s, range, desc]) => {
                const sv = sev(s);
                return new TableRow({ children: [
                  cell(s, { bg: sv.bg, bold: true, color: sv.fg, width: 2340 }),
                  cell(range, { width: 2340 }),
                  cell(desc, { width: 4680 })
                ] });
              })
            ]
          })
        ]
      }
    ]
  });

  return Packer.toBuffer(doc);
}

// ─── HELPER: Extract component from finding ───────────────────────────────────
function _extractComponent(f) {
  const title = f.title || "";
  if (title.includes("SQL Injection")) return "Database Layer";
  if (title.includes("XSS") || title.includes("Cross-Site")) return "Input Handling";
  if (title.includes("SSRF")) return "URL Processing";
  if (title.includes("IDOR")) return "Authorization";
  if (title.includes("Redirect")) return "URL Routing";
  if (title.includes("Header") || title.includes("CSP") || title.includes("HSTS") ||
      title.includes("X-Frame") || title.includes("X-Content") || title.includes("Server Version") ||
      title.includes("Referrer") || title.includes("Permissions") || title.includes("X-XSS")) return "HTTP Headers";
  try {
    const url = f.affected_url || f.url || "";
    const path = new URL(url).pathname;
    return path.length > 25 ? path.slice(0, 22) + "..." : path;
  } catch {
    return "Web Application";
  }
}

// ─── HELPER: Build full description text ──────────────────────────────────────
function _buildDescription(f) {
  const title = (f.title || "").toLowerCase();
  const url = f.affected_url || f.url || "the target";
  const param = f.parameter || "the input parameter";
  const evidence = f.evidence || "";

  if (title.includes("sql injection") && title.includes("error")) {
    return `The endpoint at ${url} fails to sanitize user-supplied input in the parameter '${param}' before incorporating it into SQL queries. An attacker can inject SQL payloads that cause the database to reveal error messages containing internal schema information. Evidence: ${evidence.slice(0, 150)}`;
  }
  if (title.includes("sql injection") && title.includes("time")) {
    return `The endpoint at ${url} is vulnerable to time-based blind SQL injection via the parameter '${param}'. By injecting time-delay SQL commands, an attacker can infer database contents one bit at a time without direct output. Evidence: ${evidence.slice(0, 150)}`;
  }
  if (title.includes("sql injection") && title.includes("boolean")) {
    return `The endpoint at ${url} is vulnerable to boolean-based blind SQL injection via the parameter '${param}'. The application responds differently to true/false SQL conditions, allowing an attacker to extract data by observing response variations. Evidence: ${evidence.slice(0, 150)}`;
  }
  if (title.includes("sql injection")) {
    return `The endpoint at ${url} is vulnerable to SQL injection via the parameter '${param}'. An unauthenticated attacker can manipulate SQL logic to bypass authentication, extract data, or modify database records. Evidence: ${evidence.slice(0, 150)}`;
  }
  if (title.includes("stored") && title.includes("xss")) {
    return `The application stores and renders user-supplied content at ${url} without proper encoding. The parameter '${param}' accepts HTML/JavaScript that persists and executes in the browser context of any user who views the affected page. Evidence: ${evidence.slice(0, 150)}`;
  }
  if (title.includes("dom") && title.includes("xss")) {
    return `The page at ${url} contains client-side JavaScript that passes user-controllable data (DOM sources) into dangerous execution sinks without sanitization. This creates a DOM-based XSS vulnerability exploitable without server interaction. Evidence: ${evidence.slice(0, 150)}`;
  }
  if (title.includes("xss") || title.includes("cross-site")) {
    return `The endpoint at ${url} reflects user-supplied input from the parameter '${param}' into the HTTP response without proper encoding. An attacker can craft a malicious URL that executes arbitrary JavaScript in a victim's browser. Evidence: ${evidence.slice(0, 150)}`;
  }
  if (title.includes("idor") || title.includes("object")) {
    return `The API endpoint at ${url} does not verify that the requesting user owns or has permission to access the requested resource. Any user can access resources belonging to other users by enumerating sequential IDs. Evidence: ${evidence.slice(0, 150)}`;
  }
  if (title.includes("ssrf")) {
    return `The parameter '${param}' at ${url} accepts URL values that the server fetches without proper validation. An attacker can force the server to make requests to internal services, cloud metadata endpoints, or other restricted resources. Evidence: ${evidence.slice(0, 150)}`;
  }
  if (title.includes("redirect")) {
    return `The endpoint at ${url} accepts a user-controlled redirect destination via the parameter '${param}' without validation. An attacker can craft URLs that redirect users to malicious external sites. Evidence: ${evidence.slice(0, 150)}`;
  }
  if (title.includes("content-security-policy") || title.includes("csp")) {
    return `The application at ${url} does not include a Content-Security-Policy (CSP) header. Without CSP, the browser has no restrictions on script sources, making XSS exploitation more effective and enabling data exfiltration.`;
  }
  if (title.includes("strict-transport") || title.includes("hsts")) {
    return `The application at ${url} does not include the Strict-Transport-Security (HSTS) header. Without HSTS, users are vulnerable to SSL stripping attacks where an attacker downgrades HTTPS connections to HTTP.`;
  }
  if (title.includes("x-frame")) {
    return `The application at ${url} does not include the X-Frame-Options header. Without this header, the application can be embedded in iframes on malicious sites, enabling clickjacking attacks.`;
  }
  if (title.includes("x-content-type")) {
    return `The application at ${url} does not include the X-Content-Type-Options header. Without this header, browsers may MIME-sniff response content, potentially executing uploaded files as scripts.`;
  }
  if (title.includes("x-xss-protection")) {
    return `The application at ${url} does not include the X-XSS-Protection header. While deprecated in favor of CSP, this header provides an additional layer of defense for older browsers.`;
  }
  if (title.includes("referrer-policy")) {
    return `The application at ${url} does not include a Referrer-Policy header. Without this, the browser may leak sensitive URL information (including query parameters and tokens) to third parties in the Referer header.`;
  }
  if (title.includes("permissions-policy")) {
    return `The application at ${url} does not include a Permissions-Policy header. Without this, the application does not restrict access to browser features like camera, microphone, and geolocation, expanding the attack surface.`;
  }
  if (title.includes("server version")) {
    return `The application at ${url} discloses the web server software and version in the Server HTTP response header. This information helps attackers identify known vulnerabilities for the specific software version. Evidence: ${evidence.slice(0, 150)}`;
  }

  // Generic fallback
  return `${f.title || "A vulnerability was detected"} at ${url}. ${evidence ? "Evidence: " + evidence.slice(0, 200) : "The vulnerability was confirmed during automated scanning."}`;
}

// ─── HELPER: Build impact text based on severity/type ─────────────────────────
function _buildImpactText(severity, title) {
  const lower = title.toLowerCase();
  if (lower.includes("sql injection")) {
    return "Full authentication bypass; unauthorized access to all database records; potential extraction of sensitive data including credentials and personally identifiable information (PII). May lead to complete database compromise.";
  }
  if (lower.includes("stored") && lower.includes("xss")) {
    return "Session hijacking, credential theft, malware distribution, defacement, and complete account takeover for any user who views the affected content.";
  }
  if (lower.includes("xss") || lower.includes("cross-site scripting")) {
    return "Potential session hijacking, credential theft via injected scripts, phishing attacks delivered through the trusted application domain, and user redirection to attacker-controlled sites.";
  }
  if (lower.includes("idor") || lower.includes("object")) {
    return "Unauthorized access to confidential data, documents, and resources belonging to other users. Systematic enumeration could expose the entire dataset.";
  }
  if (lower.includes("ssrf")) {
    return "Access to internal services, cloud metadata endpoints, and sensitive infrastructure. May enable pivoting to internal network resources or credential theft from cloud instance metadata.";
  }
  if (lower.includes("redirect")) {
    return "Users may be redirected to attacker-controlled phishing pages, leading to credential theft or malware delivery while leveraging trust in the legitimate domain.";
  }
  if (lower.includes("header") || lower.includes("csp") || lower.includes("hsts") ||
      lower.includes("x-frame") || lower.includes("server version") || lower.includes("referrer") ||
      lower.includes("permissions") || lower.includes("x-content") || lower.includes("x-xss")) {
    return "Increased attack surface due to missing security controls. May facilitate exploitation of other vulnerabilities or provide reconnaissance information to attackers.";
  }
  if (severity === "Critical") return "Immediate exploitation risk with potential for full system compromise, data breach, or unauthorized administrative access.";
  if (severity === "High") return "Significant risk to data confidentiality and integrity. Exploitation could lead to unauthorized access or data manipulation.";
  if (severity === "Medium") return "Moderate risk to the application. Exploitation may require specific conditions but could lead to data exposure or service disruption.";
  return "Low direct impact. May provide information useful for further attacks or represents a defense-in-depth improvement opportunity.";
}

// ─── HELPER: Build reproduction steps ─────────────────────────────────────────
function _buildSteps(f) {
  const url = f.affected_url || f.url || "the target URL";
  const param = f.parameter || "the vulnerable parameter";
  const payload = f.payload || "the test payload";
  const evidence = f.evidence || "";
  const title = (f.title || "").toLowerCase();

  if (title.includes("sql injection")) {
    return [
      `Navigate to ${url}`,
      `Identify the injectable parameter: ${param}`,
      `Inject the SQL payload: ${payload}`,
      `Observe the database error or behavioral change in the response`,
      evidence ? `Evidence observed: ${evidence.slice(0, 120)}` : "Confirm that SQL logic is modified by the injected input"
    ];
  }
  if (title.includes("xss") || title.includes("cross-site")) {
    return [
      `Navigate to ${url}`,
      `Locate the input field or parameter: ${param}`,
      `Insert the XSS payload: ${payload}`,
      `Submit the request and observe the response body`,
      evidence ? `Confirm payload reflection: ${evidence.slice(0, 120)}` : "Verify the payload is rendered unescaped in the response"
    ];
  }
  if (title.includes("idor") || title.includes("object")) {
    return [
      `Access the original resource at ${url}`,
      `Note the sequential numeric ID in the URL path`,
      `Modify the ID to access another user's resource (e.g., increment by 1)`,
      evidence ? `Observe different data returned: ${evidence.slice(0, 120)}` : "Confirm that the application returns data without authorization check"
    ];
  }
  if (title.includes("ssrf")) {
    return [
      `Navigate to ${url}`,
      `Identify the URL-accepting parameter: ${param}`,
      `Replace the value with an internal/metadata URL: ${payload}`,
      evidence ? `Observe internal data in response: ${evidence.slice(0, 120)}` : "Confirm server-side request was issued to the injected URL"
    ];
  }
  if (title.includes("redirect")) {
    return [
      `Navigate to ${url}`,
      `Identify the redirect parameter: ${param}`,
      `Set the parameter to an external URL: ${payload}`,
      evidence ? `Observe the redirect: ${evidence.slice(0, 120)}` : "Confirm 3xx redirect to the attacker-controlled domain"
    ];
  }
  if (title.includes("header") || title.includes("csp") || title.includes("hsts") ||
      title.includes("x-frame") || title.includes("server version") || title.includes("referrer") ||
      title.includes("permissions") || title.includes("x-content") || title.includes("x-xss")) {
    return [
      `Send an HTTP GET request to ${url}`,
      `Inspect the HTTP response headers using browser dev tools or curl`,
      evidence ? `Confirm: ${evidence.slice(0, 150)}` : "Verify the security header is absent from the response",
      "Cross-reference with OWASP Secure Headers recommendations"
    ];
  }
  return [
    `Navigate to ${url}`,
    `Identify the input: ${param}`,
    `Apply the test payload: ${payload}`,
    evidence ? `Observe: ${evidence.slice(0, 120)}` : "Analyse the response for vulnerability indicators"
  ];
}
