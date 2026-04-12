"""
NEXUS SPECTER PRO — Technical Report Generator v2
Full PoC evidence report with: CVSS 3.1 breakdown, CVE details,
request/response evidence, remediation roadmap, MITRE ATT&CK mapping.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json, logging, html
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, BaseLoader
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.reporting.v2")

CVSS31_VECTORS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}

TECHNICAL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NSP Technical Report — {{ session_id }}</title>
<style>
  :root {
    --nsp-purple:#7B00FF; --nsp-cyan:#00FFD4; --nsp-red:#FF003C;
    --nsp-dark:#0A0A0A;   --nsp-card:#111111; --nsp-border:#1E1E1E;
    --nsp-text:#E8E8E8;   --nsp-muted:#666;
  }
  *{margin:0;padding:0;box-sizing:border-box;}
  body{background:var(--nsp-dark);color:var(--nsp-text);
       font-family:'JetBrains Mono',monospace,sans-serif;font-size:13px;}
  .page{max-width:1200px;margin:0 auto;padding:40px 30px;}

  .header{display:flex;justify-content:space-between;align-items:center;
          border-bottom:3px solid var(--nsp-purple);padding-bottom:24px;margin-bottom:36px;}
  .logo h1{font-size:24px;color:var(--nsp-purple);letter-spacing:4px;font-weight:900;}
  .logo h2{font-size:11px;color:var(--nsp-cyan);letter-spacing:2px;margin-top:3px;}
  .meta{text-align:right;color:var(--nsp-muted);font-size:11px;line-height:1.9;}
  .classify{color:var(--nsp-red);border:1px solid var(--nsp-red);
            padding:2px 8px;display:inline-block;margin-bottom:6px;
            letter-spacing:2px;font-weight:700;font-size:12px;}

  section{margin:44px 0;}
  section>h2{font-size:15px;color:var(--nsp-purple);text-transform:uppercase;
             letter-spacing:3px;border-left:4px solid var(--nsp-purple);
             padding-left:14px;margin-bottom:22px;}

  /* VULN CARD */
  .vuln-card{background:var(--nsp-card);border:1px solid var(--nsp-border);
             border-radius:6px;margin:20px 0;overflow:hidden;}
  .vuln-header{padding:16px 20px;display:flex;align-items:center;
               gap:14px;border-bottom:1px solid var(--nsp-border);}
  .vuln-id{background:var(--nsp-purple);color:#fff;padding:3px 10px;
           border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap;}
  .vuln-title{font-size:15px;font-weight:700;flex:1;}
  .vuln-body{padding:20px;}
  .vuln-body table{width:100%;border-collapse:collapse;margin-bottom:18px;}
  .vuln-body td{padding:8px 12px;border-bottom:1px solid var(--nsp-border);vertical-align:top;}
  .vuln-body td:first-child{color:var(--nsp-cyan);width:160px;font-size:11px;
                             text-transform:uppercase;letter-spacing:1px;}

  /* SEVERITY BADGE */
  .sev{padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;
       text-transform:uppercase;letter-spacing:1px;}
  .sev-critical{background:rgba(255,0,60,0.2);color:#FF003C;border:1px solid #FF003C;}
  .sev-high{background:rgba(255,140,0,0.2);color:#FF8C00;border:1px solid #FF8C00;}
  .sev-medium{background:rgba(255,215,0,0.15);color:#FFD700;border:1px solid #FFD700;}
  .sev-low{background:rgba(0,255,212,0.12);color:#00FFD4;border:1px solid #00FFD4;}
  .sev-info{background:rgba(136,136,136,0.1);color:#888;border:1px solid #333;}

  /* CVSS */
  .cvss-block{background:#0D0D0D;border:1px solid var(--nsp-border);
              border-radius:6px;padding:16px;margin:14px 0;}
  .cvss-score-big{font-size:42px;font-weight:900;display:inline-block;margin-right:16px;}
  .cvss-vector{font-size:11px;color:var(--nsp-muted);margin-top:6px;
               font-family:monospace;letter-spacing:1px;}
  .cvss-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:14px;}
  .cvss-cell{background:#111;border:1px solid var(--nsp-border);border-radius:4px;
             padding:8px 10px;font-size:11px;}
  .cvss-cell .lbl{color:var(--nsp-muted);margin-bottom:3px;}
  .cvss-cell .val{color:var(--nsp-cyan);font-weight:700;}

  /* EVIDENCE */
  .evidence-block{margin:14px 0;}
  .evidence-block h4{color:var(--nsp-cyan);font-size:11px;text-transform:uppercase;
                     letter-spacing:2px;margin-bottom:8px;}
  .code-block{background:#060606;border:1px solid var(--nsp-border);border-radius:4px;
              padding:14px;overflow-x:auto;font-family:monospace;font-size:12px;
              color:#00FF41;white-space:pre-wrap;word-break:break-all;max-height:300px;}
  .highlight-match{background:rgba(255,0,60,0.3);color:#fff;padding:0 2px;border-radius:2px;}

  /* MITRE */
  .mitre-badge{display:inline-block;background:rgba(123,0,255,0.2);
               border:1px solid var(--nsp-purple);color:var(--nsp-purple);
               padding:3px 10px;border-radius:4px;font-size:11px;
               font-weight:700;margin:2px;letter-spacing:1px;}

  /* REMEDIATION */
  .remediation-block{background:#0D0D1A;border:1px solid var(--nsp-purple);
                     border-radius:6px;padding:18px;margin:14px 0;}
  .remediation-block h4{color:var(--nsp-purple);margin-bottom:10px;
                         font-size:12px;text-transform:uppercase;letter-spacing:2px;}
  .step{padding:6px 0;border-bottom:1px solid var(--nsp-border);display:flex;gap:10px;}
  .step-num{color:var(--nsp-purple);font-weight:700;min-width:24px;}
  .step-text{color:var(--nsp-text);}

  /* TOC */
  .toc{background:var(--nsp-card);border:1px solid var(--nsp-border);
       border-radius:6px;padding:24px;margin:24px 0;}
  .toc h3{color:var(--nsp-purple);margin-bottom:16px;letter-spacing:3px;
          font-size:13px;text-transform:uppercase;}
  .toc a{color:var(--nsp-cyan);text-decoration:none;display:block;
         padding:4px 0;border-bottom:1px solid var(--nsp-border);font-size:12px;}
  .toc a:hover{color:var(--nsp-purple);}
  .toc .sev-indicator{float:right;}

  .footer{border-top:1px solid var(--nsp-border);padding-top:20px;margin-top:50px;
          display:flex;justify-content:space-between;color:var(--nsp-muted);font-size:11px;}
  .footer .brand{color:var(--nsp-purple);font-weight:700;}
  .divider{border:none;border-top:1px solid var(--nsp-border);margin:28px 0;}
  p{line-height:1.8;margin:8px 0;}
</style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div class="header">
    <div class="logo">
      <h1>⚡ NEXUS SPECTER PRO</h1>
      <h2>TECHNICAL PENETRATION TEST REPORT</h2>
    </div>
    <div class="meta">
      <div class="classify">CONFIDENTIAL — TECHNICAL</div><br>
      <strong>Client:</strong> {{ client_name }}<br>
      <strong>Target:</strong> {{ target }}<br>
      <strong>Date:</strong> {{ report_date }}<br>
      <strong>Session:</strong> {{ session_id }}<br>
      <strong>Assessor:</strong> OPTIMIUM NEXUS LLC
    </div>
  </div>

  <!-- INTRO -->
  <section>
    <h2>📋 Technical Report Overview</h2>
    <p>
      This technical report documents all vulnerabilities identified during the
      <strong>{{ engagement_type }}</strong> conducted against <strong>{{ target }}</strong>
      for <strong>{{ client_name }}</strong>. Each finding includes full technical details,
      proof-of-concept evidence, CVSS 3.1 scoring, MITRE ATT&CK mapping, and
      step-by-step remediation guidance.
    </p>
    <p style="margin-top:12px;">
      Total findings: <span style="color:#FF003C;font-weight:700;">{{ counts.critical }} Critical</span> |
      <span style="color:#FF8C00;font-weight:700;">{{ counts.high }} High</span> |
      <span style="color:#FFD700;font-weight:700;">{{ counts.medium }} Medium</span> |
      <span style="color:#00FFD4;font-weight:700;">{{ counts.low }} Low</span> |
      <span style="color:#666;">{{ counts.info }} Info</span>
    </p>
  </section>

  <!-- TOC -->
  <div class="toc">
    <h3>📑 Table of Contents</h3>
    {% for f in all_findings %}
    <a href="#finding-{{ loop.index }}">
      {{ loop.index }}. {{ f.name }}
      <span class="sev-indicator">
        <span class="sev sev-{{ f.severity }}">{{ f.severity | upper }}</span>
      </span>
    </a>
    {% endfor %}
  </div>

  <!-- FINDINGS -->
  <section>
    <h2>⚡ Vulnerability Details</h2>

    {% for f in all_findings %}
    <div class="vuln-card" id="finding-{{ loop.index }}">
      <div class="vuln-header">
        <div class="vuln-id">NSP-{{ loop.index | string | zfill(3) }}</div>
        <div class="vuln-title">{{ f.name }}</div>
        <span class="sev sev-{{ f.severity }}">{{ f.severity | upper }}</span>
      </div>
      <div class="vuln-body">

        <!-- Overview -->
        <table>
          <tr><td>Host / URL</td><td>{{ f.host }}</td></tr>
          <tr><td>Tool Source</td><td>{{ f.source | upper }}</td></tr>
          {% if f.cve %}<tr><td>CVE ID</td><td><strong>{{ f.cve }}</strong></td></tr>{% endif %}
          {% if f.cwe %}<tr><td>CWE ID</td><td>{{ f.cwe }}</td></tr>{% endif %}
          <tr><td>MITRE ATT&CK</td>
            <td>{% for m in f.mitre %}<span class="mitre-badge">{{ m }}</span>{% endfor %}</td>
          </tr>
          <tr><td>Description</td><td>{{ f.description }}</td></tr>
        </table>

        <!-- CVSS 3.1 -->
        {% if f.cvss > 0 %}
        <div class="cvss-block">
          <span class="cvss-score-big"
            style="color:{% if f.cvss>=9 %}#FF003C{% elif f.cvss>=7 %}#FF8C00{% elif f.cvss>=4 %}#FFD700{% else %}#00FFD4{% endif %}">
            {{ f.cvss }}
          </span>
          <span class="sev sev-{{ f.severity }}">{{ f.severity | upper }}</span>
          {% if f.cvss_vector %}
          <div class="cvss-vector">{{ f.cvss_vector }}</div>
          <div class="cvss-grid">
            {% for k, v in f.cvss_breakdown.items() %}
            <div class="cvss-cell">
              <div class="lbl">{{ k }}</div>
              <div class="val">{{ v }}</div>
            </div>
            {% endfor %}
          </div>
          {% endif %}
        </div>
        {% endif %}

        <!-- Evidence -->
        {% if f.request %}
        <div class="evidence-block">
          <h4>📤 HTTP Request (PoC)</h4>
          <div class="code-block">{{ f.request | e }}</div>
        </div>
        {% endif %}
        {% if f.response %}
        <div class="evidence-block">
          <h4>📥 HTTP Response (Evidence)</h4>
          <div class="code-block">{{ f.response | e }}</div>
        </div>
        {% endif %}
        {% if f.evidence %}
        <div class="evidence-block">
          <h4>🔍 Evidence / Output</h4>
          <div class="code-block">{{ f.evidence | e }}</div>
        </div>
        {% endif %}

        <!-- Remediation -->
        <div class="remediation-block">
          <h4>🛠️ Remediation Steps</h4>
          {% for step in f.remediation_steps %}
          <div class="step">
            <span class="step-num">{{ loop.index }}.</span>
            <span class="step-text">{{ step }}</span>
          </div>
          {% endfor %}
          {% if f.references %}
          <p style="margin-top:12px;color:var(--nsp-muted);font-size:11px;">
            <strong>References:</strong> {{ f.references | join(" | ") }}
          </p>
          {% endif %}
        </div>

      </div>
    </div>
    {% endfor %}
  </section>

  <hr class="divider">

  <!-- FOOTER -->
  <div class="footer">
    <div><span class="brand">OPTIMIUM NEXUS LLC</span> | contact@optimiumnexus.com</div>
    <div>NEXUS SPECTER PRO v1.0.0-SPECTER | CONFIDENTIAL TECHNICAL REPORT</div>
    <div>{{ report_date }}</div>
  </div>

</div>
</body>
</html>"""


# ── Default remediation library ─────────────────────────────────────────────
REMEDIATION_LIBRARY = {
    "sqli": [
        "Use parameterized queries or prepared statements — never concatenate user input into SQL.",
        "Implement an allowlist input validation for all database-bound parameters.",
        "Apply the principle of least privilege on database accounts — restrict INSERT/DELETE/DROP.",
        "Enable a Web Application Firewall (WAF) with SQL injection rule signatures.",
        "Conduct a full code audit for all database interaction points.",
    ],
    "xss": [
        "Encode all user-supplied output using context-aware encoding (HTML, JS, URL, CSS).",
        "Implement a strict Content Security Policy (CSP) header.",
        "Use modern frameworks that auto-escape template variables (React, Angular, Vue).",
        "Validate and sanitize all input server-side using an allowlist approach.",
        "Set HttpOnly and Secure flags on all session cookies.",
    ],
    "ssrf": [
        "Validate and allowlist permitted URL schemes, hosts, and ports.",
        "Block requests to RFC-1918 private IP ranges and cloud metadata endpoints.",
        "Disable unnecessary URL fetch functionality or sandbox it in an isolated network.",
        "Enforce IMDSv2 on AWS EC2 instances to require session-oriented requests.",
        "Log and alert on outbound requests to non-approved destinations.",
    ],
    "default": [
        "Apply the vendor-recommended security patch or configuration change immediately.",
        "Test the remediation in a staging environment before production deployment.",
        "Conduct a post-remediation verification scan to confirm resolution.",
        "Document the finding and remediation in your vulnerability management system.",
        "Review similar components in the codebase/infrastructure for the same issue.",
    ],
}

MITRE_WEB_MAP = {
    "sqli":          ["T1190 — Exploit Public-Facing Application", "T1059 — Command and Scripting Interpreter"],
    "xss":           ["T1059.007 — JavaScript", "T1185 — Browser Session Hijacking"],
    "ssrf":          ["T1090 — Proxy", "T1552.005 — Cloud Instance Metadata API"],
    "rce":           ["T1190 — Exploit Public-Facing Application", "T1059 — Command Execution"],
    "default-login": ["T1078 — Valid Accounts", "T1110.002 — Brute Force: Password Spraying"],
    "misconfig":     ["T1592 — Gather Victim Host Information"],
    "exposure":      ["T1213 — Data from Information Repositories"],
    "lfi":           ["T1005 — Data from Local System"],
    "jwt":           ["T1078 — Valid Accounts", "T1550 — Use Alternate Authentication Material"],
}


class TechnicalReportGenerator:
    """
    NEXUS SPECTER PRO Technical Report Generator v2.
    Produces full PoC evidence reports with CVSS 3.1 breakdown,
    MITRE ATT&CK mapping, and step-by-step remediation.
    """

    def __init__(self, results: dict, session_id: str, output_dir: Path,
                 client_name: str = "Client", target: str = "Target",
                 engagement_type: str = "Black Box Penetration Test"):
        self.results         = results
        self.session_id      = session_id
        self.output_dir      = Path(output_dir)
        self.client_name     = client_name
        self.target          = target
        self.engagement_type = engagement_type
        self.report_date     = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _cvss_severity(self, score: float) -> str:
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        if score >= 0.1: return "low"
        return "info"

    def _get_remediation(self, finding: dict) -> list:
        tags = finding.get("tags", [])
        for tag in tags:
            if tag in REMEDIATION_LIBRARY:
                return REMEDIATION_LIBRARY[tag]
        title_lower = finding.get("name","").lower()
        for key in REMEDIATION_LIBRARY:
            if key in title_lower:
                return REMEDIATION_LIBRARY[key]
        return REMEDIATION_LIBRARY["default"]

    def _get_mitre(self, finding: dict) -> list:
        tags = finding.get("tags", [])
        for tag in tags:
            if tag in MITRE_WEB_MAP:
                return MITRE_WEB_MAP[tag]
        return ["T1190 — Exploit Public-Facing Application"]

    def _parse_cvss_vector(self, vector: str) -> dict:
        breakdown = {}
        if not vector or "CVSS" not in vector:
            return breakdown
        try:
            parts = vector.split("/")
            labels = {"AV":"Attack Vector","AC":"Attack Complexity","PR":"Privileges Required",
                      "UI":"User Interaction","S":"Scope","C":"Confidentiality",
                      "I":"Integrity","A":"Availability"}
            for part in parts[1:]:
                k, v = part.split(":")
                full_val = CVSS31_VECTORS.get(k, {}).get(v, v)
                breakdown[labels.get(k, k)] = full_val
        except Exception:
            pass
        return breakdown

    def _build_all_findings(self) -> list:
        """Flatten all findings from all phases into a single sorted list."""
        all_f = []
        vuln_data = self.results.get("vuln_scan", {})

        # Nuclei findings
        nuclei = vuln_data.get("nuclei", {}).get("by_severity", {})
        for sev in ["critical","high","medium","low","info"]:
            for f in nuclei.get(sev, []):
                vector = f.get("cvss_vector","")
                all_f.append({
                    "name":             f.get("name","Unknown"),
                    "severity":         sev,
                    "source":           "nuclei",
                    "host":             f.get("host",""),
                    "cve":              f.get("cve_id",""),
                    "cwe":              "",
                    "cvss":             f.get("cvss_score", 0.0),
                    "cvss_vector":      vector,
                    "cvss_breakdown":   self._parse_cvss_vector(vector),
                    "description":      f.get("description",""),
                    "evidence":         f.get("raw_response","")[:1500],
                    "request":          f.get("curl_command",""),
                    "response":         "",
                    "tags":             f.get("tags",[]),
                    "mitre":            self._get_mitre(f),
                    "references":       f.get("reference",[]),
                    "remediation_steps":self._get_remediation(f),
                })

        # Web scanner findings
        web = vuln_data.get("web_scan", {}).get("by_severity", {})
        for sev in ["critical","high","medium","low","info"]:
            for f in web.get(sev, []):
                all_f.append({
                    "name":             f.get("title","Unknown"),
                    "severity":         sev,
                    "source":           f.get("source","scanner"),
                    "host":             f.get("url",""),
                    "cve":              "",
                    "cwe":              f.get("cwe",""),
                    "cvss":             f.get("cvss",0.0),
                    "cvss_vector":      "",
                    "cvss_breakdown":   {},
                    "description":      f.get("description",""),
                    "evidence":         f.get("evidence",""),
                    "request":          "",
                    "response":         "",
                    "tags":             [],
                    "mitre":            self._get_mitre(f),
                    "references":       [f.get("reference","")] if f.get("reference") else [],
                    "remediation_steps":self._get_remediation(f),
                })

        return all_f

    def _count_by_severity(self, findings: list) -> dict:
        c = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
        for f in findings:
            c[f.get("severity","info")] = c.get(f.get("severity","info"),0) + 1
        return c

    def generate_html_technical(self) -> Path:
        all_findings = self._build_all_findings()
        counts       = self._count_by_severity(all_findings)

        env      = Environment(loader=BaseLoader())
        template = env.from_string(TECHNICAL_TEMPLATE)
        rendered = template.render(
            session_id      = self.session_id,
            client_name     = self.client_name,
            target          = self.target,
            report_date     = self.report_date,
            engagement_type = self.engagement_type,
            all_findings    = all_findings,
            counts          = counts,
        )
        out = self.output_dir / f"{self.session_id}_technical.html"
        out.write_text(rendered, encoding="utf-8")
        console.print(f"[bold #00FFD4]  ✅ Technical HTML report: {out}[/bold #00FFD4]")
        return out

    def generate_pdf(self, html_path: Path) -> Path:
        pdf = html_path.with_suffix(".pdf")
        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(pdf))
            console.print(f"[bold #00FFD4]  ✅ Technical PDF report: {pdf}[/bold #00FFD4]")
        except ImportError:
            try:
                import subprocess
                subprocess.run(["wkhtmltopdf","--enable-local-file-access",
                                "--page-size","A4", str(html_path), str(pdf)],
                               capture_output=True, timeout=180)
            except Exception as e:
                log.warning(f"[REPORT] PDF generation failed: {e}")
        return pdf

    def generate_all(self) -> dict:
        console.print(f"[bold #7B00FF]  📊 Generating Technical Report v2 — {self.session_id}[/bold #7B00FF]")
        html = self.generate_html_technical()
        pdf  = self.generate_pdf(html)
        return {
            "technical_html": str(html),
            "technical_pdf":  str(pdf),
            "session_id":     self.session_id,
        }
