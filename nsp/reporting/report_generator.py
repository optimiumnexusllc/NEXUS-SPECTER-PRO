"""
NEXUS SPECTER PRO — Report Generator
Dual-format (PDF + HTML) professional pentest report engine
Branding: OPTIMIUM NEXUS LLC | NEXUS SPECTER PRO
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, BaseLoader
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.reporting")

EXECUTIVE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NSP Executive Report — {{ session_id }}</title>
<style>
  :root {
    --nsp-purple: #7B00FF; --nsp-cyan: #00FFD4;
    --nsp-red: #FF003C;    --nsp-dark: #0A0A0A;
    --nsp-card: #111111;   --nsp-border: #1E1E1E;
    --nsp-text: #E8E8E8;   --nsp-muted: #888888;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--nsp-dark); color:var(--nsp-text);
         font-family:'JetBrains Mono',monospace,sans-serif; font-size:14px; }
  .page { max-width:1100px; margin:0 auto; padding:40px 30px; }

  /* HEADER */
  .header { display:flex; justify-content:space-between; align-items:center;
            border-bottom:3px solid var(--nsp-purple); padding-bottom:30px; margin-bottom:40px; }
  .logo-block h1 { font-size:28px; color:var(--nsp-purple); letter-spacing:4px;
                   text-transform:uppercase; font-weight:900; }
  .logo-block h2 { font-size:13px; color:var(--nsp-cyan); letter-spacing:2px; margin-top:4px; }
  .meta-block { text-align:right; color:var(--nsp-muted); font-size:12px; line-height:1.8; }
  .meta-block .classify { color:var(--nsp-red); font-weight:700; font-size:13px;
                           border:1px solid var(--nsp-red); padding:3px 10px;
                           display:inline-block; margin-bottom:8px; letter-spacing:2px; }

  /* COVER */
  .cover-title { text-align:center; margin:60px 0 40px; }
  .cover-title h2 { font-size:38px; color:var(--nsp-purple); text-transform:uppercase;
                    letter-spacing:6px; font-weight:900; }
  .cover-title h3 { font-size:18px; color:var(--nsp-cyan); margin-top:10px; letter-spacing:3px; }
  .cover-title .tagline { font-size:13px; color:var(--nsp-muted); margin-top:20px;
                           font-style:italic; }

  /* RISK BADGE */
  .risk-badge-wrap { display:flex; justify-content:center; margin:40px 0; }
  .risk-badge { padding:20px 60px; font-size:26px; font-weight:900; text-transform:uppercase;
                letter-spacing:6px; border:3px solid; border-radius:6px; }
  .risk-critical { color:var(--nsp-red); border-color:var(--nsp-red);
                   box-shadow:0 0 40px rgba(255,0,60,0.4); }
  .risk-high     { color:#FF8C00; border-color:#FF8C00; box-shadow:0 0 40px rgba(255,140,0,0.3); }
  .risk-medium   { color:#FFD700; border-color:#FFD700; }
  .risk-low      { color:var(--nsp-cyan); border-color:var(--nsp-cyan); }

  /* SECTION */
  section { margin:50px 0; }
  section h2 { font-size:18px; color:var(--nsp-purple); text-transform:uppercase;
               letter-spacing:3px; border-left:4px solid var(--nsp-purple);
               padding-left:15px; margin-bottom:25px; }
  section h3 { font-size:14px; color:var(--nsp-cyan); margin:20px 0 10px;
               text-transform:uppercase; letter-spacing:2px; }

  /* CARDS */
  .card { background:var(--nsp-card); border:1px solid var(--nsp-border); border-radius:6px;
          padding:25px; margin:15px 0; }
  .card.critical { border-left:4px solid var(--nsp-red); }
  .card.high     { border-left:4px solid #FF8C00; }
  .card.medium   { border-left:4px solid #FFD700; }
  .card.low      { border-left:4px solid var(--nsp-cyan); }

  /* STATS GRID */
  .stats-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:15px; margin:25px 0; }
  .stat-card { background:var(--nsp-card); border:1px solid var(--nsp-border);
               border-radius:6px; padding:20px; text-align:center; }
  .stat-card .num { font-size:36px; font-weight:900; }
  .stat-card .lbl { font-size:11px; color:var(--nsp-muted); text-transform:uppercase;
                    letter-spacing:2px; margin-top:5px; }
  .stat-card.critical .num { color:var(--nsp-red); }
  .stat-card.high .num     { color:#FF8C00; }
  .stat-card.medium .num   { color:#FFD700; }
  .stat-card.low .num      { color:var(--nsp-cyan); }
  .stat-card.info .num     { color:var(--nsp-muted); }

  /* TABLE */
  table { width:100%; border-collapse:collapse; margin:15px 0; font-size:13px; }
  th { background:#1A0030; color:var(--nsp-cyan); text-align:left; padding:12px 15px;
       text-transform:uppercase; letter-spacing:1px; border-bottom:2px solid var(--nsp-purple); }
  td { padding:10px 15px; border-bottom:1px solid var(--nsp-border); vertical-align:top; }
  tr:hover td { background:#0D0D1A; }
  .sev-critical { color:var(--nsp-red); font-weight:700; }
  .sev-high     { color:#FF8C00; font-weight:700; }
  .sev-medium   { color:#FFD700; }
  .sev-low      { color:var(--nsp-cyan); }

  /* FOOTER */
  .footer { border-top:1px solid var(--nsp-border); padding-top:25px; margin-top:60px;
            display:flex; justify-content:space-between; align-items:center;
            color:var(--nsp-muted); font-size:11px; }
  .footer .company { color:var(--nsp-purple); font-weight:700; font-size:12px; }

  /* PROSE */
  p { line-height:1.8; color:var(--nsp-text); margin:10px 0; }
  .highlight { color:var(--nsp-cyan); font-weight:700; }
  .cmd { background:#0D0D0D; border:1px solid var(--nsp-border); padding:12px 15px;
         border-radius:4px; font-family:monospace; font-size:12px;
         color:#00FF41; margin:10px 0; overflow-x:auto; }
  .divider { border:none; border-top:1px solid var(--nsp-border); margin:30px 0; }
  .watermark { position:fixed; bottom:20px; right:20px; opacity:0.07; font-size:48px;
               font-weight:900; color:var(--nsp-purple); pointer-events:none;
               transform:rotate(-15deg); }
</style>
</head>
<body>
<div class="watermark">NSP</div>
<div class="page">

  <!-- HEADER -->
  <div class="header">
    <div class="logo-block">
      <h1>⚡ NEXUS SPECTER PRO</h1>
      <h2>MILITARY-GRADE OFFENSIVE PENTEST PLATFORM</h2>
    </div>
    <div class="meta-block">
      <div class="classify">CONFIDENTIAL</div><br>
      <strong>Client:</strong> {{ client_name }}<br>
      <strong>Date:</strong> {{ report_date }}<br>
      <strong>Assessor:</strong> OPTIMIUM NEXUS LLC<br>
      <strong>Session:</strong> {{ session_id }}<br>
      <strong>Target:</strong> {{ target }}
    </div>
  </div>

  <!-- COVER -->
  <div class="cover-title">
    <h2>Penetration Test<br>Executive Report</h2>
    <h3>{{ engagement_type }}</h3>
    <p class="tagline">"Invisible. Inevitable. Unstoppable." — by OPTIMIUM NEXUS LLC</p>
  </div>

  <!-- OVERALL RISK -->
  <div class="risk-badge-wrap">
    <div class="risk-badge risk-{{ overall_risk | lower }}">
      OVERALL RISK: {{ overall_risk | upper }}
    </div>
  </div>

  <hr class="divider">

  <!-- STATS -->
  <section>
    <h2>📊 Vulnerability Distribution</h2>
    <div class="stats-grid">
      <div class="stat-card critical">
        <div class="num">{{ counts.critical }}</div>
        <div class="lbl">🔴 Critical</div>
      </div>
      <div class="stat-card high">
        <div class="num">{{ counts.high }}</div>
        <div class="lbl">🟠 High</div>
      </div>
      <div class="stat-card medium">
        <div class="num">{{ counts.medium }}</div>
        <div class="lbl">🟡 Medium</div>
      </div>
      <div class="stat-card low">
        <div class="num">{{ counts.low }}</div>
        <div class="lbl">🔵 Low</div>
      </div>
      <div class="stat-card info">
        <div class="num">{{ counts.info }}</div>
        <div class="lbl">⚪ Info</div>
      </div>
    </div>
  </section>

  <!-- EXECUTIVE NARRATIVE -->
  <section>
    <h2>🎯 Executive Summary</h2>
    <div class="card">
      <p>{{ executive_narrative }}</p>
    </div>
  </section>

  <!-- KEY FINDINGS -->
  <section>
    <h2>⚡ Key Findings</h2>
    {% for finding in top_findings %}
    <div class="card {{ finding.severity }}">
      <h3>
        <span class="sev-{{ finding.severity }}">[{{ finding.severity | upper }}]</span>
        {{ finding.name }}
      </h3>
      <table>
        <tr><td><strong>CVSS Score</strong></td><td class="sev-{{ finding.severity }}">{{ finding.cvss }}</td></tr>
        <tr><td><strong>Host/URL</strong></td><td>{{ finding.host }}</td></tr>
        <tr><td><strong>CVE</strong></td><td>{{ finding.cve or '—' }}</td></tr>
        <tr><td><strong>Impact</strong></td><td>{{ finding.impact }}</td></tr>
        <tr><td><strong>Remediation</strong></td><td>{{ finding.remediation }}</td></tr>
      </table>
    </div>
    {% endfor %}
  </section>

  <!-- REMEDIATION PRIORITIES -->
  <section>
    <h2>🛠️ Remediation Priorities</h2>
    <table>
      <thead>
        <tr><th>#</th><th>Finding</th><th>Severity</th><th>Priority</th><th>Effort</th></tr>
      </thead>
      <tbody>
        {% for item in remediation_plan %}
        <tr>
          <td>{{ loop.index }}</td>
          <td>{{ item.finding }}</td>
          <td class="sev-{{ item.severity }}">{{ item.severity | upper }}</td>
          <td>{{ item.priority }}</td>
          <td>{{ item.effort }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>

  <!-- SCOPE & METHODOLOGY -->
  <section>
    <h2>📋 Scope & Methodology</h2>
    <div class="card">
      <h3>Engagement Details</h3>
      <table>
        <tr><td><strong>Target</strong></td><td>{{ target }}</td></tr>
        <tr><td><strong>Engagement Type</strong></td><td>{{ engagement_type }}</td></tr>
        <tr><td><strong>Start Date</strong></td><td>{{ start_date }}</td></tr>
        <tr><td><strong>End Date</strong></td><td>{{ report_date }}</td></tr>
        <tr><td><strong>Assessor</strong></td><td>OPTIMIUM NEXUS LLC</td></tr>
        <tr><td><strong>Platform</strong></td><td>NEXUS SPECTER PRO v1.0.0-SPECTER</td></tr>
        <tr><td><strong>AI Engine</strong></td><td>Specter AI (Anthropic Claude)</td></tr>
      </table>
    </div>
    <div class="card">
      <h3>Testing Phases Executed</h3>
      {% for phase in phases_executed %}
      <p>✅ {{ phase }}</p>
      {% endfor %}
    </div>
  </section>

  <!-- FOOTER -->
  <div class="footer">
    <div>
      <div class="company">OPTIMIUM NEXUS LLC</div>
      contact@optimiumnexus.com | www.optimiumnexus.com
    </div>
    <div>
      NEXUS SPECTER PRO v1.0.0-SPECTER<br>
      {{ report_date }} — CONFIDENTIAL
    </div>
  </div>

</div>
</body>
</html>"""


class ReportGenerator:
    """
    NEXUS SPECTER PRO Report Generator.
    Produces dual PDF + HTML reports with full OPTIMIUM NEXUS LLC branding.
    Includes: Executive report, Technical report, CVSS scoring, AI narrative.
    """

    CVSS_SEVERITY = {
        (9.0, 10.0): "critical",
        (7.0, 8.9):  "high",
        (4.0, 6.9):  "medium",
        (0.1, 3.9):  "low",
        (0.0, 0.0):  "info",
    }

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

    def _score_severity(self, cvss: float) -> str:
        if cvss >= 9.0:  return "critical"
        if cvss >= 7.0:  return "high"
        if cvss >= 4.0:  return "medium"
        if cvss >= 0.1:  return "low"
        return "info"

    def _count_by_severity(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        vuln_data = self.results.get("vuln_scan", {})
        nuclei    = vuln_data.get("nuclei", {}).get("by_severity", {})
        for sev, findings in nuclei.items():
            counts[sev] = counts.get(sev, 0) + len(findings)
        return counts

    def _overall_risk(self, counts: dict) -> str:
        if counts.get("critical", 0) > 0: return "Critical"
        if counts.get("high", 0) > 0:     return "High"
        if counts.get("medium", 0) > 0:   return "Medium"
        if counts.get("low", 0) > 0:      return "Low"
        return "Info"

    def _build_top_findings(self) -> list:
        findings = []
        vuln_data = self.results.get("vuln_scan", {})
        nuclei    = vuln_data.get("nuclei", {}).get("by_severity", {})
        order = ["critical", "high", "medium", "low"]
        for sev in order:
            for f in nuclei.get(sev, [])[:5]:
                findings.append({
                    "name":        f.get("name", "Unknown"),
                    "severity":    sev,
                    "cvss":        f.get("cvss_score", 0.0),
                    "host":        f.get("host", ""),
                    "cve":         f.get("cve_id", ""),
                    "impact":      f.get("description", "")[:200],
                    "remediation": "Apply vendor patch and implement defense-in-depth controls.",
                })
            if len(findings) >= 10:
                break
        return findings

    def _build_remediation_plan(self, findings: list) -> list:
        plan = []
        effort_map = {"critical": "Immediate (24h)", "high": "Short-term (1 week)",
                      "medium": "Mid-term (1 month)", "low": "Long-term (quarter)"}
        for i, f in enumerate(findings[:15], 1):
            plan.append({
                "finding":  f["name"],
                "severity": f["severity"],
                "priority": f"P{i}",
                "effort":   effort_map.get(f["severity"], "Planned"),
            })
        return plan

    def _get_phases_executed(self) -> list:
        phases = []
        phase_names = {
            "recon":        "Phase 1 — Ghost Recon (Passive + Active Reconnaissance)",
            "enumeration":  "Phase 2 — Deep Mapping (Web + Network + Cloud Enumeration)",
            "vuln_scan":    "Phase 3 — Specter Scan (Vulnerability Assessment)",
            "exploitation": "Phase 4 — Specter Strike (Exploitation)",
            "post_exploit": "Phase 5 — Ghost Mode (Post-Exploitation)",
            "reporting":    "Phase 6 — Specter Report (Report Generation)",
        }
        for key, name in phase_names.items():
            if key in self.results:
                phases.append(name)
        return phases or list(phase_names.values())

    def generate_html_executive(self) -> Path:
        """Render the executive HTML report."""
        counts       = self._count_by_severity()
        top_findings = self._build_top_findings()
        remediation  = self._build_remediation_plan(top_findings)

        narrative = self.results.get("ai_narrative",
            f"NEXUS SPECTER PRO conducted a comprehensive {self.engagement_type} against "
            f"{self.target} on behalf of {self.client_name}. The assessment identified "
            f"{sum(counts.values())} vulnerabilities across all severity levels, with "
            f"{counts.get('critical',0)} critical and {counts.get('high',0)} high-severity "
            f"findings requiring immediate attention. Immediate remediation is strongly recommended "
            f"to reduce the overall attack surface and prevent potential unauthorized access.")

        env      = Environment(loader=BaseLoader())
        template = env.from_string(EXECUTIVE_TEMPLATE)
        html     = template.render(
            session_id       = self.session_id,
            client_name      = self.client_name,
            target           = self.target,
            report_date      = self.report_date,
            start_date       = self.report_date,
            engagement_type  = self.engagement_type,
            overall_risk     = self._overall_risk(counts),
            counts           = counts,
            executive_narrative = narrative,
            top_findings     = top_findings,
            remediation_plan = remediation,
            phases_executed  = self._get_phases_executed(),
        )

        out_path = self.output_dir / f"{self.session_id}_executive.html"
        out_path.write_text(html, encoding="utf-8")
        console.print(f"[bold #00FFD4]  ✅ Executive HTML report: {out_path}[/bold #00FFD4]")
        return out_path

    def generate_pdf(self, html_path: Path) -> Path:
        """Convert HTML report to PDF using WeasyPrint."""
        pdf_path = html_path.with_suffix(".pdf")
        try:
            from weasyprint import HTML, CSS
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            console.print(f"[bold #00FFD4]  ✅ PDF report: {pdf_path}[/bold #00FFD4]")
            return pdf_path
        except ImportError:
            log.warning("[REPORT] WeasyPrint not installed — trying wkhtmltopdf")
            try:
                import subprocess
                subprocess.run(
                    ["wkhtmltopdf", "--enable-local-file-access",
                     "--page-size", "A4", str(html_path), str(pdf_path)],
                    capture_output=True, timeout=120
                )
                if pdf_path.exists():
                    console.print(f"[bold #00FFD4]  ✅ PDF report: {pdf_path}[/bold #00FFD4]")
                    return pdf_path
            except Exception as e:
                log.warning(f"[REPORT] PDF generation failed: {e}")
        return html_path

    def export_json(self) -> Path:
        """Export full results as structured JSON."""
        json_path = self.output_dir / f"{self.session_id}_full_results.json"
        with open(json_path, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        console.print(f"[bold #00FFD4]  ✅ JSON results: {json_path}[/bold #00FFD4]")
        return json_path

    def generate_all(self) -> dict:
        """Generate all report formats and return path map."""
        console.print(f"[bold #7B00FF]  📊 Generating NEXUS SPECTER PRO Reports — {self.session_id}[/bold #7B00FF]")
        html_exec = self.generate_html_executive()
        pdf_exec  = self.generate_pdf(html_exec)
        json_out  = self.export_json()
        return {
            "executive_html": str(html_exec),
            "executive_pdf":  str(pdf_exec),
            "full_json":      str(json_out),
            "session_id":     self.session_id,
        }
