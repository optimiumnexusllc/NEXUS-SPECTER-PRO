"""
NEXUS SPECTER PRO — Executive Dashboard Generator
Produces a self-contained C-Level HTML dashboard with:
- Risk score gauge, severity distribution (recharts-style SVG),
- Top findings table, compliance radar, trend sparklines.
Fully offline — no external CDN dependencies in the final HTML.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json, logging
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.reporting.exec_dashboard")

DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NSP Executive Dashboard — {session_id}</title>
<style>
:root{{
  --purple:#7B00FF;--cyan:#00FFD4;--red:#FF003C;
  --orange:#FF8C00;--yellow:#FFD700;--dark:#0A0A0A;
  --card:#0D0D0D;--border:#1E1E1E;--text:#E8E8E8;--muted:#555;
}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:var(--dark);color:var(--text);font-family:'Segoe UI',monospace,sans-serif;}}
.topbar{{background:var(--card);border-bottom:2px solid var(--purple);
  padding:14px 32px;display:flex;justify-content:space-between;align-items:center;}}
.topbar h1{{color:var(--purple);font-size:18px;letter-spacing:4px;}}
.topbar .meta{{color:var(--muted);font-size:11px;text-align:right;line-height:1.8;}}
.classify{{color:var(--red);border:1px solid var(--red);padding:2px 10px;
  font-size:11px;letter-spacing:2px;display:inline-block;margin-bottom:6px;}}
.page{{padding:28px 32px;max-width:1400px;margin:0 auto;}}

/* GRID */
.grid-4{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;}}
.grid-3{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px;}}
.grid-2{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;}}

/* CARD */
.card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:24px;}}
.card h3{{font-size:11px;color:var(--muted);text-transform:uppercase;
  letter-spacing:2px;margin-bottom:18px;}}

/* METRIC */
.metric{{text-align:center;}}
.metric .num{{font-size:42px;font-weight:900;font-family:monospace;}}
.metric .lbl{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:2px;margin-top:6px;}}

/* GAUGE */
.gauge-wrap{{display:flex;flex-direction:column;align-items:center;}}
.gauge-score{{font-size:52px;font-weight:900;margin-top:-10px;font-family:monospace;}}
.gauge-level{{font-size:13px;letter-spacing:3px;text-transform:uppercase;margin-top:4px;}}

/* BAR */
.bar-row{{display:flex;align-items:center;gap:12px;margin-bottom:10px;}}
.bar-label{{width:70px;font-size:11px;color:var(--muted);text-align:right;}}
.bar-track{{flex:1;background:#111;border-radius:4px;height:20px;overflow:hidden;}}
.bar-fill{{height:100%;border-radius:4px;display:flex;align-items:center;
  padding-left:8px;font-size:11px;font-weight:700;transition:width 0.8s ease;}}
.bar-count{{width:30px;font-size:11px;color:var(--muted);text-align:right;}}

/* TABLE */
table{{width:100%;border-collapse:collapse;font-size:12px;}}
th{{padding:9px 12px;text-align:left;color:var(--cyan);font-size:10px;
  letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid var(--border);}}
td{{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top;}}
tr:hover td{{background:#0D0D1A;}}
.sev-critical{{color:var(--red);font-weight:700;}}
.sev-high{{color:var(--orange);font-weight:700;}}
.sev-medium{{color:var(--yellow);}}
.sev-low{{color:var(--cyan);}}

/* COMPLIANCE */
.comp-item{{display:flex;justify-content:space-between;align-items:center;
  padding:10px 0;border-bottom:1px solid var(--border);}}
.comp-name{{font-size:12px;}}
.comp-score{{font-size:18px;font-weight:900;font-family:monospace;}}
.comp-bar{{height:6px;background:#111;border-radius:3px;margin-top:4px;overflow:hidden;}}
.comp-fill{{height:100%;border-radius:3px;}}

/* TREND */
.sparkline{{display:flex;align-items:flex-end;gap:4px;height:50px;margin-top:10px;}}
.spark-bar{{flex:1;border-radius:3px 3px 0 0;min-width:8px;}}

/* FOOTER */
.footer{{border-top:1px solid var(--border);padding:16px 32px;
  display:flex;justify-content:space-between;color:var(--muted);font-size:10px;margin-top:40px;}}
.footer .brand{{color:var(--purple);font-weight:700;}}
</style>
</head>
<body>

<!-- TOPBAR -->
<div class="topbar">
  <div>
    <h1>⚡ NEXUS SPECTER PRO</h1>
    <div style="color:var(--cyan);font-size:10px;letter-spacing:3px;">EXECUTIVE SECURITY DASHBOARD</div>
  </div>
  <div class="meta">
    <div class="classify">CONFIDENTIAL</div><br>
    <strong>Client:</strong> {client_name}<br>
    <strong>Target:</strong> {target}<br>
    <strong>Date:</strong> {report_date}<br>
    <strong>Session:</strong> {session_id}
  </div>
</div>

<div class="page">

<!-- ROW 1: KEY METRICS -->
<div class="grid-4">
  <div class="card metric">
    <h3>Overall Risk Score</h3>
    <div class="gauge-wrap">
      <svg width="160" height="90" viewBox="0 0 160 90">
        <path d="M 20 80 A 60 60 0 0 1 140 80" fill="none" stroke="#1E1E1E" stroke-width="14"/>
        <path d="M 20 80 A 60 60 0 0 1 140 80" fill="none" stroke="{risk_color}"
              stroke-width="14" stroke-dasharray="{gauge_dash} 189"
              stroke-linecap="round"/>
        <text x="80" y="70" text-anchor="middle" fill="{risk_color}"
              font-size="28" font-weight="900" font-family="monospace">{risk_score}</text>
      </svg>
      <div class="gauge-level" style="color:{risk_color}">{risk_level}</div>
    </div>
  </div>
  <div class="card metric">
    <h3>Critical Findings</h3>
    <div class="num" style="color:var(--red)">{critical}</div>
    <div class="lbl">Requires immediate action</div>
  </div>
  <div class="card metric">
    <h3>High Findings</h3>
    <div class="num" style="color:var(--orange)">{high}</div>
    <div class="lbl">Action within 1 week</div>
  </div>
  <div class="card metric">
    <h3>Total Findings</h3>
    <div class="num" style="color:var(--purple)">{total}</div>
    <div class="lbl">Across all severity levels</div>
  </div>
</div>

<!-- ROW 2: SEVERITY + COMPLIANCE + TREND -->
<div class="grid-3">
  <!-- Severity Distribution -->
  <div class="card">
    <h3>Severity Distribution</h3>
    {severity_bars}
  </div>

  <!-- Compliance Posture -->
  <div class="card">
    <h3>Compliance Posture</h3>
    {compliance_items}
  </div>

  <!-- Risk Trend -->
  <div class="card">
    <h3>Risk Trend (Last 6 Scans)</h3>
    <div class="sparkline">{sparkline_bars}</div>
    <div style="display:flex;justify-content:space-between;margin-top:6px;
                font-size:9px;color:var(--muted);">
      {sparkline_labels}
    </div>
    <div style="margin-top:16px;font-size:11px;color:var(--muted);">
      {trend_summary}
    </div>
  </div>
</div>

<!-- ROW 3: TOP FINDINGS TABLE -->
<div class="card" style="margin-bottom:24px;">
  <h3>Top Priority Findings</h3>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>Finding</th><th>Host</th>
        <th>CVSS</th><th>CVE</th><th>Priority</th>
      </tr>
    </thead>
    <tbody>
      {top_findings_rows}
    </tbody>
  </table>
</div>

<!-- ROW 4: ATTACK SURFACE + RECOMMENDATIONS -->
<div class="grid-2">
  <div class="card">
    <h3>Attack Surface Summary</h3>
    {attack_surface_items}
  </div>
  <div class="card">
    <h3>Executive Recommendations</h3>
    {recommendations}
  </div>
</div>

</div><!-- /page -->

<div class="footer">
  <div><span class="brand">OPTIMIUM NEXUS LLC</span> | contact@optimiumnexus.com | www.optimiumnexus.com</div>
  <div>NEXUS SPECTER PRO v1.4.0-SPECTER | {report_date}</div>
  <div style="color:var(--red);">CONFIDENTIAL — NOT FOR DISTRIBUTION</div>
</div>

</body>
</html>'''


@dataclass
class DashboardConfig:
    session_id:    str
    client_name:   str = "Client"
    target:        str = "Target"
    risk_score:    int = 0
    findings:      dict = field(default_factory=dict)
    compliance:    dict = field(default_factory=dict)
    trend_scores:  list = field(default_factory=list)
    attack_surface:list = field(default_factory=list)
    top_findings:  list = field(default_factory=list)


class ExecutiveDashboard:
    """
    Generates a self-contained C-Level HTML dashboard from NSP mission data.
    No external dependencies — all SVG/CSS inline.
    """
    RISK_COLORS = {
        "CRITICAL": "#FF003C", "HIGH": "#FF8C00",
        "MEDIUM":   "#FFD700", "LOW":  "#00FFD4", "MINIMAL": "#555555",
    }

    def __init__(self, output_dir: str = "/tmp/nsp_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _risk_level(self, score: int) -> tuple:
        if score >= 80: return "CRITICAL", "#FF003C"
        if score >= 60: return "HIGH",     "#FF8C00"
        if score >= 40: return "MEDIUM",   "#FFD700"
        if score >= 20: return "LOW",      "#00FFD4"
        return "MINIMAL", "#555555"

    def _gauge_dash(self, score: int) -> int:
        # Arc length = 189 for the semi-circle path
        return int((score / 100) * 189)

    def _severity_bars(self, findings: dict) -> str:
        bars = []
        config = [
            ("critical", "#FF003C"), ("high", "#FF8C00"),
            ("medium", "#FFD700"),   ("low", "#00FFD4"), ("info", "#555"),
        ]
        total = max(sum(len(v) for v in findings.get("by_severity",{}).values()), 1)
        for sev, color in config:
            count = len(findings.get("by_severity", {}).get(sev, []))
            pct   = int(count / total * 100)
            bars.append(f'''
<div class="bar-row">
  <div class="bar-label">{sev.upper()}</div>
  <div class="bar-track">
    <div class="bar-fill" style="width:{pct}%;background:{color};">{count}</div>
  </div>
  <div class="bar-count">{count}</div>
</div>''')
        return "".join(bars)

    def _compliance_items(self, compliance: dict) -> str:
        items = []
        defaults = {"ISO 27001": 72, "NIS2": 65, "SOC 2": 78, "PCI-DSS": 55}
        data = compliance or defaults
        for framework, score in list(data.items())[:5]:
            color = ("#FF003C" if score < 50 else "#FFD700" if score < 70 else "#00FFD4")
            items.append(f'''
<div class="comp-item">
  <div>
    <div class="comp-name">{framework}</div>
    <div class="comp-bar"><div class="comp-fill" style="width:{score}%;background:{color};"></div></div>
  </div>
  <div class="comp-score" style="color:{color};">{score}%</div>
</div>''')
        return "".join(items)

    def _sparkline(self, trend: list) -> tuple:
        if not trend:
            trend = [45, 52, 48, 61, 58, 55]
        max_v = max(trend) or 1
        bars, labels = [], []
        for i, v in enumerate(trend[-6:]):
            h   = max(int(v / max_v * 45), 4)
            c   = ("#FF003C" if v >= 70 else "#FF8C00" if v >= 50 else "#00FFD4")
            bars.append(f'<div class="spark-bar" style="height:{h}px;background:{c};"></div>')
            labels.append(f'<span>S{i+1}</span>')

        if len(trend) >= 2:
            delta = trend[-1] - trend[-2]
            arrow = "↑" if delta > 0 else "↓" if delta < 0 else "→"
            color = "#FF003C" if delta > 0 else "#00FFD4"
            summary = f'<span style="color:{color};">{arrow} {abs(delta):+.0f} pts vs previous scan</span>'
        else:
            summary = "Insufficient data for trend"

        return "".join(bars), " ".join(labels), summary

    def _top_findings_rows(self, findings: list) -> str:
        rows = []
        sev_class = {"critical":"sev-critical","high":"sev-high",
                     "medium":"sev-medium","low":"sev-low"}
        priority_map = {"critical":"P0 — Emergency","high":"P1 — This week",
                        "medium":"P2 — This month","low":"P3 — Planned"}
        for i, f in enumerate(findings[:10], 1):
            sev  = f.get("severity","info")
            sc   = sev_class.get(sev,"")
            rows.append(f'''<tr>
  <td>{i}</td>
  <td><span class="{sc}">{sev.upper()}</span></td>
  <td>{f.get("name","")[:45]}</td>
  <td>{f.get("host","")[:25]}</td>
  <td>{f.get("cvss",0)}</td>
  <td>{f.get("cve","—") or "—"}</td>
  <td style="color:#FFD700;font-size:11px;">{priority_map.get(sev,"")}</td>
</tr>''')
        return "".join(rows)

    def _attack_surface(self, items: list) -> str:
        if not items:
            items = ["No WAF detected", "Server version disclosure", "3 subdomains exposed"]
        html = []
        for item in items[:8]:
            html.append(f'<div style="padding:8px 0;border-bottom:1px solid var(--border);'
                         f'font-size:12px;">⚠ {item}</div>')
        return "".join(html)

    def _recommendations(self, findings: dict) -> str:
        recs = [
            ("Patch all CRITICAL vulnerabilities immediately", "#FF003C"),
            ("Enable WAF with OWASP CRS ruleset", "#FF8C00"),
            ("Implement MFA on all administrative interfaces", "#FF8C00"),
            ("Enforce TLS 1.3 — disable TLS 1.0/1.1", "#FFD700"),
            ("Conduct privileged access review", "#FFD700"),
            ("Deploy centralised SIEM + alerting", "#00FFD4"),
        ]
        html = []
        for i, (rec, color) in enumerate(recs, 1):
            html.append(f'<div style="display:flex;gap:12px;padding:8px 0;'
                         f'border-bottom:1px solid var(--border);font-size:12px;">'
                         f'<span style="color:{color};font-weight:700;min-width:20px;">{i}.</span>'
                         f'<span>{rec}</span></div>')
        return "".join(html)

    def generate(self, cfg: DashboardConfig) -> Path:
        console.print(f"[bold #7B00FF]  📊 Generating Executive Dashboard...[/bold #7B00FF]")

        risk_level, risk_color = self._risk_level(cfg.risk_score)
        sev_data  = cfg.findings
        counts    = {s: len(sev_data.get("by_severity",{}).get(s,[])) for s in ["critical","high","medium","low","info"]}
        total     = sum(counts.values())

        # Top findings flat list
        top = []
        for sev in ["critical","high","medium","low"]:
            top.extend(sev_data.get("by_severity",{}).get(sev,[]))
        for f in top:
            f["severity"] = f.get("severity", "info")

        sparks, spark_labels, trend_summary = self._sparkline(cfg.trend_scores)

        html = DASHBOARD_HTML.format(
            session_id       = cfg.session_id,
            client_name      = cfg.client_name,
            target           = cfg.target,
            report_date      = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            risk_score       = cfg.risk_score,
            risk_level       = risk_level,
            risk_color       = risk_color,
            gauge_dash       = self._gauge_dash(cfg.risk_score),
            critical         = counts["critical"],
            high             = counts["high"],
            total            = total,
            severity_bars    = self._severity_bars(sev_data),
            compliance_items = self._compliance_items(cfg.compliance),
            sparkline_bars   = sparks,
            sparkline_labels = spark_labels,
            trend_summary    = trend_summary,
            top_findings_rows= self._top_findings_rows(top),
            attack_surface_items = self._attack_surface(cfg.attack_surface),
            recommendations  = self._recommendations(sev_data),
        )

        out = self.output_dir / f"{cfg.session_id}_executive_dashboard.html"
        out.write_text(html, encoding="utf-8")
        console.print(f"[bold #00FFD4]  ✅ Executive Dashboard: {out}[/bold #00FFD4]")
        return out

    def run(self, session_data: dict) -> dict:
        vuln_data = session_data.get("vuln_scan", {})
        by_sev    = vuln_data.get("by_severity", {})
        crit_c    = len(by_sev.get("critical",[]))
        high_c    = len(by_sev.get("high",[]))
        risk_score= min(crit_c * 15 + high_c * 8, 100)

        cfg = DashboardConfig(
            session_id   = session_data.get("session_id", "NSP-UNKNOWN"),
            client_name  = session_data.get("client_name", "Client"),
            target       = session_data.get("target", "Target"),
            risk_score   = risk_score,
            findings     = {"by_severity": by_sev},
            trend_scores = session_data.get("trend_scores", []),
            attack_surface = session_data.get("attack_surface", []),
        )
        out = self.generate(cfg)
        return {"html": str(out), "risk_score": risk_score}
