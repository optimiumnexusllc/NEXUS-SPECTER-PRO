"""
NEXUS SPECTER PRO — Compliance Gap Reporter
Maps NSP findings to: ISO 27001:2022 · NIS2 · SOC 2 · PCI-DSS v4 · GDPR
Generates per-framework gap analysis with remediation guidance.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json, logging
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.reporting.compliance")

# ── Framework control mappings ────────────────────────────────────────────────
FRAMEWORKS = {
    "ISO 27001:2022": {
        "A.5  Organizational Controls": {
            "A.5.1 Policies":               {"tags":["misconfig"],            "weight":5},
            "A.5.7 Threat Intelligence":    {"tags":["cve","exposed"],        "weight":8},
            "A.5.14 Info Transfer":         {"tags":["ssl","tls"],            "weight":6},
            "A.5.23 Cloud Security":        {"tags":["cloud","s3","azure"],   "weight":9},
        },
        "A.6  People Controls": {
            "A.6.1 Screening":              {"tags":["default-login"],        "weight":4},
            "A.6.8 Info Security Events":   {"tags":["exposed"],              "weight":5},
        },
        "A.8  Technology Controls": {
            "A.8.2 Privileged Access":      {"tags":["auth","default-login"], "weight":10},
            "A.8.7 Protection vs Malware":  {"tags":["rce","webshell"],      "weight":9},
            "A.8.9 Config Management":      {"tags":["misconfig"],            "weight":8},
            "A.8.20 Network Security":      {"tags":["exposed","cors"],       "weight":8},
            "A.8.23 Web Filtering":         {"tags":["xss","sqli"],           "weight":9},
            "A.8.24 Cryptography":          {"tags":["ssl","jwt"],            "weight":8},
            "A.8.28 Secure Coding":         {"tags":["sqli","xss","rce"],    "weight":10},
        },
    },
    "NIS2": {
        "Art.21 Risk Management": {
            "21.a Policies & Procedures":   {"tags":["misconfig"],            "weight":8},
            "21.b Incident Handling":       {"tags":["exposed","rce"],        "weight":9},
            "21.c Business Continuity":     {"tags":["rce","ransomware"],     "weight":8},
            "21.d Supply Chain":            {"tags":["cve","default-login"],  "weight":7},
            "21.e Secure Acquisition":      {"tags":["cve","misconfig"],      "weight":8},
            "21.f Access Control":          {"tags":["auth","brute","idor"],  "weight":10},
            "21.g Cryptography":            {"tags":["ssl","jwt"],            "weight":9},
        },
    },
    "SOC 2": {
        "CC6  Logical Access": {
            "CC6.1 Logical Access Controls":{"tags":["auth","idor"],          "weight":10},
            "CC6.2 Authentication":         {"tags":["default-login","brute"],"weight":10},
            "CC6.3 Authorization":          {"tags":["idor","auth"],          "weight":9},
            "CC6.6 External Threats":       {"tags":["exposed","cve"],        "weight":8},
            "CC6.7 Data in Transit":        {"tags":["ssl","cors"],           "weight":8},
        },
        "CC7  System Ops": {
            "CC7.1 Configuration":          {"tags":["misconfig"],            "weight":8},
            "CC7.2 Monitoring":             {"tags":["exposed"],              "weight":7},
            "CC7.3 Vulnerability Mgmt":     {"tags":["cve"],                 "weight":9},
        },
        "CC8  Change Mgmt": {
            "CC8.1 Change Control":         {"tags":["misconfig","cve"],      "weight":7},
        },
        "A1  Availability": {
            "A1.1 Capacity":                {"tags":["exposed"],              "weight":5},
        },
    },
    "PCI-DSS v4": {
        "Req 1 Network Controls": {
            "1.3 Network Access":           {"tags":["exposed","cors"],       "weight":9},
            "1.4 Network Connections":      {"tags":["exposed"],              "weight":8},
        },
        "Req 2 Secure Config": {
            "2.2 System Components":        {"tags":["misconfig","default-login"],"weight":10},
            "2.3 Wireless Environments":    {"tags":["exposed"],              "weight":7},
        },
        "Req 3 Protect Data": {
            "3.3 SAD Protection":           {"tags":["sqli","exposed"],       "weight":10},
            "3.4 PAN Rendering":            {"tags":["sqli"],                 "weight":10},
        },
        "Req 4 Encrypt Transmission": {
            "4.2 Encrypt in Transit":       {"tags":["ssl","tls"],            "weight":10},
        },
        "Req 6 Secure Systems": {
            "6.2 Security in SDLC":         {"tags":["sqli","xss","rce"],    "weight":10},
            "6.3 Security Vulnerabilities": {"tags":["cve"],                 "weight":9},
            "6.4 Web-facing Apps":          {"tags":["xss","sqli","cors"],   "weight":10},
        },
        "Req 7 Access Control": {
            "7.2 Access Control":           {"tags":["auth","idor"],          "weight":10},
        },
        "Req 8 User Auth": {
            "8.2 User IDs":                 {"tags":["default-login","brute"],"weight":10},
            "8.3 Strong Auth":              {"tags":["default-login"],        "weight":10},
        },
        "Req 11 Testing": {
            "11.3 External Pen Testing":    {"tags":["cve","exposed"],        "weight":8},
            "11.4 Intrusion Detection":     {"tags":["exposed"],              "weight":7},
        },
    },
    "GDPR": {
        "Art.25 Privacy by Design": {
            "Data Minimisation":            {"tags":["exposed"],              "weight":8},
            "Access Controls":              {"tags":["auth","idor"],          "weight":10},
        },
        "Art.32 Security of Processing": {
            "Pseudonymisation":             {"tags":["exposed","sqli"],       "weight":9},
            "Confidentiality & Integrity":  {"tags":["ssl","sqli"],           "weight":10},
            "Regular Testing":              {"tags":["cve","misconfig"],      "weight":8},
        },
        "Art.33 Breach Notification": {
            "Breach Detection":             {"tags":["exposed","rce"],        "weight":8},
        },
    },
}


@dataclass
class ControlResult:
    control_id:   str
    control_name: str
    status:       str    # PASS | FAIL | PARTIAL | NA
    score:        int    # 0-100
    findings:     list   = field(default_factory=list)
    gap:          str    = ""


@dataclass
class FrameworkResult:
    framework:    str
    overall_score:float  = 0.0
    controls:     list   = field(default_factory=list)
    pass_count:   int    = 0
    fail_count:   int    = 0
    partial_count:int    = 0
    gaps:         list   = field(default_factory=list)
    rating:       str    = ""


class ComplianceReporter:
    """
    Maps NSP pentest findings to compliance framework controls and
    generates an actionable gap analysis report.
    """

    def __init__(self, output_dir: str = "/tmp/nsp_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _get_finding_tags(self, findings: dict) -> dict:
        """Build tag → [findings] mapping from scan results."""
        tag_map: dict = {}
        for sev in ["critical","high","medium","low","info"]:
            for f in findings.get("by_severity",{}).get(sev,[]):
                for tag in f.get("tags",[]):
                    tag_map.setdefault(tag.lower(),[]).append({
                        "name":     f.get("name","")[:60],
                        "severity": sev,
                        "host":     f.get("host",""),
                    })
        return tag_map

    def _evaluate_control(self, ctrl_name: str, ctrl_cfg: dict,
                           tag_map: dict) -> ControlResult:
        tags     = ctrl_cfg.get("tags",[])
        weight   = ctrl_cfg.get("weight", 5)
        hits     = []
        for tag in tags:
            hits.extend(tag_map.get(tag,[]))

        if not hits:
            status = "PASS"
            score  = 100
        elif any(f["severity"] in ("critical","high") for f in hits):
            status = "FAIL"
            score  = max(0, 100 - weight * 10)
        else:
            status = "PARTIAL"
            score  = max(20, 100 - weight * 5)

        gap = (f"{len(hits)} finding(s) impact this control: "
               f"{', '.join(f['name'] for f in hits[:2])}"
               if hits else "")

        return ControlResult(
            control_id   = ctrl_name,
            control_name = ctrl_name,
            status       = status,
            score        = score,
            findings     = hits[:5],
            gap          = gap,
        )

    def evaluate_framework(self, framework_name: str, findings: dict) -> FrameworkResult:
        controls_def = FRAMEWORKS.get(framework_name, {})
        tag_map      = self._get_finding_tags(findings)
        all_controls = []
        scores       = []

        for domain, controls in controls_def.items():
            for ctrl_name, ctrl_cfg in controls.items():
                result = self._evaluate_control(ctrl_name, ctrl_cfg, tag_map)
                all_controls.append(result)
                scores.append(result.score)

        pass_c    = sum(1 for c in all_controls if c.status == "PASS")
        fail_c    = sum(1 for c in all_controls if c.status == "FAIL")
        partial_c = sum(1 for c in all_controls if c.status == "PARTIAL")
        overall   = round(sum(scores) / max(len(scores),1), 1)

        if overall >= 90:   rating = "Compliant"
        elif overall >= 70: rating = "Substantially Compliant"
        elif overall >= 50: rating = "Partially Compliant"
        else:               rating = "Non-Compliant"

        gaps = [c.gap for c in all_controls if c.gap]

        return FrameworkResult(
            framework     = framework_name,
            overall_score = overall,
            controls      = all_controls,
            pass_count    = pass_c,
            fail_count    = fail_c,
            partial_count = partial_c,
            gaps          = gaps,
            rating        = rating,
        )

    def _print_results(self, results: list):
        table = Table(
            title="[bold #7B00FF]📋 COMPLIANCE GAP ANALYSIS[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Framework",  width=18)
        table.add_column("Score",      width=8,  justify="right")
        table.add_column("Rating",     width=28)
        table.add_column("Pass",       width=6,  justify="right")
        table.add_column("Fail",       width=6,  justify="right")
        table.add_column("Partial",    width=8,  justify="right")
        table.add_column("Gaps",       width=5,  justify="right")

        for r in results:
            sc = r.overall_score
            color = ("#FF003C" if sc < 50 else "#FFD700" if sc < 70 else "#00FFD4")
            table.add_row(
                r.framework,
                f"[bold {color}]{sc}%[/bold {color}]",
                f"[{color}]{r.rating}[/{color}]",
                str(r.pass_count),
                f"[bold #FF003C]{r.fail_count}[/bold #FF003C]",
                str(r.partial_count),
                str(len(r.gaps)),
            )
        console.print(table)

    def generate_html(self, results: list, session_id: str) -> Path:
        rows = "".join(
            f"""<tr>
  <td style="font-weight:700;">{r.framework}</td>
  <td style="color:{'#FF003C' if r.overall_score<50 else '#FFD700' if r.overall_score<70 else '#00FFD4'};
     font-weight:900;font-size:18px;">{r.overall_score}%</td>
  <td style="color:{'#FF003C' if 'Non' in r.rating else '#FFD700' if 'Partial' in r.rating else '#00FFD4'};">{r.rating}</td>
  <td style="color:#00FFD4;">{r.pass_count}</td>
  <td style="color:#FF003C;font-weight:700;">{r.fail_count}</td>
  <td style="color:#FFD700;">{r.partial_count}</td>
</tr>""" for r in results
        )
        gap_detail = "".join(
            f"""<div style="margin-bottom:20px;">
  <div style="color:#7B00FF;font-weight:700;margin-bottom:8px;font-size:13px;">{r.framework}</div>
  {"".join(f'<div style="padding:6px 0;border-bottom:1px solid #1E1E1E;font-size:12px;color:#FFD700;">⚠ {g}</div>' for g in r.gaps[:5])}
</div>""" for r in results if r.gaps
        )

        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>NSP Compliance — {session_id}</title>
<style>
  body{{background:#0A0A0A;color:#E8E8E8;font-family:monospace;margin:0;}}
  .header{{background:#0D0D0D;border-bottom:2px solid #7B00FF;padding:14px 32px;
    display:flex;justify-content:space-between;align-items:center;}}
  h1{{color:#7B00FF;font-size:16px;letter-spacing:4px;margin:0;}}
  .page{{padding:32px;max-width:1200px;margin:0 auto;}}
  table{{width:100%;border-collapse:collapse;font-size:13px;margin:16px 0;}}
  th{{padding:10px 14px;color:#00FFD4;font-size:10px;letter-spacing:2px;
    border-bottom:1px solid #1E1E1E;text-align:left;}}
  td{{padding:10px 14px;border-bottom:1px solid #1E1E1E;}}
  .section{{color:#7B00FF;font-size:12px;font-weight:700;letter-spacing:3px;
    margin:28px 0 12px;text-transform:uppercase;}}
</style>
</head><body>
<div class="header">
  <h1>⚡ NSP — COMPLIANCE GAP ANALYSIS</h1>
  <div style="color:#555;font-size:11px;">{datetime.utcnow().strftime('%Y-%m-%d')} | OPTIMIUM NEXUS LLC</div>
</div>
<div class="page">
  <div class="section">Framework Summary</div>
  <table>
    <thead><tr><th>Framework</th><th>Score</th><th>Rating</th><th>Pass</th><th>Fail</th><th>Partial</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="section">Identified Gaps</div>
  {gap_detail}
</div></body></html>"""

        out = self.output_dir / f"{session_id}_compliance.html"
        out.write_text(html, encoding="utf-8")
        console.print(f"[bold #00FFD4]  ✅ Compliance Report: {out}[/bold #00FFD4]")
        return out

    def run(self, findings: dict, session_id: str = "NSP",
            frameworks: list = None) -> dict:
        console.print("[bold #7B00FF]  📋 Compliance Reporter...[/bold #7B00FF]")
        fws     = frameworks or list(FRAMEWORKS.keys())
        results = [self.evaluate_framework(fw, findings) for fw in fws]
        self._print_results(results)
        html = self.generate_html(results, session_id)
        return {
            "frameworks": [
                {"name": r.framework, "score": r.overall_score,
                 "rating": r.rating, "fail_count": r.fail_count,
                 "gap_count": len(r.gaps)}
                for r in results
            ],
            "html": str(html),
        }
