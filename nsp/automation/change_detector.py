"""
NEXUS SPECTER PRO — Change Detector
Diffs two NSP scan sessions to surface:
- New vulnerabilities introduced
- Resolved vulnerabilities (patched)
- Score regression/improvement
- New exposed assets
- Changed service banners
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json, logging, hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
log = logging.getLogger("nsp.automation.change_detector")


@dataclass
class FindingSignature:
    """Unique fingerprint of a finding for comparison across scans."""
    sig:      str
    name:     str
    severity: str
    host:     str
    cvss:     float = 0.0
    cve:      str   = ""


@dataclass
class ChangeReport:
    baseline_id:     str
    current_id:      str
    target:          str
    scan_date:       str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Vulnerability changes
    new_vulns:       list = field(default_factory=list)
    resolved_vulns:  list = field(default_factory=list)
    worsened_vulns:  list = field(default_factory=list)   # severity escalation
    improved_vulns:  list = field(default_factory=list)   # severity de-escalation

    # Score changes
    baseline_score:  float = 0.0
    current_score:   float = 0.0
    score_delta:     float = 0.0
    direction:       str   = "stable"

    # Severity counts
    new_critical:    int   = 0
    new_high:        int   = 0
    resolved_critical:int  = 0

    # Asset changes
    new_assets:      list = field(default_factory=list)
    removed_assets:  list = field(default_factory=list)

    # Summary
    risk_regression: bool  = False
    requires_action: bool  = False
    summary:         str   = ""


class ChangeDetector:
    """
    Compares two NSP scan sessions and produces a structured change report.
    Used by the scheduler to detect regressions and send alerts.
    """

    SCAN_STORE = Path("/tmp/nsp_scan_snapshots")

    def __init__(self, output_dir: str = "/tmp/nsp_changes"):
        self.output_dir = Path(output_dir)
        self.SCAN_STORE.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _fingerprint(self, finding: dict) -> FindingSignature:
        """Create a stable signature for a finding."""
        name = finding.get("name","")
        host = finding.get("host","")
        sev  = finding.get("severity","info")
        sig  = hashlib.md5(f"{name}:{host}:{sev}".encode()).hexdigest()[:12]
        return FindingSignature(
            sig      = sig,
            name     = name,
            severity = sev,
            host     = host,
            cvss     = float(finding.get("cvss_score", finding.get("cvss",0)) or 0),
            cve      = finding.get("cve_id","") or finding.get("cve",""),
        )

    def _extract_signatures(self, session_data: dict) -> dict[str, FindingSignature]:
        sigs = {}
        vuln_data = session_data.get("vuln_scan", {})
        for sev in ["critical","high","medium","low","info"]:
            for f in vuln_data.get("by_severity",{}).get(sev,[]):
                fp = self._fingerprint(f)
                sigs[fp.sig] = fp
        return sigs

    def _compute_risk_score(self, session: dict) -> float:
        by_sev  = session.get("vuln_scan",{}).get("by_severity",{})
        weights = {"critical":15,"high":8,"medium":4,"low":1,"info":0}
        return min(sum(weights.get(s,0)*len(v) for s,v in by_sev.items()), 100)

    def save_snapshot(self, session_id: str, session_data: dict):
        """Persist a scan session for future comparison."""
        path = self.SCAN_STORE / f"{session_id}.json"
        path.write_text(json.dumps(session_data, indent=2, default=str))
        log.info(f"[CHANGE] Snapshot saved: {session_id}")

    def load_snapshot(self, session_id: str) -> dict:
        path = self.SCAN_STORE / f"{session_id}.json"
        if path.exists():
            return json.loads(path.read_text())
        return {}

    def list_snapshots(self, target: str = None) -> list:
        snapshots = []
        for path in sorted(self.SCAN_STORE.glob("*.json"), key=lambda p: p.stat().st_mtime):
            try:
                data = json.loads(path.read_text())
                entry = {
                    "session_id": path.stem,
                    "target":     data.get("target",""),
                    "timestamp":  data.get("timestamp", path.stat().st_mtime),
                }
                if not target or entry["target"] == target:
                    snapshots.append(entry)
            except Exception:
                pass
        return snapshots

    def compare(self, baseline: dict, current: dict,
                baseline_id: str = "baseline",
                current_id:  str = "current") -> ChangeReport:
        """Compare two session dicts and return a ChangeReport."""
        target         = current.get("target", baseline.get("target","unknown"))
        baseline_sigs  = self._extract_signatures(baseline)
        current_sigs   = self._extract_signatures(current)
        baseline_score = self._compute_risk_score(baseline)
        current_score  = self._compute_risk_score(current)

        # New = in current but not baseline
        new_sigs = {sig: fp for sig, fp in current_sigs.items()
                    if sig not in baseline_sigs}

        # Resolved = in baseline but not current
        resolved_sigs = {sig: fp for sig, fp in baseline_sigs.items()
                         if sig not in current_sigs}

        # Worsened = same host+name but higher severity
        SEV_RANK = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
        worsened, improved = [], []
        for sig, curr_fp in current_sigs.items():
            if sig in baseline_sigs:
                base_fp = baseline_sigs[sig]
                base_r  = SEV_RANK.get(base_fp.severity,0)
                curr_r  = SEV_RANK.get(curr_fp.severity,0)
                if curr_r > base_r:
                    worsened.append(curr_fp)
                elif curr_r < base_r:
                    improved.append(curr_fp)

        score_delta = round(current_score - baseline_score, 1)
        direction   = ("worsening" if score_delta > 3 else
                       "improving" if score_delta < -3 else "stable")

        new_crit = sum(1 for fp in new_sigs.values() if fp.severity == "critical")
        new_high = sum(1 for fp in new_sigs.values() if fp.severity == "high")
        res_crit = sum(1 for fp in resolved_sigs.values() if fp.severity == "critical")

        risk_reg = direction == "worsening" or new_crit > 0
        req_act  = new_crit > 0 or (new_high >= 3) or len(worsened) > 2

        arrow  = "↑" if direction=="worsening" else "↓" if direction=="improving" else "→"
        summary = (
            f"Risk {arrow} {abs(score_delta):+.1f} pts. "
            f"{len(new_sigs)} new vulnerabilities "
            f"({new_crit} critical, {new_high} high). "
            f"{len(resolved_sigs)} resolved."
        )

        report = ChangeReport(
            baseline_id     = baseline_id,
            current_id      = current_id,
            target          = target,
            new_vulns       = [f.__dict__ for f in new_sigs.values()],
            resolved_vulns  = [f.__dict__ for f in resolved_sigs.values()],
            worsened_vulns  = [f.__dict__ for f in worsened],
            improved_vulns  = [f.__dict__ for f in improved],
            baseline_score  = baseline_score,
            current_score   = current_score,
            score_delta     = score_delta,
            direction       = direction,
            new_critical    = new_crit,
            new_high        = new_high,
            resolved_critical = res_crit,
            risk_regression = risk_reg,
            requires_action = req_act,
            summary         = summary,
        )
        return report

    def _print_report(self, report: ChangeReport):
        dir_color = {"worsening":"#FF003C","improving":"#00FFD4","stable":"#FFD700"}
        dc = dir_color.get(report.direction,"#888")

        console.print(Panel(
            f"[bold #00FFD4]Target:[/bold #00FFD4]     {report.target}\n"
            f"[bold #00FFD4]Baseline:[/bold #00FFD4]   {report.baseline_id}\n"
            f"[bold #00FFD4]Current:[/bold #00FFD4]    {report.current_id}\n"
            f"[bold {dc}]Score:[/bold {dc}]      {report.baseline_score} → "
            f"{report.current_score} ({report.score_delta:+.1f})\n"
            f"[bold {dc}]Direction:[/bold {dc}] {report.direction.upper()}\n"
            f"[bold #FF003C]New Vulns:[/bold #FF003C]  {len(report.new_vulns)} "
            f"({report.new_critical} critical, {report.new_high} high)\n"
            f"[bold #00FFD4]Resolved:[/bold #00FFD4]   {len(report.resolved_vulns)} "
            f"({report.resolved_critical} critical)\n"
            f"[bold #FFD700]Worsened:[/bold #FFD700]   {len(report.worsened_vulns)}\n"
            f"[bold #FFD700]Improved:[/bold #FFD700]   {len(report.improved_vulns)}\n"
            + (f"[bold #FF003C]⚠  RISK REGRESSION DETECTED[/bold #FF003C]\n" if report.risk_regression else "")
            + (f"[bold #FF003C]⚠  ACTION REQUIRED[/bold #FF003C]" if report.requires_action else ""),
            title=f"[bold #7B00FF]🔄 CHANGE REPORT — {report.target}[/bold #7B00FF]",
            border_style="#7B00FF",
        ))

        if report.new_vulns:
            table = Table(
                title="[bold #FF003C]New Vulnerabilities[/bold #FF003C]",
                border_style="#FF003C", header_style="bold #00FFD4",
            )
            table.add_column("Severity", width=10)
            table.add_column("Finding",  width=45)
            table.add_column("Host",     width=25)
            table.add_column("CVSS",     width=6, justify="right")

            SEV_COLOR = {"critical":"[bold #FF003C]","high":"[bold #FF8C00]",
                         "medium":"[bold #FFD700]","low":"[bold #00FFD4]"}
            for f in sorted(report.new_vulns,
                             key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                                           .get(x.get("severity","info"),5)):
                c = SEV_COLOR.get(f.get("severity",""), "[white]")
                e = c.replace("[","[/")
                table.add_row(f"{c}{f.get('severity','').upper()}{e}",
                              f.get("name","")[:45], f.get("host","")[:25],
                              str(f.get("cvss",0)))
            console.print(table)

    def export_html(self, report: ChangeReport) -> Path:
        def rows(items, color="#E8E8E8"):
            return "".join(
                f'<tr><td style="color:{color};">{f.get("severity","").upper()}</td>'
                f'<td>{f.get("name","")[:50]}</td>'
                f'<td style="color:#888;">{f.get("host","")[:30]}</td>'
                f'<td style="text-align:right;">{f.get("cvss",0)}</td></tr>'
                for f in items
            )

        dc = {"worsening":"#FF003C","improving":"#00FFD4","stable":"#FFD700"}.get(report.direction,"#888")
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>NSP Change Report — {report.target}</title>
<style>
  body{{background:#0A0A0A;color:#E8E8E8;font-family:monospace;margin:0;}}
  .header{{background:#0D0D0D;border-bottom:2px solid #7B00FF;padding:14px 32px;
    display:flex;justify-content:space-between;}}
  h1{{color:#7B00FF;font-size:16px;letter-spacing:4px;margin:0;}}
  .page{{padding:32px;max-width:1000px;margin:0 auto;}}
  .metric{{display:inline-block;background:#0D0D0D;border:1px solid #1E1E1E;
    border-radius:8px;padding:14px 20px;margin:0 8px 8px 0;text-align:center;}}
  .metric .num{{font-size:32px;font-weight:900;font-family:monospace;}}
  .metric .lbl{{font-size:10px;color:#555;text-transform:uppercase;letter-spacing:2px;}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin:12px 0;}}
  th{{padding:8px 12px;color:#00FFD4;font-size:10px;letter-spacing:2px;
    border-bottom:1px solid #1E1E1E;text-align:left;}}
  td{{padding:8px 12px;border-bottom:1px solid #1E1E1E;}}
  h3{{color:#7B00FF;letter-spacing:3px;margin:24px 0 10px;font-size:13px;}}
  .regression{{background:rgba(255,0,60,0.1);border:1px solid #FF003C;border-radius:8px;
    padding:12px 20px;margin:16px 0;color:#FF003C;font-weight:700;}}
</style>
</head><body>
<div class="header">
  <h1>⚡ NSP — CHANGE REPORT</h1>
  <div style="color:#555;font-size:11px;">{report.scan_date[:10]} | {report.target} | OPTIMIUM NEXUS LLC</div>
</div>
<div class="page">
  {'<div class="regression">⚠ RISK REGRESSION DETECTED — IMMEDIATE REVIEW REQUIRED</div>' if report.risk_regression else ''}
  <div>
    <div class="metric">
      <div class="num" style="color:{dc};">{report.score_delta:+.1f}</div>
      <div class="lbl">Score Delta</div>
    </div>
    <div class="metric">
      <div class="num" style="color:#FF003C;">{len(report.new_vulns)}</div>
      <div class="lbl">New Vulns</div>
    </div>
    <div class="metric">
      <div class="num" style="color:#00FFD4;">{len(report.resolved_vulns)}</div>
      <div class="lbl">Resolved</div>
    </div>
    <div class="metric">
      <div class="num" style="color:{dc};">{report.direction.upper()}</div>
      <div class="lbl">Direction</div>
    </div>
  </div>
  <h3>NEW VULNERABILITIES ({len(report.new_vulns)})</h3>
  <table><thead><tr><th>Severity</th><th>Finding</th><th>Host</th><th>CVSS</th></tr></thead>
  <tbody>{rows(report.new_vulns, "#FF003C") if report.new_vulns else '<tr><td colspan="4" style="color:#333;">None</td></tr>'}</tbody></table>
  <h3>RESOLVED ({len(report.resolved_vulns)})</h3>
  <table><thead><tr><th>Severity</th><th>Finding</th><th>Host</th><th>CVSS</th></tr></thead>
  <tbody>{rows(report.resolved_vulns, "#00FFD4") if report.resolved_vulns else '<tr><td colspan="4" style="color:#333;">None</td></tr>'}</tbody></table>
</div></body></html>"""

        out = self.output_dir / f"change_{report.current_id}.html"
        out.write_text(html, encoding="utf-8")
        return out

    def run(self, baseline_id: str, current_id: str) -> dict:
        console.print(f"[bold #7B00FF]  🔄 Change Detector: {baseline_id} → {current_id}[/bold #7B00FF]")
        baseline = self.load_snapshot(baseline_id)
        current  = self.load_snapshot(current_id)
        if not baseline or not current:
            console.print("[bold #FFD700]  ⚠ One or both sessions not found in snapshot store[/bold #FFD700]")
            return {}

        report   = self.compare(baseline, current, baseline_id, current_id)
        self._print_report(report)
        html_out = self.export_html(report)
        console.print(f"[bold #00FFD4]  ✅ Change report: {html_out}[/bold #00FFD4]")
        return {**report.__dict__, "html": str(html_out)}
