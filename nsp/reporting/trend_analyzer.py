"""
NEXUS SPECTER PRO — Risk Trend Analyzer
Compares consecutive NSP scan sessions to identify risk evolution:
new findings, resolved findings, score delta, exposure drift.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json, logging
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.reporting.trend")


@dataclass
class ScanSnapshot:
    session_id:    str
    timestamp:     str
    target:        str
    risk_score:    float
    total_findings:int
    by_severity:   dict = field(default_factory=dict)
    top_findings:  list = field(default_factory=list)


@dataclass
class TrendDelta:
    prev_session:  str
    curr_session:  str
    score_delta:   float
    direction:     str   # improving | worsening | stable
    new_findings:  list = field(default_factory=list)
    resolved:      list = field(default_factory=list)
    severity_deltas: dict = field(default_factory=dict)
    new_critical:  int  = 0
    new_high:      int  = 0
    summary:       str  = ""


class TrendAnalyzer:
    """
    Tracks risk evolution across NSP scan sessions.
    Persists snapshots as JSON. Computes deltas between scans.
    Generates trend sparkline data and HTML trend report.
    """

    STORE_DIR = Path("/tmp/nsp_trend_store")

    def __init__(self, output_dir: str = "/tmp/nsp_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.STORE_DIR.mkdir(parents=True, exist_ok=True)

    def _store_path(self, target: str) -> Path:
        safe = target.replace("/","_").replace(":","_").replace(".","_")
        return self.STORE_DIR / f"trend_{safe}.json"

    def _load_history(self, target: str) -> list:
        p = self._store_path(target)
        if p.exists():
            try:
                return json.loads(p.read_text())
            except Exception:
                pass
        return []

    def _save_history(self, target: str, history: list):
        self._store_path(target).write_text(
            json.dumps(history, indent=2, default=str)
        )

    def _compute_risk_score(self, findings: dict) -> float:
        by_sev = findings.get("by_severity", {})
        weights = {"critical": 15, "high": 8, "medium": 4, "low": 1, "info": 0}
        score = sum(
            weights.get(sev, 0) * len(items)
            for sev, items in by_sev.items()
        )
        return min(round(score, 1), 100)

    def record_snapshot(self, session_id: str, target: str,
                         findings: dict) -> ScanSnapshot:
        by_sev    = findings.get("by_severity", {})
        risk      = self._compute_risk_score(findings)
        top       = []
        for sev in ["critical","high","medium"]:
            top.extend(f.get("name","")[:50] for f in by_sev.get(sev,[])[:3])

        snap = ScanSnapshot(
            session_id     = session_id,
            timestamp      = datetime.utcnow().isoformat(),
            target         = target,
            risk_score     = risk,
            total_findings = sum(len(v) for v in by_sev.values()),
            by_severity    = {k: len(v) for k, v in by_sev.items()},
            top_findings   = top[:9],
        )
        history = self._load_history(target)
        history.append(snap.__dict__)
        history = history[-20:]   # keep last 20 scans
        self._save_history(target, history)
        log.info(f"[TREND] Snapshot saved: {session_id} | risk={risk}")
        return snap

    def compute_delta(self, target: str) -> TrendDelta | None:
        history = self._load_history(target)
        if len(history) < 2:
            log.info("[TREND] Not enough history for delta")
            return None

        prev = ScanSnapshot(**{k:v for k,v in history[-2].items()
                               if k in ScanSnapshot.__dataclass_fields__})
        curr = ScanSnapshot(**{k:v for k,v in history[-1].items()
                               if k in ScanSnapshot.__dataclass_fields__})

        score_delta = round(curr.risk_score - prev.risk_score, 1)
        if score_delta > 5:     direction = "worsening"
        elif score_delta < -5:  direction = "improving"
        else:                   direction = "stable"

        # New findings (in curr top but not prev)
        prev_set = set(prev.top_findings)
        new_f    = [f for f in curr.top_findings if f not in prev_set]
        resolved = [f for f in prev.top_findings if f not in set(curr.top_findings)]

        # Severity deltas
        sev_deltas = {}
        for sev in ["critical","high","medium","low","info"]:
            delta = curr.by_severity.get(sev,0) - prev.by_severity.get(sev,0)
            if delta != 0:
                sev_deltas[sev] = delta

        new_crit = max(0, curr.by_severity.get("critical",0) - prev.by_severity.get("critical",0))
        new_high = max(0, curr.by_severity.get("high",0) - prev.by_severity.get("high",0))

        arrow = "↑" if direction == "worsening" else "↓" if direction == "improving" else "→"
        summary = (f"Risk {arrow} {abs(score_delta):+.1f} pts vs previous scan. "
                   f"{len(new_f)} new findings. {len(resolved)} resolved. "
                   f"Direction: {direction.upper()}.")

        return TrendDelta(
            prev_session   = prev.session_id,
            curr_session   = curr.session_id,
            score_delta    = score_delta,
            direction      = direction,
            new_findings   = new_f,
            resolved       = resolved,
            severity_deltas= sev_deltas,
            new_critical   = new_crit,
            new_high       = new_high,
            summary        = summary,
        )

    def get_sparkline_data(self, target: str) -> list:
        history = self._load_history(target)
        return [round(h.get("risk_score",0),1) for h in history[-12:]]

    def _print_delta(self, delta: TrendDelta):
        dir_color = {"worsening":"#FF003C","improving":"#00FFD4","stable":"#FFD700"}
        dc = dir_color.get(delta.direction,"#888")
        console.print(f"  [bold {dc}]Trend: {delta.direction.upper()} | "
                       f"Δ Score: {delta.score_delta:+.1f}[/bold {dc}]")
        if delta.new_findings:
            console.print(f"  [bold #FF003C]  ⚡ New: {', '.join(delta.new_findings[:3])}[/bold #FF003C]")
        if delta.resolved:
            console.print(f"  [bold #00FFD4]  ✅ Resolved: {', '.join(delta.resolved[:3])}[/bold #00FFD4]")

    def generate_html(self, target: str, session_id: str) -> Path:
        history   = self._load_history(target)
        sparkline = self.get_sparkline_data(target)
        delta     = self.compute_delta(target)

        max_score = max(sparkline) if sparkline else 100
        bars = "".join(
            f'<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">'
            f'<div style="font-size:9px;color:#555;">{int(s)}</div>'
            f'<div style="height:{int(s/max_score*120)}px;min-height:4px;'
            f'background:{"#FF003C" if s>=70 else "#FF8C00" if s>=50 else "#00FFD4"};'
            f'border-radius:3px 3px 0 0;width:100%;"></div>'
            f'<div style="font-size:9px;color:#333;">S{i+1}</div>'
            f'</div>'
            for i, s in enumerate(sparkline)
        )

        delta_html = ""
        if delta:
            dc = {"worsening":"#FF003C","improving":"#00FFD4","stable":"#FFD700"}.get(delta.direction,"#888")
            new_rows = "".join(f'<li style="color:#FF003C;">{f}</li>' for f in delta.new_findings[:5])
            res_rows = "".join(f'<li style="color:#00FFD4;">{f}</li>' for f in delta.resolved[:5])
            delta_html = f"""
<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin:16px 0;">
  <div style="background:#0D0D0D;border:1px solid #1E1E1E;border-radius:8px;padding:16px;">
    <div style="font-size:10px;color:#555;letter-spacing:2px;margin-bottom:8px;">SCORE DELTA</div>
    <div style="font-size:36px;font-weight:900;color:{dc};">{delta.score_delta:+.1f}</div>
    <div style="color:{dc};font-size:12px;margin-top:4px;">{delta.direction.upper()}</div>
  </div>
  <div style="background:#0D0D0D;border:1px solid #1E1E1E;border-radius:8px;padding:16px;">
    <div style="font-size:10px;color:#555;letter-spacing:2px;margin-bottom:8px;">NEW FINDINGS</div>
    <ul style="padding-left:16px;font-size:12px;">{new_rows or '<li style="color:#555;">None</li>'}</ul>
  </div>
  <div style="background:#0D0D0D;border:1px solid #1E1E1E;border-radius:8px;padding:16px;">
    <div style="font-size:10px;color:#555;letter-spacing:2px;margin-bottom:8px;">RESOLVED</div>
    <ul style="padding-left:16px;font-size:12px;">{res_rows or '<li style="color:#555;">None</li>'}</ul>
  </div>
</div>"""

        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>NSP Trend — {target}</title>
<style>
  body{{background:#0A0A0A;color:#E8E8E8;font-family:monospace;margin:0;}}
  .header{{background:#0D0D0D;border-bottom:2px solid #7B00FF;padding:14px 32px;
    display:flex;justify-content:space-between;align-items:center;}}
  h1{{color:#7B00FF;font-size:16px;letter-spacing:4px;margin:0;}}
  .page{{padding:32px;max-width:900px;margin:0 auto;}}
  .section{{color:#7B00FF;font-size:12px;font-weight:700;letter-spacing:3px;margin:24px 0 12px;}}
</style>
</head><body>
<div class="header">
  <h1>⚡ NSP — RISK TREND ANALYSIS</h1>
  <div style="color:#555;font-size:11px;">{datetime.utcnow().strftime('%Y-%m-%d')} | {target}</div>
</div>
<div class="page">
  <div class="section">Risk Score Over Time ({len(sparkline)} scans)</div>
  <div style="background:#0D0D0D;border:1px solid #1E1E1E;border-radius:10px;padding:24px;">
    <div style="display:flex;align-items:flex-end;gap:6px;height:140px;">
      {bars}
    </div>
  </div>

  {delta_html}

  <div class="section">Scan History</div>
  <table style="width:100%;border-collapse:collapse;font-size:12px;">
    <thead><tr>
      {"".join(f'<th style="padding:8px 12px;color:#00FFD4;font-size:10px;letter-spacing:2px;border-bottom:1px solid #1E1E1E;text-align:left;">{h}</th>' for h in ['Session','Timestamp','Risk Score','Critical','High','Total'])}
    </tr></thead>
    <tbody>
      {"".join(f'<tr>{"".join(f"<td style=padding:8px_12px;border-bottom:1px_solid_#1E1E1E;>{v}</td>" for v in [h.get("session_id","")[-14:],h.get("timestamp","")[:10],h.get("risk_score",0),h.get("by_severity",{{}}).get("critical",0),h.get("by_severity",{{}}).get("high",0),h.get("total_findings",0)])}</tr>' for h in history[-10:])}
    </tbody>
  </table>
</div></body></html>"""

        out = self.output_dir / f"{session_id}_trend.html"
        out.write_text(html, encoding="utf-8")
        console.print(f"[bold #00FFD4]  ✅ Trend Report: {out}[/bold #00FFD4]")
        return out

    def run(self, session_id: str, target: str, findings: dict) -> dict:
        console.print(f"[bold #7B00FF]  📈 Trend Analyzer — {target}[/bold #7B00FF]")
        snap      = self.record_snapshot(session_id, target, findings)
        delta     = self.compute_delta(target)
        sparkline = self.get_sparkline_data(target)
        if delta:
            self._print_delta(delta)
        html = self.generate_html(target, session_id)
        return {
            "risk_score":  snap.risk_score,
            "sparkline":   sparkline,
            "delta":       delta.__dict__ if delta else None,
            "html":        str(html),
        }
