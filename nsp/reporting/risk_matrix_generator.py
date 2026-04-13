"""
NEXUS SPECTER PRO — Risk Matrix Generator
Interactive 5x5 risk matrix (Likelihood × Impact) with heatmap.
Plots all findings, generates SVG + standalone HTML.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json, logging
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.reporting.risk_matrix")


@dataclass
class RiskItem:
    name:       str
    likelihood: int   # 1-5
    impact:     int   # 1-5
    severity:   str   = ""
    cve:        str   = ""
    host:       str   = ""
    score:      float = 0.0

    @property
    def risk_level(self) -> int:
        return self.likelihood * self.impact

    @property
    def risk_label(self) -> str:
        r = self.risk_level
        if r >= 20: return "CRITICAL"
        if r >= 15: return "HIGH"
        if r >= 10: return "MEDIUM"
        if r >=  5: return "LOW"
        return "MINIMAL"


CELL_COLORS = {
    (1,1):"#1A1A1A",(1,2):"#1A2A1A",(1,3):"#1A2A1A",(1,4):"#1A3A1A",(1,5):"#1A4A1A",
    (2,1):"#1A1A1A",(2,2):"#1A2A1A",(2,3):"#2A2A1A",(2,4):"#3A2A1A",(2,5):"#4A2A1A",
    (3,1):"#1A1A1A",(3,2):"#2A2A1A",(3,3):"#3A2A1A",(3,4):"#4A2A1A",(3,5):"#5A1A1A",
    (4,1):"#1A2A1A",(4,2):"#3A2A1A",(4,3):"#4A2A1A",(4,4):"#5A1A1A",(4,5):"#6A1A1A",
    (5,1):"#2A2A1A",(5,2):"#4A2A1A",(5,3):"#5A1A1A",(5,4):"#6A1A1A",(5,5):"#FF003C22",
}

DOT_COLORS = {
    "CRITICAL":"#FF003C","HIGH":"#FF8C00","MEDIUM":"#FFD700","LOW":"#00FFD4","MINIMAL":"#555",
}

RISK_ZONE_COLORS = {
    # (likelihood, impact) -> background color
}

def _cell_bg(l: int, i: int) -> str:
    score = l * i
    if score >= 20: return "rgba(255,0,60,0.20)"
    if score >= 15: return "rgba(255,140,0,0.15)"
    if score >= 10: return "rgba(255,215,0,0.12)"
    if score >=  5: return "rgba(0,255,212,0.08)"
    return "rgba(85,85,85,0.05)"


class RiskMatrixGenerator:
    """
    Generates an interactive 5×5 risk matrix HTML page.
    Each finding is plotted as a dot. Hover shows details.
    Colour zones: Critical (red) / High (orange) / Medium (yellow) / Low (cyan).
    """

    LIKELIHOOD_LABELS = ["Rare","Unlikely","Possible","Likely","Almost Certain"]
    IMPACT_LABELS     = ["Negligible","Minor","Moderate","Major","Catastrophic"]

    def __init__(self, output_dir: str = "/tmp/nsp_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _cvss_to_coords(self, cvss: float, severity: str) -> tuple:
        """Map CVSS score → (likelihood, impact) for the matrix."""
        impact_map = {"CRITICAL":(5,5),"HIGH":(4,4),"MEDIUM":(3,3),"LOW":(2,2),"INFO":(1,1)}
        # Fine-grained mapping using CVSS
        if cvss >= 9.0: return (5, 5)
        if cvss >= 7.5: return (4, 5)
        if cvss >= 7.0: return (4, 4)
        if cvss >= 6.0: return (3, 4)
        if cvss >= 5.0: return (3, 3)
        if cvss >= 4.0: return (3, 3)
        if cvss >= 3.0: return (2, 3)
        if cvss >= 2.0: return (2, 2)
        return impact_map.get(severity.upper(), (1,1))

    def _findings_to_items(self, findings: dict) -> list:
        items = []
        for sev in ["critical","high","medium","low","info"]:
            for f in findings.get("by_severity",{}).get(sev,[]):
                cvss = f.get("cvss_score", f.get("cvss", 0)) or 0
                l, i = self._cvss_to_coords(float(cvss), sev)
                items.append(RiskItem(
                    name       = f.get("name", f.get("title",""))[:40],
                    likelihood = l,
                    impact     = i,
                    severity   = sev,
                    cve        = f.get("cve_id", f.get("cve","")) or "",
                    host       = f.get("host", f.get("url",""))[:30] or "",
                    score      = float(cvss),
                ))
        return items

    def _build_grid_cells(self) -> str:
        cells = []
        cell_w, cell_h = 100, 80
        for li in range(1, 6):   # likelihood (row, bottom to top)
            for imp in range(1, 6):  # impact (col)
                x   = (imp - 1) * cell_w
                y   = (5 - li)  * cell_h
                bg  = _cell_bg(li, imp)
                score = li * imp
                cells.append(
                    f'<rect x="{x}" y="{y}" width="{cell_w}" height="{cell_h}" '
                    f'fill="{bg}" stroke="#1E1E1E" stroke-width="1"/>'
                )
                cells.append(
                    f'<text x="{x+cell_w-6}" y="{y+14}" font-size="9" '
                    f'fill="#333" text-anchor="end">{score}</text>'
                )
        return "\n".join(cells)

    def _build_dots(self, items: list) -> str:
        dots = []
        cell_w, cell_h = 100, 80
        # Group by cell to offset overlapping dots
        cell_groups: dict = {}
        for item in items:
            key = (item.likelihood, item.impact)
            cell_groups.setdefault(key, []).append(item)

        for (li, imp), group in cell_groups.items():
            base_x = (imp - 1) * cell_w + cell_w // 2
            base_y = (5 - li)  * cell_h + cell_h // 2
            for k, item in enumerate(group[:6]):
                # Offset dots in a small cluster
                ox = (k % 3 - 1) * 14
                oy = (k // 3 - 0) * 14
                color = DOT_COLORS.get(item.risk_label, "#888")
                tip   = f"{item.name} | {item.host} | CVSS:{item.score}"
                dots.append(
                    f'<circle cx="{base_x+ox}" cy="{base_y+oy}" r="7" '
                    f'fill="{color}" stroke="#0A0A0A" stroke-width="1.5" '
                    f'opacity="0.9" class="dot">'
                    f'<title>{tip}</title></circle>'
                )
        return "\n".join(dots)

    def generate(self, items: list, session_id: str = "NSP") -> Path:
        cell_w, cell_h = 100, 80
        svg_w, svg_h   = 5 * cell_w, 5 * cell_h

        grid_cells = self._build_grid_cells()
        dots       = self._build_dots(items)

        # Axis labels
        y_labels = "".join(
            f'<text x="-6" y="{(5-i)*cell_h + cell_h//2 + 4}" '
            f'font-size="10" fill="#888" text-anchor="end">{self.LIKELIHOOD_LABELS[i-1][:10]}</text>'
            for i in range(1, 6)
        )
        x_labels = "".join(
            f'<text x="{(i-1)*cell_w + cell_w//2}" y="{svg_h+16}" '
            f'font-size="10" fill="#888" text-anchor="middle">{self.IMPACT_LABELS[i-1][:10]}</text>'
            for i in range(1, 6)
        )

        # Summary stats
        by_level: dict = {}
        for item in items:
            by_level.setdefault(item.risk_label, []).append(item.name)

        stats_html = "".join(
            f'<div style="display:flex;justify-content:space-between;padding:6px 0;'
            f'border-bottom:1px solid #1E1E1E;font-size:12px;">'
            f'<span style="color:{DOT_COLORS.get(lvl,"#888")};">{lvl}</span>'
            f'<span style="font-weight:700;">{len(names)}</span></div>'
            for lvl, names in sorted(by_level.items(),
                                      key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","MINIMAL"].index(x[0])
                                      if x[0] in ["CRITICAL","HIGH","MEDIUM","LOW","MINIMAL"] else 9)
        )

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>NSP Risk Matrix — {session_id}</title>
<style>
  body{{background:#0A0A0A;color:#E8E8E8;font-family:monospace;margin:0;}}
  .header{{background:#0D0D0D;border-bottom:2px solid #7B00FF;padding:14px 32px;
    display:flex;justify-content:space-between;align-items:center;}}
  .header h1{{color:#7B00FF;font-size:16px;letter-spacing:4px;}}
  .page{{padding:32px;max-width:900px;margin:0 auto;}}
  .matrix-wrap{{display:flex;gap:40px;align-items:flex-start;margin-top:24px;}}
  .matrix-svg-wrap{{position:relative;}}
  .axis-title{{font-size:11px;color:#555;letter-spacing:2px;text-transform:uppercase;}}
  .sidebar{{min-width:200px;}}
  .dot{{cursor:pointer;transition:r 0.2s;}}
  .dot:hover{{r:10;}}
  .legend{{display:flex;flex-wrap:wrap;gap:12px;margin-top:16px;}}
  .legend-item{{display:flex;align-items:center;gap:6px;font-size:11px;color:#888;}}
  .legend-dot{{width:10px;height:10px;border-radius:50%;}}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ NSP — RISK MATRIX</h1>
  <div style="color:#555;font-size:11px;">{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | OPTIMIUM NEXUS LLC</div>
</div>
<div class="page">
  <div style="margin-bottom:16px;">
    <div style="color:#7B00FF;font-size:13px;font-weight:700;letter-spacing:3px;">5×5 RISK MATRIX</div>
    <div style="color:#555;font-size:11px;margin-top:4px;">{len(items)} findings plotted | Session: {session_id}</div>
  </div>

  <div class="matrix-wrap">
    <!-- Matrix -->
    <div class="matrix-svg-wrap">
      <div class="axis-title" style="margin-bottom:8px;text-align:center;">
        ← IMPACT →
      </div>
      <div style="display:flex;align-items:center;gap:0;">
        <div class="axis-title" style="writing-mode:vertical-lr;transform:rotate(180deg);
             margin-right:8px;">← LIKELIHOOD →</div>
        <svg width="{svg_w+40}" height="{svg_h+30}" style="overflow:visible;">
          <g transform="translate(0,0)">
            {grid_cells}
            {dots}
            {y_labels}
            {x_labels}
          </g>
        </svg>
      </div>
      <div class="legend">
        {"".join(f'<div class="legend-item"><div class="legend-dot" style="background:{c};"></div>{lvl}</div>' for lvl,c in DOT_COLORS.items())}
      </div>
    </div>

    <!-- Sidebar -->
    <div class="sidebar">
      <div style="color:#00FFD4;font-size:11px;letter-spacing:2px;margin-bottom:12px;">RISK SUMMARY</div>
      {stats_html}

      <div style="margin-top:24px;color:#00FFD4;font-size:11px;letter-spacing:2px;margin-bottom:12px;">ZONE GUIDE</div>
      <div style="font-size:11px;color:#555;line-height:1.9;">
        <span style="color:#FF003C;">■</span> Critical (20-25)<br>
        <span style="color:#FF8C00;">■</span> High (15-19)<br>
        <span style="color:#FFD700;">■</span> Medium (10-14)<br>
        <span style="color:#00FFD4;">■</span> Low (5-9)<br>
        <span style="color:#333;">■</span> Minimal (1-4)
      </div>
    </div>
  </div>
</div>
</body></html>"""

        out = self.output_dir / f"{session_id}_risk_matrix.html"
        out.write_text(html, encoding="utf-8")
        console.print(f"[bold #00FFD4]  ✅ Risk Matrix: {out}[/bold #00FFD4]")
        return out

    def run(self, findings: dict, session_id: str = "NSP") -> dict:
        console.print("[bold #7B00FF]  📊 Risk Matrix Generator...[/bold #7B00FF]")
        items = self._findings_to_items(findings)
        out   = self.generate(items, session_id)
        return {"html": str(out), "total_plotted": len(items)}
