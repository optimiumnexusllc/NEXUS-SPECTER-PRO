"""
NEXUS SPECTER PRO — MITRE ATT&CK Mapper
Generates an integrated ATT&CK Navigator-style HTML report directly from NSP findings.
Maps findings → Tactics → Techniques → Sub-techniques.
Produces: interactive HTML heatmap + JSON layer for official Navigator.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json, logging
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.reporting.mitre_mapper")

# Full ATT&CK Enterprise tactics + key techniques (representative subset)
ATTACK_MATRIX = {
    "TA0043 Reconnaissance":    ["T1595","T1592","T1589","T1590","T1591","T1596","T1593","T1594"],
    "TA0042 Resource Dev":      ["T1583","T1584","T1585","T1586","T1587","T1588","T1608"],
    "TA0001 Initial Access":    ["T1190","T1133","T1200","T1566","T1091","T1195","T1078","T1189"],
    "TA0002 Execution":         ["T1059","T1203","T1047","T1053","T1129","T1106","T1204"],
    "TA0003 Persistence":       ["T1547","T1037","T1543","T1546","T1574","T1505","T1136","T1078"],
    "TA0004 Privilege Esc":     ["T1548","T1134","T1068","T1574","T1055","T1053","T1078"],
    "TA0005 Defense Evasion":   ["T1140","T1562","T1070","T1036","T1027","T1055","T1218","T1497"],
    "TA0006 Credential Access": ["T1110","T1003","T1056","T1558","T1555","T1552","T1539"],
    "TA0007 Discovery":         ["T1087","T1010","T1217","T1482","T1083","T1046","T1018","T1082"],
    "TA0008 Lateral Movement":  ["T1210","T1534","T1570","T1563","T1021","T1550","T1080"],
    "TA0009 Collection":        ["T1557","T1560","T1123","T1119","T1115","T1213","T1005","T1039"],
    "TA0011 C2":                ["T1071","T1092","T1132","T1001","T1568","T1008","T1095","T1090"],
    "TA0010 Exfiltration":      ["T1041","T1011","T1052","T1048","T1567","T1029","T1030"],
    "TA0040 Impact":            ["T1531","T1485","T1486","T1565","T1491","T1498","T1496","T1489"],
}

TAG_TO_TECHNIQUES = {
    "sqli":           ["T1190","T1059"],
    "xss":            ["T1059.007","T1185"],
    "ssrf":           ["T1190","T1552.005"],
    "rce":            ["T1190","T1059"],
    "lfi":            ["T1083","T1005"],
    "cve":            ["T1190","T1203"],
    "misconfig":      ["T1592","T1082"],
    "exposed":        ["T1595","T1046"],
    "default-login":  ["T1078","T1110"],
    "auth":           ["T1078","T1556"],
    "cors":           ["T1071.001"],
    "jwt":            ["T1550","T1078"],
    "ssl":            ["T1557.002"],
    "graphql":        ["T1190"],
    "api":            ["T1190"],
    "takeover":       ["T1584","T1583"],
    "cloud":          ["T1552.005","T1530"],
    "s3":             ["T1530"],
    "idor":           ["T1078"],
    "brute":          ["T1110"],
}


@dataclass
class TechniqueHit:
    technique_id: str
    count:        int  = 0
    score:        int  = 0
    findings:     list = field(default_factory=list)


class MITREAttackMapper:
    """
    Maps NSP findings to MITRE ATT&CK and generates:
    1. Interactive inline HTML ATT&CK heatmap
    2. ATT&CK Navigator compatible JSON layer
    3. Rich console TTP coverage table
    """

    def __init__(self, output_dir: str = "/tmp/nsp_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.hits: dict[str, TechniqueHit] = {}

    def _map_findings(self, findings: dict):
        """Map all findings to MITRE techniques via tag lookup."""
        for sev in ["critical","high","medium","low","info"]:
            weight = {"critical":20,"high":15,"medium":10,"low":5,"info":2}.get(sev,1)
            for f in findings.get("by_severity",{}).get(sev,[]):
                tags = f.get("tags",[]) + [sev]
                mapped = set()
                for tag in tags:
                    for t_id in TAG_TO_TECHNIQUES.get(tag.lower(),[]):
                        mapped.add(t_id)
                for t_id in mapped:
                    if t_id not in self.hits:
                        self.hits[t_id] = TechniqueHit(t_id)
                    self.hits[t_id].count  += 1
                    self.hits[t_id].score   = min(self.hits[t_id].score + weight, 100)
                    self.hits[t_id].findings.append(f.get("name","")[:40])

    def _score_color(self, score: int) -> str:
        if score >= 80: return "#FF003C"
        if score >= 60: return "#FF8C00"
        if score >= 40: return "#FFD700"
        if score >= 20: return "#7B00FF"
        return "#00FFD4"

    def _build_html_matrix(self) -> str:
        """Build an inline HTML ATT&CK matrix."""
        tactic_cols = []
        for tactic, techniques in ATTACK_MATRIX.items():
            tactic_id, tactic_name = tactic.split(" ", 1)
            cells = []
            for t_id in techniques:
                hit   = self.hits.get(t_id)
                score = hit.score if hit else 0
                bg    = self._score_color(score) if score > 0 else "#111"
                opacity = f"opacity:{max(0.2, score/100):.1f};" if score > 0 else ""
                count_badge = f'<span style="font-size:8px;background:#0A0A0A;padding:1px 4px;border-radius:2px;">{hit.count}×</span>' if hit else ""
                tip   = f"{t_id}: {', '.join(hit.findings[:2])}" if hit else t_id
                cells.append(f'''
<div title="{tip}" style="background:{bg};{opacity}border:1px solid #1E1E1E;
  border-radius:4px;padding:5px 6px;font-size:9px;cursor:pointer;
  margin-bottom:3px;{'color:#fff;' if score>0 else 'color:#333;'}">
  {t_id} {count_badge}
</div>''')

            tactic_cols.append(f'''
<div style="min-width:110px;">
  <div style="background:#0D0D0D;border:1px solid #7B00FF;border-radius:4px;
    padding:6px;font-size:9px;color:#7B00FF;font-weight:700;letter-spacing:1px;
    margin-bottom:6px;text-align:center;">{tactic_name}</div>
  {"".join(cells)}
</div>''')

        return f'''
<div style="display:flex;gap:8px;overflow-x:auto;padding:8px;">
  {"".join(tactic_cols)}
</div>'''

    def export_navigator_layer(self, session_id: str) -> Path:
        techniques = []
        for t_id, hit in self.hits.items():
            techniques.append({
                "techniqueID":       t_id,
                "score":             hit.score,
                "color":             self._score_color(hit.score),
                "comment":           f"Observed {hit.count}× | NSP | OPTIMIUM NEXUS LLC",
                "enabled":           True,
                "metadata":          [],
                "showSubtechniques": False,
            })
        layer = {
            "name":        f"NSP — {session_id}",
            "versions":    {"attack":"14","navigator":"4.9","layer":"4.4"},
            "domain":      "enterprise-attack",
            "description": f"NEXUS SPECTER PRO engagement | OPTIMIUM NEXUS LLC | {datetime.utcnow().strftime('%Y-%m-%d')}",
            "techniques":  techniques,
            "gradient":    {"colors":["#ffe3e3","#ff6666","#ff0000"],"minValue":0,"maxValue":100},
        }
        out = self.output_dir / f"{session_id}_navigator_layer.json"
        out.write_text(json.dumps(layer, indent=2))
        return out

    def generate_html_report(self, session_id: str) -> Path:
        matrix_html = self._build_html_matrix()

        # Coverage stats
        covered_tactics = set()
        for t_id in self.hits:
            for tactic, techs in ATTACK_MATRIX.items():
                if t_id in techs:
                    covered_tactics.add(tactic.split(" ",1)[1])

        top_techniques = sorted(self.hits.values(), key=lambda h: -h.score)[:10]
        top_rows = "".join(
            f'<tr><td>{h.technique_id}</td>'
            f'<td style="color:{self._score_color(h.score)};font-weight:700;">{h.score}</td>'
            f'<td>{h.count}</td>'
            f'<td>{", ".join(h.findings[:2])[:50]}</td></tr>'
            for h in top_techniques
        )

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>NSP ATT&CK Map — {session_id}</title>
<style>
  body{{background:#0A0A0A;color:#E8E8E8;font-family:monospace;margin:0;}}
  .header{{background:#0D0D0D;border-bottom:2px solid #7B00FF;padding:14px 32px;
    display:flex;justify-content:space-between;align-items:center;}}
  .header h1{{color:#7B00FF;font-size:16px;letter-spacing:4px;}}
  .page{{padding:24px 32px;}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px;}}
  th{{padding:8px 12px;color:#00FFD4;font-size:10px;letter-spacing:2px;
    border-bottom:1px solid #1E1E1E;}}
  td{{padding:8px 12px;border-bottom:1px solid #1E1E1E;}}
  .section-title{{color:#7B00FF;font-size:12px;font-weight:700;letter-spacing:3px;
    margin:24px 0 12px;text-transform:uppercase;}}
  .stat{{display:inline-block;background:#0D0D0D;border:1px solid #1E1E1E;
    border-radius:8px;padding:12px 20px;margin:0 8px 8px 0;text-align:center;}}
  .stat .num{{font-size:28px;font-weight:900;font-family:monospace;color:#7B00FF;}}
  .stat .lbl{{font-size:10px;color:#555;text-transform:uppercase;letter-spacing:2px;}}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ NSP — MITRE ATT&CK COVERAGE</h1>
  <div style="color:#555;font-size:11px;">{datetime.utcnow().strftime('%Y-%m-%d')} | OPTIMIUM NEXUS LLC</div>
</div>
<div class="page">
  <!-- Stats -->
  <div style="margin-bottom:24px;">
    <div class="stat"><div class="num">{len(self.hits)}</div><div class="lbl">Techniques Mapped</div></div>
    <div class="stat"><div class="num">{len(covered_tactics)}</div><div class="lbl">Tactics Covered</div></div>
    <div class="stat"><div class="num">{sum(h.count for h in self.hits.values())}</div><div class="lbl">Total Observations</div></div>
    <div class="stat"><div class="num">{len(ATTACK_MATRIX)}</div><div class="lbl">Total Tactics</div></div>
  </div>

  <div class="section-title">ATT&CK Enterprise Matrix</div>
  {matrix_html}

  <div class="section-title">Top Observed Techniques</div>
  <table>
    <thead><tr><th>Technique ID</th><th>Score</th><th>Count</th><th>Top Findings</th></tr></thead>
    <tbody>{top_rows}</tbody>
  </table>

  <div style="margin-top:24px;font-size:11px;color:#555;">
    Import the Navigator JSON layer at:
    <a href="https://mitre-attack.github.io/attack-navigator/" style="color:#7B00FF;">
    mitre-attack.github.io/attack-navigator</a>
  </div>
</div>
</body></html>"""

        out = self.output_dir / f"{session_id}_mitre_attack.html"
        out.write_text(html, encoding="utf-8")
        console.print(f"[bold #00FFD4]  ✅ MITRE ATT&CK Report: {out}[/bold #00FFD4]")
        return out

    def run(self, findings: dict, session_id: str = "NSP") -> dict:
        console.print("[bold #7B00FF]  🎯 MITRE ATT&CK Mapper...[/bold #7B00FF]")
        self._map_findings(findings)
        html_path = self.generate_html_report(session_id)
        nav_path  = self.export_navigator_layer(session_id)
        console.print(f"  [#00FFD4]→ {len(self.hits)} techniques mapped across "
                       f"{len(ATTACK_MATRIX)} tactics[/#00FFD4]")
        return {
            "techniques_mapped": len(self.hits),
            "html":              str(html_path),
            "navigator_layer":   str(nav_path),
            "hits":              {k: {"score":v.score,"count":v.count}
                                  for k,v in self.hits.items()},
        }
