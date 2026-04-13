"""
NEXUS SPECTER PRO — Container Scanner
Trivy + Grype orchestration for container image vulnerability scanning.
Checks: OS packages, application dependencies, secrets, misconfigurations.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import subprocess, shutil, logging, json
from dataclasses import dataclass, field
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.devsecops.container")


@dataclass
class ContainerVuln:
    pkg_name:     str
    installed_ver:str
    fixed_ver:    str
    severity:     str
    cve_id:       str   = ""
    description:  str   = ""
    layer:        str   = ""
    scanner:      str   = "trivy"


@dataclass
class ContainerScanResult:
    image:          str
    total_vulns:    int   = 0
    by_severity:    dict  = field(default_factory=dict)
    os_info:        str   = ""
    secrets_found:  list  = field(default_factory=list)
    misconfigs:     list  = field(default_factory=list)
    vulns:          list  = field(default_factory=list)
    risk_score:     int   = 0


class ContainerScanner:
    """
    Container image security scanner for NEXUS SPECTER PRO.
    Trivy (preferred) → Grype (fallback).
    Scans: OS packages, language dependencies, secrets, config issues.
    """

    def __init__(self, output_dir: str = "/tmp/nsp_container"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _best_tool(self) -> str:
        for tool in ("trivy", "grype"):
            if shutil.which(tool):
                return tool
        return ""

    # ── Trivy ─────────────────────────────────────────────────────────────────
    def _run_trivy(self, image: str) -> ContainerScanResult:
        result   = ContainerScanResult(image=image)
        out_file = self.output_dir / "trivy_result.json"
        cmd = [
            "trivy", "image",
            "--format",    "json",
            "--output",    str(out_file),
            "--quiet",
            "--severity",  "CRITICAL,HIGH,MEDIUM,LOW",
            image,
        ]
        console.print(f"[#00FFD4]  [TRIVY] Scanning: {image}[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            log.warning("[CONTAINER] Trivy timeout")
            result.misconfigs.append("Scan timed out after 300s")
            return result

        if not out_file.exists():
            return result

        try:
            data = json.loads(out_file.read_text())
        except Exception as e:
            log.error(f"[CONTAINER] Trivy parse error: {e}")
            return result

        # OS metadata
        result.os_info = data.get("Metadata",{}).get("OS",{}).get("Name","")

        for report in data.get("Results",[]):
            # Vulnerabilities
            for v in report.get("Vulnerabilities",[]):
                sev = v.get("Severity","UNKNOWN").lower()
                vuln = ContainerVuln(
                    pkg_name     = v.get("PkgName",""),
                    installed_ver= v.get("InstalledVersion",""),
                    fixed_ver    = v.get("FixedVersion","") or "No fix",
                    severity     = sev,
                    cve_id       = v.get("VulnerabilityID",""),
                    description  = v.get("Description","")[:200],
                    layer        = v.get("Layer",{}).get("DiffID",""),
                    scanner      = "trivy",
                )
                result.vulns.append(vuln)
                result.by_severity[sev] = result.by_severity.get(sev,0) + 1

            # Secrets
            for s in report.get("Secrets",[]):
                result.secrets_found.append({
                    "type":   s.get("RuleID",""),
                    "title":  s.get("Title",""),
                    "target": s.get("Target",""),
                })

            # Misconfigurations
            for m in report.get("Misconfigurations",[]):
                result.misconfigs.append({
                    "id":          m.get("ID",""),
                    "title":       m.get("Title",""),
                    "severity":    m.get("Severity",""),
                    "description": m.get("Description","")[:150],
                })

        result.total_vulns = len(result.vulns)
        return result

    # ── Grype ─────────────────────────────────────────────────────────────────
    def _run_grype(self, image: str) -> ContainerScanResult:
        result   = ContainerScanResult(image=image)
        out_file = self.output_dir / "grype_result.json"
        cmd = ["grype", image, "--output", "json", "--file", str(out_file), "--quiet"]

        console.print(f"[#00FFD4]  [GRYPE] Scanning: {image}[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            return result

        if not out_file.exists():
            return result

        try:
            data = json.loads(out_file.read_text())
        except Exception:
            return result

        for match in data.get("matches",[]):
            art = match.get("artifact",{})
            vuln_data = match.get("vulnerability",{})
            sev = vuln_data.get("severity","unknown").lower()
            vuln = ContainerVuln(
                pkg_name     = art.get("name",""),
                installed_ver= art.get("version",""),
                fixed_ver    = ", ".join(
                    [f.get("version","") for f in vuln_data.get("fix",{}).get("versions",[])]
                ) or "No fix",
                severity = sev,
                cve_id   = vuln_data.get("id",""),
                description = vuln_data.get("description","")[:200],
                scanner  = "grype",
            )
            result.vulns.append(vuln)
            result.by_severity[sev] = result.by_severity.get(sev,0) + 1

        result.total_vulns = len(result.vulns)
        return result

    def _compute_risk(self, result: ContainerScanResult) -> int:
        weights = {"critical":15,"high":8,"medium":4,"low":1}
        score   = sum(weights.get(s,0)*c for s,c in result.by_severity.items())
        if result.secrets_found:
            score += 20 * len(result.secrets_found)
        return min(score, 100)

    def _print_result(self, result: ContainerScanResult):
        console.print(f"\n  [bold #7B00FF]Image:[/bold #7B00FF] {result.image}")
        if result.os_info:
            console.print(f"  [#00FFD4]OS: {result.os_info}[/#00FFD4]")

        table = Table(
            title=f"[bold #7B00FF]🐳 CONTAINER VULNS — {result.total_vulns}[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4", show_lines=False,
        )
        table.add_column("Severity",  width=10)
        table.add_column("Package",   width=28)
        table.add_column("Installed", width=15)
        table.add_column("Fixed In",  width=15)
        table.add_column("CVE",       width=20)

        SEV_COLOR = {"critical":"[bold #FF003C]","high":"[bold #FF8C00]",
                     "medium":"[bold #FFD700]","low":"[bold #00FFD4]"}
        SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
        sorted_vulns = sorted(result.vulns,
                               key=lambda v: SEV_ORDER.get(v.severity,4))
        for v in sorted_vulns[:25]:
            c = SEV_COLOR.get(v.severity,"[white]")
            e = c.replace("[","[/")
            table.add_row(
                f"{c}{v.severity.upper()}{e}",
                v.pkg_name[:28], v.installed_ver[:15],
                v.fixed_ver[:15], v.cve_id[:20],
            )
        console.print(table)

        if result.secrets_found:
            console.print(f"\n  [bold #FF003C]🔑 SECRETS FOUND: {len(result.secrets_found)}[/bold #FF003C]")
            for s in result.secrets_found[:5]:
                console.print(f"    → {s.get('type','')} in {s.get('target','')} — {s.get('title','')}")

        if result.misconfigs:
            console.print(f"  [bold #FFD700]⚠ MISCONFIGURATIONS: {len(result.misconfigs)}[/bold #FFD700]")

        console.print(f"\n  [#00FFD4]By Severity:[/#00FFD4] " +
                       " | ".join(f"{s.upper()}:{c}" for s,c in result.by_severity.items()))
        console.print(f"  [#7B00FF]Risk Score: {result.risk_score}/100[/#7B00FF]")

    def scan(self, image: str) -> dict:
        console.print(f"[bold #7B00FF]  🐳 Container Scanner — {image}[/bold #7B00FF]")
        tool = self._best_tool()
        if not tool:
            log.error("[CONTAINER] No scanner found. Install: trivy or grype")
            return {"error":"No scanner (trivy/grype) found","image":image}

        result = self._run_trivy(image) if tool=="trivy" else self._run_grype(image)
        result.risk_score = self._compute_risk(result)
        self._print_result(result)
        console.print(f"[bold #00FFD4]  ✅ Container scan complete — "
                       f"{result.total_vulns} vulns | tool: {tool}[/bold #00FFD4]")
        return {
            "image":      result.image,
            "os":         result.os_info,
            "tool":       tool,
            "total_vulns":result.total_vulns,
            "by_severity":result.by_severity,
            "risk_score": result.risk_score,
            "secrets":    result.secrets_found,
            "misconfigs": result.misconfigs,
            "vulns": [
                {"package":v.pkg_name,"installed":v.installed_ver,
                 "fixed":v.fixed_ver,"severity":v.severity,"cve":v.cve_id}
                for v in result.vulns[:50]
            ],
        }

    def scan_multiple(self, images: list) -> list:
        results = []
        for img in images:
            results.append(self.scan(img))
        return sorted(results, key=lambda r: r.get("risk_score",0), reverse=True)
