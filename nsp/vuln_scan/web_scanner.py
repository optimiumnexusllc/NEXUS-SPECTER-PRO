"""
NEXUS SPECTER PRO — Web Scanner Orchestrator
Combines: Nikto + OWASP ZAP API + Nuclei (web templates)
Aggregates, deduplicates, and scores all findings.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import subprocess, shutil, logging, json, re, time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.vuln_scan.web")


@dataclass
class WebFinding:
    source:      str          # nikto | zap | nuclei
    title:       str
    severity:    str          # critical | high | medium | low | info
    url:         str
    description: str = ""
    evidence:    str = ""
    cvss:        float = 0.0
    cwe:         str = ""
    reference:   str = ""


class WebScanner:
    """
    Orchestrates Nikto + ZAP + Nuclei for comprehensive web vulnerability scanning.
    Deduplicates findings across tools and produces a unified severity-sorted report.
    """

    NIKTO_SEVERITY_MAP = {
        "0": "info", "1": "info", "2": "low", "3": "medium",
        "4": "high", "5": "critical", "6": "high",
    }

    def __init__(
        self,
        target_url:  str,
        output_dir:  str = "/tmp/nsp_webscan",
        zap_host:    str = "localhost",
        zap_port:    int = 8090,
        zap_api_key: str = "",
        timeout:     int = 300,
        user_agent:  str = None,
        cookies:     str = None,
        proxy:       str = None,
        mode:        str = "black_box",
    ):
        self.target_url  = target_url.rstrip("/")
        self.output_dir  = Path(output_dir)
        self.zap_host    = zap_host
        self.zap_port    = zap_port
        self.zap_api_key = zap_api_key
        self.timeout     = timeout
        self.user_agent  = user_agent or "Mozilla/5.0 (NSP-SPECTER)"
        self.cookies     = cookies
        self.proxy       = proxy
        self.mode        = mode
        self.findings    = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── NIKTO ──────────────────────────────────────────────────────────────
    def run_nikto(self) -> list:
        """Run Nikto web server scanner."""
        if not shutil.which("nikto"):
            log.warning("[WEB] nikto not found — skipping")
            return []

        out_file = self.output_dir / "nikto_results.json"
        console.print(f"[#00FFD4]  [NIKTO] Scanning: {self.target_url}[/#00FFD4]")

        cmd = [
            "nikto", "-h", self.target_url,
            "-Format", "json", "-output", str(out_file),
            "-useragent", self.user_agent,
            "-nointeractive", "-Tuning", "123457890abc",
        ]
        if self.cookies:
            cmd += ["-cookies", self.cookies]
        if self.proxy:
            cmd += ["-useproxy", self.proxy]

        try:
            subprocess.run(cmd, capture_output=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            log.warning("[NIKTO] Timeout")

        return self._parse_nikto(out_file)

    def _parse_nikto(self, out_file: Path) -> list:
        findings = []
        if not out_file.exists():
            return findings
        try:
            data = json.loads(out_file.read_text())
            for host in data.get("host", []):
                for item in host.get("vulnerabilities", []):
                    findings.append(WebFinding(
                        source      = "nikto",
                        title       = item.get("msg", "")[:120],
                        severity    = self.NIKTO_SEVERITY_MAP.get(str(item.get("OSVDB","0"))[:1], "info"),
                        url         = item.get("url", self.target_url),
                        description = item.get("msg", ""),
                        reference   = f"OSVDB-{item.get('OSVDB','')}" if item.get("OSVDB") else "",
                    ))
        except Exception as e:
            log.debug(f"[NIKTO] Parse error: {e}")
        log.info(f"[NIKTO] Parsed {len(findings)} findings")
        return findings

    # ── ZAP ────────────────────────────────────────────────────────────────
    def run_zap(self) -> list:
        """Trigger OWASP ZAP active scan via REST API."""
        try:
            import requests as req
            base = f"http://{self.zap_host}:{self.zap_port}"
            params = {"apikey": self.zap_api_key}

            # Check ZAP is running
            req.get(f"{base}/JSON/core/view/version/", params=params, timeout=5)
            console.print(f"[#00FFD4]  [ZAP] Connected — scanning: {self.target_url}[/#00FFD4]")

            # Spider
            r = req.get(f"{base}/JSON/spider/action/scan/",
                        params={**params, "url": self.target_url}, timeout=30)
            scan_id = r.json().get("scan", "0")
            for _ in range(60):
                prog = req.get(f"{base}/JSON/spider/view/status/",
                               params={**params, "scanId": scan_id}, timeout=10)
                if prog.json().get("status") == "100":
                    break
                time.sleep(3)

            # Active scan
            r = req.get(f"{base}/JSON/ascan/action/scan/",
                        params={**params, "url": self.target_url,
                                "recurse": "true"}, timeout=30)
            ascan_id = r.json().get("scan", "0")
            for _ in range(120):
                prog = req.get(f"{base}/JSON/ascan/view/status/",
                               params={**params, "scanId": ascan_id}, timeout=10)
                if prog.json().get("status") == "100":
                    break
                time.sleep(5)

            # Get alerts
            alerts_r = req.get(f"{base}/JSON/core/view/alerts/",
                                params={**params, "baseurl": self.target_url,
                                        "count": "500"}, timeout=30)
            return self._parse_zap_alerts(alerts_r.json().get("alerts", []))

        except Exception as e:
            log.warning(f"[ZAP] Not available or error: {e}")
            return []

    def _parse_zap_alerts(self, alerts: list) -> list:
        ZAP_RISK = {"High": "high", "Medium": "medium", "Low": "low",
                    "Informational": "info", "Critical": "critical"}
        findings = []
        for a in alerts:
            findings.append(WebFinding(
                source      = "zap",
                title       = a.get("name", ""),
                severity    = ZAP_RISK.get(a.get("risk", ""), "info"),
                url         = a.get("url", ""),
                description = a.get("description", "")[:300],
                evidence    = a.get("evidence", "")[:200],
                cwe         = f"CWE-{a.get('cweid', '')}",
                reference   = a.get("reference", "")[:200],
                cvss        = float(a.get("riskcode", 0)) * 2.5,
            ))
        log.info(f"[ZAP] Parsed {len(findings)} alerts")
        return findings

    # ── NUCLEI (web subset) ─────────────────────────────────────────────────
    def run_nuclei_web(self) -> list:
        """Run Nuclei with web-focused tags only."""
        if not shutil.which("nuclei"):
            log.warning("[WEB] nuclei not found — skipping")
            return []

        out_file = self.output_dir / "nuclei_web.jsonl"
        console.print(f"[#00FFD4]  [NUCLEI-WEB] Scanning: {self.target_url}[/#00FFD4]")

        cmd = [
            "nuclei", "-u", self.target_url,
            "-tags", "xss,sqli,ssrf,redirect,exposure,misconfiguration,default-login,cors,crlf,lfi",
            "-severity", "critical,high,medium,low",
            "-rate-limit", "100",
            "-timeout", "5",
            "-jsonl", "-output", str(out_file),
            "-no-color", "-silent",
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            log.warning("[NUCLEI-WEB] Timeout")

        return self._parse_nuclei_jsonl(out_file)

    def _parse_nuclei_jsonl(self, out_file: Path) -> list:
        findings = []
        if not out_file.exists():
            return findings
        for line in out_file.read_text().splitlines():
            try:
                d    = json.loads(line)
                info = d.get("info", {})
                findings.append(WebFinding(
                    source      = "nuclei",
                    title       = info.get("name", ""),
                    severity    = info.get("severity", "info").lower(),
                    url         = d.get("matched-at", self.target_url),
                    description = info.get("description", ""),
                    reference   = ", ".join(info.get("reference", [])),
                    cvss        = float((info.get("classification") or {}).get("cvss-score", 0) or 0),
                ))
            except Exception:
                pass
        log.info(f"[NUCLEI-WEB] Parsed {len(findings)} findings")
        return findings

    # ── AGGREGATION & DISPLAY ───────────────────────────────────────────────
    def _deduplicate(self, findings: list) -> list:
        seen, unique = set(), []
        for f in findings:
            key = f"{f.severity}:{f.title[:40]}:{f.url[:60]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _print_summary(self, findings: list):
        SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        sorted_f  = sorted(findings, key=lambda x: SEV_ORDER.get(x.severity, 5))

        table = Table(
            title=f"[bold #7B00FF]🌐 WEB SCAN — {len(findings)} findings[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4", show_lines=False,
        )
        table.add_column("Sev",     width=10)
        table.add_column("Tool",    width=8)
        table.add_column("Title",   width=45)
        table.add_column("URL",     width=40)

        SEV_COLOR = {
            "critical":"[bold #FF003C]","high":"[bold #FF8C00]",
            "medium":"[bold #FFD700]","low":"[bold #00FFD4]","info":"[dim white]",
        }
        for f in sorted_f[:40]:
            c = SEV_COLOR.get(f.severity, "[white]")
            e = c.replace("[","[/")
            table.add_row(f"{c}{f.severity.upper()}{e}",
                          f.source[:8], f.title[:45], f.url[-40:])
        console.print(table)

        counts = {s: sum(1 for f in findings if f.severity==s)
                  for s in ["critical","high","medium","low","info"]}
        console.print(
            f"  [bold #FF003C]🔴 {counts['critical']}[/bold #FF003C]  "
            f"[bold #FF8C00]🟠 {counts['high']}[/bold #FF8C00]  "
            f"[bold #FFD700]🟡 {counts['medium']}[/bold #FFD700]  "
            f"[bold #00FFD4]🔵 {counts['low']}[/bold #00FFD4]  "
            f"[dim]⚪ {counts['info']}[/dim]"
        )

    def to_dict(self, findings: list) -> dict:
        by_sev = {}
        for f in findings:
            by_sev.setdefault(f.severity, []).append({
                "source": f.source, "title": f.title, "url": f.url,
                "description": f.description, "evidence": f.evidence,
                "cvss": f.cvss, "cwe": f.cwe, "reference": f.reference,
            })
        return {"target": self.target_url, "total": len(findings),
                "by_severity": by_sev}

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🌐 Web Scanner starting — {self.target_url}[/bold #7B00FF]")
        all_findings = []
        all_findings += self.run_nikto()
        all_findings += self.run_zap()
        all_findings += self.run_nuclei_web()
        self.findings = self._deduplicate(all_findings)
        self._print_summary(self.findings)
        console.print(f"[bold #00FFD4]  ✅ Web scan complete — {len(self.findings)} unique findings[/bold #00FFD4]")
        return self.to_dict(self.findings)
