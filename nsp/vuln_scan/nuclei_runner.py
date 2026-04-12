"""
NEXUS SPECTER PRO — Nuclei Runner
Vulnerability scanning engine powered by ProjectDiscovery Nuclei
Manages templates, severity filtering, custom payloads, and result parsing
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import subprocess
import shutil
import logging
import json
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.vuln_scan.nuclei")


@dataclass
class NucleiFinding:
    template_id:   str
    template_name: str
    severity:      str
    host:          str
    matched_at:    str
    description:   str = ""
    reference:     list = field(default_factory=list)
    tags:          list = field(default_factory=list)
    cvss_score:    float = 0.0
    cve_id:        str = ""
    curl_command:  str = ""
    raw_request:   str = ""
    raw_response:  str = ""


class NucleiRunner:
    """
    Nuclei scanning engine for NEXUS SPECTER PRO.
    Orchestrates template selection, scanning, result parsing, and severity triage.
    Supports: web, network, cloud, dns, ssl, headless, code templates.
    """

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

    SEVERITY_COLORS = {
        "critical": "[bold #FF003C]",
        "high":     "[bold #FF8C00]",
        "medium":   "[bold #FFD700]",
        "low":      "[bold #00FFD4]",
        "info":     "[bold white]",
        "unknown":  "[dim white]",
    }

    NSP_CUSTOM_TEMPLATES = Path(__file__).parent / "nuclei_templates"

    DEFAULT_TAGS = {
        "black_box":   ["cve", "exposed", "misconfig", "takeover", "xss", "sqli", "ssrf", "xxe",
                        "ssti", "rce", "lfi", "jwt", "cors", "default-login", "oauth", "graphql"],
        "gray_box":    ["cve", "exposed", "misconfig", "auth", "idor", "injection", "xss", "sqli",
                        "ssrf", "xxe", "ssti", "rce", "lfi", "jwt", "api", "graphql"],
        "white_box":   ["cve", "exposed", "misconfig", "auth", "idor", "injection", "xss", "sqli",
                        "ssrf", "xxe", "ssti", "rce", "lfi", "jwt", "api", "graphql",
                        "debug", "backup", "config", "secrets"],
        "red_team":    ["cve", "exposed", "misconfig", "takeover", "rce", "sqli", "ssrf", "ssti",
                        "default-login", "auth-bypass", "jwt", "api", "cloud", "aws", "azure"],
        "cloud_audit": ["aws", "azure", "gcp", "cloud", "s3", "iam", "misconfig", "exposure"],
    }

    def __init__(
        self,
        targets:        list,
        mode:           str = "black_box",
        severities:     list = None,
        rate_limit:     int = 150,
        concurrency:    int = 25,
        timeout:        int = 5,
        retries:        int = 1,
        output_dir:     str = "/tmp/nsp_nuclei",
        custom_headers: dict = None,
        proxy:          str = None,
    ):
        self.targets        = targets if isinstance(targets, list) else [targets]
        self.mode           = mode
        self.severities     = severities or ["critical", "high", "medium", "low"]
        self.rate_limit     = rate_limit
        self.concurrency    = concurrency
        self.timeout        = timeout
        self.retries        = retries
        self.output_dir     = Path(output_dir)
        self.custom_headers = custom_headers or {}
        self.proxy          = proxy
        self.findings       = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _check_nuclei(self) -> bool:
        if not shutil.which("nuclei"):
            log.error("[NUCLEI] nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return False
        return True

    def _update_templates(self):
        """Update Nuclei templates to latest version."""
        console.print("[#00FFD4]  [NUCLEI] Updating templates...[/#00FFD4]")
        try:
            subprocess.run(["nuclei", "-update-templates", "-silent"],
                           capture_output=True, timeout=120)
            log.info("[NUCLEI] Templates updated successfully")
        except Exception as e:
            log.warning(f"[NUCLEI] Template update failed: {e}")

    def _build_targets_file(self) -> Path:
        """Write targets to a temp file for Nuclei."""
        targets_file = self.output_dir / "targets.txt"
        targets_file.write_text("\n".join(self.targets))
        return targets_file

    def _build_nuclei_command(self, targets_file: Path, output_file: Path) -> list:
        """Build the Nuclei command with all options."""
        tags = self.DEFAULT_TAGS.get(self.mode, self.DEFAULT_TAGS["black_box"])
        tags_str = ",".join(tags)
        severities_str = ",".join(self.severities)

        cmd = [
            "nuclei",
            "-list",        str(targets_file),
            "-tags",        tags_str,
            "-severity",    severities_str,
            "-rate-limit",  str(self.rate_limit),
            "-concurrency", str(self.concurrency),
            "-timeout",     str(self.timeout),
            "-retries",     str(self.retries),
            "-jsonl",
            "-output",      str(output_file),
            "-stats",
            "-no-color",
        ]

        # Custom templates
        if self.NSP_CUSTOM_TEMPLATES.exists():
            cmd += ["-t", str(self.NSP_CUSTOM_TEMPLATES)]

        # Custom headers
        for header, value in self.custom_headers.items():
            cmd += ["-header", f"{header}: {value}"]

        # Proxy
        if self.proxy:
            cmd += ["-proxy", self.proxy]

        return cmd

    def _parse_results(self, output_file: Path) -> list:
        """Parse Nuclei JSONL output into NucleiFinding objects."""
        findings = []
        if not output_file.exists():
            return findings
        try:
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        info = data.get("info", {})
                        classification = info.get("classification", {})
                        finding = NucleiFinding(
                            template_id=data.get("template-id", ""),
                            template_name=info.get("name", ""),
                            severity=info.get("severity", "unknown").lower(),
                            host=data.get("host", ""),
                            matched_at=data.get("matched-at", ""),
                            description=info.get("description", ""),
                            reference=info.get("reference", []),
                            tags=info.get("tags", []),
                            cvss_score=float(classification.get("cvss-score", 0) or 0),
                            cve_id=",".join(classification.get("cve-id", [])),
                            curl_command=data.get("curl-command", ""),
                            raw_request=data.get("request", ""),
                            raw_response=data.get("response", "")[:2000],
                        )
                        findings.append(finding)
                    except (json.JSONDecodeError, KeyError, ValueError) as e:
                        log.debug(f"[NUCLEI] Skipping malformed line: {e}")
            log.info(f"[NUCLEI] Parsed {len(findings)} findings")
        except Exception as e:
            log.error(f"[NUCLEI] Failed to parse results: {e}")
        return findings

    def _print_findings_table(self, findings: list):
        """Display findings in a rich table sorted by severity."""
        if not findings:
            console.print("[bold #00FFD4]  ✅ No vulnerabilities found by Nuclei.[/bold #00FFD4]")
            return

        sorted_findings = sorted(findings, key=lambda f: self.SEVERITY_ORDER.get(f.severity, 5))
        table = Table(
            title=f"[bold #7B00FF]🎯 NUCLEI FINDINGS — {len(findings)} vulnerabilities[/bold #7B00FF]",
            border_style="#7B00FF",
            header_style="bold #00FFD4",
            show_lines=True,
        )
        table.add_column("Severity", width=10, justify="center")
        table.add_column("Template",  width=35)
        table.add_column("Host",      width=30)
        table.add_column("Matched At",width=35)
        table.add_column("CVE",       width=18)
        table.add_column("CVSS",      width=6, justify="right")

        for f in sorted_findings:
            color = self.SEVERITY_COLORS.get(f.severity, "[white]")
            end   = color.replace("[", "[/")
            sev_display = f"{color}{'▲ ' if f.severity in ('critical','high') else ''}{f.severity.upper()}{end}"
            table.add_row(
                sev_display,
                f.template_name[:35],
                f.host[:30],
                f.matched_at[:35],
                f.cve_id[:18] if f.cve_id else "-",
                str(f.cvss_score) if f.cvss_score else "-",
            )

        console.print(table)

    def _print_summary(self, findings: list):
        """Print severity distribution summary."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        console.print()
        console.print(f"  [bold #FF003C]🔴 CRITICAL : {counts['critical']}[/bold #FF003C]  "
                       f"[bold #FF8C00]🟠 HIGH    : {counts['high']}[/bold #FF8C00]  "
                       f"[bold #FFD700]🟡 MEDIUM  : {counts['medium']}[/bold #FFD700]  "
                       f"[bold #00FFD4]🔵 LOW     : {counts['low']}[/bold #00FFD4]  "
                       f"[white]⚪ INFO   : {counts['info']}[/white]")
        console.print()

    def to_dict(self, findings: list) -> dict:
        """Convert findings list to JSON-serializable dict."""
        by_severity = {}
        for f in findings:
            by_severity.setdefault(f.severity, []).append({
                "template_id":   f.template_id,
                "name":          f.template_name,
                "severity":      f.severity,
                "host":          f.host,
                "matched_at":    f.matched_at,
                "description":   f.description,
                "reference":     f.reference,
                "cve_id":        f.cve_id,
                "cvss_score":    f.cvss_score,
                "curl_command":  f.curl_command,
                "raw_request":   f.raw_request,
                "raw_response":  f.raw_response,
            })
        return {
            "total":       len(findings),
            "by_severity": by_severity,
            "targets":     self.targets,
            "mode":        self.mode,
        }

    def run(self) -> dict:
        """Execute Nuclei scan and return structured results."""
        console.print(f"[bold #7B00FF]  🎯 Nuclei Runner starting — {len(self.targets)} target(s) | mode: {self.mode}[/bold #7B00FF]")

        if not self._check_nuclei():
            return {"error": "nuclei not installed", "total": 0}

        self._update_templates()

        targets_file = self._build_targets_file()
        output_file  = self.output_dir / "nuclei_results.jsonl"
        cmd          = self._build_nuclei_command(targets_file, output_file)

        console.print(f"[#00FFD4]  [NUCLEI] Launching scan — rate:{self.rate_limit} | concurrency:{self.concurrency}[/#00FFD4]")
        log.info(f"[NUCLEI] Command: {' '.join(cmd)}")

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            log.debug(f"[NUCLEI] stdout: {proc.stdout[-2000:]}")
            if proc.returncode not in (0, 1):
                log.warning(f"[NUCLEI] Non-zero exit: {proc.returncode}")
        except subprocess.TimeoutExpired:
            log.error("[NUCLEI] Scan timed out after 3600s")
            return {"error": "timeout", "total": 0}
        except Exception as e:
            log.error(f"[NUCLEI] Execution error: {e}")
            return {"error": str(e), "total": 0}

        self.findings = self._parse_results(output_file)
        self._print_findings_table(self.findings)
        self._print_summary(self.findings)

        console.print(f"[bold #00FFD4]  ✅ Nuclei scan complete — {len(self.findings)} findings[/bold #00FFD4]")
        return self.to_dict(self.findings)
