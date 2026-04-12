"""
NEXUS SPECTER PRO — AI Remediation Advisor
Generates prioritized, context-aware remediation roadmaps using Specter AI.
Maps findings to: CIS Controls, NIST CSF, OWASP ASVS, ISO 27001 controls.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json, logging
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
log = logging.getLogger("nsp.reporting.remediation")

# ── Compliance framework mappings ────────────────────────────────────────────
CIS_CONTROLS = {
    "sqli":           ("CIS-16", "Application Software Security"),
    "xss":            ("CIS-16", "Application Software Security"),
    "ssrf":           ("CIS-12", "Network Infrastructure Management"),
    "default-login":  ("CIS-5",  "Account Management"),
    "misconfig":      ("CIS-4",  "Secure Configuration of Enterprise Assets"),
    "exposed":        ("CIS-12", "Network Infrastructure Management"),
    "ssl":            ("CIS-3",  "Data Protection"),
    "rce":            ("CIS-16", "Application Software Security"),
    "lfi":            ("CIS-16", "Application Software Security"),
    "cve":            ("CIS-7",  "Continuous Vulnerability Management"),
    "cloud":          ("CIS-4",  "Secure Configuration of Enterprise Assets"),
    "auth":           ("CIS-6",  "Access Control Management"),
    "cors":           ("CIS-16", "Application Software Security"),
    "jwt":            ("CIS-6",  "Access Control Management"),
    "info":           ("CIS-3",  "Data Protection"),
    "takeover":       ("CIS-12", "Network Infrastructure Management"),
}

NIST_CSF = {
    "sqli":           ("ID.RA-1", "Asset vulnerabilities identified"),
    "xss":            ("PR.IP-2", "System Development Life Cycle managed"),
    "ssrf":           ("PR.AC-5", "Network integrity protected"),
    "default-login":  ("PR.AC-1", "Identities/credentials managed"),
    "misconfig":      ("PR.IP-1", "Baseline config established"),
    "exposed":        ("PR.AC-5", "Network integrity protected"),
    "ssl":            ("PR.DS-2", "Data-in-transit protected"),
    "cve":            ("ID.RA-1", "Asset vulnerabilities identified"),
    "auth":           ("PR.AC-1", "Identities/credentials managed"),
    "info":           ("PR.DS-1", "Data-at-rest protected"),
}

OWASP_ASVS = {
    "sqli":    "V5 — Validation, Sanitization and Encoding",
    "xss":     "V5 — Validation, Sanitization and Encoding",
    "ssrf":    "V10 — Malicious Code",
    "auth":    "V2 — Authentication",
    "jwt":     "V3 — Session Management",
    "cors":    "V14 — Configuration",
    "ssl":     "V9 — Communication",
    "rce":     "V12 — Files and Resources",
    "lfi":     "V12 — Files and Resources",
    "default-login": "V2 — Authentication",
}

ISO27001 = {
    "sqli":    "A.14.2.5 — Secure System Engineering Principles",
    "xss":     "A.14.2.5 — Secure System Engineering Principles",
    "misconfig":"A.12.1.1 — Documented Operating Procedures",
    "ssl":     "A.10.1.1 — Policy on the Use of Cryptographic Controls",
    "auth":    "A.9.2.1 — User Registration and De-registration",
    "exposed": "A.13.1.1 — Network Controls",
    "cve":     "A.12.6.1 — Management of Technical Vulnerabilities",
    "info":    "A.8.2.3 — Handling of Assets",
    "cloud":   "A.15.1.1 — Information Security Policy for Supplier Relationships",
}

EFFORT_LEVELS = {
    "critical": {"effort": "Immediate (< 24h)", "priority": "P0 — Emergency"},
    "high":     {"effort": "Short-term (< 1 week)", "priority": "P1 — High"},
    "medium":   {"effort": "Mid-term (< 1 month)", "priority": "P2 — Medium"},
    "low":      {"effort": "Planned (< 1 quarter)", "priority": "P3 — Low"},
    "info":     {"effort": "Informational", "priority": "P4 — Backlog"},
}

GENERIC_STEPS = {
    "sqli": [
        "Replace dynamic SQL concatenation with parameterized queries / prepared statements.",
        "Apply allowlist validation on all database-bound inputs.",
        "Enforce least-privilege DB accounts — no DDL rights for app accounts.",
        "Enable a WAF with SQL injection signatures (ModSecurity CRS).",
        "Run SAST tooling (Semgrep, CodeQL) to find all SQL interaction points.",
        "Verify fix with automated SQLMap rescan.",
    ],
    "xss": [
        "Apply context-sensitive output encoding (HTML entities, JS escaping, URL encoding).",
        "Implement a strict Content-Security-Policy header (script-src 'self' + nonces).",
        "Set HttpOnly + Secure + SameSite=Strict flags on session cookies.",
        "Use a templating engine that auto-escapes by default (Jinja2, React, Blade).",
        "Audit all innerHTML / document.write / eval usage in JavaScript.",
    ],
    "ssl": [
        "Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 — enforce TLS 1.2+ only.",
        "Remove weak cipher suites (RC4, 3DES, NULL, EXPORT ciphers).",
        "Enable and enforce HSTS (min-age: 31536000, includeSubDomains, preload).",
        "Renew certificates before expiry — automate with Let's Encrypt / ACME.",
        "Implement certificate pinning for mobile/thick client applications.",
    ],
    "default-login": [
        "Change all default credentials on internet-facing and internal systems immediately.",
        "Implement a mandatory credential rotation policy during provisioning.",
        "Enable multi-factor authentication on all administrative interfaces.",
        "Block default usernames (admin, root, administrator) via account policy.",
        "Audit all systems for default credentials using an automated scanner.",
    ],
    "misconfig": [
        "Apply CIS Benchmark hardening for the affected platform/service.",
        "Remove unnecessary services, ports, and features from production systems.",
        "Implement Infrastructure-as-Code (Terraform / Ansible) to enforce baseline configs.",
        "Schedule quarterly configuration drift scans.",
        "Enforce change management for all configuration changes.",
    ],
    "exposed": [
        "Restrict access using network-layer controls (firewall rules, security groups).",
        "Enforce IP allowlisting for administrative interfaces.",
        "Move sensitive services to private subnets — not internet-facing.",
        "Implement a zero-trust network architecture where feasible.",
        "Enable monitoring and alerting on access to sensitive endpoints.",
    ],
    "cve": [
        "Apply the vendor security patch immediately or implement a documented compensating control.",
        "Test the patch in a staging environment before production deployment.",
        "Update the vulnerability management system to track remediation.",
        "Implement automated patch management tooling (WSUS, Satellite, Ansible).",
        "Subscribe to vendor security advisories for affected products.",
    ],
    "default": [
        "Review the finding in detail and apply the vendor-recommended mitigation.",
        "Test the fix in a non-production environment first.",
        "Verify the remediation with a targeted rescan.",
        "Update your vulnerability management register.",
        "Consider broader systemic fixes if this pattern appears elsewhere.",
    ],
}


@dataclass
class RemediationItem:
    finding_name:   str
    severity:       str
    priority:       str
    effort:         str
    steps:          list
    cis_control:    str = ""
    nist_csf:       str = ""
    owasp_asvs:     str = ""
    iso27001:       str = ""
    estimated_hours: int = 0
    owner:          str = "Security Team"
    tags:           list = field(default_factory=list)


class RemediationAdvisor:
    """
    AI-powered Remediation Advisor for NEXUS SPECTER PRO.
    Generates prioritized remediation roadmaps mapped to compliance frameworks.
    Optionally enriches recommendations with Specter AI narrative.
    """

    def __init__(self, findings: list, ai_engine=None,
                 client_name: str = "Client", target: str = "Target"):
        self.findings    = findings
        self.ai          = ai_engine
        self.client_name = client_name
        self.target      = target
        self.plan        = []

    def _get_tags(self, finding: dict) -> list:
        return finding.get("tags", []) or []

    def _match_tag(self, tags: list, mapping: dict) -> str:
        for tag in tags:
            if tag in mapping:
                return mapping[tag]
        name = ""
        for tag in tags:
            for key in mapping:
                if key in tag or tag in key:
                    return mapping[key]
        return ""

    def _get_steps(self, tags: list, name: str) -> list:
        for tag in tags:
            if tag in GENERIC_STEPS:
                return GENERIC_STEPS[tag]
        name_lower = name.lower()
        for key in GENERIC_STEPS:
            if key in name_lower:
                return GENERIC_STEPS[key]
        return GENERIC_STEPS["default"]

    def _estimate_hours(self, severity: str, steps: list) -> int:
        base = {"critical": 8, "high": 16, "medium": 24, "low": 8, "info": 2}
        return base.get(severity, 8) * max(1, len(steps) // 2)

    def build_plan(self) -> list:
        """Build the full remediation plan from findings."""
        SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (SEV_ORDER.get(f.get("severity","info"), 5),
                           -f.get("cvss_base", f.get("cvss_score", 0.0)))
        )

        for i, f in enumerate(sorted_findings):
            sev  = f.get("severity", "info")
            tags = self._get_tags(f)
            name = f.get("name", f.get("title", "Unknown"))

            effort_info = EFFORT_LEVELS.get(sev, EFFORT_LEVELS["info"])
            steps = self._get_steps(tags, name)

            cis     = self._match_tag(tags, CIS_CONTROLS)
            nist    = self._match_tag(tags, NIST_CSF)
            owasp   = self._match_tag(tags, OWASP_ASVS)
            iso     = self._match_tag(tags, ISO27001)
            hours   = self._estimate_hours(sev, steps)

            item = RemediationItem(
                finding_name    = name,
                severity        = sev,
                priority        = effort_info["priority"],
                effort          = effort_info["effort"],
                steps           = steps,
                cis_control     = cis,
                nist_csf        = nist,
                owasp_asvs      = owasp,
                iso27001        = iso,
                estimated_hours = hours,
                tags            = tags,
            )
            self.plan.append(item)
        return self.plan

    def ai_enrich(self) -> str:
        """Use Specter AI to generate an executive remediation narrative."""
        if not self.ai:
            return ""
        summary = {
            "client": self.client_name, "target": self.target,
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f.get("severity")=="critical"),
            "high":     sum(1 for f in self.findings if f.get("severity")=="high"),
            "top_items": [p.finding_name for p in self.plan[:5]],
        }
        try:
            prompt = f"""
Write a 300-word professional remediation strategy summary for a CISO audience.
Include: overall risk posture, remediation phasing (immediate/short/long-term),
resource estimation, and key success metrics.

Findings summary: {json.dumps(summary)}
Company: OPTIMIUM NEXUS LLC | Platform: NEXUS SPECTER PRO
Write in professional English — no JSON, only flowing prose.
            """
            return self.ai._query(prompt, max_tokens=1024)
        except Exception as e:
            log.warning(f"[REMEDIATION] AI enrichment failed: {e}")
            return ""

    def print_roadmap(self):
        """Display the remediation roadmap as a rich table."""
        SEV_COLOR = {
            "critical": "[bold #FF003C]", "high": "[bold #FF8C00]",
            "medium": "[bold #FFD700]",   "low": "[bold #00FFD4]",
            "info": "[dim white]",
        }
        table = Table(
            title=f"[bold #7B00FF]🛠️  REMEDIATION ROADMAP — {len(self.plan)} findings[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4", show_lines=True,
        )
        table.add_column("#",        width=4,  justify="right")
        table.add_column("Priority", width=20)
        table.add_column("Finding",  width=35)
        table.add_column("Severity", width=10)
        table.add_column("Effort",   width=22)
        table.add_column("Hours",    width=7,  justify="right")
        table.add_column("CIS",      width=8)

        for i, item in enumerate(self.plan, 1):
            c = SEV_COLOR.get(item.severity, "[white]")
            e = c.replace("[","[/")
            table.add_row(
                str(i), item.priority, item.finding_name[:35],
                f"{c}{item.severity.upper()}{e}",
                item.effort, str(item.estimated_hours),
                item.cis_control[:8],
            )
        console.print(table)

        total_hours = sum(p.estimated_hours for p in self.plan)
        console.print(f"\n  [bold #00FFD4]Total estimated remediation effort: "
                       f"~{total_hours}h ({total_hours//8} business days)[/bold #00FFD4]")

    def to_dict(self) -> dict:
        total_hours = sum(p.estimated_hours for p in self.plan)
        phases = {
            "immediate":   [p for p in self.plan if p.severity == "critical"],
            "short_term":  [p for p in self.plan if p.severity == "high"],
            "mid_term":    [p for p in self.plan if p.severity == "medium"],
            "long_term":   [p for p in self.plan if p.severity in ("low","info")],
        }
        return {
            "total_findings":     len(self.plan),
            "total_hours":        total_hours,
            "total_days":         total_hours // 8,
            "phases":             {
                k: [{"finding": p.finding_name, "priority": p.priority,
                     "steps": p.steps, "hours": p.estimated_hours,
                     "cis": p.cis_control, "nist": p.nist_csf,
                     "owasp": p.owasp_asvs, "iso27001": p.iso27001}
                    for p in v]
                for k, v in phases.items()
            },
        }

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🛠️  Remediation Advisor — {len(self.findings)} findings[/bold #7B00FF]")
        self.build_plan()
        self.print_roadmap()
        ai_narrative = self.ai_enrich()
        result = self.to_dict()
        result["ai_narrative"] = ai_narrative
        return result
