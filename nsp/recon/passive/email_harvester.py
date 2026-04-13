"""
NEXUS SPECTER PRO — Email Harvester
Passive email discovery using theHarvester + Hunter.io API + DNS analysis.
Builds org employee list for phishing simulation scope analysis.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import subprocess, shutil, logging, json, re, os
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.recon.email")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


@dataclass
class EmailResult:
    domain:       str
    emails:       list = field(default_factory=list)
    linkedin:     list = field(default_factory=list)
    pattern:      str = ""
    organization: str = ""
    sources:      list = field(default_factory=list)
    spf_record:   str = ""
    dmarc_record: str = ""
    dkim_present: bool = False
    email_sec_issues: list = field(default_factory=list)


class EmailHarvester:
    """
    Passive email harvesting engine for NEXUS SPECTER PRO.
    Combines theHarvester (multi-source OSINT) + Hunter.io API
    + DNS mail security analysis (SPF/DMARC/DKIM).
    """

    SOURCES = ["google", "bing", "yahoo", "duckduckgo", "linkedin",
               "twitter", "github", "baidu", "certspotter"]

    def __init__(self, domain: str, hunter_api_key: str = None,
                 output_dir: str = "/tmp/nsp_emails", limit: int = 200):
        self.domain       = domain
        self.hunter_key   = hunter_api_key or os.getenv("HUNTER_API_KEY","")
        self.output_dir   = output_dir
        self.limit        = limit
        self.result       = EmailResult(domain=domain)

    # ── theHarvester ────────────────────────────────────────────────────────
    def _run_theharvester(self) -> list:
        tool = shutil.which("theHarvester") or shutil.which("theharvester")
        if not tool:
            log.warning("[EMAIL] theHarvester not found. "
                        "Install: pip install theHarvester")
            return []

        emails = []
        for source in self.SOURCES[:4]:   # limit to 4 sources per run
            console.print(f"[#00FFD4]  [theHARVESTER] Source: {source} — {self.domain}[/#00FFD4]")
            try:
                result = subprocess.run(
                    [tool, "-d", self.domain, "-b", source,
                     "-l", str(self.limit), "-f",
                     f"{self.output_dir}/harvester_{source}.json"],
                    capture_output=True, text=True, timeout=120,
                )
                # Parse emails from stdout (theHarvester format)
                for line in result.stdout.splitlines():
                    m = re.findall(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", line)
                    emails.extend(m)
            except subprocess.TimeoutExpired:
                log.warning(f"[EMAIL] theHarvester timeout on {source}")
            except Exception as e:
                log.debug(f"[EMAIL] theHarvester error: {e}")

        found = list(set(
            e.lower() for e in emails
            if self.domain in e.lower()
        ))
        log.info(f"[EMAIL] theHarvester: {len(found)} emails from {self.domain}")
        return found

    # ── Hunter.io API ────────────────────────────────────────────────────────
    def _query_hunter(self) -> dict:
        if not self.hunter_key or not REQUESTS_OK:
            log.warning("[EMAIL] Hunter.io key not configured — skipping")
            return {}
        try:
            console.print(f"[#00FFD4]  [HUNTER.IO] Querying: {self.domain}[/#00FFD4]")
            r = requests.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": self.domain, "api_key": self.hunter_key,
                        "limit": 100},
                timeout=15,
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            emails_raw = data.get("emails", [])
            emails = [e["value"] for e in emails_raw if "value" in e]
            pattern = data.get("pattern","")
            org     = data.get("organization","")
            console.print(f"[#00FFD4]  → Hunter.io: {len(emails)} emails | "
                           f"pattern: {pattern} | org: {org}[/#00FFD4]")
            return {
                "emails":       emails,
                "pattern":      pattern,
                "organization": org,
                "webmail":      data.get("webmail", False),
                "disposable":   data.get("disposable", False),
            }
        except Exception as e:
            log.error(f"[EMAIL] Hunter.io error: {e}")
            return {}

    # ── DNS Mail Security ────────────────────────────────────────────────────
    def _check_mail_security(self):
        """Check SPF, DMARC, and DKIM configuration."""
        issues = []
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()

            # SPF
            try:
                txts = resolver.resolve(self.domain, "TXT")
                spf = next((str(r) for r in txts if "v=spf1" in str(r).lower()), "")
                self.result.spf_record = spf
                if not spf:
                    issues.append("No SPF record — domain can be spoofed for phishing")
                elif "~all" in spf:
                    issues.append("SPF uses ~all (softfail) — consider -all (hardfail)")
                elif "+all" in spf:
                    issues.append("CRITICAL: SPF +all — allows ANY server to send as this domain")
            except Exception:
                issues.append("SPF check failed — domain may lack SPF record")

            # DMARC
            try:
                dmarc = resolver.resolve(f"_dmarc.{self.domain}", "TXT")
                dmarc_str = " ".join(str(r) for r in dmarc)
                self.result.dmarc_record = dmarc_str
                if "p=none" in dmarc_str:
                    issues.append("DMARC policy is p=none — emails not rejected or quarantined")
                elif not dmarc_str:
                    issues.append("No DMARC record — phishing protection missing")
            except Exception:
                issues.append("No DMARC record found — domain vulnerable to email spoofing")

            # DKIM (check common selectors)
            for selector in ["default", "google", "mail", "smtp", "email", "k1", "s1"]:
                try:
                    resolver.resolve(f"{selector}._domainkey.{self.domain}", "TXT")
                    self.result.dkim_present = True
                    break
                except Exception:
                    pass
            if not self.result.dkim_present:
                issues.append("No DKIM record found on common selectors")

        except ImportError:
            log.warning("[EMAIL] dnspython not installed — skipping mail security checks")

        self.result.email_sec_issues = issues
        if issues:
            console.print(f"[bold #FFD700]  ⚠️  Mail security issues: {len(issues)}[/bold #FFD700]")
            for issue in issues:
                console.print(f"  [#FFD700]→ {issue}[/#FFD700]")

    def _print_results(self):
        emails = self.result.emails
        if emails:
            table = Table(
                title=f"[bold #7B00FF]📧 EMAILS FOUND — {len(emails)}[/bold #7B00FF]",
                border_style="#7B00FF", header_style="bold #00FFD4",
            )
            table.add_column("#",      width=5,  justify="right")
            table.add_column("Email",  width=40)
            table.add_column("Source", width=20)
            for i, email in enumerate(emails[:30], 1):
                table.add_row(str(i), email, "")
            if len(emails) > 30:
                table.add_row("...", f"+ {len(emails)-30} more", "")
            console.print(table)

        if self.result.pattern:
            console.print(f"  [bold #00FFD4]Email pattern: {self.result.pattern}[/bold #00FFD4]")
        if self.result.organization:
            console.print(f"  [bold #00FFD4]Organization: {self.result.organization}[/bold #00FFD4]")

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  📧 Email Harvester — {self.domain}[/bold #7B00FF]")
        import os; os.makedirs(self.output_dir, exist_ok=True)

        harvester_emails = self._run_theharvester()
        hunter_data      = self._query_hunter()
        self._check_mail_security()

        all_emails = list(set(
            harvester_emails + hunter_data.get("emails", [])
        ))
        self.result.emails       = all_emails
        self.result.pattern      = hunter_data.get("pattern","")
        self.result.organization = hunter_data.get("organization","")
        self.result.sources      = ["theHarvester"] + (["hunter.io"] if hunter_data else [])

        self._print_results()
        console.print(f"[bold #00FFD4]  ✅ Email harvest complete — {len(all_emails)} addresses[/bold #00FFD4]")

        from dataclasses import asdict
        return asdict(self.result)
