"""
NEXUS SPECTER PRO — Certificate Transparency Intelligence
Queries crt.sh + CT log APIs to discover subdomains, org assets, email addresses.
Detects wildcard certs, expired certs, and shadow IT infrastructure.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import re, logging, time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.recon.ct")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


@dataclass
class CertRecord:
    common_name:   str
    issuer:        str
    not_before:    str
    not_after:     str
    serial:        str  = ""
    sans:          list = field(default_factory=list)
    expired:       bool = False
    days_left:     int  = 999
    wildcard:      bool = False
    interesting:   bool = False
    org:           str  = ""
    log_name:      str  = ""


class CertificateTransparency:
    """
    Certificate Transparency (CT) log intelligence engine.
    Discovers all certificates ever issued for a domain via crt.sh.
    Extracts: subdomains, SANs, org names, email addresses, wildcard certs.
    Identifies: shadow IT, expired certs, interesting subdomains.
    """

    CRTSH_API    = "https://crt.sh/?q={domain}&output=json"
    SHADOW_KEYWORDS = ["dev","staging","test","uat","qa","internal","admin",
                       "vpn","remote","api","backend","db","database","debug",
                       "old","backup","legacy","demo","sandbox","lab"]

    def __init__(self, domain: str, timeout: int = 20, deduplicate: bool = True):
        self.domain      = domain
        self.timeout     = timeout
        self.deduplicate = deduplicate
        self.certs:      list[CertRecord] = []
        self.subdomains: set              = set()

    def _query_crtsh(self) -> list:
        if not REQUESTS_OK:
            return []
        try:
            url = self.CRTSH_API.format(domain=f"%.{self.domain}")
            console.print(f"[#00FFD4]  [CT] Querying crt.sh for %.{self.domain}[/#00FFD4]")
            r = requests.get(url, timeout=self.timeout,
                             headers={"User-Agent":"Mozilla/5.0 (NSP-SPECTER)"})
            if r.status_code == 200:
                data = r.json()
                log.info(f"[CT] crt.sh returned {len(data)} certificates")
                return data
        except Exception as e:
            log.error(f"[CT] crt.sh error: {e}")
        return []

    def _parse_cert(self, entry: dict) -> CertRecord:
        cn       = entry.get("common_name","").strip()
        issuer   = entry.get("issuer_name","").strip()
        nb       = entry.get("not_before","")[:10]
        na       = entry.get("not_after","")[:10]
        name_val = entry.get("name_value","")

        # Parse SANs from name_value
        sans = [n.strip().lower() for n in name_val.split("\n") if n.strip()]

        # Days left
        days_left = 999
        expired   = False
        try:
            exp = datetime.strptime(na, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (exp - now).days
            expired   = days_left < 0
        except Exception:
            pass

        # Wildcard
        wildcard = cn.startswith("*.")

        # Extract org from issuer
        org_match = re.search(r"O=([^,]+)", issuer)
        org = org_match.group(1).strip() if org_match else ""

        # Interesting flag
        interesting = any(kw in cn.lower() for kw in self.SHADOW_KEYWORDS)
        interesting = interesting or expired or (0 < days_left <= 30)

        return CertRecord(
            common_name = cn,
            issuer      = issuer[:80],
            not_before  = nb,
            not_after   = na,
            serial      = str(entry.get("id","")),
            sans        = sans[:10],
            expired     = expired,
            days_left   = days_left,
            wildcard    = wildcard,
            interesting = interesting,
            org         = org,
            log_name    = entry.get("entry_timestamp","")[:10],
        )

    def _extract_subdomains(self, certs: list) -> set:
        subs = set()
        for cert in certs:
            for name in [cert.common_name] + cert.sans:
                name = name.strip().lower().lstrip("*.")
                if name and self.domain in name:
                    subs.add(name)
        return subs

    def _print_results(self, certs: list, subdomains: set):
        # Interesting certs table
        interesting = [c for c in certs if c.interesting]
        if interesting:
            table = Table(
                title=f"[bold #7B00FF]🔐 INTERESTING CERTS — {len(interesting)}[/bold #7B00FF]",
                border_style="#7B00FF", header_style="bold #00FFD4",
            )
            table.add_column("CN",        width=35)
            table.add_column("Issuer",    width=25)
            table.add_column("Expires",   width=12)
            table.add_column("Days Left", width=10, justify="right")
            table.add_column("Flags",     width=25)

            for c in interesting[:15]:
                flags = []
                if c.expired:    flags.append("[bold #FF003C]EXPIRED[/bold #FF003C]")
                if 0 < c.days_left <= 30: flags.append("[bold #FF8C00]EXPIRING SOON[/bold #FF8C00]")
                if c.wildcard:   flags.append("[bold #FFD700]WILDCARD[/bold #FFD700]")
                if any(kw in c.common_name.lower() for kw in self.SHADOW_KEYWORDS):
                    flags.append("[bold #00FFD4]SHADOW IT[/bold #00FFD4]")
                table.add_row(c.common_name[:35], c.org[:25],
                              c.not_after, str(c.days_left), " ".join(flags))
            console.print(table)

        console.print(f"  [#00FFD4]Total unique subdomains: {len(subdomains)}[/#00FFD4]")
        console.print(f"  [#00FFD4]Total certs: {len(certs)} | "
                       f"Expired: {sum(1 for c in certs if c.expired)} | "
                       f"Wildcards: {sum(1 for c in certs if c.wildcard)}[/#00FFD4]")

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🔐 CT Intelligence — {self.domain}[/bold #7B00FF]")
        raw   = self._query_crtsh()
        certs = [self._parse_cert(e) for e in raw]

        if self.deduplicate:
            seen, unique = set(), []
            for c in certs:
                if c.common_name not in seen:
                    seen.add(c.common_name)
                    unique.append(c)
            certs = unique

        subdomains    = self._extract_subdomains(certs)
        self.certs    = certs
        self.subdomains = subdomains
        self._print_results(certs, subdomains)
        console.print(f"[bold #00FFD4]  ✅ CT complete — {len(certs)} certs | "
                       f"{len(subdomains)} subdomains[/bold #00FFD4]")

        return {
            "domain":      self.domain,
            "total_certs": len(certs),
            "subdomains":  sorted(subdomains),
            "expired":     [c.common_name for c in certs if c.expired],
            "expiring":    [c.common_name for c in certs if 0 < c.days_left <= 30],
            "wildcards":   [c.common_name for c in certs if c.wildcard],
            "shadow_it":   [c.common_name for c in certs
                            if any(kw in c.common_name.lower() for kw in self.SHADOW_KEYWORDS)],
            "certs": [
                {"cn": c.common_name, "issuer_org": c.org, "not_after": c.not_after,
                 "days_left": c.days_left, "expired": c.expired,
                 "wildcard": c.wildcard, "sans": c.sans[:5]}
                for c in certs[:100]
            ],
        }
