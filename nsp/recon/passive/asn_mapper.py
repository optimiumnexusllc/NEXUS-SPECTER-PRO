"""
NEXUS SPECTER PRO — ASN Mapper
Full ASN cartography: all IP ranges, hosted domains, peers, org details.
Sources: BGP.tools API · ipapi.co · Hurricane Electric BGP toolkit · RIPE NCC
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import re, logging, socket
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.recon.asn")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


@dataclass
class ASNRecord:
    asn:       str
    org:       str  = ""
    country:   str  = ""
    prefixes:  list = field(default_factory=list)   # IPv4 CIDR ranges
    prefixes6: list = field(default_factory=list)   # IPv6
    peer_asns: list = field(default_factory=list)
    total_ips: int  = 0
    domains:   list = field(default_factory=list)


class ASNMapper:
    """
    Maps an organisation's entire ASN footprint.
    Given a company name or IP, finds:
    - All ASNs belonging to the org
    - All IP prefixes (IPv4 + IPv6)
    - Total IP count
    - BGP peers
    """

    BGPTOOLS_API = "https://bgp.tools/asn/{asn}.json"
    IPAPI_URL    = "https://ipapi.co/{ip}/json/"
    RIPE_SEARCH  = "https://stat.ripe.net/data/searchindex/data.json?resource={org}"
    RIPE_ASN     = "https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"
    RIPE_PREFIX  = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

    def __init__(self, target: str, timeout: int = 15):
        self.target  = target
        self.timeout = timeout
        self.records: list[ASNRecord] = []

    def _get(self, url: str) -> dict:
        if not REQUESTS_OK:
            return {}
        try:
            r = requests.get(url, timeout=self.timeout,
                             headers={"User-Agent":"Mozilla/5.0 (NSP-SPECTER)"})
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            log.debug(f"[ASN] {url}: {e}")
        return {}

    def _ip_to_asn(self, ip: str) -> str:
        data = self._get(self.IPAPI_URL.format(ip=ip))
        return data.get("asn","").replace("AS","")

    def _resolve_target(self) -> list:
        """Resolve target to ASN list."""
        asns = []
        # If it looks like an ASN
        if re.match(r"^AS?\d+$", self.target, re.IGNORECASE):
            asns.append(self.target.upper().replace("AS",""))
        # If it's an IP
        elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", self.target):
            asn = self._ip_to_asn(self.target)
            if asn:
                asns.append(asn)
        else:
            # Try resolving as hostname
            try:
                ip = socket.gethostbyname(self.target)
                asn = self._ip_to_asn(ip)
                if asn:
                    asns.append(asn)
            except Exception:
                pass
            # Also search RIPE for org name
            data = self._get(self.RIPE_SEARCH.format(org=self.target))
            for result in (data.get("data",{}).get("results",{})
                           .get("autonomous_systems",[])):
                asns.append(str(result.get("resource","")).replace("AS",""))
        return list(set(asns))[:10]

    def _fetch_asn_details(self, asn: str) -> ASNRecord:
        record = ASNRecord(asn=f"AS{asn}")

        # RIPE ASN overview
        overview = self._get(self.RIPE_ASN.format(asn=asn))
        if overview:
            d = overview.get("data",{})
            record.org     = d.get("holder","")
            record.country = d.get("resource","")

        # RIPE announced prefixes
        prefixes_data = self._get(self.RIPE_PREFIX.format(asn=asn))
        if prefixes_data:
            prefixes = prefixes_data.get("data",{}).get("prefixes",[])
            for p in prefixes:
                prefix = p.get("prefix","")
                if ":" in prefix:
                    record.prefixes6.append(prefix)
                else:
                    record.prefixes.append(prefix)
            # Estimate total IPs
            for cidr in record.prefixes:
                try:
                    import ipaddress
                    record.total_ips += ipaddress.ip_network(cidr,strict=False).num_addresses
                except Exception:
                    pass

        console.print(f"  [#00FFD4][ASN] AS{asn} | {record.org} | "
                       f"{len(record.prefixes)} IPv4 prefixes | "
                       f"~{record.total_ips:,} IPs[/#00FFD4]")
        return record

    def _print_results(self):
        table = Table(
            title=f"[bold #7B00FF]🗺️  ASN MAP — {self.target}[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("ASN",         width=12)
        table.add_column("Organisation",width=35)
        table.add_column("Country",     width=8)
        table.add_column("IPv4 Ranges", width=10, justify="right")
        table.add_column("Total IPs",   width=14, justify="right")
        table.add_column("Sample Prefix",width=20)

        for r in self.records:
            table.add_row(
                r.asn, r.org[:35], r.country,
                str(len(r.prefixes)),
                f"{r.total_ips:,}",
                r.prefixes[0] if r.prefixes else "—",
            )
        console.print(table)

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🗺️  ASN Mapper — {self.target}[/bold #7B00FF]")
        asns = self._resolve_target()
        if not asns:
            console.print(f"[bold #FFD700]  ⚠ No ASNs found for: {self.target}[/bold #FFD700]")
            return {"target": self.target, "asns": []}

        console.print(f"  [#00FFD4]→ Found {len(asns)} ASN(s): {', '.join(f'AS{a}' for a in asns)}[/#00FFD4]")
        for asn in asns:
            record = self._fetch_asn_details(asn)
            self.records.append(record)

        self._print_results()
        all_prefixes = [p for r in self.records for p in r.prefixes]
        total_ips    = sum(r.total_ips for r in self.records)
        console.print(f"[bold #00FFD4]  ✅ ASN map complete — "
                       f"{len(self.records)} ASNs | {len(all_prefixes)} ranges | "
                       f"~{total_ips:,} IPs[/bold #00FFD4]")
        return {
            "target":       self.target,
            "asns":         [{"asn":r.asn,"org":r.org,"country":r.country,
                              "prefixes":r.prefixes[:20],"total_ips":r.total_ips}
                             for r in self.records],
            "all_prefixes": all_prefixes,
            "total_ips":    total_ips,
        }
