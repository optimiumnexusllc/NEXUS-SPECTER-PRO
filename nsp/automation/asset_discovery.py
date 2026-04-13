"""
NEXUS SPECTER PRO — Continuous Asset Discovery
Monitors an organisation's attack surface for new assets:
new subdomains, new IPs, new open ports, new cloud buckets.
Runs on a schedule and alerts on newly discovered assets.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json, logging, hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.automation.asset_discovery")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


@dataclass
class DiscoveredAsset:
    asset_id:    str
    asset_type:  str     # subdomain | ip | port | bucket | certificate | api
    value:       str
    source:      str     # ct_logs | shodan | dns | brute | cloud
    first_seen:  str     = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen:   str     = field(default_factory=lambda: datetime.utcnow().isoformat())
    is_new:      bool    = True
    risk_score:  int     = 0
    metadata:    dict    = field(default_factory=dict)


class AssetDiscovery:
    """
    Continuous asset discovery engine for NEXUS SPECTER PRO.
    Maintains a persistent inventory of known assets.
    On each run, compares with previous inventory → surfaces NEW assets.
    New assets are flagged for immediate scanning.
    """

    INVENTORY_DIR = Path("/tmp/nsp_asset_inventory")

    def __init__(self, org: str, domain: str,
                 alert_engine=None, output_dir: str = "/tmp/nsp_assets"):
        self.org          = org
        self.domain       = domain
        self.alert_engine = alert_engine
        self.output_dir   = Path(output_dir)
        self.INVENTORY_DIR.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._known:   dict[str, DiscoveredAsset] = {}
        self._new:     list[DiscoveredAsset]      = []
        self._load_inventory()

    def _inventory_path(self) -> Path:
        safe = self.domain.replace(".","_")
        return self.INVENTORY_DIR / f"inventory_{safe}.json"

    def _load_inventory(self):
        p = self._inventory_path()
        if p.exists():
            try:
                raw = json.loads(p.read_text())
                for aid, data in raw.items():
                    self._known[aid] = DiscoveredAsset(**data)
                log.info(f"[ASSET] Loaded {len(self._known)} known assets")
            except Exception as e:
                log.warning(f"[ASSET] Inventory load error: {e}")

    def _save_inventory(self):
        data = {aid: a.__dict__ for aid, a in self._known.items()}
        self._inventory_path().write_text(json.dumps(data, indent=2, default=str))

    def _asset_id(self, asset_type: str, value: str) -> str:
        return hashlib.md5(f"{asset_type}:{value}".encode()).hexdigest()[:12]

    def _register(self, asset_type: str, value: str, source: str,
                  risk: int = 10, metadata: dict = None) -> DiscoveredAsset:
        aid   = self._asset_id(asset_type, value)
        is_new= aid not in self._known
        asset = DiscoveredAsset(
            asset_id   = aid,
            asset_type = asset_type,
            value      = value,
            source     = source,
            is_new     = is_new,
            risk_score = risk,
            metadata   = metadata or {},
        )
        if not is_new:
            asset.first_seen = self._known[aid].first_seen
            asset.is_new     = False
        else:
            self._new.append(asset)
        self._known[aid] = asset
        return asset

    # ── Discovery sources ─────────────────────────────────────────────────────
    def _discover_from_ct(self) -> list:
        """Certificate Transparency log subdomains."""
        found = []
        try:
            from nsp.recon.passive.certificate_transparency import CertificateTransparency
            ct   = CertificateTransparency(self.domain)
            data = ct.run()
            for sub in data.get("subdomains", []):
                a = self._register("subdomain", sub, "ct_logs", risk=15)
                found.append(a)
            console.print(f"  [#00FFD4][CT] {len(data.get('subdomains',[]))} "
                           f"subdomains from CT logs[/#00FFD4]")
        except Exception as e:
            log.debug(f"[ASSET][CT] {e}")
        return found

    def _discover_from_dns(self) -> list:
        """DNS brute-force subdomain discovery."""
        found = []
        try:
            from nsp.recon.active.subdomain_enum import SubdomainEnumerator
            se   = SubdomainEnumerator(self.domain, wordlist_size="small")
            data = se.run()
            for sub in data.get("all_subdomains", []):
                a = self._register("subdomain", sub, "dns_brute", risk=15)
                found.append(a)
            console.print(f"  [#00FFD4][DNS] {len(data.get('all_subdomains',[]))} "
                           f"subdomains via DNS[/#00FFD4]")
        except Exception as e:
            log.debug(f"[ASSET][DNS] {e}")
        return found

    def _discover_from_shodan(self, shodan_key: str = "") -> list:
        """Shodan org search for new IPs and services."""
        found = []
        if not shodan_key:
            return found
        try:
            import shodan as shodan_lib
            api     = shodan_lib.Shodan(shodan_key)
            results = api.search(f"org:{self.org}")
            for r in results.get("matches", [])[:100]:
                ip   = r.get("ip_str","")
                port = r.get("port", 0)
                if ip:
                    a = self._register("ip", ip, "shodan", risk=20,
                                       metadata={"org": r.get("org",""),
                                                 "country": r.get("country_name","")})
                    found.append(a)
                if ip and port:
                    a = self._register("port", f"{ip}:{port}", "shodan", risk=15,
                                       metadata={"product": r.get("product",""),
                                                 "version": r.get("version","")})
                    found.append(a)
            console.print(f"  [#00FFD4][SHODAN] {len(found)} assets discovered[/#00FFD4]")
        except Exception as e:
            log.debug(f"[ASSET][SHODAN] {e}")
        return found

    def _discover_cloud(self) -> list:
        """Cloud asset discovery."""
        found = []
        try:
            from nsp.recon.active.cloud_recon import CloudRecon
            cr   = CloudRecon(self.domain, org=self.org, max_buckets=20)
            data = cr.run()
            for asset in data.get("assets", []):
                if asset.get("public"):
                    a = self._register(
                        "bucket", asset["name"], "cloud_recon",
                        risk={"critical":90,"high":70,"medium":50,"low":20,"info":5}
                           .get(asset.get("severity","info"),10),
                        metadata={"provider": asset.get("provider",""),
                                  "url":      asset.get("url","")},
                    )
                    found.append(a)
            console.print(f"  [#00FFD4][CLOUD] {len(found)} cloud assets discovered[/#00FFD4]")
        except Exception as e:
            log.debug(f"[ASSET][CLOUD] {e}")
        return found

    def _print_new_assets(self):
        if not self._new:
            console.print("[bold #00FFD4]  ✅ No new assets discovered.[/bold #00FFD4]")
            return

        table = Table(
            title=f"[bold #FF003C]⚡ NEW ASSETS — {len(self._new)} discovered[/bold #FF003C]",
            border_style="#FF003C", header_style="bold #00FFD4",
        )
        table.add_column("Type",     width=12)
        table.add_column("Value",    width=40)
        table.add_column("Source",   width=15)
        table.add_column("Risk",     width=6, justify="right")
        table.add_column("First Seen",width=12)

        for a in sorted(self._new, key=lambda x: -x.risk_score)[:30]:
            rc = ("#FF003C" if a.risk_score>=70 else "#FF8C00" if a.risk_score>=40
                  else "#FFD700" if a.risk_score>=20 else "#00FFD4")
            table.add_row(
                a.asset_type, a.value[:40], a.source,
                f"[bold {rc}]{a.risk_score}[/bold {rc}]",
                a.first_seen[:10],
            )
        console.print(table)

    def get_inventory_summary(self) -> dict:
        by_type: dict = {}
        for a in self._known.values():
            by_type.setdefault(a.asset_type, []).append(a.value)
        return {
            "domain":      self.domain,
            "org":         self.org,
            "total_assets":len(self._known),
            "by_type":     {k: len(v) for k,v in by_type.items()},
            "new_this_run":len(self._new),
            "last_updated":datetime.utcnow().isoformat(),
        }

    def run(self, shodan_key: str = "") -> dict:
        console.print(f"[bold #7B00FF]  🔍 Asset Discovery — {self.domain} | "
                       f"org: {self.org}[/bold #7B00FF]")
        self._new = []

        self._discover_from_ct()
        self._discover_from_dns()
        self._discover_from_shodan(shodan_key)
        self._discover_cloud()

        self._save_inventory()
        self._print_new_assets()

        # Alert on high-risk new assets
        if self.alert_engine and self._new:
            high_risk = [a for a in self._new if a.risk_score >= 50]
            if high_risk:
                self.alert_engine.send(
                    title   = f"⚡ NSP: {len(high_risk)} high-risk new assets for {self.domain}",
                    message = "\n".join(f"• {a.asset_type}: {a.value}" for a in high_risk[:5]),
                    level   = "warning",
                )

        summary = self.get_inventory_summary()
        console.print(f"[bold #00FFD4]  ✅ Asset Discovery complete — "
                       f"{summary['total_assets']} total | {len(self._new)} new[/bold #00FFD4]")
        return {
            **summary,
            "new_assets": [a.__dict__ for a in self._new],
            "high_risk_new": [a.__dict__ for a in self._new if a.risk_score >= 50],
        }
