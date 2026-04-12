"""
NEXUS SPECTER PRO — OSINT Engine
Passive intelligence gathering: Shodan, Censys, FOFA, ZoomEye, Hunter.io
by OPTIMIUM NEXUS LLC
"""

import os
import json
import logging
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.recon.osint")


@dataclass
class OSINTResult:
    target:      str
    shodan:      dict = field(default_factory=dict)
    censys:      dict = field(default_factory=dict)
    fofa:        dict = field(default_factory=dict)
    zoomEye:     dict = field(default_factory=dict)
    hunter:      dict = field(default_factory=dict)
    breach_data: dict = field(default_factory=dict)
    errors:      list = field(default_factory=list)


class OSINTEngine:
    """
    Passive OSINT engine — aggregates data from multiple intelligence sources.
    Sources: Shodan, Censys, FOFA, ZoomEye, Hunter.io, HIBP, DeHashed, LeakIX
    """

    def __init__(self, target: str, config: Optional[dict] = None):
        self.target = target
        self.config = config or {}
        self.result = OSINTResult(target=target)
        self._load_api_keys()

    def _load_api_keys(self):
        """Load API keys from environment variables or config."""
        self.shodan_key   = os.getenv("SHODAN_API_KEY",   self.config.get("shodan_api_key", ""))
        self.censys_id    = os.getenv("CENSYS_API_ID",    self.config.get("censys_api_id", ""))
        self.censys_secret= os.getenv("CENSYS_API_SECRET",self.config.get("censys_api_secret", ""))
        self.hunter_key   = os.getenv("HUNTER_API_KEY",   self.config.get("hunter_api_key", ""))
        self.hibp_key     = os.getenv("HIBP_API_KEY",     self.config.get("hibp_api_key", ""))

    def query_shodan(self) -> dict:
        """Query Shodan for host/domain intelligence."""
        if not self.shodan_key:
            log.warning("[OSINT] Shodan API key not configured — skipping")
            return {}
        try:
            import shodan
            api = shodan.Shodan(self.shodan_key)
            console.print(f"[#00FFD4]  [SHODAN] Querying: {self.target}[/#00FFD4]")
            results = api.search(f"hostname:{self.target}")
            data = {
                "total":   results.get("total", 0),
                "matches": []
            }
            for match in results.get("matches", [])[:20]:
                data["matches"].append({
                    "ip":       match.get("ip_str"),
                    "port":     match.get("port"),
                    "org":      match.get("org"),
                    "product":  match.get("product"),
                    "version":  match.get("version"),
                    "os":       match.get("os"),
                    "hostnames":match.get("hostnames", []),
                    "vulns":    list(match.get("vulns", {}).keys()),
                    "banner":   match.get("data", "")[:200],
                })
            log.info(f"[OSINT][SHODAN] Found {data['total']} results for {self.target}")
            return data
        except ImportError:
            log.warning("[OSINT] shodan library not installed. Run: pip install shodan")
            return {"error": "shodan library not installed"}
        except Exception as e:
            log.error(f"[OSINT][SHODAN] Error: {e}")
            self.result.errors.append(f"Shodan: {str(e)}")
            return {}

    def query_censys(self) -> dict:
        """Query Censys for certificate/host intelligence."""
        if not self.censys_id or not self.censys_secret:
            log.warning("[OSINT] Censys credentials not configured — skipping")
            return {}
        try:
            import censys.search
            console.print(f"[#00FFD4]  [CENSYS] Querying: {self.target}[/#00FFD4]")
            h = censys.search.CensysHosts(api_id=self.censys_id, api_secret=self.censys_secret)
            results = list(h.search(f"parsed.names: {self.target}", per_page=20))
            data = {
                "total": len(results),
                "hosts": []
            }
            for host in results:
                data["hosts"].append({
                    "ip":       host.get("ip"),
                    "services": host.get("services", []),
                    "labels":   host.get("labels", []),
                })
            log.info(f"[OSINT][CENSYS] Found {data['total']} hosts for {self.target}")
            return data
        except ImportError:
            log.warning("[OSINT] censys library not installed. Run: pip install censys")
            return {"error": "censys library not installed"}
        except Exception as e:
            log.error(f"[OSINT][CENSYS] Error: {e}")
            self.result.errors.append(f"Censys: {str(e)}")
            return {}

    def query_hunter(self) -> dict:
        """Query Hunter.io for email addresses associated with the domain."""
        if not self.hunter_key:
            log.warning("[OSINT] Hunter.io API key not configured — skipping")
            return {}
        try:
            import requests
            console.print(f"[#00FFD4]  [HUNTER] Email enumeration: {self.target}[/#00FFD4]")
            url = f"https://api.hunter.io/v2/domain-search?domain={self.target}&api_key={self.hunter_key}"
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            raw = resp.json().get("data", {})
            data = {
                "organization":   raw.get("organization"),
                "emails_found":   raw.get("emails", []),
                "pattern":        raw.get("pattern"),
                "total":          len(raw.get("emails", [])),
            }
            log.info(f"[OSINT][HUNTER] Found {data['total']} emails for {self.target}")
            return data
        except Exception as e:
            log.error(f"[OSINT][HUNTER] Error: {e}")
            self.result.errors.append(f"Hunter: {str(e)}")
            return {}

    def query_breach_data(self) -> dict:
        """Check for breach data using HIBP API."""
        if not self.hibp_key:
            log.warning("[OSINT] HIBP API key not configured — skipping")
            return {}
        try:
            import requests
            console.print(f"[#00FFD4]  [HIBP] Breach lookup: {self.target}[/#00FFD4]")
            headers = {"hibp-api-key": self.hibp_key, "user-agent": "NSP-Specter"}
            url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{self.target}"
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 404:
                return {"breaches": [], "total": 0, "status": "clean"}
            resp.raise_for_status()
            breaches = resp.json()
            return {"breaches": breaches, "total": len(breaches), "status": "breached"}
        except Exception as e:
            log.error(f"[OSINT][HIBP] Error: {e}")
            return {}

    def whois_lookup(self) -> dict:
        """Perform WHOIS lookup for the target domain."""
        try:
            import whois as python_whois
            console.print(f"[#00FFD4]  [WHOIS] Lookup: {self.target}[/#00FFD4]")
            w = python_whois.whois(self.target)
            return {
                "registrar":       str(w.registrar),
                "creation_date":   str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers":    w.name_servers or [],
                "emails":          w.emails or [],
                "org":             str(w.org),
                "country":         str(w.country),
            }
        except ImportError:
            log.warning("[OSINT] python-whois not installed. Run: pip install python-whois")
            return {}
        except Exception as e:
            log.error(f"[OSINT][WHOIS] Error: {e}")
            return {}

    def run(self) -> dict:
        """
        Execute all OSINT sources and return aggregated results.
        Returns a dict suitable for JSON serialization and report generation.
        """
        console.print(f"[bold #7B00FF]  🔍 OSINT Engine starting on: {self.target}[/bold #7B00FF]")

        self.result.shodan      = self.query_shodan()
        self.result.censys      = self.query_censys()
        self.result.hunter      = self.query_hunter()
        self.result.breach_data = self.query_breach_data()

        whois_data = self.whois_lookup()

        summary = {
            "target":       self.target,
            "shodan":       self.result.shodan,
            "censys":       self.result.censys,
            "hunter_io":    self.result.hunter,
            "breach_data":  self.result.breach_data,
            "whois":        whois_data,
            "errors":       self.result.errors,
        }

        log.info(f"[OSINT] Scan complete for {self.target}")
        return summary
