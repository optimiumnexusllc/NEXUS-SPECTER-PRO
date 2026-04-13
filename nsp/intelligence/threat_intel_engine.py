"""
NEXUS SPECTER PRO — Threat Intelligence Engine
Multi-source passive intelligence aggregation & target scoring.
Sources: Shodan · Censys · GreyNoise · VirusTotal · AbuseIPDB · URLScan
Produces a unified ThreatScore (0-100) with confidence bands.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import os, logging, json, hashlib, time
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timedelta
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
log = logging.getLogger("nsp.intelligence.threat_intel")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ── Scoring weights ────────────────────────────────────────────────────────
SCORE_WEIGHTS = {
    "shodan_vulns":          25,   # Known CVEs on Shodan
    "shodan_open_ports":      5,   # Attack surface
    "greyNoise_malicious":   20,   # Known bad actor
    "virustotal_detections": 20,   # AV/threat intel detections
    "abuseipdb_score":       15,   # Community abuse reports
    "censys_exposure":       10,   # Exposed services
    "urlscan_threats":        5,   # Malicious URL detections
}

THREAT_LEVELS = [
    (80, 100, "CRITICAL",  "#FF003C"),
    (60,  79, "HIGH",      "#FF8C00"),
    (40,  59, "MEDIUM",    "#FFD700"),
    (20,  39, "LOW",       "#00FFD4"),
    ( 0,  19, "MINIMAL",   "#555555"),
]


@dataclass
class SourceResult:
    source:     str
    raw:        dict = field(default_factory=dict)
    score:      float = 0.0
    findings:   list  = field(default_factory=list)
    error:      str   = ""
    queried_at: str   = ""


@dataclass
class ThreatProfile:
    target:        str
    target_type:   str   = ""        # ip | domain | url | hash
    threat_score:  float = 0.0
    threat_level:  str   = "MINIMAL"
    threat_color:  str   = "#555555"
    confidence:    str   = "Low"
    sources:       dict  = field(default_factory=dict)
    tags:          list  = field(default_factory=list)
    open_ports:    list  = field(default_factory=list)
    known_vulns:   list  = field(default_factory=list)
    malware_family:list  = field(default_factory=list)
    country:       str   = ""
    asn:           str   = ""
    org:           str   = ""
    last_seen:     str   = ""
    first_seen:    str   = ""
    summary:       str   = ""
    queried_at:    str   = field(default_factory=lambda: datetime.utcnow().isoformat())


class ThreatIntelEngine:
    """
    Multi-source Threat Intelligence aggregator for NEXUS SPECTER PRO.
    Queries public threat intel APIs in parallel, normalises results,
    computes a composite ThreatScore, and surfaces actionable intelligence.

    Supports: IPv4, IPv6, domains, URLs, file hashes (MD5/SHA1/SHA256).
    Cache layer: per-target JSON cache (TTL configurable).
    """

    CACHE_TTL_HOURS = 24

    def __init__(
        self,
        shodan_key:     str = None,
        censys_id:      str = None,
        censys_secret:  str = None,
        greynoise_key:  str = None,
        virustotal_key: str = None,
        abuseipdb_key:  str = None,
        cache_dir:      str = "/tmp/nsp_intel_cache",
        timeout:        int = 15,
    ):
        self.keys = {
            "shodan":     shodan_key     or os.getenv("SHODAN_API_KEY",     ""),
            "censys_id":  censys_id      or os.getenv("CENSYS_API_ID",      ""),
            "censys_sec": censys_secret  or os.getenv("CENSYS_API_SECRET",  ""),
            "greynoise":  greynoise_key  or os.getenv("GREYNOISE_API_KEY",  ""),
            "virustotal": virustotal_key or os.getenv("VIRUSTOTAL_API_KEY", ""),
            "abuseipdb":  abuseipdb_key  or os.getenv("ABUSEIPDB_API_KEY",  ""),
        }
        self.timeout   = timeout
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ── Cache helpers ────────────────────────────────────────────────────────
    def _cache_path(self, target: str) -> Path:
        h = hashlib.md5(target.encode()).hexdigest()[:12]
        return self.cache_dir / f"intel_{h}.json"

    def _load_cache(self, target: str) -> Optional[dict]:
        p = self._cache_path(target)
        if not p.exists():
            return None
        try:
            data  = json.loads(p.read_text())
            saved = datetime.fromisoformat(data.get("queried_at", "2000-01-01"))
            if datetime.utcnow() - saved < timedelta(hours=self.CACHE_TTL_HOURS):
                log.info(f"[INTEL] Cache hit: {target}")
                return data
        except Exception:
            pass
        return None

    def _save_cache(self, target: str, data: dict):
        try:
            self._cache_path(target).write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            log.debug(f"[INTEL] Cache write error: {e}")

    def _get(self, url: str, headers: dict = None, params: dict = None) -> Optional[dict]:
        if not REQUESTS_OK:
            return None
        try:
            r = requests.get(url, headers=headers or {}, params=params or {},
                             timeout=self.timeout, verify=True)
            if r.status_code == 200:
                return r.json()
            log.debug(f"[INTEL] {url} → HTTP {r.status_code}")
        except Exception as e:
            log.debug(f"[INTEL] Request error {url}: {e}")
        return None

    # ── Shodan ────────────────────────────────────────────────────────────────
    def _query_shodan(self, target: str) -> SourceResult:
        result = SourceResult(source="shodan",
                               queried_at=datetime.utcnow().isoformat())
        if not self.keys["shodan"]:
            result.error = "No SHODAN_API_KEY"
            return result
        try:
            import shodan as shodan_lib
            api  = shodan_lib.Shodan(self.keys["shodan"])
            data = api.host(target)
            result.raw = data

            # Ports
            ports  = data.get("ports", [])
            vulns  = list(data.get("vulns", {}).keys())
            org    = data.get("org", "")
            country= data.get("country_name", "")

            result.findings = [
                f"Organisation: {org}",
                f"Country: {country}",
                f"Open ports: {', '.join(str(p) for p in ports[:10])}",
                *[f"CVE: {v}" for v in vulns[:10]],
            ]
            # Score: 3pts/vuln, 1pt/5ports
            vuln_score = min(len(vulns) * 3, 25)
            port_score = min(len(ports) // 5, 5)
            result.score = vuln_score + port_score

            console.print(f"  [#00FFD4][SHODAN] {target} → {len(ports)} ports, "
                           f"{len(vulns)} CVEs, org: {org}[/#00FFD4]")
        except ImportError:
            result.error = "shodan library not installed"
        except Exception as e:
            result.error = str(e)[:100]
            log.debug(f"[INTEL][SHODAN] {e}")
        return result

    # ── Censys ────────────────────────────────────────────────────────────────
    def _query_censys(self, target: str) -> SourceResult:
        result = SourceResult(source="censys",
                               queried_at=datetime.utcnow().isoformat())
        if not self.keys["censys_id"]:
            result.error = "No CENSYS credentials"
            return result
        try:
            import censys.search
            h    = censys.search.CensysHosts(
                api_id     = self.keys["censys_id"],
                api_secret = self.keys["censys_sec"],
            )
            data = h.view(target)
            result.raw      = data
            services        = data.get("services", [])
            protocols       = [s.get("transport_protocol","") + "/"
                               + str(s.get("port","")) for s in services]
            result.findings = [f"Service: {p}" for p in protocols[:10]]
            result.score    = min(len(services) * 1.5, 10)
            console.print(f"  [#00FFD4][CENSYS] {target} → {len(services)} services[/#00FFD4]")
        except ImportError:
            result.error = "censys library not installed"
        except Exception as e:
            result.error = str(e)[:100]
        return result

    # ── GreyNoise ─────────────────────────────────────────────────────────────
    def _query_greynoise(self, target: str) -> SourceResult:
        result = SourceResult(source="greynoise",
                               queried_at=datetime.utcnow().isoformat())
        headers = {"key": self.keys["greynoise"], "Accept": "application/json"}
        data    = self._get(f"https://api.greynoise.io/v3/community/{target}",
                             headers=headers)
        if not data:
            result.error = "No response or no GREYNOISE_API_KEY"
            return result

        classification = data.get("classification", "unknown")
        noise          = data.get("noise", False)
        riot           = data.get("riot", False)
        name           = data.get("name", "")

        result.raw      = data
        result.findings = [
            f"Classification: {classification}",
            f"Noise: {noise}",
            f"RIOT (known-good): {riot}",
            f"Name: {name}",
        ]
        # Malicious = high score
        if classification == "malicious":
            result.score = 20
            console.print(f"  [bold #FF003C][GREYNOISE] {target} → MALICIOUS: {name}[/bold #FF003C]")
        elif classification == "benign" or riot:
            result.score = 0
            console.print(f"  [#00FFD4][GREYNOISE] {target} → benign/known-good[/#00FFD4]")
        else:
            result.score = 5
            console.print(f"  [#FFD700][GREYNOISE] {target} → unknown[/#FFD700]")
        return result

    # ── VirusTotal ────────────────────────────────────────────────────────────
    def _query_virustotal(self, target: str, target_type: str) -> SourceResult:
        result = SourceResult(source="virustotal",
                               queried_at=datetime.utcnow().isoformat())
        if not self.keys["virustotal"]:
            result.error = "No VIRUSTOTAL_API_KEY"
            return result

        endpoint_map = {
            "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{target}",
            "url":    f"https://www.virustotal.com/api/v3/urls/{hashlib.sha256(target.encode()).hexdigest()}",
            "hash":   f"https://www.virustotal.com/api/v3/files/{target}",
        }
        url = endpoint_map.get(target_type, endpoint_map["ip"])
        data = self._get(url, headers={"x-apikey": self.keys["virustotal"]})

        if not data:
            result.error = "No VT response"
            return result

        attrs     = data.get("data", {}).get("attributes", {})
        stats     = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious= stats.get("suspicious", 0)
        total     = sum(stats.values()) or 1
        detection_rate = round((malicious + suspicious) / total * 100, 1)

        result.raw      = attrs
        result.findings = [
            f"Malicious detections: {malicious}/{total}",
            f"Suspicious: {suspicious}/{total}",
            f"Detection rate: {detection_rate}%",
            f"Categories: {', '.join(list(attrs.get('categories', {}).values())[:3])}",
        ]
        result.score = min(detection_rate * 0.20, 20)

        if malicious > 0:
            console.print(f"  [bold #FF003C][VIRUSTOTAL] {target} → "
                           f"{malicious}/{total} malicious detections[/bold #FF003C]")
        else:
            console.print(f"  [#00FFD4][VIRUSTOTAL] {target} → clean[/#00FFD4]")
        return result

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    def _query_abuseipdb(self, ip: str) -> SourceResult:
        result = SourceResult(source="abuseipdb",
                               queried_at=datetime.utcnow().isoformat())
        if not self.keys["abuseipdb"]:
            result.error = "No ABUSEIPDB_API_KEY"
            return result

        data = self._get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.keys["abuseipdb"], "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        )
        if not data:
            result.error = "No AbuseIPDB response"
            return result

        d = data.get("data", {})
        abuse_score   = d.get("abuseConfidenceScore", 0)
        total_reports = d.get("totalReports", 0)
        country       = d.get("countryCode", "")
        isp           = d.get("isp", "")
        usage         = d.get("usageType", "")

        result.raw      = d
        result.findings = [
            f"Abuse confidence score: {abuse_score}%",
            f"Total reports: {total_reports}",
            f"Country: {country} | ISP: {isp}",
            f"Usage type: {usage}",
        ]
        result.score = min(abuse_score * 0.15, 15)

        if abuse_score > 50:
            console.print(f"  [bold #FF003C][ABUSEIPDB] {ip} → score {abuse_score}% "
                           f"({total_reports} reports)[/bold #FF003C]")
        else:
            console.print(f"  [#00FFD4][ABUSEIPDB] {ip} → score {abuse_score}%[/#00FFD4]")
        return result

    # ── URLScan.io ────────────────────────────────────────────────────────────
    def _query_urlscan(self, target: str) -> SourceResult:
        result = SourceResult(source="urlscan",
                               queried_at=datetime.utcnow().isoformat())
        data = self._get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{target}", "size": 5},
        )
        if not data:
            result.error = "URLScan unavailable"
            return result

        results    = data.get("results", [])
        malicious  = sum(1 for r in results
                         if r.get("verdicts", {}).get("overall", {}).get("malicious"))
        result.raw = data
        result.findings = [
            f"Scans found: {len(results)}",
            f"Malicious verdicts: {malicious}",
        ]
        result.score    = min(malicious * 2.5, 5)
        console.print(f"  [#00FFD4][URLSCAN] {target} → "
                       f"{len(results)} scans, {malicious} malicious[/#00FFD4]")
        return result

    # ── Target type detection ─────────────────────────────────────────────────
    def _detect_type(self, target: str) -> str:
        import re
        if re.match(r"^[0-9a-fA-F]{32,64}$", target):
            return "hash"
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return "ip"
        if target.startswith("http://") or target.startswith("https://"):
            return "url"
        return "domain"

    # ── Score aggregation ─────────────────────────────────────────────────────
    def _compute_score(self, sources: dict) -> tuple:
        total = 0.0
        for src, result in sources.items():
            if isinstance(result, SourceResult):
                total += result.score
        total = min(total, 100)

        for lo, hi, level, color in THREAT_LEVELS:
            if lo <= total <= hi:
                return round(total, 1), level, color

        return round(total, 1), "MINIMAL", "#555555"

    def _compute_confidence(self, sources: dict) -> str:
        ok = sum(1 for v in sources.values()
                 if isinstance(v, SourceResult) and not v.error)
        if ok >= 4:  return "High"
        if ok >= 2:  return "Medium"
        return "Low"

    # ── Display ───────────────────────────────────────────────────────────────
    def _print_profile(self, profile: ThreatProfile):
        sc = profile.threat_color
        console.print(Panel(
            f"[bold {sc}]THREAT SCORE: {profile.threat_score}/100 "
            f"— {profile.threat_level}[/bold {sc}]\n"
            f"[bold #00FFD4]Target:[/bold #00FFD4]      {profile.target}\n"
            f"[bold #00FFD4]Type:[/bold #00FFD4]        {profile.target_type.upper()}\n"
            f"[bold #00FFD4]Country:[/bold #00FFD4]     {profile.country}\n"
            f"[bold #00FFD4]ASN/Org:[/bold #00FFD4]     {profile.asn} {profile.org}\n"
            f"[bold #00FFD4]Confidence:[/bold #00FFD4]  {profile.confidence}\n"
            f"[bold #00FFD4]Sources:[/bold #00FFD4]     "
            f"{', '.join(profile.sources.keys())}\n"
            + (f"[bold #FF003C]Known CVEs:[/bold #FF003C]  "
               f"{', '.join(profile.known_vulns[:5])}\n"
               if profile.known_vulns else "")
            + (f"[bold #FF8C00]Tags:[/bold #FF8C00]       "
               f"{', '.join(profile.tags)}\n"
               if profile.tags else ""),
            title=f"[bold #7B00FF]🧠 THREAT INTELLIGENCE — {profile.target}[/bold #7B00FF]",
            border_style="#7B00FF",
        ))

        # Source detail table
        table = Table(border_style="#1E1E1E", header_style="bold #00FFD4",
                      title="Source Details")
        table.add_column("Source",   width=14)
        table.add_column("Score",    width=8,  justify="right")
        table.add_column("Findings", width=60)
        table.add_column("Status",   width=10)

        for src, res in profile.sources.items():
            if not isinstance(res, SourceResult):
                continue
            status = "[bold #FF003C]ERROR[/bold #FF003C]" if res.error \
                else "[bold #00FFD4]✅ OK[/bold #00FFD4]"
            findings_str = " | ".join(res.findings[:2])[:60]
            table.add_row(src.upper(), f"{res.score:.1f}", findings_str, status)
        console.print(table)

    # ── Main entry point ──────────────────────────────────────────────────────
    def run(self, target: str, use_cache: bool = True) -> dict:
        console.print(f"[bold #7B00FF]  🧠 Threat Intel Engine — {target}[/bold #7B00FF]")

        # Cache check
        if use_cache:
            cached = self._load_cache(target)
            if cached:
                console.print(f"[dim]  → Cache hit ({self.CACHE_TTL_HOURS}h TTL)[/dim]")
                return cached

        target_type = self._detect_type(target)
        sources     = {}

        # Query all sources
        if target_type in ("ip", "domain"):
            sources["shodan"]    = self._query_shodan(target) \
                                   if target_type == "ip" else SourceResult("shodan", error="domain only for cert search")
            sources["censys"]    = self._query_censys(target)
            sources["greynoise"] = self._query_greynoise(target) \
                                   if target_type == "ip" else SourceResult("greynoise", error="IP only")
            sources["abuseipdb"] = self._query_abuseipdb(target) \
                                   if target_type == "ip" else SourceResult("abuseipdb", error="IP only")
            sources["urlscan"]   = self._query_urlscan(target)

        sources["virustotal"] = self._query_virustotal(target, target_type)

        score, level, color = self._compute_score(sources)
        confidence          = self._compute_confidence(sources)

        # Extract enriched data from Shodan if available
        shodan_raw  = sources.get("shodan", SourceResult("")).raw
        known_vulns = list(shodan_raw.get("vulns", {}).keys())
        open_ports  = shodan_raw.get("ports", [])
        country     = shodan_raw.get("country_name", "")
        org         = shodan_raw.get("org", "")
        asn         = str(shodan_raw.get("asn", ""))

        # Tags
        tags = []
        if score >= 80:    tags.append("malicious")
        if score >= 60:    tags.append("high-risk")
        if known_vulns:    tags.append(f"{len(known_vulns)}-CVEs")
        if open_ports:     tags.append(f"{len(open_ports)}-ports-open")

        profile = ThreatProfile(
            target        = target,
            target_type   = target_type,
            threat_score  = score,
            threat_level  = level,
            threat_color  = color,
            confidence    = confidence,
            sources       = {k: v.__dict__ for k, v in sources.items()
                             if isinstance(v, SourceResult)},
            tags          = tags,
            open_ports    = open_ports,
            known_vulns   = known_vulns,
            country       = country,
            asn           = asn,
            org           = org,
            queried_at    = datetime.utcnow().isoformat(),
        )

        self._print_profile(profile)
        console.print(f"[bold #00FFD4]  ✅ Intel complete — score: {score}/100 "
                       f"[{level}][/bold #00FFD4]")

        from dataclasses import asdict
        result = asdict(profile)
        self._save_cache(target, result)
        return result

    def batch_run(self, targets: list, delay: float = 1.0) -> list:
        """Run intel on multiple targets with polite delay."""
        results = []
        console.print(f"[bold #7B00FF]  🧠 Batch Intel — {len(targets)} targets[/bold #7B00FF]")
        for i, target in enumerate(targets, 1):
            console.print(f"\n[#7B00FF]  [{i}/{len(targets)}] {target}[/#7B00FF]")
            results.append(self.run(target))
            if i < len(targets):
                time.sleep(delay)

        # Sort by threat score descending
        results.sort(key=lambda x: x.get("threat_score", 0), reverse=True)
        self._print_batch_summary(results)
        return results

    def _print_batch_summary(self, results: list):
        table = Table(
            title=f"[bold #7B00FF]🧠 BATCH INTEL — {len(results)} TARGETS[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Target",   width=30)
        table.add_column("Score",    width=8,  justify="right")
        table.add_column("Level",    width=12)
        table.add_column("CVEs",     width=6,  justify="right")
        table.add_column("Ports",    width=6,  justify="right")
        table.add_column("Tags",     width=30)

        LEVEL_COLOR = {
            "CRITICAL": "[bold #FF003C]", "HIGH": "[bold #FF8C00]",
            "MEDIUM": "[bold #FFD700]",   "LOW": "[bold #00FFD4]",
            "MINIMAL": "[dim]",
        }
        for r in results:
            lc = LEVEL_COLOR.get(r.get("threat_level",""), "[white]")
            le = lc.replace("[","[/")
            table.add_row(
                r.get("target","")[:30],
                f"{r.get('threat_score',0):.0f}",
                f"{lc}{r.get('threat_level','')}{le}",
                str(len(r.get("known_vulns",[]))),
                str(len(r.get("open_ports",[]))),
                ", ".join(r.get("tags",[]))[:30],
            )
        console.print(table)
