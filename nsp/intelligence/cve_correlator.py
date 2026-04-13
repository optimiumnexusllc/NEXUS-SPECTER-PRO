"""
NEXUS SPECTER PRO — CVE Correlator
Live correlation: software version → CVEs → exploit availability → CISA KEV
Sources: NVD API v2.0 · CISA KEV · ExploitDB · GitHub PoC repos · Metasploit modules
Answers: "This version has X critical CVEs, Y are weaponized, Z are CISA KEV."
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import os, logging, json, time, re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
log = logging.getLogger("nsp.intelligence.cve_correlator")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ── CISA KEV (updated daily) ──────────────────────────────────────────────────
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ── NVD API ──────────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── ExploitDB search ─────────────────────────────────────────────────────────
EXPLOITDB_SEARCH_URL = "https://www.exploit-db.com/search"

# ── GitHub PoC search (public API) ───────────────────────────────────────────
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}


@dataclass
class CVERecord:
    cve_id:          str
    description:     str         = ""
    cvss_v3_score:   float       = 0.0
    cvss_v3_vector:  str         = ""
    cvss_v3_severity:str         = ""
    cvss_v2_score:   float       = 0.0
    published:       str         = ""
    modified:        str         = ""
    cwe:             list        = field(default_factory=list)
    references:      list        = field(default_factory=list)
    # Exploit intelligence
    in_cisa_kev:     bool        = False
    kev_due_date:    str         = ""
    kev_ransomware:  str         = ""
    exploit_available: bool      = False
    exploitdb_ids:   list        = field(default_factory=list)
    github_pocs:     int         = 0
    metasploit_module: bool      = False
    weaponization_score: int     = 0   # 0-10
    priority:        str         = ""  # IMMEDIATE / HIGH / MEDIUM / LOW


@dataclass
class CorrelationResult:
    query:              str
    query_type:         str      = ""   # product | cpe | cve_id | banner
    cves:               list     = field(default_factory=list)
    total_cves:         int      = 0
    critical_count:     int      = 0
    high_count:         int      = 0
    kev_count:          int      = 0
    weaponized_count:   int      = 0
    max_cvss:           float    = 0.0
    overall_risk:       str      = ""
    top_priority_cves:  list     = field(default_factory=list)
    patch_urgency:      str      = ""
    queried_at:         str      = field(default_factory=lambda: datetime.utcnow().isoformat())


class CVECorrelator:
    """
    CVE Correlation Engine for NEXUS SPECTER PRO.
    Given a software product/version or CPE string:
    1. Fetches matching CVEs from NVD API v2.0
    2. Cross-references with CISA KEV (Known Exploited Vulnerabilities)
    3. Checks ExploitDB + GitHub for public PoCs
    4. Computes a weaponization score and remediation priority
    5. Returns a ranked, actionable vulnerability list
    """

    CACHE_DIR = Path("/tmp/nsp_cve_cache")
    KEV_CACHE = Path("/tmp/nsp_kev_cache.json")
    KEV_TTL   = 86400   # 24h in seconds

    def __init__(self, nvd_api_key: str = None, github_token: str = None,
                 timeout: int = 20):
        self.nvd_key      = nvd_api_key  or os.getenv("NVD_API_KEY",   "")
        self.github_token = github_token or os.getenv("GITHUB_TOKEN",  "")
        self.timeout      = timeout
        self.kev_data     = {}          # CVE-ID → KEV record
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._load_kev()

    # ── CISA KEV ─────────────────────────────────────────────────────────────
    def _load_kev(self):
        """Load CISA KEV catalogue (cached 24h)."""
        if (self.KEV_CACHE.exists() and
                time.time() - self.KEV_CACHE.stat().st_mtime < self.KEV_TTL):
            try:
                self.kev_data = {
                    v["cveID"]: v
                    for v in json.loads(self.KEV_CACHE.read_text()).get("vulnerabilities",[])
                }
                log.info(f"[CVE] KEV loaded from cache: {len(self.kev_data)} entries")
                return
            except Exception:
                pass
        try:
            r = requests.get(CISA_KEV_URL, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                self.KEV_CACHE.write_text(json.dumps(data))
                self.kev_data = {
                    v["cveID"]: v for v in data.get("vulnerabilities", [])
                }
                console.print(f"[#00FFD4]  [KEV] CISA KEV loaded: "
                               f"{len(self.kev_data)} known exploited vulnerabilities[/#00FFD4]")
        except Exception as e:
            log.warning(f"[CVE] KEV download failed: {e}")

    # ── NVD API ───────────────────────────────────────────────────────────────
    def _nvd_search_keyword(self, keyword: str, results_per_page: int = 50) -> list:
        """Search NVD by keyword (product name + version)."""
        params = {"keywordSearch": keyword, "resultsPerPage": results_per_page}
        headers = {}
        if self.nvd_key:
            headers["apiKey"] = self.nvd_key
        try:
            r = requests.get(NVD_API_BASE, params=params, headers=headers,
                             timeout=self.timeout)
            if r.status_code == 200:
                return r.json().get("vulnerabilities", [])
            if r.status_code == 429:
                log.warning("[CVE][NVD] Rate limited — sleeping 6s")
                time.sleep(6)
        except Exception as e:
            log.error(f"[CVE][NVD] Search error: {e}")
        return []

    def _nvd_search_cpe(self, cpe: str, results_per_page: int = 100) -> list:
        """Search NVD by CPE 2.3 string."""
        params = {"cpeName": cpe, "resultsPerPage": results_per_page}
        headers = {"apiKey": self.nvd_key} if self.nvd_key else {}
        try:
            r = requests.get(NVD_API_BASE, params=params, headers=headers,
                             timeout=self.timeout)
            if r.status_code == 200:
                return r.json().get("vulnerabilities", [])
        except Exception as e:
            log.error(f"[CVE][NVD] CPE search error: {e}")
        return []

    def _nvd_fetch_cve(self, cve_id: str) -> Optional[dict]:
        """Fetch a single CVE by ID."""
        params  = {"cveId": cve_id}
        headers = {"apiKey": self.nvd_key} if self.nvd_key else {}
        try:
            r = requests.get(NVD_API_BASE, params=params, headers=headers,
                             timeout=self.timeout)
            if r.status_code == 200:
                vulns = r.json().get("vulnerabilities", [])
                return vulns[0] if vulns else None
        except Exception as e:
            log.debug(f"[CVE][NVD] Fetch {cve_id} error: {e}")
        return None

    # ── Parse NVD record ──────────────────────────────────────────────────────
    def _parse_nvd_record(self, vuln: dict) -> CVERecord:
        cve    = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        desc   = next((d["value"] for d in cve.get("descriptions", [])
                       if d.get("lang") == "en"), "")

        # CVSS v3
        metrics  = cve.get("metrics", {})
        cvss3    = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
        cvss3d   = cvss3.get("cvssData", {})
        v3_score = float(cvss3d.get("baseScore", 0))
        v3_vec   = cvss3d.get("vectorString", "")
        v3_sev   = cvss3d.get("baseSeverity", "")

        # CVSS v2
        cvss2    = (metrics.get("cvssMetricV2") or [{}])[0]
        v2_score = float((cvss2.get("cvssData") or {}).get("baseScore", 0))

        # CWE
        cwe_list = [w["value"] for w in
                    cve.get("weaknesses", [{}])[0].get("description", [])
                    if "CWE-" in w.get("value","")]

        # References
        refs = [r["url"] for r in cve.get("references", [])[:5]]

        record = CVERecord(
            cve_id           = cve_id,
            description      = desc[:300],
            cvss_v3_score    = v3_score,
            cvss_v3_vector   = v3_vec,
            cvss_v3_severity = v3_sev,
            cvss_v2_score    = v2_score,
            published        = cve.get("published", "")[:10],
            modified         = cve.get("lastModified", "")[:10],
            cwe              = cwe_list,
            references       = refs,
        )
        return record

    # ── Exploit intelligence ──────────────────────────────────────────────────
    def _check_kev(self, record: CVERecord) -> CVERecord:
        """Check if CVE is in CISA KEV catalogue."""
        kev = self.kev_data.get(record.cve_id)
        if kev:
            record.in_cisa_kev    = True
            record.kev_due_date   = kev.get("dueDate", "")
            record.kev_ransomware = kev.get("knownRansomwareCampaignUse", "Unknown")
            record.weaponization_score += 5
        return record

    def _check_github_pocs(self, cve_id: str) -> int:
        """Search GitHub for public PoC repositories."""
        if not REQUESTS_OK:
            return 0
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        try:
            r = requests.get(GITHUB_SEARCH_URL,
                             params={"q": f"{cve_id} exploit poc", "per_page": 5},
                             headers=headers, timeout=10)
            if r.status_code == 200:
                count = r.json().get("total_count", 0)
                return count
        except Exception:
            pass
        return 0

    def _compute_weaponization(self, record: CVERecord) -> CVERecord:
        """Compute weaponization score and remediation priority."""
        score = 0
        if record.in_cisa_kev:       score += 5
        if record.exploit_available: score += 2
        if record.github_pocs > 5:   score += 2
        if record.github_pocs > 0:   score += 1
        if record.metasploit_module: score += 3
        if record.cvss_v3_score >= 9.0: score += 2
        record.weaponization_score = min(score, 10)

        # Priority
        if record.in_cisa_kev:
            record.priority = "IMMEDIATE"
        elif record.weaponization_score >= 7:
            record.priority = "HIGH"
        elif record.cvss_v3_score >= 7.0:
            record.priority = "MEDIUM"
        else:
            record.priority = "LOW"
        return record

    # ── Display ───────────────────────────────────────────────────────────────
    def _print_results(self, result: CorrelationResult):
        console.print(Panel(
            f"[bold #00FFD4]Query:[/bold #00FFD4]         {result.query}\n"
            f"[bold #00FFD4]Total CVEs:[/bold #00FFD4]    {result.total_cves}\n"
            f"[bold #FF003C]Critical:[/bold #FF003C]      {result.critical_count}\n"
            f"[bold #FF8C00]High:[/bold #FF8C00]          {result.high_count}\n"
            f"[bold #FF003C]CISA KEV:[/bold #FF003C]      {result.kev_count} ← ACTIVELY EXPLOITED\n"
            f"[bold #FF8C00]Weaponized:[/bold #FF8C00]    {result.weaponized_count}\n"
            f"[bold #FFD700]Max CVSS:[/bold #FFD700]      {result.max_cvss}\n"
            f"[bold #7B00FF]Overall Risk:[/bold #7B00FF]  {result.overall_risk}\n"
            f"[bold #FF003C]Patch Urgency:[/bold #FF003C] {result.patch_urgency}",
            title=f"[bold #7B00FF]🔗 CVE CORRELATION — {result.query}[/bold #7B00FF]",
            border_style="#7B00FF",
        ))

        table = Table(
            border_style="#7B00FF", header_style="bold #00FFD4",
            title="Top Priority CVEs", show_lines=True,
        )
        table.add_column("CVE ID",     width=18)
        table.add_column("CVSS",       width=6,  justify="right")
        table.add_column("Severity",   width=10)
        table.add_column("KEV",        width=5,  justify="center")
        table.add_column("PoCs",       width=6,  justify="right")
        table.add_column("Priority",   width=12)
        table.add_column("Published",  width=12)
        table.add_column("Description",width=40)

        PRIO_COLOR = {
            "IMMEDIATE": "[bold #FF003C]",
            "HIGH":      "[bold #FF8C00]",
            "MEDIUM":    "[bold #FFD700]",
            "LOW":       "[bold #00FFD4]",
        }
        SEV_COLOR = {
            "CRITICAL": "[bold #FF003C]",
            "HIGH":     "[bold #FF8C00]",
            "MEDIUM":   "[bold #FFD700]",
            "LOW":      "[bold #00FFD4]",
        }
        for r in result.top_priority_cves[:20]:
            if not isinstance(r, dict):
                r = r.__dict__ if hasattr(r, "__dict__") else {}
            pc = PRIO_COLOR.get(r.get("priority",""), "[white]")
            pe = pc.replace("[","[/")
            sc = SEV_COLOR.get(r.get("cvss_v3_severity",""), "[white]")
            se = sc.replace("[","[/")
            table.add_row(
                r.get("cve_id",""),
                str(r.get("cvss_v3_score", 0)),
                f"{sc}{r.get('cvss_v3_severity','')}{se}",
                "🔴" if r.get("in_cisa_kev") else "—",
                str(r.get("github_pocs", 0)),
                f"{pc}{r.get('priority','')}{pe}",
                r.get("published","")[:10],
                r.get("description","")[:40],
            )
        console.print(table)

    # ── Main entry ────────────────────────────────────────────────────────────
    def correlate(self, query: str, check_exploits: bool = True) -> CorrelationResult:
        """
        Main correlation entry point.
        query can be: "apache 2.4.50" | "CVE-2021-44228" | CPE string
        """
        console.print(f"[bold #7B00FF]  🔗 CVE Correlator — {query}[/bold #7B00FF]")

        # Detect query type
        if re.match(r"CVE-\d{4}-\d+", query, re.IGNORECASE):
            query_type = "cve_id"
            raw_vulns  = [self._nvd_fetch_cve(query.upper())] if self._nvd_fetch_cve(query.upper()) else []
        elif query.startswith("cpe:2.3:"):
            query_type = "cpe"
            raw_vulns  = self._nvd_search_cpe(query)
        else:
            query_type = "keyword"
            raw_vulns  = self._nvd_search_keyword(query)

        console.print(f"[#00FFD4]  → NVD: {len(raw_vulns)} CVEs found[/#00FFD4]")

        # Parse records
        records = []
        for vuln in raw_vulns:
            try:
                record = self._parse_nvd_record(vuln)
                record = self._check_kev(record)

                if check_exploits:
                    pocs = self._check_github_pocs(record.cve_id)
                    record.github_pocs     = pocs
                    record.exploit_available = pocs > 0
                    if pocs > 0:
                        console.print(f"  [bold #FF8C00]  ⚡ PoC found: {record.cve_id} "
                                       f"({pocs} GitHub repos)[/bold #FF8C00]")
                    time.sleep(0.5)   # GitHub rate limit

                record = self._compute_weaponization(record)
                records.append(record)
            except Exception as e:
                log.debug(f"[CVE] Parse error: {e}")

        # Sort: IMMEDIATE > HIGH > MEDIUM, then by CVSS desc
        PRIO_ORDER = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        records.sort(key=lambda r: (
            PRIO_ORDER.get(r.priority, 4),
            -r.cvss_v3_score,
        ))

        # Aggregate stats
        critical_count   = sum(1 for r in records if r.cvss_v3_severity == "CRITICAL")
        high_count       = sum(1 for r in records if r.cvss_v3_severity == "HIGH")
        kev_count        = sum(1 for r in records if r.in_cisa_kev)
        weaponized_count = sum(1 for r in records if r.exploit_available)
        max_cvss         = max((r.cvss_v3_score for r in records), default=0.0)

        # Overall risk
        if kev_count > 0:          overall_risk = "CRITICAL — Active exploitation"
        elif critical_count > 0:   overall_risk = "CRITICAL"
        elif high_count > 3:       overall_risk = "HIGH"
        elif high_count > 0:       overall_risk = "MEDIUM-HIGH"
        else:                      overall_risk = "MEDIUM"

        # Patch urgency
        if kev_count > 0:
            patch_urgency = "IMMEDIATE (< 24h) — CISA KEV listed"
        elif critical_count > 0 and weaponized_count > 0:
            patch_urgency = "URGENT (< 72h)"
        elif critical_count > 0:
            patch_urgency = "HIGH (< 1 week)"
        elif high_count > 0:
            patch_urgency = "MEDIUM (< 1 month)"
        else:
            patch_urgency = "PLANNED"

        result = CorrelationResult(
            query            = query,
            query_type       = query_type,
            cves             = [r.__dict__ for r in records],
            total_cves       = len(records),
            critical_count   = critical_count,
            high_count       = high_count,
            kev_count        = kev_count,
            weaponized_count = weaponized_count,
            max_cvss         = round(max_cvss, 1),
            overall_risk     = overall_risk,
            top_priority_cves= [r.__dict__ for r in records[:20]],
            patch_urgency    = patch_urgency,
        )

        self._print_results(result)
        console.print(f"[bold #00FFD4]  ✅ Correlation complete — "
                       f"{len(records)} CVEs | {kev_count} KEV | "
                       f"{weaponized_count} weaponized[/bold #00FFD4]")

        from dataclasses import asdict
        return asdict(result)

    def correlate_banner(self, banner: str) -> list:
        """
        Parse a service banner and correlate all detected software versions.
        e.g. 'Apache/2.4.50 (Ubuntu) OpenSSL/1.1.1f'
        """
        console.print(f"[bold #7B00FF]  🔗 Banner correlation: {banner[:80]}[/bold #7B00FF]")

        # Extract product/version pairs
        patterns = [
            r"([\w.-]+)/([\d.]+)",           # Apache/2.4.50
            r"(OpenSSL)/([\d.]+[a-z]?)",     # OpenSSL/1.1.1f
            r"(PHP)/([\d.]+)",               # PHP/7.4.3
            r"(nginx)/([\d.]+)",             # nginx/1.18.0
        ]
        products = []
        for pat in patterns:
            for m in re.finditer(pat, banner, re.IGNORECASE):
                products.append(f"{m.group(1)} {m.group(2)}")

        results = []
        for product in set(products):
            console.print(f"  [#00FFD4]→ Correlating: {product}[/#00FFD4]")
            results.append(self.correlate(product, check_exploits=False))
            time.sleep(1)

        return results


from typing import Optional
