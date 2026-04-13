"""
NEXUS SPECTER PRO — IOC Tracker & MITRE ATT&CK Mapper
Tracks Indicators of Compromise, maps TTPs to ATT&CK framework,
scores threat actor similarity, and generates ATT&CK Navigator layers.
Sources: OpenCTI · MITRE ATT&CK STIX · AlienVault OTX · Abuse.ch
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import os, json, logging, re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
log = logging.getLogger("nsp.intelligence.ioc_tracker")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ── IOC Types ────────────────────────────────────────────────────────────────
IOC_TYPES = {
    "ipv4":     r"^\d{1,3}(\.\d{1,3}){3}$",
    "ipv6":     r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
    "domain":   r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
    "url":      r"^https?://",
    "md5":      r"^[0-9a-fA-F]{32}$",
    "sha1":     r"^[0-9a-fA-F]{40}$",
    "sha256":   r"^[0-9a-fA-F]{64}$",
    "email":    r"^[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}$",
    "cve":      r"^CVE-\d{4}-\d+$",
    "cpe":      r"^cpe:2\.3:",
}

# ── MITRE ATT&CK Tactics (ordered) ───────────────────────────────────────────
MITRE_TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

# ── Common TTP → technique mapping ───────────────────────────────────────────
TTP_LIBRARY = {
    # Initial Access
    "phishing":            ("T1566",     "TA0001", "Phishing"),
    "exploit_public":      ("T1190",     "TA0001", "Exploit Public-Facing Application"),
    "supply_chain":        ("T1195",     "TA0001", "Supply Chain Compromise"),
    "valid_accounts":      ("T1078",     "TA0001", "Valid Accounts"),
    # Execution
    "powershell":          ("T1059.001", "TA0002", "PowerShell"),
    "cmd":                 ("T1059.003", "TA0002", "Windows Command Shell"),
    "wmi":                 ("T1047",     "TA0002", "WMI"),
    "scheduled_task":      ("T1053.005", "TA0002", "Scheduled Task"),
    # Persistence
    "registry_run":        ("T1547.001", "TA0003", "Registry Run Keys"),
    "web_shell":           ("T1505.003", "TA0003", "Web Shell"),
    "create_account":      ("T1136",     "TA0003", "Create Account"),
    # Privilege Escalation
    "token_impersonation": ("T1134",     "TA0004", "Access Token Manipulation"),
    "bypass_uac":          ("T1548.002", "TA0004", "Bypass UAC"),
    "exploit_privesc":     ("T1068",     "TA0004", "Exploitation for Privilege Escalation"),
    # Defense Evasion
    "obfuscation":         ("T1027",     "TA0005", "Obfuscated Files/Information"),
    "disable_av":          ("T1562.001", "TA0005", "Disable/Modify Security Tools"),
    "timestomping":        ("T1070.006", "TA0005", "Timestomping"),
    # Credential Access
    "mimikatz":            ("T1003.001", "TA0006", "LSASS Memory"),
    "kerberoasting":       ("T1558.003", "TA0006", "Kerberoasting"),
    "brute_force":         ("T1110",     "TA0006", "Brute Force"),
    "secretsdump":         ("T1003",     "TA0006", "OS Credential Dumping"),
    # Discovery
    "network_scan":        ("T1046",     "TA0007", "Network Service Discovery"),
    "account_discovery":   ("T1087",     "TA0007", "Account Discovery"),
    "ad_discovery":        ("T1018",     "TA0007", "Remote System Discovery"),
    # Lateral Movement
    "pass_the_hash":       ("T1550.002", "TA0008", "Pass the Hash"),
    "pass_the_ticket":     ("T1550.003", "TA0008", "Pass the Ticket"),
    "rdp":                 ("T1021.001", "TA0008", "Remote Desktop Protocol"),
    "smb":                 ("T1021.002", "TA0008", "SMB/Windows Admin Shares"),
    # Collection
    "email_collection":    ("T1114",     "TA0009", "Email Collection"),
    "screen_capture":      ("T1113",     "TA0009", "Screen Capture"),
    "keylogging":          ("T1056.001", "TA0009", "Keylogging"),
    # C2
    "dns_c2":              ("T1071.004", "TA0011", "DNS"),
    "https_c2":            ("T1071.001", "TA0011", "Web Protocols"),
    "domain_fronting":     ("T1090.004", "TA0011", "Domain Fronting"),
    # Exfiltration
    "exfil_c2":            ("T1041",     "TA0010", "Exfiltration Over C2 Channel"),
    "exfil_web":           ("T1567",     "TA0010", "Exfiltration Over Web Service"),
    # Impact
    "ransomware":          ("T1486",     "TA0040", "Data Encrypted for Impact"),
    "data_destruction":    ("T1485",     "TA0040", "Data Destruction"),
    "defacement":          ("T1491",     "TA0040", "Defacement"),
}

# ── Known threat actor TTP profiles (illustrative) ───────────────────────────
THREAT_ACTOR_PROFILES = {
    "APT28":  {"ttps": ["phishing","powershell","mimikatz","pass_the_hash","rdp","https_c2"],
               "aliases": ["Fancy Bear","Sofacy"], "nation": "RU"},
    "APT29":  {"ttps": ["supply_chain","valid_accounts","domain_fronting","exfil_web","obfuscation"],
               "aliases": ["Cozy Bear","Nobelium"], "nation": "RU"},
    "Lazarus":{"ttps": ["phishing","exploit_public","web_shell","ransomware","exfil_c2"],
               "aliases": ["Hidden Cobra","ZINC"], "nation": "KP"},
    "APT41":  {"ttps": ["exploit_public","valid_accounts","web_shell","scheduled_task","kerberoasting"],
               "aliases": ["Double Dragon","Winnti"], "nation": "CN"},
    "FIN7":   {"ttps": ["phishing","powershell","mimikatz","rdp","exfil_web","ransomware"],
               "aliases": ["Carbanak","Carbon Spider"], "nation": "UNK"},
}


@dataclass
class IOC:
    value:      str
    ioc_type:   str
    source:     str      = ""
    confidence: int      = 0    # 0-100
    severity:   str      = "info"
    tags:       list     = field(default_factory=list)
    context:    str      = ""
    first_seen: str      = ""
    last_seen:  str      = ""
    ttps:       list     = field(default_factory=list)   # MITRE T-IDs
    threat_actors: list  = field(default_factory=list)


@dataclass
class TTPRecord:
    technique_id:  str
    technique_name:str
    tactic_id:     str
    tactic_name:   str
    description:   str = ""
    count:         int = 1    # times observed
    score:         int = 0    # 0-100 for Navigator layer


@dataclass
class IOCReport:
    target:          str
    iocs:            list = field(default_factory=list)
    ttps:            list = field(default_factory=list)
    matched_actors:  list = field(default_factory=list)
    total_iocs:      int  = 0
    critical_iocs:   int  = 0
    tactic_coverage: dict = field(default_factory=dict)
    queried_at:      str  = field(default_factory=lambda: datetime.utcnow().isoformat())


class IOCTracker:
    """
    IOC Tracker & MITRE ATT&CK mapper for NEXUS SPECTER PRO.
    Ingests raw indicators from all scan phases, enriches from OTX/abuse.ch,
    maps to MITRE ATT&CK techniques, computes threat actor similarity,
    and exports an ATT&CK Navigator layer JSON.
    """

    OTX_BASE   = "https://otx.alienvault.com/api/v1"
    ABUSE_BASE = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, otx_key: str = None, output_dir: str = "/tmp/nsp_iocs"):
        self.otx_key    = otx_key or os.getenv("OTX_API_KEY", "")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.iocs:  list[IOC]       = []
        self.ttps_: list[TTPRecord] = []
        self._ttp_map: dict         = {}   # T-ID → TTPRecord

    # ── IOC type detection ────────────────────────────────────────────────────
    def detect_type(self, value: str) -> str:
        v = value.strip()
        for ioc_type, pattern in IOC_TYPES.items():
            if re.match(pattern, v, re.IGNORECASE):
                return ioc_type
        return "unknown"

    # ── OTX enrichment ────────────────────────────────────────────────────────
    def _enrich_otx_ip(self, ip: str) -> dict:
        if not self.otx_key or not REQUESTS_OK:
            return {}
        try:
            r = requests.get(
                f"{self.OTX_BASE}/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": self.otx_key},
                timeout=12,
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            log.debug(f"[IOC][OTX] IP {ip}: {e}")
        return {}

    def _enrich_otx_domain(self, domain: str) -> dict:
        if not self.otx_key or not REQUESTS_OK:
            return {}
        try:
            r = requests.get(
                f"{self.OTX_BASE}/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": self.otx_key},
                timeout=12,
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            log.debug(f"[IOC][OTX] Domain {domain}: {e}")
        return {}

    def _enrich_abusech_url(self, url: str) -> dict:
        if not REQUESTS_OK:
            return {}
        try:
            r = requests.post(
                f"{self.ABUSE_BASE}/url/",
                data={"url": url},
                timeout=12,
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            log.debug(f"[IOC][ABUSE] URL {url}: {e}")
        return {}

    # ── TTP registration ──────────────────────────────────────────────────────
    def register_ttp(self, ttp_key: str, count: int = 1):
        """Register a TTP by library key (e.g. 'mimikatz', 'kerberoasting')."""
        entry = TTP_LIBRARY.get(ttp_key.lower())
        if not entry:
            log.debug(f"[IOC] Unknown TTP key: {ttp_key}")
            return

        t_id, tactic_id, t_name = entry
        tactic_name = next((name for tid, name in MITRE_TACTICS
                             if tid == tactic_id), "Unknown")

        if t_id in self._ttp_map:
            self._ttp_map[t_id].count += count
            self._ttp_map[t_id].score = min(self._ttp_map[t_id].score + 10, 100)
        else:
            record = TTPRecord(
                technique_id   = t_id,
                technique_name = t_name,
                tactic_id      = tactic_id,
                tactic_name    = tactic_name,
                count          = count,
                score          = 30 + min(count * 10, 70),
            )
            self._ttp_map[t_id] = record
            self.ttps_.append(record)

    def register_ttps_from_findings(self, findings: dict):
        """
        Auto-map NSP scan findings to MITRE TTPs.
        findings: vuln_scan results dict.
        """
        by_sev = findings.get("by_severity", {})

        # Map finding tags to TTPs
        TAG_TO_TTP = {
            "sqli":          "exploit_public",
            "xss":           "exploit_public",
            "rce":           "exploit_public",
            "ssrf":          "exploit_public",
            "default-login": "valid_accounts",
            "brute-force":   "brute_force",
            "kerberoast":    "kerberoasting",
            "pth":           "pass_the_hash",
            "mimikatz":      "mimikatz",
            "web-shell":     "web_shell",
            "phishing":      "phishing",
            "lfi":           "exploit_public",
            "cve":           "exploit_public",
        }
        for sev_list in by_sev.values():
            for finding in sev_list:
                for tag in finding.get("tags", []):
                    ttp_key = TAG_TO_TTP.get(tag.lower())
                    if ttp_key:
                        self.register_ttp(ttp_key)

    # ── Threat actor matching ─────────────────────────────────────────────────
    def match_threat_actors(self) -> list:
        """
        Compute similarity between observed TTPs and known threat actor profiles.
        Returns ranked list of possible threat actors.
        """
        observed = {self._ttp_map[t].technique_name.lower()
                    for t in self._ttp_map}
        # Map TTP library names to technique names
        observed_keys = set(self._ttp_map.keys())

        matches = []
        for actor, profile in THREAT_ACTOR_PROFILES.items():
            actor_ttp_keys = profile["ttps"]
            # Map actor TTP names to T-IDs
            actor_tids = set()
            for key in actor_ttp_keys:
                entry = TTP_LIBRARY.get(key)
                if entry:
                    actor_tids.add(entry[0])

            intersection = observed_keys & actor_tids
            if not actor_tids:
                continue
            similarity = round(len(intersection) / len(actor_tids) * 100, 1)

            if similarity > 0:
                matches.append({
                    "actor":       actor,
                    "aliases":     profile.get("aliases", []),
                    "nation":      profile.get("nation", "UNK"),
                    "similarity":  similarity,
                    "matched_ttps":[t for t in actor_ttp_keys
                                    if TTP_LIBRARY.get(t,("","",""))[0] in observed_keys],
                })

        matches.sort(key=lambda x: x["similarity"], reverse=True)
        return matches

    # ── ATT&CK Navigator export ───────────────────────────────────────────────
    def export_navigator_layer(self, name: str = "NEXUS SPECTER PRO") -> Path:
        """
        Generate ATT&CK Navigator JSON layer.
        Import at https://mitre-attack.github.io/attack-navigator/
        """
        techniques = []
        for t_id, record in self._ttp_map.items():
            techniques.append({
                "techniqueID": t_id,
                "score":       record.score,
                "color":       self._score_to_color(record.score),
                "comment":     f"Observed {record.count}x during engagement | NSP",
                "enabled":     True,
                "metadata":    [],
                "showSubtechniques": False,
            })

        layer = {
            "name":        f"{name} — Attack Profile",
            "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.4"},
            "domain":      "enterprise-attack",
            "description": f"NEXUS SPECTER PRO engagement TTPs | "
                           f"OPTIMIUM NEXUS LLC | {datetime.utcnow().strftime('%Y-%m-%d')}",
            "filters":     {"platforms": ["Windows","Linux","macOS","Network","Cloud"]},
            "sorting":     3,
            "layout":      {"layout": "side", "showID": True, "showName": True},
            "hideDisabled":False,
            "techniques":  techniques,
            "gradient": {
                "colors":  ["#ffe3e3", "#ff6666", "#ff0000"],
                "minValue":0,
                "maxValue":100,
            },
            "legendItems":[
                {"label": "Observed TTP",       "color": "#FF003C"},
                {"label": "NSP Engagement",     "color": "#7B00FF"},
            ],
        }
        out = self.output_dir / "attack_navigator_layer.json"
        out.write_text(json.dumps(layer, indent=2))
        console.print(f"[bold #00FFD4]  ✅ ATT&CK Navigator layer: {out}[/bold #00FFD4]")
        console.print(f"  [dim]→ Import at: https://mitre-attack.github.io/attack-navigator/[/dim]")
        return out

    def _score_to_color(self, score: int) -> str:
        if score >= 80: return "#FF003C"
        if score >= 60: return "#FF8C00"
        if score >= 40: return "#FFD700"
        return "#7B00FF"

    # ── Display ───────────────────────────────────────────────────────────────
    def _print_ttp_coverage(self):
        table = Table(
            title="[bold #7B00FF]🎯 MITRE ATT&CK COVERAGE[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Tactic",    width=25)
        table.add_column("Technique", width=14)
        table.add_column("Name",      width=35)
        table.add_column("Count",     width=7,  justify="right")
        table.add_column("Score",     width=7,  justify="right")

        for record in sorted(self.ttps_, key=lambda r: -r.score):
            sc = ("#FF003C" if record.score >= 80 else
                  "#FF8C00" if record.score >= 60 else
                  "#FFD700" if record.score >= 40 else "#7B00FF")
            table.add_row(
                record.tactic_name,
                record.technique_id,
                record.technique_name,
                str(record.count),
                f"[bold {sc}]{record.score}[/bold {sc}]",
            )
        console.print(table)

    def _print_actor_matches(self, matches: list):
        if not matches:
            return
        table = Table(
            title="[bold #7B00FF]🕵️  THREAT ACTOR SIMILARITY[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Actor",      width=12)
        table.add_column("Nation",     width=8)
        table.add_column("Similarity", width=12)
        table.add_column("Aliases",    width=25)
        table.add_column("Matched TTPs", width=40)

        for m in matches[:5]:
            sim = m["similarity"]
            sc  = ("#FF003C" if sim >= 70 else "#FF8C00" if sim >= 40 else "#FFD700")
            table.add_row(
                m["actor"],
                m["nation"],
                f"[bold {sc}]{sim}%[/bold {sc}]",
                ", ".join(m["aliases"][:2]),
                ", ".join(m["matched_ttps"][:4]),
            )
        console.print(table)

    def _print_ioc_summary(self):
        if not self.iocs:
            return
        by_type: dict = {}
        for ioc in self.iocs:
            by_type.setdefault(ioc.ioc_type, []).append(ioc)

        table = Table(
            title=f"[bold #7B00FF]🔍 IOC SUMMARY — {len(self.iocs)} indicators[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Type",       width=12)
        table.add_column("Count",      width=8,  justify="right")
        table.add_column("Critical",   width=10, justify="right")
        table.add_column("Samples",    width=50)

        for ioc_type, iocs_list in by_type.items():
            crit  = sum(1 for i in iocs_list if i.severity in ("critical","high"))
            sample= " | ".join(i.value[:20] for i in iocs_list[:2])
            table.add_row(ioc_type, str(len(iocs_list)), str(crit), sample)
        console.print(table)

    # ── Ingest IOCs ───────────────────────────────────────────────────────────
    def ingest(self, values: list, source: str = "nsp",
               auto_enrich: bool = True) -> list:
        """
        Ingest a list of raw IOC values, detect types, and optionally enrich.
        """
        console.print(f"[bold #7B00FF]  🔍 Ingesting {len(values)} IOCs...[/bold #7B00FF]")
        ingested = []
        for value in values:
            ioc_type = self.detect_type(str(value))
            ioc = IOC(
                value    = str(value),
                ioc_type = ioc_type,
                source   = source,
                confidence = 50,
                first_seen = datetime.utcnow().isoformat(),
                last_seen  = datetime.utcnow().isoformat(),
            )
            # Enrich
            if auto_enrich and REQUESTS_OK:
                if ioc_type == "ipv4":
                    otx = self._enrich_otx_ip(value)
                    if otx.get("reputation", 0) < -1:
                        ioc.severity   = "high"
                        ioc.confidence = 80
                        ioc.tags       = list(otx.get("tags",{}).keys())[:5]
                elif ioc_type == "domain":
                    otx = self._enrich_otx_domain(value)
                    if otx.get("pulse_count", 0) > 5:
                        ioc.severity   = "high"
                        ioc.confidence = 75

            self.iocs.append(ioc)
            ingested.append(ioc)

        console.print(f"[#00FFD4]  → {len(ingested)} IOCs processed[/#00FFD4]")
        return ingested

    # ── Main entry ────────────────────────────────────────────────────────────
    def run(self, target: str, ioc_values: list = None,
            findings: dict = None, ttp_keys: list = None) -> dict:
        console.print(f"[bold #7B00FF]  🕵️  IOC Tracker & ATT&CK Mapper — {target}[/bold #7B00FF]")

        # Ingest IOCs
        if ioc_values:
            self.ingest(ioc_values)

        # Register TTPs from findings
        if findings:
            self.register_ttps_from_findings(findings)

        # Register manual TTP keys
        for key in (ttp_keys or []):
            self.register_ttp(key)

        # Match threat actors
        actor_matches = self.match_threat_actors()

        # Tactic coverage
        tactic_coverage = {}
        for record in self.ttps_:
            tactic_coverage.setdefault(record.tactic_name, []).append(record.technique_id)

        # Print summaries
        self._print_ioc_summary()
        self._print_ttp_coverage()
        self._print_actor_matches(actor_matches)

        # Export ATT&CK Navigator
        nav_path = self.export_navigator_layer()

        console.print(f"[bold #00FFD4]  ✅ IOC Tracker complete — "
                       f"{len(self.iocs)} IOCs | {len(self.ttps_)} TTPs | "
                       f"{len(actor_matches)} actor matches[/bold #00FFD4]")

        return {
            "target":          target,
            "total_iocs":      len(self.iocs),
            "iocs": [{"value":i.value,"type":i.ioc_type,"severity":i.severity,
                      "confidence":i.confidence,"tags":i.tags}
                     for i in self.iocs],
            "ttps": [{"id":r.technique_id,"name":r.technique_name,
                      "tactic":r.tactic_name,"count":r.count,"score":r.score}
                     for r in self.ttps_],
            "tactic_coverage":  tactic_coverage,
            "actor_matches":    actor_matches,
            "navigator_layer":  str(nav_path),
            "queried_at":       datetime.utcnow().isoformat(),
        }
