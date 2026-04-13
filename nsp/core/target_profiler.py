"""
NEXUS SPECTER PRO — Target Profiler
Multi-dimensional target profiling: resolves IPs, detects tech stack,
classifies target type, and builds a complete intelligence profile
before any scan phase begins.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import socket, re, logging, json
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
log = logging.getLogger("nsp.core.profiler")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False


@dataclass
class TargetProfile:
    raw_input:    str
    target_type:  str = ""    # domain | ip | cidr | url | email
    host:         str = ""
    ip_addresses: list = field(default_factory=list)
    asn:          str = ""
    asn_org:      str = ""
    country:      str = ""
    city:         str = ""
    isp:          str = ""
    open_ports:   list = field(default_factory=list)
    tech_stack:   list = field(default_factory=list)
    headers:      dict = field(default_factory=dict)
    dns_records:  dict = field(default_factory=dict)
    mx_records:   list = field(default_factory=list)
    cloud_provider: str = ""
    cdn:          str = ""
    waf:          str = ""
    is_cdn:       bool = False
    server:       str = ""
    cms:          str = ""
    framework:    str = ""
    language:     str = ""
    hosting:      str = ""
    risk_level:   str = ""
    attack_surface: list = field(default_factory=list)


class TargetProfiler:
    """
    Builds a comprehensive intelligence profile for any target before scanning.
    Resolves DNS, geo-locates IPs, fingerprints technology stack, detects CDN/WAF,
    and estimates the attack surface.
    """

    # Cloud IP ranges (representative — not exhaustive)
    CLOUD_RANGES = {
        "AWS":         ["52.", "54.", "34.", "3.", "18.", "13.", "15.", "35.180.",
                        "35.153.", "35.157."],
        "Azure":       ["13.64.", "13.68.", "13.72.", "13.76.", "20.", "40.", "51."],
        "GCP":         ["34.64.", "34.80.", "34.96.", "34.100.", "35.184.", "35.188.",
                        "35.192.", "35.196.", "35.200.", "35.204."],
        "Cloudflare":  ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
                        "104.21.", "104.22.", "172.64.", "172.65.", "172.66.", "172.67."],
        "Fastly":      ["151.101.", "199.27.", "185.31."],
        "Akamai":      ["23.32.", "23.64.", "23.192.", "104.64.", "104.72.", "104.73."],
    }

    CDN_HEADERS = {
        "Cloudflare":  ["cf-ray", "cf-cache-status", "cf-request-id"],
        "Akamai":      ["x-akamai-request-id", "x-check-cacheable", "akamaighost"],
        "Fastly":      ["x-served-by", "x-cache", "fastly-restarts"],
        "CloudFront":  ["x-amz-cf-id", "x-amz-cf-pop"],
        "Varnish":     ["x-varnish", "via"],
        "Sucuri":      ["x-sucuri-id", "x-sucuri-cache"],
    }

    WAF_SIGNATURES = {
        "Cloudflare":  ["cloudflare", "__cfduid", "cf-ray"],
        "Sucuri":      ["sucuri", "x-sucuri"],
        "ModSecurity": ["mod_security", "modsecurity", "nf_conntrack"],
        "Imperva":     ["incap_ses", "visid_incap", "x-iinfo"],
        "AWS WAF":     ["x-amzn-requestid", "x-amzn-trace-id"],
        "F5 BIG-IP":   ["bigipserver", "f5_st", "ts"],
        "Barracuda":   ["barra_counter_session"],
    }

    TECH_HEADERS = {
        "server": {
            "nginx":           "Nginx",
            "apache":          "Apache",
            "iis":             "IIS",
            "lighttpd":        "Lighttpd",
            "caddy":           "Caddy",
            "gunicorn":        "Gunicorn",
            "uvicorn":         "Uvicorn",
        },
        "x-powered-by": {
            "php":             "PHP",
            "asp.net":         "ASP.NET",
            "express":         "Express.js",
            "django":          "Django",
            "rails":           "Ruby on Rails",
            "next.js":         "Next.js",
            "laravel":         "Laravel",
        },
    }

    CMS_PATHS = {
        "WordPress":  ["/wp-login.php", "/wp-admin/", "/wp-content/"],
        "Drupal":     ["/sites/default/", "/core/install.php"],
        "Joomla":     ["/administrator/", "/components/"],
        "Magento":    ["/admin/", "/skin/frontend/"],
        "Shopify":    ["/cdn.shopify.com", "/s/files/"],
    }

    def __init__(self, target: str, timeout: int = 8):
        self.target  = target.strip()
        self.timeout = timeout
        self.profile = TargetProfile(raw_input=target)

    def _detect_type(self) -> str:
        t = self.target
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d+)?$", t):
            return "cidr" if "/" in t else "ip"
        if t.startswith("http://") or t.startswith("https://"):
            return "url"
        if "@" in t:
            return "email"
        return "domain"

    def _extract_host(self) -> str:
        t = self.target
        for s in ("https://", "http://"):
            if t.startswith(s):
                t = t[len(s):]
        return t.split("/")[0].split(":")[0].split("@")[-1]

    def _resolve_dns(self):
        host = self.profile.host
        try:
            ips = socket.getaddrinfo(host, None)
            self.profile.ip_addresses = list({r[4][0] for r in ips})
            log.info(f"[PROFILER] DNS: {host} → {self.profile.ip_addresses}")
        except socket.gaierror as e:
            log.warning(f"[PROFILER] DNS resolution failed for {host}: {e}")

        if DNS_OK:
            try:
                resolver = dns.resolver.Resolver()
                for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                    try:
                        answers = resolver.resolve(host, rtype)
                        self.profile.dns_records[rtype] = [str(r) for r in answers]
                    except Exception:
                        pass
                mx = self.profile.dns_records.get("MX", [])
                self.profile.mx_records = mx
            except Exception as e:
                log.debug(f"[PROFILER] DNS detailed lookup error: {e}")

    def _geoip(self):
        if not self.profile.ip_addresses or not REQUESTS_OK:
            return
        ip = self.profile.ip_addresses[0]
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/",
                             timeout=self.timeout, headers={"User-Agent":"NSP-SPECTER"})
            if r.status_code == 200:
                data = r.json()
                self.profile.asn     = data.get("asn","")
                self.profile.asn_org = data.get("org","")
                self.profile.country = data.get("country_name","")
                self.profile.city    = data.get("city","")
                self.profile.isp     = data.get("org","")
                log.info(f"[PROFILER] GeoIP: {ip} → {self.profile.country}, "
                         f"{self.profile.city} | {self.profile.asn_org}")
        except Exception as e:
            log.debug(f"[PROFILER] GeoIP failed: {e}")

    def _detect_cloud(self):
        for ip in self.profile.ip_addresses:
            for provider, prefixes in self.CLOUD_RANGES.items():
                if any(ip.startswith(p) for p in prefixes):
                    self.profile.cloud_provider = provider
                    if provider in ("Cloudflare","Fastly","Akamai"):
                        self.profile.is_cdn = True
                        self.profile.cdn    = provider
                    return

    def _probe_http(self):
        if not REQUESTS_OK:
            return
        host = self.profile.host
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{host}/", timeout=self.timeout,
                                  verify=False, allow_redirects=True,
                                  headers={"User-Agent":"Mozilla/5.0 (NSP-SPECTER)"})
                hdrs_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
                self.profile.headers = dict(r.headers)

                # Server & powered-by
                self.profile.server = hdrs_lower.get("server","")
                for hdr, mapping in self.TECH_HEADERS.items():
                    val = hdrs_lower.get(hdr,"")
                    for key, label in mapping.items():
                        if key in val:
                            if label not in self.profile.tech_stack:
                                self.profile.tech_stack.append(label)

                # CDN detection via headers
                for cdn, hdrs in self.CDN_HEADERS.items():
                    if any(h in hdrs_lower for h in hdrs):
                        self.profile.cdn    = cdn
                        self.profile.is_cdn = True

                # WAF detection
                all_vals = " ".join(list(hdrs_lower.values()) + [r.text[:500]])
                for waf, sigs in self.WAF_SIGNATURES.items():
                    if any(s in all_vals.lower() for s in sigs):
                        self.profile.waf = waf

                # CMS detection
                for cms, paths in self.CMS_PATHS.items():
                    if any(p in r.text or p in r.url for p in paths):
                        self.profile.cms = cms
                        if cms not in self.profile.tech_stack:
                            self.profile.tech_stack.append(cms)

                log.info(f"[PROFILER] HTTP probe OK: {scheme}://{host} "
                         f"[{r.status_code}] server={self.profile.server}")
                break
            except Exception as e:
                log.debug(f"[PROFILER] HTTP {scheme}://{host} error: {e}")

    def _build_attack_surface(self):
        surface = []
        if self.profile.dns_records.get("MX"):
            surface.append("Email infrastructure exposed (MX records)")
        if self.profile.dns_records.get("TXT"):
            txts = " ".join(self.profile.dns_records["TXT"])
            if "v=spf1" not in txts:
                surface.append("No SPF record — phishing risk")
        if not self.profile.waf:
            surface.append("No WAF detected — direct application exposure")
        if self.profile.cms:
            surface.append(f"CMS detected: {self.profile.cms} — check for known CVEs")
        if self.profile.is_cdn:
            surface.append(f"CDN in front ({self.profile.cdn}) — may hide real IP")
        if not self.profile.cloud_provider:
            surface.append("Self-hosted infrastructure — broader attack surface")
        if self.profile.headers.get("Server",""):
            surface.append(f"Server banner disclosure: {self.profile.server}")
        self.profile.attack_surface = surface

    def _assess_risk(self):
        score = 0
        if not self.profile.waf:             score += 3
        if not self.profile.is_cdn:          score += 1
        if self.profile.cms:                 score += 2
        if self.profile.dns_records.get("MX"): score += 1
        if len(self.profile.ip_addresses) == 1: score += 1
        if score >= 6:   self.profile.risk_level = "High"
        elif score >= 4: self.profile.risk_level = "Medium"
        else:            self.profile.risk_level = "Low"

    def print_profile(self):
        p = self.profile
        RISK_COLOR = {"High":"#FF003C","Medium":"#FFD700","Low":"#00FFD4"}
        rc = RISK_COLOR.get(p.risk_level,"#888")

        console.print(Panel(
            f"[bold #00FFD4]Target:[/bold #00FFD4]       {p.raw_input}\n"
            f"[bold #00FFD4]Type:[/bold #00FFD4]         {p.target_type.upper()}\n"
            f"[bold #00FFD4]Host:[/bold #00FFD4]         {p.host}\n"
            f"[bold #00FFD4]IPs:[/bold #00FFD4]          {', '.join(p.ip_addresses[:4])}\n"
            f"[bold #00FFD4]Location:[/bold #00FFD4]     {p.city}, {p.country}\n"
            f"[bold #00FFD4]ASN:[/bold #00FFD4]          {p.asn} {p.asn_org}\n"
            f"[bold #00FFD4]Cloud:[/bold #00FFD4]        {p.cloud_provider or 'Self-hosted'}\n"
            f"[bold #00FFD4]CDN:[/bold #00FFD4]          {p.cdn or 'None detected'}\n"
            f"[bold #00FFD4]WAF:[/bold #00FFD4]          {p.waf or 'None detected'}\n"
            f"[bold #00FFD4]Server:[/bold #00FFD4]       {p.server or 'Unknown'}\n"
            f"[bold #00FFD4]CMS:[/bold #00FFD4]          {p.cms or 'None detected'}\n"
            f"[bold #00FFD4]Tech Stack:[/bold #00FFD4]   {', '.join(p.tech_stack) or 'Unknown'}\n"
            f"[bold #00FFD4]DNS Records:[/bold #00FFD4]  {', '.join(p.dns_records.keys())}\n"
            f"[bold {rc}]Risk Level:[/bold {rc}]   [{p.risk_level}]\n"
            f"\n[bold #7B00FF]Attack Surface:[/bold #7B00FF]\n"
            + "\n".join(f"  ⚠ {s}" for s in p.attack_surface),
            title=f"[bold #7B00FF]🎯 TARGET PROFILE — {p.host}[/bold #7B00FF]",
            border_style="#7B00FF",
        ))

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🎯 Profiling target: {self.target}[/bold #7B00FF]")
        self.profile.target_type = self._detect_type()
        self.profile.host        = self._extract_host()
        self._resolve_dns()
        self._geoip()
        self._detect_cloud()
        self._probe_http()
        self._build_attack_surface()
        self._assess_risk()
        self.print_profile()
        console.print(f"[bold #00FFD4]  ✅ Profile complete — risk: {self.profile.risk_level}[/bold #00FFD4]")

        from dataclasses import asdict
        return asdict(self.profile)
