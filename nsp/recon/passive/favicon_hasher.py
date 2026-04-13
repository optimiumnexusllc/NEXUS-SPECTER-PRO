"""
NEXUS SPECTER PRO — Favicon Hash Asset Discovery
Computes MurmurHash3 of favicon.ico → searches Shodan for identical assets.
Identifies related infrastructure, CDN origins, load balancers, dev/staging servers.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import struct, logging, base64, os
from dataclasses import dataclass, field
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.recon.favicon")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


def _mmh3_32(data: bytes) -> int:
    """Pure-Python MurmurHash3 (32-bit) — same as Shodan uses."""
    c1, c2  = 0xcc9e2d51, 0x1b873593
    h1      = 0
    length  = len(data)
    nblocks = length // 4

    for block in range(nblocks):
        k1  = struct.unpack_from("<I", data, block * 4)[0]
        k1  = (k1 * c1) & 0xFFFFFFFF
        k1  = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1  = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1  = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1  = ((h1 * 5) + 0xe6546b64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k1   = 0
    t    = len(tail)
    if t >= 3: k1 ^= tail[2] << 16
    if t >= 2: k1 ^= tail[1] << 8
    if t >= 1:
        k1 ^= tail[0]
        k1  = (k1 * c1) & 0xFFFFFFFF
        k1  = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1  = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1  = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1  = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Return signed 32-bit
    return struct.unpack("i", struct.pack("I", h1))[0]


@dataclass
class FaviconResult:
    target:          str
    favicon_url:     str
    hash_value:      int   = 0
    hash_str:        str   = ""
    shodan_results:  list  = field(default_factory=list)
    related_hosts:   int   = 0
    interesting:     list  = field(default_factory=list)


class FaviconHasher:
    """
    Favicon-based asset discovery for NEXUS SPECTER PRO.
    1. Fetches favicon.ico from target
    2. Computes Shodan-compatible MurmurHash3
    3. Searches Shodan for other assets with identical favicon
    4. Identifies related infrastructure (dev, staging, hidden assets)
    """

    FAVICON_PATHS = [
        "/favicon.ico", "/favicon.png", "/favicon.gif",
        "/apple-touch-icon.png", "/images/favicon.ico",
        "/static/favicon.ico", "/assets/favicon.ico",
    ]

    INTERESTING_KEYWORDS = [
        "staging","dev","test","internal","admin","backend",
        "api","vpn","mgmt","management","console","panel",
    ]

    def __init__(self, target: str, shodan_key: str = None, timeout: int = 10):
        self.target     = target.rstrip("/")
        self.shodan_key = shodan_key or os.getenv("SHODAN_API_KEY","")
        self.timeout    = timeout

    def _fetch_favicon(self) -> tuple:
        """Fetch favicon bytes from target. Returns (url, bytes)."""
        if not REQUESTS_OK:
            return "", b""
        for path in self.FAVICON_PATHS:
            url = f"https://{self.target}{path}"
            try:
                r = requests.get(url, timeout=self.timeout, verify=False,
                                  headers={"User-Agent":"Mozilla/5.0 (NSP-SPECTER)"},
                                  allow_redirects=True)
                if r.status_code == 200 and len(r.content) > 100:
                    log.info(f"[FAVICON] Found at: {url} ({len(r.content)}B)")
                    return url, r.content
            except Exception:
                pass
        # Try HTTP
        for path in self.FAVICON_PATHS[:2]:
            url = f"http://{self.target}{path}"
            try:
                r = requests.get(url, timeout=self.timeout,
                                  headers={"User-Agent":"Mozilla/5.0 (NSP-SPECTER)"})
                if r.status_code == 200 and len(r.content) > 100:
                    return url, r.content
            except Exception:
                pass
        return "", b""

    def compute_hash(self, data: bytes) -> int:
        """Compute Shodan favicon hash (base64 + MurmurHash3)."""
        # Shodan encodes to standard base64 with newlines every 76 chars
        b64 = base64.encodebytes(data).decode("utf-8")
        return _mmh3_32(b64.encode("utf-8"))

    def search_shodan(self, hash_value: int) -> list:
        """Search Shodan for hosts with matching favicon hash."""
        if not self.shodan_key:
            log.warning("[FAVICON] No SHODAN_API_KEY — skipping search")
            return []
        try:
            import shodan as shodan_lib
            api     = shodan_lib.Shodan(self.shodan_key)
            query   = f"http.favicon.hash:{hash_value}"
            results = api.search(query)
            matches = []
            for r in results.get("matches",[])[:50]:
                matches.append({
                    "ip":       r.get("ip_str",""),
                    "port":     r.get("port",80),
                    "hostnames":r.get("hostnames",[]),
                    "org":      r.get("org",""),
                    "country":  r.get("country_name",""),
                    "product":  r.get("product",""),
                })
            console.print(f"  [bold #FF003C]  ⚡ Shodan: {results.get('total',0)} hosts "
                           f"with same favicon hash[/bold #FF003C]")
            return matches
        except ImportError:
            log.warning("[FAVICON] shodan library not installed")
        except Exception as e:
            log.error(f"[FAVICON] Shodan error: {e}")
        return []

    def _flag_interesting(self, results: list) -> list:
        interesting = []
        for r in results:
            hosts = r.get("hostnames",[]) + [r.get("ip","")]
            for h in hosts:
                if any(kw in str(h).lower() for kw in self.INTERESTING_KEYWORDS):
                    interesting.append({
                        "host":    h,
                        "ip":      r.get("ip",""),
                        "org":     r.get("org",""),
                        "country": r.get("country",""),
                    })
        return interesting

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🌐 Favicon Hasher — {self.target}[/bold #7B00FF]")
        url, favicon_bytes = self._fetch_favicon()

        if not favicon_bytes:
            console.print(f"[bold #FFD700]  ⚠ No favicon found at {self.target}[/bold #FFD700]")
            return {"target":self.target,"error":"favicon not found"}

        hash_val     = self.compute_hash(favicon_bytes)
        hash_str     = str(hash_val)
        shodan_res   = self.search_shodan(hash_val)
        interesting  = self._flag_interesting(shodan_res)

        console.print(f"  [#00FFD4][FAVICON] URL: {url}[/#00FFD4]")
        console.print(f"  [#00FFD4][FAVICON] Hash: {hash_str}[/#00FFD4]")
        console.print(f"  [#00FFD4][FAVICON] Related hosts: {len(shodan_res)}[/#00FFD4]")
        if interesting:
            console.print(f"  [bold #FF003C]  ⚡ Interesting shadow assets: {len(interesting)}[/bold #FF003C]")
            for asset in interesting[:5]:
                console.print(f"    → {asset['host']} ({asset['ip']}) | {asset['org']}")

        console.print(f"[bold #00FFD4]  ✅ Favicon hash complete — "
                       f"Shodan query: http.favicon.hash:{hash_str}[/bold #00FFD4]")
        return {
            "target":        self.target,
            "favicon_url":   url,
            "hash":          hash_val,
            "hash_str":      hash_str,
            "shodan_query":  f"http.favicon.hash:{hash_str}",
            "related_hosts": len(shodan_res),
            "interesting":   interesting,
            "results":       shodan_res[:20],
        }
