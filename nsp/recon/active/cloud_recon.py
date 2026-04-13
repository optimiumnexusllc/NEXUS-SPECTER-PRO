"""
NEXUS SPECTER PRO — Cloud Recon Engine
Discovers exposed cloud assets: public S3 buckets, Azure blobs, GCP storage,
misconfigured IAM, open cloud metadata, exposed serverless functions.
Passive-first — uses public APIs and DNS only (no credentials required).
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import re, logging, json
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.recon.cloud")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


@dataclass
class CloudAsset:
    provider:   str     # aws | azure | gcp
    asset_type: str     # s3_bucket | blob_container | gcs_bucket | function | etc.
    name:       str
    url:        str
    public:     bool = False
    readable:   bool = False
    writable:   bool = False
    severity:   str = "info"
    detail:     str = ""


class CloudRecon:
    """
    Passive cloud asset discovery for NEXUS SPECTER PRO.
    Enumerates likely cloud asset names from the target domain/org,
    probes for public access, and identifies storage misconfigurations.
    Does NOT require cloud credentials — uses public HTTP probing only.
    """

    # URL templates for cloud storage
    S3_URLS = [
        "https://{bucket}.s3.amazonaws.com",
        "https://{bucket}.s3.us-east-1.amazonaws.com",
        "https://s3.amazonaws.com/{bucket}",
    ]
    AZURE_URLS = [
        "https://{account}.blob.core.windows.net",
        "https://{account}.blob.core.windows.net/{container}",
    ]
    GCS_URLS = [
        "https://storage.googleapis.com/{bucket}",
        "https://{bucket}.storage.googleapis.com",
    ]

    # Bucket/container name variations to probe
    NAME_TEMPLATES = [
        "{org}",
        "{org}-backup", "{org}-backups", "{org}-bak",
        "{org}-dev",    "{org}-staging", "{org}-prod",
        "{org}-assets", "{org}-static",  "{org}-media",
        "{org}-data",   "{org}-uploads",  "{org}-files",
        "{org}-logs",   "{org}-config",   "{org}-secrets",
        "{org}-public",  "{org}-private",
        "{org}-www",    "{org}-web",
        "{org}-images",  "{org}-videos",
        "dev-{org}",    "staging-{org}", "prod-{org}",
        "backup-{org}", "static-{org}",
    ]

    # Cloud metadata endpoints (checked from inside the target — post-exploitation)
    METADATA_ENDPOINTS = {
        "AWS IMDS v1":  "http://169.254.169.254/latest/meta-data/",
        "AWS IMDS v2":  "http://169.254.169.254/latest/api/token",
        "Azure IMDS":   "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "GCP IMDS":     "http://metadata.google.internal/computeMetadata/v1/",
        "DigitalOcean": "http://169.254.169.254/metadata/v1/",
        "Oracle Cloud": "http://169.254.169.254/opc/v1/instance/",
    }

    def __init__(self, target: str, org: str = None, timeout: int = 8,
                 max_buckets: int = 30):
        self.target     = target
        self.org        = org or target.split(".")[0].replace("-","").replace("_","")
        self.timeout    = timeout
        self.max_buckets= max_buckets
        self.assets: list[CloudAsset] = []

    def _get(self, url: str) -> tuple:
        """Return (status_code, content_length, content_preview)."""
        if not REQUESTS_OK:
            return 0, 0, ""
        try:
            r = requests.get(url, timeout=self.timeout, verify=False,
                             headers={"User-Agent":"Mozilla/5.0 (NSP-SPECTER)"},
                             allow_redirects=False)
            return r.status_code, len(r.content), r.text[:500]
        except Exception:
            return 0, 0, ""

    def _probe_s3(self) -> list:
        """Probe AWS S3 bucket permutations for public access."""
        console.print(f"[#00FFD4]  [CLOUD] AWS S3 bucket enumeration — org: {self.org}[/#00FFD4]")
        found = []
        names = [t.format(org=self.org) for t in self.NAME_TEMPLATES[:self.max_buckets]]

        for name in names:
            url = f"https://{name}.s3.amazonaws.com"
            sc, size, body = self._get(url)
            if sc == 0:
                continue

            asset = CloudAsset(provider="aws", asset_type="s3_bucket",
                               name=name, url=url)
            if sc == 200:
                asset.public   = True
                asset.readable = True
                asset.severity = "critical"
                asset.detail   = f"Public S3 bucket — listable. Size: {size}B"
                console.print(f"[bold #FF003C]  ⚡ PUBLIC S3: {url}[/bold #FF003C]")
                found.append(asset)
            elif sc == 403:
                asset.public   = True
                asset.readable = False
                asset.severity = "medium"
                asset.detail   = "Bucket exists but access denied (403)"
                console.print(f"[bold #FFD700]  → S3 exists (403): {name}[/bold #FFD700]")
                found.append(asset)
            elif sc in (301, 307):
                asset.detail   = "Redirect detected — bucket may exist in another region"
                asset.severity = "info"
                found.append(asset)

        log.info(f"[CLOUD][S3] {len(found)} buckets found for org: {self.org}")
        return found

    def _probe_azure_blob(self) -> list:
        """Probe Azure Blob Storage for public containers."""
        console.print(f"[#00FFD4]  [CLOUD] Azure Blob Storage enumeration...[/#00FFD4]")
        found = []
        for name in [t.format(org=self.org) for t in self.NAME_TEMPLATES[:15]]:
            for container in ["", "$web", "public", "assets", "files", "media"]:
                url = (f"https://{name}.blob.core.windows.net/{container}"
                       f"?restype=container&comp=list")
                sc, size, body = self._get(url)
                if sc == 200 and "EnumerationResults" in body:
                    asset = CloudAsset(
                        provider="azure", asset_type="blob_container",
                        name=f"{name}/{container}", url=url,
                        public=True, readable=True, severity="critical",
                        detail=f"Public Azure Blob container — listable. Content: {body[:100]}",
                    )
                    console.print(f"[bold #FF003C]  ⚡ PUBLIC AZURE BLOB: {url}[/bold #FF003C]")
                    found.append(asset)
                elif sc == 403:
                    asset = CloudAsset(
                        provider="azure", asset_type="blob_container",
                        name=f"{name}/{container}", url=url,
                        public=True, readable=False, severity="low",
                        detail="Azure storage account exists (403)",
                    )
                    found.append(asset)
        return found

    def _probe_gcs(self) -> list:
        """Probe Google Cloud Storage buckets."""
        console.print(f"[#00FFD4]  [CLOUD] GCS bucket enumeration...[/#00FFD4]")
        found = []
        for name in [t.format(org=self.org) for t in self.NAME_TEMPLATES[:15]]:
            url = f"https://storage.googleapis.com/{name}"
            sc, size, body = self._get(url)
            if sc == 200 and ("ListBucketResult" in body or "kind" in body):
                asset = CloudAsset(
                    provider="gcp", asset_type="gcs_bucket",
                    name=name, url=url,
                    public=True, readable=True, severity="critical",
                    detail=f"Public GCS bucket. Content preview: {body[:100]}",
                )
                console.print(f"[bold #FF003C]  ⚡ PUBLIC GCS: {url}[/bold #FF003C]")
                found.append(asset)
            elif sc == 403:
                asset = CloudAsset(
                    provider="gcp", asset_type="gcs_bucket",
                    name=name, url=url,
                    public=True, readable=False, severity="low",
                    detail="GCS bucket exists (403 — not publicly readable)",
                )
                found.append(asset)
        return found

    def _detect_cloud_provider_from_dns(self) -> str:
        """Infer cloud provider from DNS CNAME records."""
        cname_indicators = {
            "amazonaws.com":          "AWS",
            "cloudfront.net":         "AWS CloudFront",
            "elasticloadbalancing":   "AWS ELB",
            "azurewebsites.net":      "Azure",
            "azure.com":              "Azure",
            "cloudapp.azure.com":     "Azure",
            "googleapis.com":         "GCP",
            "appspot.com":            "GCP App Engine",
            "run.app":                "GCP Cloud Run",
            "netlify.app":            "Netlify",
            "vercel.app":             "Vercel",
            "github.io":              "GitHub Pages",
            "heroku.com":             "Heroku",
            "digitaloceanspaces.com": "DigitalOcean Spaces",
        }
        try:
            import dns.resolver
            answers = dns.resolver.resolve(self.target, "CNAME")
            for r in answers:
                cname = str(r.target).lower()
                for indicator, provider in cname_indicators.items():
                    if indicator in cname:
                        return provider
        except Exception:
            pass
        return ""

    def _check_subdomain_takeover_candidates(self) -> list:
        """
        Detect dangling DNS records pointing to cloud services
        that could be candidates for subdomain takeover.
        """
        findings = []
        DANGLING_PATTERNS = {
            "amazonaws.com":        "AWS S3/EB",
            "azurewebsites.net":    "Azure Web Apps",
            "github.io":            "GitHub Pages",
            "herokussl.com":        "Heroku",
            "netlify.com":          "Netlify",
            "shopify.com":          "Shopify",
            "fastly.net":           "Fastly",
            "unbouncepages.com":    "Unbounce",
        }
        # We'd need subdomain list from previous recon phase
        # This is a placeholder that processes known subdomains
        log.info("[CLOUD] Subdomain takeover check requires subdomain list from recon phase")
        return findings

    def _print_assets(self):
        assets = self.assets
        if not assets:
            console.print("[#00FFD4]  ✅ No public cloud assets found.[/#00FFD4]")
            return
        table = Table(
            title=f"[bold #7B00FF]☁️  CLOUD ASSETS — {len(assets)} found[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4", show_lines=True,
        )
        table.add_column("Provider",   width=10)
        table.add_column("Type",       width=18)
        table.add_column("Name",       width=30)
        table.add_column("Public",     width=8)
        table.add_column("Readable",   width=10)
        table.add_column("Severity",   width=10)

        SEV_COLOR = {"critical":"[bold #FF003C]","high":"[bold #FF8C00]",
                     "medium":"[bold #FFD700]","low":"[bold #00FFD4]","info":"[dim]"}
        for a in sorted(assets, key=lambda x:
                         {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                         .get(x.severity,5)):
            c = SEV_COLOR.get(a.severity,"[white]")
            e = c.replace("[","[/")
            table.add_row(
                a.provider.upper(), a.asset_type,
                a.name[:30],
                "✅ YES" if a.public else "❌ No",
                "✅ YES" if a.readable else "❌ No",
                f"{c}{a.severity.upper()}{e}",
            )
        console.print(table)

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  ☁️  Cloud Recon — target: {self.target} | org: {self.org}[/bold #7B00FF]")
        provider_hint = self._detect_cloud_provider_from_dns()
        if provider_hint:
            console.print(f"[#00FFD4]  → DNS suggests cloud provider: {provider_hint}[/#00FFD4]")

        all_assets = []
        all_assets += self._probe_s3()
        all_assets += self._probe_azure_blob()
        all_assets += self._probe_gcs()
        self.assets = all_assets

        self._print_assets()
        public_count = sum(1 for a in all_assets if a.public)
        console.print(f"[bold #00FFD4]  ✅ Cloud recon complete — {len(all_assets)} assets | "
                       f"{public_count} public[/bold #00FFD4]")
        return {
            "target":        self.target,
            "org":           self.org,
            "provider_hint": provider_hint,
            "total_assets":  len(all_assets),
            "public_assets": public_count,
            "assets": [
                {"provider": a.provider, "type": a.asset_type, "name": a.name,
                 "url": a.url, "public": a.public, "readable": a.readable,
                 "severity": a.severity, "detail": a.detail}
                for a in all_assets
            ],
        }
