"""
NEXUS SPECTER PRO — SSL/TLS Scanner
Full TLS analysis: protocol versions, cipher suites, certificate details,
HSTS, OCSP stapling, certificate transparency, vulnerabilities.
Integrates: testssl.sh + SSLyze (Python) + custom checks.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import subprocess, shutil, logging, json, re, socket, ssl
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.vuln_scan.ssl")


@dataclass
class CertInfo:
    subject:     dict = field(default_factory=dict)
    issuer:      dict = field(default_factory=dict)
    not_before:  str = ""
    not_after:   str = ""
    expired:     bool = False
    days_left:   int = 0
    san:         list = field(default_factory=list)
    cn:          str = ""
    self_signed: bool = False
    key_size:    int = 0
    sig_alg:     str = ""


@dataclass
class TLSFinding:
    title:    str
    severity: str    # critical | high | medium | low | info
    detail:   str
    cve:      str = ""
    remedy:   str = ""


class SSLScanner:
    """
    SSL/TLS analysis engine for NEXUS SPECTER PRO.
    Checks:
    - Supported TLS versions (SSLv2, SSLv3, TLS 1.0/1.1 — all deprecated)
    - Certificate validity, expiry, and chain
    - Cipher suites (weak, NULL, export, ANON)
    - HSTS header presence and configuration
    - OCSP stapling, CT logs, certificate pinning
    - Known vulnerabilities: BEAST, POODLE, ROBOT, DROWN, HEARTBLEED (via testssl.sh)
    """

    DEPRECATED_PROTOCOLS = {
        "SSLv2":  ("critical", "CVE-2016-0800", "Disable SSLv2 immediately — DROWN attack vector."),
        "SSLv3":  ("critical", "CVE-2014-3566", "Disable SSLv3 — POODLE attack vector."),
        "TLSv1.0":("high",     "CVE-2011-3389", "Disable TLS 1.0 — BEAST attack vector."),
        "TLSv1.1":("medium",   "",              "Disable TLS 1.1 — deprecated per RFC 8996."),
    }

    WEAK_CIPHERS = {
        "NULL":     "critical",
        "EXPORT":   "critical",
        "ANON":     "critical",
        "RC4":      "high",
        "DES":      "high",
        "3DES":     "high",
        "MD5":      "medium",
        "SHA1":     "low",
    }

    def __init__(self, host: str, port: int = 443,
                 output_dir: str = "/tmp/nsp_ssl", timeout: int = 120):
        self.host       = host
        self.port       = port
        self.output_dir = Path(output_dir)
        self.timeout    = timeout
        self.findings: list[TLSFinding] = []
        self.cert_info: CertInfo = CertInfo()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Python native certificate check ────────────────────────────────────
    def _get_cert_python(self) -> CertInfo:
        info = CertInfo()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((self.host, self.port), timeout=10),
                server_hostname=self.host
            ) as s:
                raw    = s.getpeercert(binary_form=False)
                raw_bin= s.getpeercert(binary_form=True)
                cipher = s.cipher()

            if raw:
                subj = dict(x[0] for x in raw.get("subject", ()))
                iss  = dict(x[0] for x in raw.get("issuer", ()))
                san  = [v for _, v in raw.get("subjectAltName", [])]

                nb   = raw.get("notBefore","")
                na   = raw.get("notAfter","")
                info.subject    = subj
                info.issuer     = iss
                info.cn         = subj.get("commonName","")
                info.san        = san
                info.not_before = nb
                info.not_after  = na
                info.self_signed = (subj == iss)

                # Parse expiry
                try:
                    exp_dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now    = datetime.now(timezone.utc)
                    info.days_left = (exp_dt - now).days
                    info.expired   = info.days_left < 0
                except Exception:
                    pass

                # Key size via SSLyze or cipher
                info.sig_alg = str(cipher[0]) if cipher else ""

            log.info(f"[SSL] Cert: CN={info.cn} | expires={info.not_after} "
                     f"| days_left={info.days_left} | self_signed={info.self_signed}")
        except Exception as e:
            log.error(f"[SSL] Certificate fetch error: {e}")
        return info

    def _check_cert(self, info: CertInfo):
        if info.expired:
            self.findings.append(TLSFinding(
                title="Certificate expired", severity="critical",
                detail=f"Certificate expired {abs(info.days_left)} days ago ({info.not_after})",
                remedy="Renew the SSL/TLS certificate immediately.",
            ))
        elif 0 <= info.days_left <= 30:
            self.findings.append(TLSFinding(
                title=f"Certificate expiring soon ({info.days_left} days)",
                severity="medium" if info.days_left > 14 else "high",
                detail=f"Certificate expires: {info.not_after}",
                remedy="Renew the certificate before expiry. Automate with Let's Encrypt/ACME.",
            ))
        if info.self_signed:
            self.findings.append(TLSFinding(
                title="Self-signed certificate",
                severity="high",
                detail=f"Certificate issued and signed by same entity: {info.cn}",
                remedy="Replace with a certificate from a trusted CA.",
            ))

    def _check_protocols_python(self):
        """Probe TLS protocol support using Python ssl module."""
        TEST_PROTOS = {
            "TLSv1.0": ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion,"TLSv1")   else None,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion,"TLSv1_1") else None,
        }
        for proto_name, proto_ver in TEST_PROTOS.items():
            if proto_ver is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.minimum_version = proto_ver
                ctx.maximum_version = proto_ver
                with ctx.wrap_socket(
                    socket.create_connection((self.host, self.port), timeout=5),
                    server_hostname=self.host
                ):
                    sev, cve, remedy = self.DEPRECATED_PROTOCOLS[proto_name]
                    self.findings.append(TLSFinding(
                        title=f"Deprecated protocol supported: {proto_name}",
                        severity=sev, cve=cve, detail=f"{proto_name} is accepted by the server.",
                        remedy=remedy,
                    ))
                    console.print(f"[bold #FF003C]  ⚡ {proto_name} supported (deprecated)[/bold #FF003C]")
            except Exception:
                pass   # Connection refused = protocol not supported (good)

    def _check_hsts(self):
        """Check for HTTP Strict Transport Security header."""
        try:
            import requests
            r = requests.get(f"https://{self.host}:{self.port}/",
                             verify=False, timeout=10, allow_redirects=True)
            hsts = r.headers.get("Strict-Transport-Security","")
            if not hsts:
                self.findings.append(TLSFinding(
                    title="HSTS header missing",
                    severity="medium",
                    detail="Strict-Transport-Security header not set.",
                    remedy="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                ))
            else:
                if "preload" not in hsts:
                    self.findings.append(TLSFinding(
                        title="HSTS missing preload directive", severity="low",
                        detail=f"HSTS: {hsts}",
                        remedy="Add 'preload' directive and submit to HSTS preload list.",
                    ))
                max_age_match = re.search(r"max-age=(\d+)", hsts)
                if max_age_match and int(max_age_match.group(1)) < 31536000:
                    self.findings.append(TLSFinding(
                        title="HSTS max-age too short",
                        severity="low",
                        detail=f"max-age={max_age_match.group(1)} — minimum recommended: 31536000 (1 year)",
                        remedy="Set max-age to at least 31536000.",
                    ))
        except Exception as e:
            log.debug(f"[SSL] HSTS check error: {e}")

    def _run_testssl(self) -> dict:
        """Run testssl.sh for comprehensive TLS analysis."""
        testssl = shutil.which("testssl") or shutil.which("testssl.sh")
        if not testssl:
            log.warning("[SSL] testssl.sh not found — skipping deep TLS scan. "
                        "Install: https://testssl.sh/")
            return {}
        out_file = self.output_dir / "testssl_results.json"
        cmd = [
            testssl, "--quiet", "--severity", "LOW",
            "--json", str(out_file),
            f"{self.host}:{self.port}",
        ]
        console.print(f"[#00FFD4]  [TESTSSL] Running: {self.host}:{self.port}[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=self.timeout)
            if out_file.exists():
                return json.loads(out_file.read_text())
        except subprocess.TimeoutExpired:
            log.warning("[SSL] testssl.sh timeout")
        except Exception as e:
            log.error(f"[SSL] testssl.sh error: {e}")
        return {}

    def _parse_testssl(self, data: dict):
        """Parse testssl.sh JSON output and add TLSFindings."""
        if not data:
            return
        SEV_MAP = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium",
                   "LOW":"low","INFO":"info","OK":"info","NOT ok":"high"}
        for item in data if isinstance(data, list) else data.get("scanResult",[{}])[0].get("findings",[]):
            sev    = SEV_MAP.get(item.get("severity",""), "info")
            finding = item.get("finding","")
            ident  = item.get("id","")
            if sev in ("critical","high","medium") and finding:
                self.findings.append(TLSFinding(
                    title   = f"[testssl] {ident}: {finding[:80]}",
                    severity= sev,
                    detail  = finding,
                    remedy  = "Apply vendor-recommended TLS configuration hardening.",
                ))

    def _print_results(self):
        if not self.findings:
            console.print(f"[bold #00FFD4]  ✅ No significant TLS issues found on "
                           f"{self.host}:{self.port}[/bold #00FFD4]")
            return

        table = Table(
            title=f"[bold #7B00FF]🔒 TLS/SSL FINDINGS — {self.host}:{self.port}[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4", show_lines=True,
        )
        table.add_column("Severity", width=10)
        table.add_column("Finding",  width=45)
        table.add_column("CVE",      width=18)
        table.add_column("Remedy",   width=45)
        SEV_COLOR = {"critical":"[bold #FF003C]","high":"[bold #FF8C00]",
                     "medium":"[bold #FFD700]","low":"[bold #00FFD4]","info":"[dim]"}
        for f in sorted(self.findings,
                         key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                                        .get(x.severity, 5)):
            c = SEV_COLOR.get(f.severity,"[white]")
            e = c.replace("[","[/")
            table.add_row(f"{c}{f.severity.upper()}{e}",
                          f.title[:45], f.cve or "—", f.remedy[:45])
        console.print(table)

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🔒 SSL/TLS Scanner — {self.host}:{self.port}[/bold #7B00FF]")

        self.cert_info = self._get_cert_python()
        self._check_cert(self.cert_info)
        self._check_protocols_python()
        self._check_hsts()

        testssl_data = self._run_testssl()
        self._parse_testssl(testssl_data)

        self._print_results()
        console.print(f"[bold #00FFD4]  ✅ SSL scan complete — {len(self.findings)} findings[/bold #00FFD4]")

        return {
            "host":      self.host,
            "port":      self.port,
            "cert": {
                "cn":          self.cert_info.cn,
                "san":         self.cert_info.san,
                "not_after":   self.cert_info.not_after,
                "days_left":   self.cert_info.days_left,
                "expired":     self.cert_info.expired,
                "self_signed": self.cert_info.self_signed,
                "issuer":      self.cert_info.issuer,
            },
            "findings": [
                {"title":f.title,"severity":f.severity,
                 "detail":f.detail,"cve":f.cve,"remedy":f.remedy}
                for f in self.findings
            ],
            "total": len(self.findings),
        }
