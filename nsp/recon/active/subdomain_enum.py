"""
NEXUS SPECTER PRO — Subdomain Enumerator
Active subdomain discovery: Amass, Subfinder, AssetFinder, bruteforce
by OPTIMIUM NEXUS LLC
"""

import subprocess
import logging
import shutil
from typing import Optional
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.recon.subdomain")


class SubdomainEnumerator:
    """
    Multi-tool subdomain enumeration engine.
    Orchestrates: Amass, Subfinder, AssetFinder, custom DNS bruteforce
    """

    WORDLISTS = {
        "small":  "/usr/share/wordlists/subdomains-top1million-5000.txt",
        "medium": "/usr/share/wordlists/subdomains-top1million-20000.txt",
        "large":  "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    }

    def __init__(self, target: str, wordlist_size: str = "medium", timeout: int = 300):
        self.target        = target
        self.wordlist_size = wordlist_size
        self.timeout       = timeout
        self.subdomains    = set()

    def _tool_available(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def _run_subfinder(self) -> set:
        """Run Subfinder for passive subdomain discovery."""
        if not self._tool_available("subfinder"):
            log.warning("[SUBDOMAIN] subfinder not found — skipping (install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)")
            return set()
        try:
            console.print(f"[#00FFD4]    [SUBFINDER] Enumerating: {self.target}[/#00FFD4]")
            result = subprocess.run(
                ["subfinder", "-d", self.target, "-silent", "-o", "/tmp/nsp_subfinder.txt"],
                capture_output=True, text=True, timeout=self.timeout
            )
            subs = set()
            try:
                with open("/tmp/nsp_subfinder.txt") as f:
                    subs = {line.strip() for line in f if line.strip()}
            except FileNotFoundError:
                pass
            log.info(f"[SUBDOMAIN][SUBFINDER] Found {len(subs)} subdomains")
            return subs
        except subprocess.TimeoutExpired:
            log.warning("[SUBDOMAIN][SUBFINDER] Timeout expired")
            return set()
        except Exception as e:
            log.error(f"[SUBDOMAIN][SUBFINDER] Error: {e}")
            return set()

    def _run_amass(self) -> set:
        """Run Amass passive enumeration."""
        if not self._tool_available("amass"):
            log.warning("[SUBDOMAIN] amass not found — skipping")
            return set()
        try:
            console.print(f"[#00FFD4]    [AMASS] Passive enum: {self.target}[/#00FFD4]")
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", self.target, "-o", "/tmp/nsp_amass.txt"],
                capture_output=True, text=True, timeout=self.timeout
            )
            subs = set()
            try:
                with open("/tmp/nsp_amass.txt") as f:
                    subs = {line.strip() for line in f if line.strip()}
            except FileNotFoundError:
                pass
            log.info(f"[SUBDOMAIN][AMASS] Found {len(subs)} subdomains")
            return subs
        except subprocess.TimeoutExpired:
            log.warning("[SUBDOMAIN][AMASS] Timeout expired")
            return set()
        except Exception as e:
            log.error(f"[SUBDOMAIN][AMASS] Error: {e}")
            return set()

    def _run_assetfinder(self) -> set:
        """Run AssetFinder for additional subdomain discovery."""
        if not self._tool_available("assetfinder"):
            log.warning("[SUBDOMAIN] assetfinder not found — skipping")
            return set()
        try:
            console.print(f"[#00FFD4]    [ASSETFINDER] Scanning: {self.target}[/#00FFD4]")
            result = subprocess.run(
                ["assetfinder", "--subs-only", self.target],
                capture_output=True, text=True, timeout=self.timeout
            )
            subs = {line.strip() for line in result.stdout.splitlines() if line.strip()}
            log.info(f"[SUBDOMAIN][ASSETFINDER] Found {len(subs)} subdomains")
            return subs
        except Exception as e:
            log.error(f"[SUBDOMAIN][ASSETFINDER] Error: {e}")
            return set()

    def _dns_bruteforce(self) -> set:
        """DNS bruteforce using dnsx or built-in resolver."""
        if not self._tool_available("dnsx"):
            log.warning("[SUBDOMAIN] dnsx not found — skipping bruteforce")
            return set()
        wordlist = self.WORDLISTS.get(self.wordlist_size, self.WORDLISTS["medium"])
        try:
            console.print(f"[#00FFD4]    [DNSX] Bruteforcing: {self.target} ({self.wordlist_size} list)[/#00FFD4]")
            result = subprocess.run(
                ["dnsx", "-d", self.target, "-w", wordlist, "-silent", "-resp-only"],
                capture_output=True, text=True, timeout=self.timeout
            )
            subs = {line.strip() for line in result.stdout.splitlines() if line.strip()}
            log.info(f"[SUBDOMAIN][DNSX] Resolved {len(subs)} subdomains via bruteforce")
            return subs
        except Exception as e:
            log.error(f"[SUBDOMAIN][DNSX] Error: {e}")
            return set()

    def _resolve_and_probe(self, subdomains: set) -> list:
        """Resolve IPs and probe live hosts via httpx."""
        if not self._tool_available("httpx"):
            log.warning("[SUBDOMAIN] httpx not found — skipping live probe")
            return [{"subdomain": s, "live": None} for s in subdomains]
        try:
            console.print(f"[#00FFD4]    [HTTPX] Probing {len(subdomains)} subdomains for live hosts...[/#00FFD4]")
            subs_input = "\n".join(subdomains).encode()
            result = subprocess.run(
                ["httpx", "-silent", "-status-code", "-title", "-tech-detect", "-json"],
                input=subs_input, capture_output=True, timeout=self.timeout
            )
            import json
            live_hosts = []
            for line in result.stdout.decode().splitlines():
                try:
                    live_hosts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            log.info(f"[SUBDOMAIN][HTTPX] {len(live_hosts)} live hosts found")
            return live_hosts
        except Exception as e:
            log.error(f"[SUBDOMAIN][HTTPX] Error: {e}")
            return []

    def run(self) -> dict:
        """Execute all subdomain enumeration tools and return aggregated results."""
        console.print(f"[bold #7B00FF]  🌐 Subdomain Enumerator starting on: {self.target}[/bold #7B00FF]")

        self.subdomains |= self._run_subfinder()
        self.subdomains |= self._run_amass()
        self.subdomains |= self._run_assetfinder()
        self.subdomains |= self._dns_bruteforce()

        live_hosts = self._resolve_and_probe(self.subdomains)

        console.print(f"[bold #00FFD4]  ✅ Total unique subdomains: {len(self.subdomains)}[/bold #00FFD4]")
        console.print(f"[bold #00FFD4]  ✅ Live hosts: {len(live_hosts)}[/bold #00FFD4]")

        return {
            "target":          self.target,
            "total_found":     len(self.subdomains),
            "all_subdomains":  sorted(self.subdomains),
            "live_hosts":      live_hosts,
        }
