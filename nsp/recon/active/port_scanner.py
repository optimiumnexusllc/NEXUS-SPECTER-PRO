"""
NEXUS SPECTER PRO — Port Scanner
Masscan (high-speed) → Nmap (precision + service detection) orchestration
by OPTIMIUM NEXUS LLC
"""

import subprocess
import logging
import shutil
import re
import xml.etree.ElementTree as ET
from typing import Optional
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.recon.portscan")


class PortScanner:
    """
    Two-stage port scanner:
    Stage 1 — Masscan: ultra-fast full port discovery (1-65535)
    Stage 2 — Nmap: precision service/version/script detection on open ports
    """

    NMAP_SCRIPTS = {
        "default":    "default",
        "safe":       "safe",
        "aggressive": "vuln,exploit,auth,discovery",
        "stealth":    "banner,http-title,ssl-cert",
    }

    def __init__(self, target: str, rate: int = 10000, mode: str = "default", timeout: int = 600):
        self.target  = target
        self.rate    = rate
        self.mode    = mode
        self.timeout = timeout

    def _masscan(self) -> list:
        """Run Masscan for fast full port discovery."""
        if not shutil.which("masscan"):
            log.warning("[PORTSCAN] masscan not found — using Nmap for full scan")
            return []
        try:
            console.print(f"[#00FFD4]    [MASSCAN] Full port sweep: {self.target} (rate={self.rate})[/#00FFD4]")
            result = subprocess.run([
                "masscan", self.target,
                "-p", "0-65535",
                "--rate", str(self.rate),
                "--output-format", "list",
                "--output-filename", "/tmp/nsp_masscan.lst"
            ], capture_output=True, text=True, timeout=self.timeout)

            open_ports = []
            try:
                with open("/tmp/nsp_masscan.lst") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#") or not line:
                            continue
                        # Format: open tcp 80 1.2.3.4 timestamp
                        parts = line.split()
                        if len(parts) >= 4:
                            open_ports.append({
                                "protocol": parts[1],
                                "port":     int(parts[2]),
                                "ip":       parts[3],
                            })
            except FileNotFoundError:
                pass

            log.info(f"[PORTSCAN][MASSCAN] Found {len(open_ports)} open ports")
            return open_ports
        except subprocess.TimeoutExpired:
            log.warning("[PORTSCAN][MASSCAN] Timeout expired")
            return []
        except Exception as e:
            log.error(f"[PORTSCAN][MASSCAN] Error: {e}")
            return []

    def _nmap_service_detect(self, open_ports: Optional[list] = None) -> dict:
        """Run Nmap service/version/script detection."""
        scripts = self.NMAP_SCRIPTS.get(self.mode, "default")

        if open_ports:
            port_str = ",".join(str(p["port"]) for p in open_ports)
        else:
            port_str = "1-65535"

        console.print(f"[#00FFD4]    [NMAP] Service detection on ports: {port_str[:80]}...[/#00FFD4]")

        try:
            nmap_cmd = [
                "nmap",
                "-sV",            # Service version detection
                "-sC",            # Default scripts
                "-O",             # OS detection
                "--script", scripts,
                "-p", port_str,
                "-oX", "/tmp/nsp_nmap.xml",
                "--open",
                self.target
            ]

            if self.mode == "stealth":
                nmap_cmd = [
                    "nmap", "-sS", "-T2",
                    "--script", scripts,
                    "-p", port_str,
                    "-oX", "/tmp/nsp_nmap.xml",
                    self.target
                ]

            result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=self.timeout)
            return self._parse_nmap_xml("/tmp/nsp_nmap.xml")
        except subprocess.TimeoutExpired:
            log.warning("[PORTSCAN][NMAP] Timeout expired")
            return {}
        except Exception as e:
            log.error(f"[PORTSCAN][NMAP] Error: {e}")
            return {}

    def _parse_nmap_xml(self, xml_file: str) -> dict:
        """Parse Nmap XML output into structured data."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            hosts = []
            for host in root.findall("host"):
                host_data = {"addresses": [], "hostnames": [], "ports": [], "os": None}
                for addr in host.findall("address"):
                    host_data["addresses"].append({
                        "addr":     addr.get("addr"),
                        "addrtype": addr.get("addrtype"),
                    })
                for hostname in host.findall(".//hostname"):
                    host_data["hostnames"].append(hostname.get("name"))
                for port in host.findall(".//port"):
                    state = port.find("state")
                    service = port.find("service")
                    port_data = {
                        "portid":   port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state":    state.get("state") if state is not None else "unknown",
                        "service":  service.get("name") if service is not None else "unknown",
                        "product":  service.get("product", "") if service is not None else "",
                        "version":  service.get("version", "") if service is not None else "",
                        "scripts":  []
                    }
                    for script in port.findall("script"):
                        port_data["scripts"].append({
                            "id":     script.get("id"),
                            "output": script.get("output", "")[:500],
                        })
                    host_data["ports"].append(port_data)
                os_match = host.find(".//osmatch")
                if os_match is not None:
                    host_data["os"] = {
                        "name":     os_match.get("name"),
                        "accuracy": os_match.get("accuracy"),
                    }
                hosts.append(host_data)
            log.info(f"[PORTSCAN][NMAP] Parsed {len(hosts)} hosts from XML")
            return {"hosts": hosts, "total_hosts": len(hosts)}
        except Exception as e:
            log.error(f"[PORTSCAN] Failed to parse Nmap XML: {e}")
            return {}

    def run(self) -> dict:
        """Execute full port scanning: Masscan → Nmap."""
        console.print(f"[bold #7B00FF]  🔌 Port Scanner starting on: {self.target}[/bold #7B00FF]")

        masscan_results = self._masscan()
        nmap_results    = self._nmap_service_detect(masscan_results if masscan_results else None)

        total_open = len(masscan_results) if masscan_results else 0
        console.print(f"[bold #00FFD4]  ✅ Masscan open ports: {total_open}[/bold #00FFD4]")

        return {
            "target":          self.target,
            "masscan_ports":   masscan_results,
            "nmap_detailed":   nmap_results,
        }
