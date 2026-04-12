"""
NEXUS SPECTER PRO — Scope Validator
Legal boundary enforcement: validates every target against the authorised scope.
Prevents accidental out-of-scope scanning — a critical safety and legal control.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import ipaddress, logging, re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Union
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
log = logging.getLogger("nsp.core.scope")


@dataclass
class ScopeConfig:
    client:         str = "Unknown"
    start_date:     str = ""
    end_date:       str = ""
    authorized_by:  str = ""
    reference:      str = ""
    in_scope_domains:  list = field(default_factory=list)
    in_scope_ips:      list = field(default_factory=list)
    in_scope_urls:     list = field(default_factory=list)
    out_scope_domains: list = field(default_factory=list)
    out_scope_ips:     list = field(default_factory=list)
    forbidden_actions: list = field(default_factory=list)


@dataclass
class ScopeCheckResult:
    target:    str
    in_scope:  bool
    reason:    str
    matched:   str = ""


class ScopeValidator:
    """
    Enforces the authorised pentest scope for every scan target.
    Reads scope from YAML config and validates:
    - IP addresses and CIDRs
    - Domain names (with wildcard *.domain.com support)
    - URLs (extracts host and validates)
    Blocks any out-of-scope target before a module runs.
    """

    def __init__(self, scope_file: str = None, scope_config: ScopeConfig = None):
        if scope_file and Path(scope_file).exists():
            self.scope = self._load_yaml(scope_file)
        elif scope_config:
            self.scope = scope_config
        else:
            log.warning("[SCOPE] No scope file — operating in UNRESTRICTED mode. "
                        "Ensure you have written authorisation for all targets.")
            self.scope = None

        self._in_scope_networks  = self._parse_cidrs(
            getattr(self.scope, "in_scope_ips", []) if self.scope else [])
        self._out_scope_networks = self._parse_cidrs(
            getattr(self.scope, "out_scope_ips", []) if self.scope else [])

    def _load_yaml(self, path: str) -> ScopeConfig:
        raw  = yaml.safe_load(Path(path).read_text())
        eng  = raw.get("engagement", {})
        ins  = raw.get("in_scope", {})
        outs = raw.get("out_of_scope", {})
        return ScopeConfig(
            client        = eng.get("client", ""),
            start_date    = eng.get("start_date", ""),
            end_date      = eng.get("end_date", ""),
            authorized_by = eng.get("authorized_by", ""),
            reference     = eng.get("reference", ""),
            in_scope_domains  = ins.get("domains", []),
            in_scope_ips      = ins.get("ips", []),
            in_scope_urls     = ins.get("urls", []),
            out_scope_domains = outs.get("domains", []),
            out_scope_ips     = outs.get("ips", []),
            forbidden_actions = outs.get("actions", []),
        )

    def _parse_cidrs(self, cidr_list: list) -> list:
        networks = []
        for cidr in cidr_list:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.debug(f"[SCOPE] Cannot parse CIDR: {cidr}")
        return networks

    def _extract_host(self, target: str) -> str:
        """Strip protocol and path from a URL to get the hostname/IP."""
        t = target.strip()
        for scheme in ("https://","http://","ftp://"):
            if t.startswith(scheme):
                t = t[len(scheme):]
        t = t.split("/")[0].split(":")[0]
        return t

    def _is_ip(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _ip_in_networks(self, ip_str: str, networks: list) -> tuple:
        try:
            ip = ipaddress.ip_address(ip_str)
            for net in networks:
                if ip in net:
                    return True, str(net)
        except ValueError:
            pass
        return False, ""

    def _domain_matches(self, host: str, patterns: list) -> tuple:
        """Check if host matches any domain pattern (supports wildcards *.domain.com)."""
        host_lower = host.lower().rstrip(".")
        for pattern in patterns:
            p = pattern.lower().rstrip(".")
            if p.startswith("*."):
                base = p[2:]
                if host_lower == base or host_lower.endswith("." + base):
                    return True, pattern
            else:
                if host_lower == p or host_lower.endswith("." + p):
                    return True, pattern
        return False, ""

    def check(self, target: str) -> ScopeCheckResult:
        """
        Validate a single target against the scope.
        Returns ScopeCheckResult — check .in_scope before scanning.
        """
        if not self.scope:
            return ScopeCheckResult(target=target, in_scope=True,
                                    reason="No scope defined — unrestricted mode")

        host = self._extract_host(target)

        # 1. Explicit out-of-scope check (takes priority)
        if self._is_ip(host):
            oos, match = self._ip_in_networks(host, self._out_scope_networks)
            if oos:
                return ScopeCheckResult(target, False,
                    f"IP in out-of-scope range: {match}", match)
        else:
            oos, match = self._domain_matches(host, self.scope.out_scope_domains)
            if oos:
                return ScopeCheckResult(target, False,
                    f"Domain matches out-of-scope pattern: {match}", match)

        # 2. In-scope check
        if self._is_ip(host):
            ins, match = self._ip_in_networks(host, self._in_scope_networks)
            if ins:
                return ScopeCheckResult(target, True,
                    f"IP in scope: {match}", match)
            # Not in any defined range
            return ScopeCheckResult(target, False,
                "IP not in any in-scope range", "")
        else:
            ins, match = self._domain_matches(host, self.scope.in_scope_domains)
            if ins:
                return ScopeCheckResult(target, True,
                    f"Domain in scope: {match}", match)
            # Check URLs
            for url in self.scope.in_scope_urls:
                url_host = self._extract_host(url)
                if host == url_host or host.endswith("." + url_host):
                    return ScopeCheckResult(target, True,
                        f"Host matches in-scope URL: {url}", url)

            return ScopeCheckResult(target, False,
                "Domain not found in scope", "")

    def validate_list(self, targets: list) -> tuple:
        """
        Validate a list of targets.
        Returns (in_scope_targets, blocked_targets).
        """
        approved, blocked = [], []
        for t in targets:
            result = self.check(t)
            if result.in_scope:
                approved.append(t)
            else:
                blocked.append((t, result.reason))
                log.warning(f"[SCOPE] ⛔ BLOCKED: {t} — {result.reason}")
        return approved, blocked

    def assert_in_scope(self, target: str):
        """Raise ValueError if target is out of scope. Use before any scan."""
        result = self.check(target)
        if not result.in_scope:
            msg = (f"⛔ TARGET OUT OF SCOPE: {target}\n"
                   f"   Reason: {result.reason}\n"
                   f"   NEXUS SPECTER PRO will not scan out-of-scope targets.\n"
                   f"   Update your scope file or obtain written authorisation.")
            console.print(f"[bold #FF003C]{msg}[/bold #FF003C]")
            raise ValueError(msg)

    def print_scope_summary(self):
        if not self.scope:
            console.print("[bold #FFD700]  ⚠️  No scope configured — unrestricted mode[/bold #FFD700]")
            return
        s = self.scope
        console.print(Panel(
            f"[bold #00FFD4]Client:[/bold #00FFD4]      {s.client}\n"
            f"[bold #00FFD4]Reference:[/bold #00FFD4]   {s.reference}\n"
            f"[bold #00FFD4]Auth by:[/bold #00FFD4]     {s.authorized_by}\n"
            f"[bold #00FFD4]Period:[/bold #00FFD4]      {s.start_date} → {s.end_date}\n"
            f"[bold #00FFD4]In-scope domains:[/bold #00FFD4]  {len(s.in_scope_domains)}\n"
            f"[bold #00FFD4]In-scope IPs:[/bold #00FFD4]      {len(s.in_scope_ips)}\n"
            f"[bold #FF003C]Out-of-scope:[/bold #FF003C]      {len(s.out_scope_domains)} domains, "
            f"{len(s.out_scope_ips)} IPs\n"
            f"[bold #FF003C]Forbidden actions:[/bold #FF003C] {', '.join(s.forbidden_actions)}",
            title="[bold #7B00FF]📋 ENGAGEMENT SCOPE[/bold #7B00FF]",
            border_style="#7B00FF",
        ))
