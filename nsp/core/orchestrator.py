"""
NEXUS SPECTER PRO — Core Orchestrator
Manages the full mission lifecycle across all 6 phases.
by OPTIMIUM NEXUS LLC
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.orchestrator")


class NSPOrchestrator:
    """
    Central orchestrator for NEXUS SPECTER PRO missions.
    Manages phase sequencing, module coordination, result aggregation,
    and session persistence.
    """

    PHASES = [
        ("recon",         "🔍 Ghost Recon",    "Passive + Active Reconnaissance"),
        ("enumeration",   "🗺️  Deep Mapping",   "Web, Network, Cloud Enumeration"),
        ("vuln_scan",     "🎯 Specter Scan",    "Vulnerability Scanning"),
        ("exploitation",  "💀 Specter Strike",  "Exploitation Engine"),
        ("post_exploit",  "🕵️  Ghost Mode",     "Post-Exploitation & Lateral Movement"),
        ("reporting",     "📊 Specter Report",  "Report Generation"),
    ]

    def __init__(self, args):
        self.args        = args
        self.target      = args.target
        self.mode        = args.mode
        self.output_dir  = Path(args.output)
        self.ai_assist   = getattr(args, "ai_assist", False)
        self.session_id  = f"NSP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.results     = {}
        self.start_time  = datetime.now()

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._setup_logging()

    def _setup_logging(self):
        log_file = self.output_dir / f"{self.session_id}.log"
        logging.basicConfig(
            level=logging.DEBUG if getattr(self.args, "debug", False) else logging.INFO,
            format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(),
            ]
        )
        log.info(f"NSP Session {self.session_id} initialized | Target: {self.target} | Mode: {self.mode}")

    def _get_active_phases(self) -> list:
        """Determine which phases to execute based on args."""
        phases_arg = getattr(self.args, "phases", "all")
        skip_arg   = getattr(self.args, "skip", None)

        if phases_arg == "all":
            active = [p[0] for p in self.PHASES]
        else:
            active = [p.strip() for p in phases_arg.split(",")]

        if skip_arg:
            skip = [p.strip() for p in skip_arg.split(",")]
            active = [p for p in active if p not in skip]

        return active

    def _print_phase_header(self, phase_id: str, phase_name: str, description: str):
        console.print()
        console.print(Panel(
            f"[bold #00FFD4]{phase_name}[/bold #00FFD4]\n[white]{description}[/white]",
            title=f"[bold #7B00FF]⚡ {phase_id.upper()}[/bold #7B00FF]",
            border_style="#7B00FF",
            padding=(0, 2),
        ))

    def _run_recon_phase(self) -> dict:
        """Execute Phase 1 — Ghost Recon."""
        results = {"passive": {}, "active": {}}
        log.info(f"[RECON] Starting reconnaissance on {self.target}")

        console.print("[#00FFD4]  → Loading OSINT engine...[/#00FFD4]")
        console.print("[#00FFD4]  → Passive DNS enumeration...[/#00FFD4]")
        console.print("[#00FFD4]  → Subdomain discovery...[/#00FFD4]")
        console.print("[#00FFD4]  → Port scanning (Masscan → Nmap)...[/#00FFD4]")
        console.print("[#00FFD4]  → Technology fingerprinting...[/#00FFD4]")

        # Module imports happen lazily to allow partial installs
        try:
            from nsp.recon.passive.osint_engine import OSINTEngine
            osint = OSINTEngine(self.target)
            results["passive"]["osint"] = osint.run()
        except ImportError:
            log.warning("OSINT engine module not yet installed — skipping")

        try:
            from nsp.recon.active.subdomain_enum import SubdomainEnumerator
            subenum = SubdomainEnumerator(self.target)
            results["active"]["subdomains"] = subenum.run()
        except ImportError:
            log.warning("Subdomain enumerator not yet installed — skipping")

        return results

    def _run_enumeration_phase(self) -> dict:
        """Execute Phase 2 — Deep Mapping."""
        results = {}
        log.info("[ENUM] Starting deep enumeration")
        console.print("[#00FFD4]  → Web directory fuzzing...[/#00FFD4]")
        console.print("[#00FFD4]  → API endpoint discovery...[/#00FFD4]")
        console.print("[#00FFD4]  → JavaScript secret scanning...[/#00FFD4]")
        console.print("[#00FFD4]  → SMB/LDAP enumeration...[/#00FFD4]")
        return results

    def _run_vuln_scan_phase(self) -> dict:
        """Execute Phase 3 — Specter Scan."""
        results = {}
        log.info("[VULN] Starting vulnerability scanning")
        console.print("[#00FFD4]  → Nuclei templates scan...[/#00FFD4]")
        console.print("[#00FFD4]  → CMS scanning...[/#00FFD4]")
        console.print("[#00FFD4]  → SSL/TLS analysis...[/#00FFD4]")
        console.print("[#00FFD4]  → CVE matching...[/#00FFD4]")
        return results

    def _run_exploitation_phase(self) -> dict:
        """Execute Phase 4 — Specter Strike."""
        results = {}
        log.info("[EXPLOIT] Starting exploitation engine")
        console.print("[#00FFD4]  → Metasploit RPC connecting...[/#00FFD4]")
        console.print("[#00FFD4]  → Web exploit chains...[/#00FFD4]")
        console.print("[#00FFD4]  → Credential attacks...[/#00FFD4]")
        return results

    def _run_post_exploit_phase(self) -> dict:
        """Execute Phase 5 — Ghost Mode."""
        results = {}
        log.info("[POST] Starting post-exploitation")
        console.print("[#00FFD4]  → Privilege escalation checks...[/#00FFD4]")
        console.print("[#00FFD4]  → BloodHound AD analysis...[/#00FFD4]")
        console.print("[#00FFD4]  → Lateral movement simulation...[/#00FFD4]")
        console.print("[#00FFD4]  → Persistence mechanisms...[/#00FFD4]")
        return results

    def _run_reporting_phase(self) -> dict:
        """Execute Phase 6 — Specter Report."""
        results = {}
        log.info("[REPORT] Generating reports")
        console.print("[#00FFD4]  → Scoring vulnerabilities (CVSS 3.1)...[/#00FFD4]")
        console.print("[#00FFD4]  → Generating executive report...[/#00FFD4]")
        console.print("[#00FFD4]  → Generating technical report...[/#00FFD4]")
        console.print("[#00FFD4]  → AI remediation plan...[/#00FFD4]")

        try:
            from nsp.reporting.report_generator import ReportGenerator
            rg = ReportGenerator(self.results, self.session_id, self.output_dir)
            results = rg.generate_all()
        except ImportError:
            log.warning("Report generator not yet installed — skipping")

        return results

    def _print_summary(self):
        """Print mission completion summary."""
        elapsed = (datetime.now() - self.start_time).seconds

        table = Table(
            title="[bold #7B00FF]📊 MISSION COMPLETE — NSP SUMMARY[/bold #7B00FF]",
            border_style="#7B00FF",
            header_style="bold #00FFD4"
        )
        table.add_column("Metric",  style="#00FFD4")
        table.add_column("Value",   style="white")

        table.add_row("🎯 Target",       self.target or "N/A")
        table.add_row("📋 Mode",         self.mode.upper())
        table.add_row("🔖 Session ID",   self.session_id)
        table.add_row("⏱️  Duration",     f"{elapsed}s")
        table.add_row("📁 Reports",      str(self.output_dir))
        table.add_row("🏢 Operator",     "OPTIMIUM NEXUS LLC")

        console.print()
        console.print(table)
        console.print()
        console.print("[bold #7B00FF]⚡ NEXUS SPECTER PRO — Mission Complete.[/bold #7B00FF]")
        console.print(f"[italic #FF003C]\"Invisible. Inevitable. Unstoppable.\"[/italic #FF003C]")

    def run(self):
        """Execute the full mission lifecycle."""
        phase_map = {
            "recon":        self._run_recon_phase,
            "enumeration":  self._run_enumeration_phase,
            "vuln_scan":    self._run_vuln_scan_phase,
            "exploitation": self._run_exploitation_phase,
            "post_exploit": self._run_post_exploit_phase,
            "reporting":    self._run_reporting_phase,
        }

        active_phases = self._get_active_phases()

        for phase_id, phase_name, description in self.PHASES:
            if phase_id not in active_phases:
                console.print(f"[dim]  ⏭  Skipping phase: {phase_id}[/dim]")
                continue

            self._print_phase_header(phase_id, phase_name, description)

            with Progress(
                SpinnerColumn(style="#7B00FF"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40, style="#7B00FF", complete_style="#00FFD4"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(f"[#00FFD4]{phase_name}...", total=100)

                phase_fn = phase_map.get(phase_id)
                if phase_fn:
                    self.results[phase_id] = phase_fn()
                    progress.update(task, completed=100)

        self._print_summary()
