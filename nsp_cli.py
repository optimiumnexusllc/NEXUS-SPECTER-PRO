#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           NEXUS SPECTER PRO — CLI Entry Point                    ║
║           by OPTIMIUM NEXUS LLC                                  ║
║           contact@optimiumnexus.com | www.optimiumnexus.com      ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

console = Console()

NSP_BANNER = """
[bold #7B00FF]███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗[/bold #7B00FF]
[bold #7B00FF]████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝[/bold #7B00FF]
[bold #7B00FF]██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗[/bold #7B00FF]
[bold #7B00FF]██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║[/bold #7B00FF]
[bold #7B00FF]██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║[/bold #7B00FF]
[bold #7B00FF]╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝[/bold #7B00FF]
[bold #00FFD4] ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ [/bold #00FFD4]
[bold #00FFD4] ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗[/bold #00FFD4]
[bold #00FFD4] ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝[/bold #00FFD4]
[bold #00FFD4] ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗[/bold #00FFD4]
[bold #00FFD4] ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║[/bold #00FFD4]
[bold #00FFD4] ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝[/bold #00FFD4]
[bold white]                         P  R  O[/bold white]
"""

NSP_VERSION   = "v1.0.0-SPECTER"
NSP_CODENAME  = "NSP"
NSP_COMPANY   = "OPTIMIUM NEXUS LLC"
NSP_EMAIL     = "contact@optimiumnexus.com"
NSP_WEBSITE   = "https://www.optimiumnexus.com"
NSP_TAGLINE   = "Invisible. Inevitable. Unstoppable."


def print_banner():
    """Display the NEXUS SPECTER PRO banner."""
    console.print(NSP_BANNER)
    console.print(Panel(
        f"[bold #7B00FF]{NSP_VERSION}[/bold #7B00FF]  |  "
        f"[bold #00FFD4]{NSP_COMPANY}[/bold #00FFD4]  |  "
        f"[white]{NSP_EMAIL}[/white]\n"
        f"[italic #FF003C]\"{NSP_TAGLINE}\"[/italic #FF003C]",
        border_style="#7B00FF",
        padding=(0, 2),
    ))
    console.print()


def print_mission_info(args):
    """Display mission configuration summary."""
    from rich.table import Table
    table = Table(
        title="[bold #7B00FF]⚡ MISSION BRIEFING[/bold #7B00FF]",
        border_style="#7B00FF",
        show_header=True,
        header_style="bold #00FFD4"
    )
    table.add_column("Parameter", style="#00FFD4", width=20)
    table.add_column("Value", style="white")

    table.add_row("🎯 Target",     str(args.target or "N/A"))
    table.add_row("📋 Mode",       args.mode.upper())
    table.add_row("📁 Output",     str(args.output))
    table.add_row("🤖 AI Assist",  "✅ ENABLED" if args.ai_assist else "❌ DISABLED")
    table.add_row("📊 Report",     args.report_format.upper())
    table.add_row("🕐 Started",    datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    table.add_row("🔖 Session",    f"NSP-{datetime.now().strftime('%Y%m%d-%H%M%S')}")

    console.print(table)
    console.print()


def build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="nsp",
        description=f"NEXUS SPECTER PRO {NSP_VERSION} — Military-Grade Offensive Pentest Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
EXAMPLES:
  # Black Box external assessment
  nsp --mode black_box --target example.com --output ./reports/

  # Gray Box with credentials
  nsp --mode gray_box --target 10.0.0.0/24 --creds creds.yaml --output ./reports/

  # Red Team full simulation with AI
  nsp --mode red_team --target corp.local --ai-assist --output ./reports/

  # Cloud AWS audit
  nsp --mode cloud_audit --provider aws --output ./reports/

  # Web dashboard
  nsp --dashboard

  # List all available modules
  nsp --list-modules

by {NSP_COMPANY} | {NSP_EMAIL} | {NSP_WEBSITE}
        """
    )

    # Target options
    target_group = parser.add_argument_group("🎯 Target Options")
    target_group.add_argument("--target",   "-t",  help="Target IP, domain, CIDR, or URL")
    target_group.add_argument("--targets",         help="File containing list of targets")
    target_group.add_argument("--scope",           help="Scope config YAML file", default="config/scope.yaml")
    target_group.add_argument("--exclude",         help="Exclude IPs/CIDRs (comma-separated)")

    # Mission mode
    mode_group = parser.add_argument_group("📋 Mission Mode")
    mode_group.add_argument(
        "--mode", "-m",
        choices=["black_box", "gray_box", "white_box", "red_team", "cloud_audit", "custom"],
        default="black_box",
        help="Pentest engagement mode (default: black_box)"
    )
    mode_group.add_argument("--mission",    help="Custom mission YAML file")
    mode_group.add_argument("--provider",   choices=["aws", "azure", "gcp"], help="Cloud provider (for cloud_audit mode)")
    mode_group.add_argument("--creds",      help="Credentials YAML file (for gray/white box)")

    # Phase selection
    phase_group = parser.add_argument_group("⚙️ Phase Control")
    phase_group.add_argument("--phases",    help="Run specific phases (e.g. recon,enum,exploit)", default="all")
    phase_group.add_argument("--skip",      help="Skip phases (comma-separated)")
    phase_group.add_argument("--stealth",   action="store_true", help="Enable stealth mode (slower, low noise)")
    phase_group.add_argument("--aggressive",action="store_true", help="Aggressive mode (faster, more noise)")

    # AI options
    ai_group = parser.add_argument_group("🤖 AI Engine")
    ai_group.add_argument("--ai-assist",    action="store_true", help="Enable Specter AI (Claude API)")
    ai_group.add_argument("--ai-model",     default="claude-opus-4-5", help="AI model to use")
    ai_group.add_argument("--ai-plan",      action="store_true", help="AI-generate attack plan before execution")

    # Output options
    output_group = parser.add_argument_group("📊 Output & Reporting")
    output_group.add_argument("--output",   "-o",  default="./reports", help="Output directory")
    output_group.add_argument("--report-format", choices=["pdf", "html", "both", "json"], default="both")
    output_group.add_argument("--no-report", action="store_true", help="Skip report generation")
    output_group.add_argument("--verbose",  "-v",  action="store_true", help="Verbose output")
    output_group.add_argument("--debug",           action="store_true", help="Debug mode")
    output_group.add_argument("--quiet",    "-q",  action="store_true", help="Minimal output")

    # Interface
    ui_group = parser.add_argument_group("🖥️ Interface")
    ui_group.add_argument("--dashboard",    action="store_true", help="Launch web dashboard")
    ui_group.add_argument("--port",         type=int, default=8080, help="Dashboard port (default: 8080)")
    ui_group.add_argument("--list-modules", action="store_true", help="List all available modules")
    ui_group.add_argument("--version",      action="store_true", help="Show version and exit")

    return parser


def list_modules():
    """Display all available NSP modules."""
    from rich.table import Table

    table = Table(
        title="[bold #7B00FF]📦 NEXUS SPECTER PRO — MODULE REGISTRY[/bold #7B00FF]",
        border_style="#7B00FF",
        show_header=True,
        header_style="bold #00FFD4"
    )
    table.add_column("Phase",   style="#7B00FF", width=18)
    table.add_column("Module",  style="#00FFD4", width=25)
    table.add_column("Tools",   style="white",   width=45)
    table.add_column("Status",  style="green",   width=10)

    modules = [
        # RECON
        ("🔍 Ghost Recon",    "osint_engine",        "Shodan, Censys, FOFA, ZoomEye",         "✅ Ready"),
        ("🔍 Ghost Recon",    "dns_passive",          "WHOIS, ASN, DNS history",               "✅ Ready"),
        ("🔍 Ghost Recon",    "email_harvester",      "theHarvester, Hunter.io",               "✅ Ready"),
        ("🔍 Ghost Recon",    "breach_lookup",        "HIBP, DeHashed, LeakIX",                "✅ Ready"),
        ("🔍 Ghost Recon",    "github_dorking",       "GitLeaks, TruffleHog",                  "✅ Ready"),
        ("🔍 Ghost Recon",    "google_dork",          "Custom Dork engine",                    "✅ Ready"),
        ("🔍 Ghost Recon",    "subdomain_enum",       "Amass, Subfinder, AssetFinder",         "✅ Ready"),
        ("🔍 Ghost Recon",    "port_scanner",         "Masscan → Nmap orchestration",          "✅ Ready"),
        ("🔍 Ghost Recon",    "tech_detector",        "Wappalyzer, WhatWeb",                   "✅ Ready"),
        ("🔍 Ghost Recon",    "cloud_recon",          "AWS/Azure/GCP surface mapping",         "✅ Ready"),
        # ENUM
        ("🗺️ Deep Mapping",   "dir_fuzzer",           "ffuf, Gobuster, feroxbuster",           "✅ Ready"),
        ("🗺️ Deep Mapping",   "vhost_enum",           "VHost bruteforce",                      "✅ Ready"),
        ("🗺️ Deep Mapping",   "param_miner",          "Parameter discovery",                   "✅ Ready"),
        ("🗺️ Deep Mapping",   "api_enum",             "REST, GraphQL, gRPC, SOAP",             "✅ Ready"),
        ("🗺️ Deep Mapping",   "js_analyzer",          "LinkFinder, SecretFinder",              "✅ Ready"),
        ("🗺️ Deep Mapping",   "ad_enum",              "BloodHound, SharpHound",                "✅ Ready"),
        # VULN SCAN
        ("🎯 Specter Scan",   "web_scanner",          "Nuclei, Nikto, OWASP ZAP",             "✅ Ready"),
        ("🎯 Specter Scan",   "network_scanner",      "OpenVAS, Nessus Pro API",               "✅ Ready"),
        ("🎯 Specter Scan",   "cms_scanner",          "WPScan, Droopescan, Joomscan",         "✅ Ready"),
        ("🎯 Specter Scan",   "ssl_scanner",          "testssl.sh, SSLyze",                    "✅ Ready"),
        ("🎯 Specter Scan",   "injection_scanner",    "SQLMap, NoSQLMap, tplmap",              "✅ Ready"),
        ("🎯 Specter Scan",   "cve_matcher",          "NVD API + ExploitDB",                   "✅ Ready"),
        # EXPLOIT
        ("💀 Specter Strike", "msf_controller",       "Metasploit RPC API",                    "✅ Ready"),
        ("💀 Specter Strike", "sqli_exploit",         "SQLi Error/Blind/Time/OOB",             "✅ Ready"),
        ("💀 Specter Strike", "ssrf_exploit",         "SSRF → RCE chains",                     "✅ Ready"),
        ("💀 Specter Strike", "xxe_exploit",          "XXE Classic/Blind/OOB",                 "✅ Ready"),
        ("💀 Specter Strike", "ssti_exploit",         "SSTI all template engines",             "✅ Ready"),
        ("💀 Specter Strike", "rce_exploit",          "RCE exploitation chains",               "✅ Ready"),
        ("💀 Specter Strike", "brute_forcer",         "Hydra, Medusa wrapper",                 "✅ Ready"),
        ("💀 Specter Strike", "spray_attacker",       "Password spray (lockout safe)",         "✅ Ready"),
        # POST-EXPLOIT
        ("🕵️ Ghost Mode",     "linux_privesc",        "LinPEAS, PEASS-ng",                     "✅ Ready"),
        ("🕵️ Ghost Mode",     "windows_privesc",      "WinPEAS, PrivescCheck",                 "✅ Ready"),
        ("🕵️ Ghost Mode",     "bloodhound_runner",    "AD attack path automation",             "✅ Ready"),
        ("🕵️ Ghost Mode",     "impacket_suite",       "PtH, PtT, DCSync, SecretsDump",        "✅ Ready"),
        ("🕵️ Ghost Mode",     "c2_connector",         "Sliver, Havoc, Cobalt Strike",          "✅ Ready"),
        # AI
        ("🤖 Specter AI",     "specter_ai",           "Claude API (Anthropic)",                "✅ Ready"),
        ("🤖 Specter AI",     "attack_planner",       "AI attack path planning",               "✅ Ready"),
        ("🤖 Specter AI",     "payload_generator",    "Adaptive AI payloads",                  "✅ Ready"),
        ("🤖 Specter AI",     "report_writer",        "AI narrative generation",               "✅ Ready"),
        # REPORT
        ("📊 Specter Report", "report_generator",     "PDF + HTML dual reports",               "✅ Ready"),
        ("📊 Specter Report", "cvss_scorer",          "CVSS 3.1 auto-scoring",                 "✅ Ready"),
        ("📊 Specter Report", "remediation_advisor",  "AI remediation roadmap",                "✅ Ready"),
    ]

    for phase, module, tools, status in modules:
        table.add_row(phase, module, tools, status)

    console.print(table)


def run_dashboard(port: int):
    """Launch the NSP web dashboard."""
    console.print(f"[bold #7B00FF]🖥️  Launching NEXUS SPECTER PRO Dashboard...[/bold #7B00FF]")
    console.print(f"[#00FFD4]   → Dashboard URL: http://localhost:{port}[/#00FFD4]")
    console.print(f"[#00FFD4]   → API Docs:      http://localhost:{port}/docs[/#00FFD4]")
    try:
        import uvicorn
        uvicorn.run("dashboard.backend.main:app", host="0.0.0.0", port=port, reload=True)
    except ImportError:
        console.print("[bold #FF003C]❌ Dashboard dependencies not installed.[/bold #FF003C]")
        console.print("[white]   Run: pip install -r requirements.txt[/white]")


def run_mission(args):
    """Execute the pentest mission."""
    console.print(f"[bold #7B00FF]⚡ Initializing NEXUS SPECTER PRO mission...[/bold #7B00FF]")
    console.print()

    # Validate scope
    if not args.target and not args.targets:
        console.print("[bold #FF003C]❌ No target specified. Use --target or --targets.[/bold #FF003C]")
        sys.exit(1)

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Print mission briefing
    print_mission_info(args)

    # Import and run orchestrator
    try:
        from nsp.core.orchestrator import NSPOrchestrator
        orchestrator = NSPOrchestrator(args)
        orchestrator.run()
    except ImportError as e:
        console.print(f"[bold #FF003C]❌ Module import error: {e}[/bold #FF003C]")
        console.print("[white]   Ensure all dependencies are installed: pip install -r requirements.txt[/white]")
        sys.exit(1)


def main():
    """NEXUS SPECTER PRO — Main entry point."""
    parser = build_arg_parser()
    args   = parser.parse_args()

    # Version flag
    if args.version:
        print(f"NEXUS SPECTER PRO {NSP_VERSION} by {NSP_COMPANY}")
        sys.exit(0)

    # Always print banner (unless quiet)
    if not args.quiet:
        print_banner()

    # Module listing
    if args.list_modules:
        list_modules()
        sys.exit(0)

    # Dashboard mode
    if args.dashboard:
        run_dashboard(args.port)
        sys.exit(0)

    # Run mission
    run_mission(args)


if __name__ == "__main__":
    main()
