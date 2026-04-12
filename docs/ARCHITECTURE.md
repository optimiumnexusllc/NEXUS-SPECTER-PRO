# NEXUS SPECTER PRO — Architecture Documentation
**by OPTIMIUM NEXUS LLC** | contact@optimiumnexus.com | v1.1.0-SPECTER

---

## 1. Overview

NEXUS SPECTER PRO (NSP) is a **military-grade, fully automated offensive penetration testing platform** built around a 6-phase kill chain, an async orchestration engine, an AI intelligence layer (Anthropic Claude), and a modular plugin system.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     NEXUS SPECTER PRO — SYSTEM OVERVIEW                  │
│                                                                          │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────────────┐    │
│  │   NSP CLI   │    │  Web         │    │  REST API (FastAPI)       │    │
│  │  nsp_cli.py │    │  Dashboard   │    │  /api/missions            │    │
│  │  argparse   │    │  React v2    │    │  /api/results             │    │
│  └──────┬──────┘    └──────┬───────┘    └────────────┬─────────────┘    │
│         └──────────────────┴────────────────────────┬┘                  │
│                                                     ▼                   │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    NSP CORE ORCHESTRATOR                          │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────┐   │   │
│  │  │ Session Mgr │  │ Scope        │  │  Plugin Loader         │   │   │
│  │  │ AES-256     │  │ Validator    │  │  Hot-load custom mods  │   │   │
│  │  └─────────────┘  └──────────────┘  └───────────────────────┘   │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────┐   │   │
│  │  │ Mission     │  │ Event Bus    │  │  Target Profiler       │   │   │
│  │  │ Planner     │  │ (asyncio)    │  │                        │   │   │
│  │  └─────────────┘  └──────────────┘  └───────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                              │                                           │
│         ┌────────────────────┼─────────────────────┐                    │
│         ▼                    ▼                      ▼                    │
│  ┌─────────────┐    ┌────────────────┐    ┌─────────────────┐           │
│  │ SPECTER AI  │    │  Task Queue    │    │  PostgreSQL DB   │           │
│  │ Claude API  │    │  Celery/Redis  │    │  Results Store   │           │
│  └─────────────┘    └────────────────┘    └─────────────────┘           │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The 6-Phase Kill Chain

```
PHASE 1          PHASE 2         PHASE 3         PHASE 4
GHOST RECON  →  DEEP MAPPING → SPECTER SCAN → SPECTER STRIKE
    │                │               │               │
Passive OSINT    Dir Fuzzing     Nuclei Engine   MSF RPC API
Active Recon     API Enum        ZAP + Nikto     SQLi / XSS
Subdomain        AD/LDAP         SSL Analysis    Cred Attacks
Port Scan        JS Analysis     CVE Matching    PrivEsc
Cloud Surface    Cloud Assets    CMS Scanning    Lateral Move

        PHASE 5                   PHASE 6
      GHOST MODE          →    SPECTER REPORT
          │                          │
    Linux PrivEsc              CVSS 3.1 Scoring
    Windows PrivEsc            Executive PDF/HTML
    BloodHound AD              Technical PDF/HTML
    Impacket Suite             AI Remediation Plan
    C2 Integration             Compliance Mapping
```

---

## 3. Module Directory

```
nsp/
├── core/
│   ├── orchestrator.py      Async mission lifecycle — phases, sequencing, aggregation
│   ├── mission_planner.py   Tactical planning from mission YAML templates
│   ├── session_manager.py   AES-256 encrypted session persistence + audit trail
│   ├── scope_validator.py   Legal boundary enforcement (in/out-of-scope checks)
│   ├── plugin_loader.py     Hot-load custom plugins per phase
│   ├── target_profiler.py   Multi-dimensional target profiling
│   └── event_bus.py         Async event bus (asyncio)
│
├── recon/
│   ├── passive/
│   │   ├── osint_engine.py       Shodan, Censys, FOFA, ZoomEye, Hunter.io, HIBP
│   │   ├── dns_passive.py        WHOIS, ASN, passive DNS
│   │   ├── email_harvester.py    theHarvester, Hunter.io
│   │   ├── breach_lookup.py      HIBP, DeHashed, LeakIX
│   │   ├── github_dorking.py     25+ secret patterns, org repo scan
│   │   └── google_dork.py        Automated Google Dork queries
│   └── active/
│       ├── subdomain_enum.py     Amass + Subfinder + AssetFinder + dnsx + httpx
│       ├── port_scanner.py       Masscan (speed) → Nmap (precision + scripts)
│       ├── banner_grabber.py     Service fingerprinting
│       └── tech_detector.py      Wappalyzer, WhatWeb
│
├── enumeration/
│   ├── web/
│   │   ├── dir_fuzzer.py    ffuf / Gobuster / feroxbuster orchestration
│   │   ├── vhost_enum.py    Virtual host discovery
│   │   ├── api_enum.py      REST/GraphQL/gRPC/SOAP — OpenAPI + introspection
│   │   ├── js_analyzer.py   LinkFinder, SecretFinder — JS secrets
│   │   └── cors_checker.py  CORS misconfigurations
│   ├── network/
│   │   ├── smb_enum.py      enum4linux-ng, CrackMapExec
│   │   ├── ldap_enum.py     LDAP / Active Directory
│   │   └── ad_enum.py       BloodHound, SharpHound
│   └── cloud/
│       ├── aws_enum.py      S3, IAM, Lambda, EC2, EKS
│       ├── azure_enum.py    Azure AD, Storage, DevOps
│       └── gcp_enum.py      GCP buckets, IAM, Cloud Run
│
├── vuln_scan/
│   ├── web_scanner.py       Nikto + ZAP + Nuclei (web) — unified dedup
│   ├── nuclei_runner.py     Nuclei — template management, JSONL parser
│   ├── network_scanner.py   OpenVAS + Nessus Pro API
│   ├── cms_scanner.py       WPScan, Droopescan, Joomscan
│   ├── ssl_scanner.py       testssl.sh + SSLyze + Python native checks
│   ├── injection_scanner.py SQLMap, NoSQLMap, tplmap
│   ├── api_scanner.py       OWASP API Top 10 checks
│   └── cve_matcher.py       NVD API + ExploitDB live matching
│
├── exploitation/
│   ├── msf_controller.py    Metasploit RPC — sessions, exploits, msfvenom
│   ├── web/                 Web application exploits (authorized use only)
│   └── credentials/
│       ├── spray_attacker.py   Lockout-safe spray (CME/Hydra/HTTP) + dry-run
│       └── brute_forcer.py     Targeted bruteforce wrapper
│
├── post_exploitation/
│   ├── privesc/
│   │   ├── linux_privesc.py    LinPEAS + SUID/sudo/cron/docker/capabilities
│   │   └── windows_privesc.py  WinPEAS + token privs + unquoted paths
│   ├── lateral_movement/
│   │   ├── bloodhound_runner.py  AD attack paths: Kerberoast, ASREPRoast, DCSync
│   │   └── impacket_suite.py     Authorized secretsdump/lookupsid/rpcdump/wmiexec
│   ├── persistence/
│   │   └── c2_connector.py       Sliver / Havoc / Cobalt Strike integration
│   └── exfiltration/
│       └── sensitive_finder.py   Crown jewels discovery + classification
│
├── ai_engine/
│   ├── specter_ai.py         Core AI (Claude API) — attack planning + analysis
│   ├── attack_planner.py     AI-generated attack plans from recon data
│   ├── payload_generator.py  Context-aware payload suggestions
│   └── report_writer.py      AI executive narrative generation
│
├── reporting/
│   ├── cvss_scorer.py          CVSS 3.1 Base + Temporal + Environmental
│   ├── remediation_advisor.py  Prioritized roadmap + CIS/NIST/OWASP/ISO mapping
│   ├── report_generator.py     Executive PDF/HTML report
│   └── report_generator_v2.py  Technical PDF/HTML with PoC evidence
│
└── utils/
    ├── logger.py     Rich coloured logging
    ├── crypto.py     AES-256 Fernet encryption
    ├── validator.py  IP/domain/CIDR validation
    └── network_utils.py  Helpers
```

---

## 4. Data Flow

```
Target Input
    │
    ▼
ScopeValidator ──── BLOCKED ──→ [Stop + log violation]
    │ IN SCOPE
    ▼
SessionManager.create()
    │
    ▼
Orchestrator.run()
    │
    ├─ Phase 1: Ghost Recon
    │    ├── OSINTEngine (passive)
    │    ├── SubdomainEnumerator (active)
    │    ├── PortScanner (Masscan→Nmap)
    │    └── → session.add_phase("recon", results)
    │
    ├─ Phase 2: Deep Mapping
    │    ├── DirFuzzer
    │    ├── APIEnumerator
    │    └── → session.add_phase("enumeration", results)
    │
    ├─ Phase 3: Specter Scan
    │    ├── WebScanner (Nikto+ZAP+Nuclei)
    │    ├── SSLScanner
    │    ├── NucleiRunner
    │    └── → session.add_phase("vuln_scan", results)
    │
    ├─ Phase 4: Specter Strike (authorized only)
    │    ├── MSFController
    │    ├── SprayAttacker
    │    └── → session.add_phase("exploitation", results)
    │
    ├─ Phase 5: Ghost Mode
    │    ├── LinuxPrivEsc / WindowsPrivEsc
    │    ├── BloodHoundRunner
    │    └── → session.add_phase("post_exploit", results)
    │
    └─ Phase 6: Specter Report
         ├── CVSSScorer (score all findings)
         ├── RemediationAdvisor (AI roadmap)
         ├── ReportGenerator (executive HTML+PDF)
         └── TechnicalReportGenerator (PoC evidence)
```

---

## 5. AI Integration (Specter AI)

```
                    ┌─────────────────────────────┐
                    │        SPECTER AI            │
                    │   (Anthropic Claude API)     │
                    └──────────┬──────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
 Attack Planning          Vuln Analysis          Report Writing
 (recon → plan)       (CVE prioritisation)   (executive narrative)
        │                      │                      │
        ▼                      ▼                      ▼
 Payload Suggestions    Chain Detection        Remediation Roadmap
 (context-aware)     (SSRF→RCE, etc.)       (CIS/NIST/OWASP/ISO)
```

---

## 6. Deployment Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                    PRODUCTION DEPLOYMENT                           │
│                                                                    │
│  Internet ──→ [Ingress/TLS] ──→ nsp-core (Deployment, HPA 1-5)   │
│                                      │                            │
│                          ┌───────────┼──────────────┐             │
│                          ▼           ▼              ▼             │
│                      FastAPI    Celery Workers   Scheduler        │
│                      :8080      (concurrency=4)  (beat)          │
│                          │                                        │
│                ┌─────────┼──────────────────┐                    │
│                ▼         ▼                  ▼                    │
│           PostgreSQL   Redis            PVC (reports)            │
│           (StatefulSet) (Deployment)    (50Gi)                   │
└────────────────────────────────────────────────────────────────────┘

Quick deploy:
  docker-compose up -d                    # Local/VM
  kubectl apply -f deployment/kubernetes/ # Kubernetes
  ansible-playbook deployment/ansible/setup.yml  # Bare metal
```

---

## 7. Security Design

| Control | Implementation |
|---------|----------------|
| Session encryption | AES-256 (Fernet) — all session data at rest |
| Scope enforcement | ScopeValidator blocks every out-of-scope target |
| Audit trail | Every action logged with timestamp in session |
| API authentication | JWT Bearer tokens (dashboard) |
| Secrets management | `.env` file + Kubernetes Secrets (never in git) |
| Network isolation | Docker network bridge / K8s namespace |
| TLS everywhere | Ingress with Let's Encrypt cert-manager |
| DB encryption | PostgreSQL TLS + encrypted PVC |

---

## 8. Plugin System

Custom modules can be added without modifying core code:

```python
# plugins/my_module.py
NSP_PLUGIN = {
    "name": "my_custom_recon",
    "version": "1.0.0",
    "author": "Your Name",
    "phase": "recon",
    "description": "Custom OSINT module",
    "api_version": "1.0",
}

def run(target: str, config: dict = None, session=None) -> dict:
    # Your code here
    return {"findings": [...]}
```

NSP auto-discovers plugins in `plugins/` and runs them at the right phase.

---

## 9. Compliance Mapping

NSP findings are automatically mapped to:

| Framework | Coverage |
|-----------|---------|
| **CIS Controls v8** | CIS-3 through CIS-16 |
| **NIST CSF** | Identify / Protect / Detect |
| **OWASP ASVS 4.0** | V2–V14 |
| **ISO 27001:2022** | Annex A controls |
| **MITRE ATT&CK** | Full TTP mapping per finding |
| **CVSS 3.1** | Base + Temporal + Environmental |

---

*NEXUS SPECTER PRO v1.1.0-SPECTER — by OPTIMIUM NEXUS LLC*
*contact@optimiumnexus.com | www.optimiumnexus.com*
*"Invisible. Inevitable. Unstoppable."*
