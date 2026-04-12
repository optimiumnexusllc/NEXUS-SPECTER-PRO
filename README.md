<div align="center">

```
███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
 ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗
 ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
 ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
 ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
 ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                         P  R  O
```

**Military-Grade Automated Offensive Penetration Testing Platform**

[![Version](https://img.shields.io/badge/version-1.0.0--SPECTER-7B00FF?style=for-the-badge)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.12+-00FFD4?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-Commercial-FF003C?style=for-the-badge)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-00FFD4?style=for-the-badge&logo=docker)](deployment/)
[![AI](https://img.shields.io/badge/AI-Powered-7B00FF?style=for-the-badge)](nsp/ai_engine/)

> *"Invisible. Inevitable. Unstoppable."*

**by [OPTIMIUM NEXUS LLC](https://www.optimiumnexus.com)**
📧 contact@optimiumnexus.com

</div>

---

## 🔱 Overview

**NEXUS SPECTER PRO (NSP)** is a comprehensive, fully automated offensive penetration testing platform engineered for enterprise-grade security assessments. Built with military precision, NSP orchestrates the entire pentest lifecycle — from passive OSINT reconnaissance to exploitation, post-exploitation, lateral movement, and executive-grade reporting — all powered by an AI intelligence engine.

NSP supports all engagement types:

| Mode | Description |
|------|-------------|
| 🖤 **Black Box** | Zero prior knowledge — full external recon & exploitation |
| 🩶 **Gray Box** | Partial credentials/architecture — accelerated assessment |
| 🤍 **White Box** | Full access — deep dive internal audit |
| 🔴 **Red Team** | Full adversarial simulation with C2 integration |
| ☁️ **Cloud Audit** | AWS / Azure / GCP misconfiguration assessment |

---

## ⚡ Architecture — 6-Phase Kill Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│                    NEXUS SPECTER PRO — KILL CHAIN                   │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────┤
│  PHASE 1 │  PHASE 2 │  PHASE 3 │  PHASE 4 │  PHASE 5 │   PHASE 6  │
│  GHOST   │  DEEP    │  SPECTER │  SPECTER │  GHOST   │   SPECTER  │
│  RECON   │  MAPPING │   SCAN   │  STRIKE  │   MODE   │   REPORT   │
├──────────┼──────────┼──────────┼──────────┼──────────┼─────────────┤
│ OSINT    │ Dir Fuzz │ Nuclei   │ SQLi     │ PrivEsc  │ Executive  │
│ DNS/WHOIS│ VHost    │ Nikto    │ XSS      │ BloodHnd │ Technical  │
│ Shodan   │ Param    │ ZAP      │ SSRF/XXE │ DCSync   │ CVSS Score │
│ Subdomain│ API Enum │ OpenVAS  │ SSTI/RCE │ Mimikatz │ Remediation│
│ Port Scan│ JS Leaks │ SQLMap   │ MSF      │ C2 Link  │ AI Narrate │
│ Cloud    │ AD/LDAP  │ CVE Match│ EtrnlBlue│ Exfil Sim│ PDF/HTML   │
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   SPECTER AI 🤖   │
                    │  (Claude API LLM) │
                    │  Attack Planning  │
                    │  Vuln Analysis    │
                    │  Payload Gen      │
                    │  Report Writing   │
                    └───────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

```bash
# System requirements
OS: Kali Linux / Ubuntu 22.04+ / ParrotOS
Python: 3.12+
Docker: 24.0+
RAM: 8GB minimum (16GB recommended)
Disk: 50GB minimum
```

### 1. Clone & Install

```bash
git clone https://github.com/optimiumnexusllc/NEXUS-SPECTER-PRO.git
cd NEXUS-SPECTER-PRO
pip install -r requirements.txt
python setup.py install
```

### 2. Configure

```bash
cp .env.example .env
cp config/api_keys.yaml.example config/api_keys.yaml
cp config/scope.yaml.example config/scope.yaml
# Edit .env with your API keys (Shodan, Censys, etc.)
nano .env
```

### 3. Deploy (Docker — Recommended)

```bash
docker-compose up -d
# Access dashboard → http://localhost:8080
```

### 4. Launch a Mission

```bash
# Black Box engagement
nsp --mode black_box --target example.com --output ./reports/

# Red Team with AI planning
nsp --mode red_team --target 192.168.1.0/24 --ai-assist --output ./reports/

# Cloud audit
nsp --mode cloud_audit --provider aws --profile default --output ./reports/

# Interactive dashboard
nsp --dashboard
```

---

## 🧠 Module Stack

| Module | Tools Integrated |
|--------|-----------------|
| **OSINT/Recon** | Shodan, Censys, FOFA, ZoomEye, theHarvester, Amass, Subfinder |
| **Port Scanning** | Masscan (speed) → Nmap (precision) |
| **Web Fuzzing** | ffuf, Gobuster, feroxbuster |
| **Vuln Scanning** | Nuclei, Nikto, OWASP ZAP, OpenVAS, Nessus Pro API |
| **Injection** | SQLMap, NoSQLMap, tplmap |
| **Exploitation** | Metasploit RPC, custom exploit modules |
| **AD/Windows** | BloodHound, CrackMapExec, Impacket, Mimikatz |
| **C2 Integration** | Sliver, Havoc Framework, Cobalt Strike |
| **AI Engine** | Anthropic Claude API |
| **Reporting** | WeasyPrint PDF, Jinja2 HTML, CVSS 3.1 |

---

## 🗂️ Project Structure

```
nexus-specter-pro/
├── nsp/                    # Core package
│   ├── core/               # Orchestrator, planner, session mgr
│   ├── recon/              # Passive + Active reconnaissance
│   ├── enumeration/        # Web, Network, Cloud enumeration
│   ├── vuln_scan/          # Vulnerability scanning engine
│   ├── exploitation/       # Web, Network, Credential attacks
│   ├── post_exploitation/  # PrivEsc, Lateral Movement, Persist
│   ├── ai_engine/          # Specter AI (Claude API)
│   ├── reporting/          # PDF/HTML report generation
│   └── utils/              # Helpers, crypto, logging
├── dashboard/              # FastAPI + React web interface
├── deployment/             # Docker, Kubernetes, Ansible
├── missions/               # YAML mission templates
├── config/                 # Settings, API keys, wordlists
├── docs/                   # Full documentation
└── nsp_cli.py              # CLI entry point
```

---

## 📊 Reporting

NSP generates **dual-format reports** automatically:

- 📄 **Executive Report** — C-Level / Board-ready, risk summary, business impact
- 🔬 **Technical Report** — Full vulnerability details, PoC, CVSS scores, evidence
- 🛠️ **Remediation Plan** — AI-generated prioritized remediation roadmap

All reports branded with **OPTIMIUM NEXUS LLC** identity.

---

## 🐳 Deployment Options

| Method | Command |
|--------|---------|
| **Docker Compose** | `docker-compose up -d` |
| **Kubernetes** | `kubectl apply -f deployment/kubernetes/` |
| **Ansible** | `ansible-playbook deployment/ansible/setup.yml` |
| **Direct** | `python nsp_cli.py` |

---

## ⚠️ Legal Disclaimer

> **NEXUS SPECTER PRO is intended exclusively for authorized security testing and penetration testing engagements.**
>
> Use of this tool against systems without explicit written authorization is **illegal** and violates applicable laws including but not limited to the Computer Fraud and Abuse Act (CFAA), EU NIS2 Directive, and equivalent local legislation.
>
> **OPTIMIUM NEXUS LLC** assumes **zero responsibility** for unauthorized or illegal use of this software. Users are solely responsible for ensuring all activities performed with NSP are conducted within the bounds of applicable law and with proper written authorization.
>
> This tool is provided for **professional security researchers, penetration testers, and authorized red team operators only.**

---

## 📜 License

**Commercial License — OPTIMIUM NEXUS LLC**
© 2025 OPTIMIUM NEXUS LLC. All rights reserved.
Unauthorized copying, distribution, or modification is strictly prohibited.

---

<div align="center">

**NEXUS SPECTER PRO v1.0.0-SPECTER**

*by OPTIMIUM NEXUS LLC*

📧 [contact@optimiumnexus.com](mailto:contact@optimiumnexus.com) | 🌐 [www.optimiumnexus.com](https://www.optimiumnexus.com)

*"Invisible. Inevitable. Unstoppable."*

</div>
