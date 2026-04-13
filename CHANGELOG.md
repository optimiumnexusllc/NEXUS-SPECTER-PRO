# NEXUS SPECTER PRO — Changelog

All notable changes to NEXUS SPECTER PRO by OPTIMIUM NEXUS LLC.

## [1.0.0-SPECTER] — 2025-04-13

### 🎉 Initial Release

#### Core Engine
- Full 6-phase pentest kill chain orchestrator
- Async mission execution with Celery task queue
- AES-256 session encryption
- Plugin-based modular architecture

#### Phase 1 — Ghost Recon
- OSINT engine (Shodan, Censys, FOFA, ZoomEye, Hunter.io)
- Passive DNS enumeration + WHOIS
- Breach data lookup (HIBP, DeHashed, LeakIX)
- GitHub dorking & Google dork automation
- Subdomain enumeration (Amass, Subfinder, AssetFinder, dnsx)
- Port scanning (Masscan → Nmap orchestration)
- Technology fingerprinting (Wappalyzer, WhatWeb)
- Cloud surface recon (AWS, Azure, GCP)

#### Phase 2 — Deep Mapping
- Web directory fuzzing (ffuf, Gobuster, feroxbuster)
- Virtual host enumeration
- Parameter discovery
- API endpoint enumeration (REST, GraphQL, gRPC, SOAP)
- JavaScript secret scanner (LinkFinder, SecretFinder)
- SMB/LDAP/AD enumeration
- Cloud asset mapping

#### Phase 3 — Specter Scan
- Nuclei template scanning (custom + community)
- OWASP ZAP integration
- OpenVAS + Nessus Pro API
- CMS scanners (WPScan, Droopescan, Joomscan)
- SSL/TLS analysis (testssl.sh, SSLyze)
- SQLMap + NoSQLMap integration
- Live CVE matching (NVD API + ExploitDB)

#### Phase 4 — Specter Strike
- Metasploit RPC API integration
- Web exploits: SQLi, XSS, SSRF, XXE, SSTI, LFI, RCE, Deserialization
- OAuth/OIDC attack module
- JWT attack module (alg:none, RS→HS, kid injection)
- Password spraying engine (lockout-safe)
- Hash cracking (Hashcat + John integration)

#### Phase 5 — Ghost Mode
- Linux PrivEsc automation (LinPEAS/PEASS-ng)
- Windows PrivEsc automation (WinPEAS/PrivescCheck)
- BloodHound attack path automation
- Impacket suite (PtH, PtT, DCSync, SecretsDump)
- Mimikatz integration
- C2 connector (Sliver, Havoc, Cobalt Strike)

#### Phase 6 — Specter Report
- Dual PDF + HTML report generation
- CVSS 3.1 auto-scoring engine
- Executive report (C-Level/Board ready)
- Technical report (full PoC evidence)
- AI-generated remediation roadmap

#### Specter AI Engine
- Anthropic Claude API integration
- AI attack planning from recon data
- Vulnerability chain analysis
- Adaptive payload generation
- Executive narrative writing
- AD lateral movement path suggestion

#### Dashboard
- FastAPI REST backend
- React + TailwindCSS frontend
- Real-time mission monitoring
- Report management interface

#### Deployment
- Docker Compose stack (NSP + PostgreSQL + Redis + Nuclei + OpenVAS + MSF)
- Kubernetes manifests
- Ansible setup playbook
- GitHub Actions CI/CD

## [1.1.0-SPECTER] — 2025-04-13

### ⚡ Sprint 3 — Scanners, PrivEsc, Reporting & Infrastructure

#### Vulnerability Scanning
- `web_scanner.py` — Web orchestrator: Nikto + ZAP API + Nuclei (web tags), unified dedup
- `nuclei_runner.py` — Full engine with template management, JSONL parser, rich severity table

#### Post-Exploitation
- `linux_privesc.py` — LinPEAS orchestration, SUID/sudo/cron/docker/capabilities checks, MITRE mapping
- `windows_privesc.py` — WinPEAS + PrivescCheck, token privs, AlwaysInstallElevated, unquoted service paths
- `impacket_suite.py` — Authorized secretsdump/lookupsid/rpcdump/wmiexec wrapper with output parsing

#### Credential Attacks
- `spray_attacker.py` — Lockout-safe spray (CME/Hydra/HTTP), configurable delay + jitter, dry-run mode

#### Reporting
- `report_generator_v2.py` — Technical report with PoC evidence, CVSS 3.1 breakdown,
  MITRE ATT&CK mapping, remediation library, full HTML+PDF output

#### Infrastructure
- `deployment/kubernetes/` — Full K8s stack: namespace, configmap, secrets, postgres StatefulSet,
  redis deployment, nsp-core deployment, ingress (TLS), HPA, deploy.sh script
- `deployment/ansible/setup.yml` — Full Ansible provisioning playbook (Kali/Ubuntu)

## [1.2.0-SPECTER] — 2025-04-13

### ⚡ Sprint 4 — Infrastructure, Quality & Compliance

#### Reporting & Scoring
- `cvss_scorer.py`        — Full CVSS 3.1 engine (Base + Temporal + Environmental), roundup, batch scoring
- `remediation_advisor.py`— Prioritized roadmap: CIS Controls, NIST CSF, OWASP ASVS, ISO 27001 mapping

#### Dashboard
- `AppV2.jsx`             — Redesigned React dashboard: Donut chart, Bar chart, live polling,
                           mission modal with mode selector, animated progress bars, dark theme

#### Core Infrastructure
- `session_manager.py`    — AES-256 encrypted sessions, audit trail, PostgreSQL-ready
- `plugin_loader.py`      — Hot-load custom plugins per phase, template generator, registry table
- `scope_validator.py`    — Legal scope enforcement: IP/CIDR + wildcard domain + URL extraction

#### Enumeration
- `api_enum.py`           — REST/GraphQL/gRPC discovery: OpenAPI spec, introspection, auth detection

#### Vulnerability Scanning
- `ssl_scanner.py`        — TLS analysis: deprecated protocols, cert expiry, HSTS, testssl.sh integration

#### Documentation
- `docs/ARCHITECTURE.md`  — Full system architecture: data flow, module map, deployment, compliance

#### Build System
- `pyproject.toml`        — PEP 621 modern packaging: Black, Ruff, mypy, pytest, coverage, pre-commit
- `.pre-commit-config.yaml`— Git hooks: trailing whitespace, secrets detection, black, ruff, mypy
- `tests/unit/`           — 24 unit tests: CVSSScorer, ScopeValidator, SessionManager

## [1.3.0-SPECTER] — 2025-04-13

### ⚡ Sprint 5 — Full Platform Completion

#### Core Intelligence
- `target_profiler.py`    — Multi-dim profiling: DNS, GeoIP, CDN/WAF detect, tech stack, attack surface
- `cloud_recon.py`        — S3/Azure Blob/GCS public bucket probe, subdomain takeover detection

#### Recon
- `email_harvester.py`    — theHarvester + Hunter.io API + SPF/DMARC/DKIM mail security checks

#### Enumeration
- `dir_fuzzer.py`         — ffuf→feroxbuster→gobuster auto-select, builtin wordlist fallback

#### Dashboard Backend v2
- `main_v2.py`            — WebSockets real-time events, JWT Bearer auth (python-jose),
                           full CRUD: missions/targets/results/reports + /api/stats

#### Async Workers
- `celery_tasks.py`       — Full Celery task graph: 6-phase chain, retry, signals,
                           beat scheduler (nuclei update, session cleanup, health check)

#### Testing
- `tests/integration/test_api.py` — 20 async integration tests covering full API surface

#### Documentation
- `docs/API_REFERENCE.md` — Complete REST + WebSocket API reference with SDK example
- `CONTRIBUTING.md`       — Full contribution guide: branching, standards, plugin authoring, release

#### Build & DevOps
- `Makefile`              — 35 targets: install, test, lint, docker, k8s, scan shortcuts
- `requirements-dev.txt`  — Dedicated dev dependency file

## [1.4.0-SPECTER] — 2025-04-13

### 🧠 Sprint 6 — Intelligence & Correlation Engine

#### Threat Intelligence
- `threat_intel_engine.py` — Multi-source passive intel: Shodan + Censys + GreyNoise +
  VirusTotal + AbuseIPDB + URLScan. Composite ThreatScore (0-100) with 5 severity levels.
  24h JSON cache layer. Batch mode with ranked output.

#### CVE Correlation
- `cve_correlator.py`      — NVD API v2.0 + CISA KEV daily sync + GitHub PoC detection.
  Weaponization score, remediation priority (IMMEDIATE/HIGH/MEDIUM/LOW),
  banner auto-parsing for multi-product correlation. CISA KEV 24h local cache.

#### Attack Graph
- `attack_graph.py`        — NetworkX digraph: shortest attack paths, chokepoints,
  blast radius. D3.js self-contained interactive HTML export (drag, zoom, tooltip).
  Auto-builds from NSP mission session data. MITRE ATT&CK technique edge labels.

#### IOC Tracking
- `ioc_tracker.py`         — IOC type detection (IPv4/domain/hash/CVE/URL/email).
  OTX AlienVault enrichment. MITRE ATT&CK TTP mapping (35 techniques in library).
  Threat actor similarity scoring (APT28/29/41, Lazarus, FIN7).
  ATT&CK Navigator JSON layer export (import at navigator.mitre.org).

#### Tests
- `tests/unit/test_intelligence.py` — 28 unit tests covering all 4 intelligence modules

## [1.5.0-SPECTER] — 2025-04-13

### 📊 Sprint 7 — Reporting++ & Advanced OSINT

#### Reporting
- `executive_dashboard.py`   — C-Level HTML dashboard: risk gauge SVG, severity bars,
                               compliance posture, sparkline trend, top findings table
- `risk_matrix_generator.py` — 5×5 risk matrix HTML: heatmap zones, dot-plotted findings,
                               CVSS→coordinates mapping, interactive tooltip
- `mitre_attack_mapper.py`   — Full ATT&CK Enterprise matrix inline HTML + Navigator JSON
                               layer export; 14 tactics × technique coverage heatmap
- `compliance_reporter.py`   — Gap analysis: ISO 27001:2022 · NIS2 · SOC 2 · PCI-DSS v4 · GDPR;
                               per-control PASS/FAIL/PARTIAL with HTML report
- `trend_analyzer.py`        — Scan delta: new/resolved findings, risk score evolution,
                               sparkline data, persistent JSON store, HTML trend report

#### OSINT / Passive Recon
- `certificate_transparency.py` — crt.sh CT logs: expired certs, wildcards, shadow IT
                                   detection, SAN extraction, subdomain discovery
- `asn_mapper.py`               — ASN cartography: RIPE NCC API, all IPv4/IPv6 prefixes,
                                   total IP count, org details, multi-ASN support
- `favicon_hasher.py`           — Pure-Python MurmurHash3, Shodan favicon search,
                                   shadow asset discovery, interesting host flagging

#### Intelligence
- `false_positive_filter.py`  — Heuristic FP scoring: template FP rates, evidence
                                  confirmation, cross-tool validation, severity trust,
                                  CONFIRMED→FALSE_POSITIVE 5-tier verdict
- `attack_narrative.py`       — AI (Claude API) or template attack scenario: 5-section
                                  narrative, HTML export, word count, source tracking

#### Tests
- `tests/unit/test_sprint7.py` — 55 unit tests covering all 10 Sprint 7 modules

## [1.6.0-SPECTER] — 2025-04-13

### ⚙️ Sprint 8 — Automation, Orchestration & DevSecOps

#### Automation Engine
- `mission_scheduler.py`  — APScheduler cron/interval scheduling; preset library
                            (daily/weekly/monthly/continuous); conflict detection,
                            persistent SQLite store, enable/disable/run-now API
- `parallel_executor.py`  — Asyncio semaphore pool; configurable concurrency/rate/timeout;
                            rich live progress bar; result aggregation + SARIF export
- `asset_discovery.py`    — Continuous inventory: CT logs + DNS + Shodan + Cloud;
                            MD5-keyed persistent inventory; new asset diff detection;
                            auto-alerting on high-risk new assets
- `change_detector.py`    — Finding fingerprinting; new/resolved/worsened/improved diff;
                            risk regression detection; HTML change report export;
                            snapshot store for longitudinal comparison
- `alert_engine.py`       — Slack (attachments) + Teams (MessageCard) + SMTP HTML email
                            + generic webhook; level filtering; structured mission alerts

#### DevSecOps
- `supply_chain_audit.py` — pip-audit + npm audit + govulncheck + OSV.dev batch API;
                            multi-language SBOM (Python/Node/Go/Java/Ruby);
                            SPDX-2.3 JSON export; deduplicated vuln list
- `container_scanner.py`  — Trivy (primary) + Grype (fallback); OS + app + secrets
                            + misconfigs; risk score; multi-image batch scanning
- `iac_scanner.py`        — Checkov + tfsec + Hadolint; auto-detects Terraform/CF/K8s/
                            Dockerfile/Ansible; deduplication; SARIF-compatible output
- `secret_scanner.py`     — TruffleHog (git history) + Gitleaks + 18 built-in regex
                            patterns; FP filtering; SARIF v2.1.0 for CI/CD integration
- `cloud_posture.py`      — Prowler + ScoutSuite; CIS Benchmark; by-service breakdown;
                            compliance score; mock results when tools unavailable

#### Tests
- `tests/unit/test_sprint8.py` — 70 unit tests for all 10 Sprint 8 modules
