"""
NEXUS SPECTER PRO — Cloud Security Posture Manager (CSPM)
Orchestrates Prowler + ScoutSuite for comprehensive cloud security assessment.
Frameworks: CIS AWS/Azure/GCP Benchmarks · AWS Security Hub · GDPR · SOC 2
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import subprocess, shutil, logging, json, os
from dataclasses import dataclass, field
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.devsecops.cloud_posture")


@dataclass
class CloudControl:
    control_id:   str
    title:        str
    status:       str    # PASS | FAIL | WARNING | INFO
    severity:     str
    service:      str    = ""
    resource:     str    = ""
    region:       str    = ""
    remediation:  str    = ""
    framework:    str    = ""
    tool:         str    = "prowler"


@dataclass
class PostureReport:
    provider:        str
    account_id:      str   = ""
    region:          str   = ""
    total_checks:    int   = 0
    passed:          int   = 0
    failed:          int   = 0
    warnings:        int   = 0
    compliance_score:float = 0.0
    by_severity:     dict  = field(default_factory=dict)
    by_service:      dict  = field(default_factory=dict)
    critical_fails:  list  = field(default_factory=list)
    controls:        list  = field(default_factory=list)


class CloudPosture:
    """
    Cloud Security Posture Manager for NEXUS SPECTER PRO.
    Runs Prowler (primary) + ScoutSuite (secondary) for:
    - CIS Benchmark compliance checks
    - Identity & Access Management audit
    - Encryption & key management review
    - Network security group analysis
    - Logging & monitoring gaps
    - Public exposure detection
    """

    PROWLER_SERVICES = {
        "aws":   ["iam","s3","ec2","vpc","cloudtrail","guardduty","kms",
                  "config","lambda","rds","elbv2","cloudwatch","sns","sqs"],
        "azure": ["iam","storage","network","compute","database","monitor","keyvault"],
        "gcp":   ["iam","gcs","compute","bigquery","logging","monitoring","kms"],
    }

    def __init__(self, provider: str = "aws",
                 profile: str = "default",
                 region:  str = "us-east-1",
                 output_dir: str = "/tmp/nsp_posture"):
        self.provider   = provider.lower()
        self.profile    = profile
        self.region     = region
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Prowler ───────────────────────────────────────────────────────────────
    def _run_prowler(self, services: list = None,
                     framework: str = "cis_level2_aws") -> list:
        if not shutil.which("prowler"):
            log.warning("[CSPM] prowler not found — install: pip install prowler")
            return self._mock_prowler_results()

        svc_list = services or self.PROWLER_SERVICES.get(self.provider, [])
        out_dir  = self.output_dir / "prowler"
        out_dir.mkdir(exist_ok=True)

        cmd = [
            "prowler", self.provider,
            "--output-formats", "json",
            "--output-directory", str(out_dir),
            "--quiet",
            "--compliance",    framework,
            "--services",      ",".join(svc_list[:8]),
        ]
        if self.provider == "aws":
            cmd += ["--profile", self.profile, "--region", self.region]

        console.print(f"[#00FFD4]  [PROWLER] {self.provider.upper()} audit — "
                       f"framework: {framework}[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=1800)
        except subprocess.TimeoutExpired:
            log.warning("[CSPM] Prowler timeout after 30 min")
        except Exception as e:
            log.error(f"[CSPM] Prowler error: {e}")

        return self._parse_prowler_output(out_dir)

    def _parse_prowler_output(self, out_dir: Path) -> list:
        controls = []
        for json_file in out_dir.rglob("*.json"):
            try:
                data = json.loads(json_file.read_text())
                items = data if isinstance(data, list) else data.get("findings",[])
                for item in items:
                    status_raw = item.get("Status","") or item.get("status","")
                    status     = status_raw.upper() if status_raw else "INFO"
                    sev        = (item.get("Severity","") or
                                  item.get("severity","") or "medium").lower()
                    controls.append(CloudControl(
                        control_id  = item.get("CheckID","") or item.get("check_id",""),
                        title       = item.get("CheckTitle","") or item.get("check_title","")[:80],
                        status      = status,
                        severity    = sev,
                        service     = item.get("ServiceName","") or item.get("service",""),
                        resource    = str(item.get("ResourceArn","") or item.get("resource_id",""))[:60],
                        region      = item.get("Region","") or self.region,
                        remediation = (item.get("Remediation",{}) or {}).get("Recommendation","")[:150]
                                      if isinstance(item.get("Remediation"),dict)
                                      else str(item.get("Remediation",""))[:150],
                        framework   = item.get("Compliance",{}).get("Framework",""),
                        tool        = "prowler",
                    ))
            except Exception as e:
                log.debug(f"[CSPM] Prowler parse {json_file}: {e}")
        return controls

    def _mock_prowler_results(self) -> list:
        """Demo results when Prowler is not installed."""
        mock_checks = [
            ("IAM_ROOT_ACCESS_KEY",   "Root account access key exists",           "FAIL","critical","iam"),
            ("IAM_MFA_ENABLED",       "MFA not enabled for IAM users",             "FAIL","high",    "iam"),
            ("S3_BUCKET_PUBLIC_ACL",  "S3 bucket has public ACL",                 "FAIL","critical","s3"),
            ("CLOUDTRAIL_ENABLED",    "CloudTrail enabled in all regions",         "PASS","medium",  "cloudtrail"),
            ("VPC_FLOW_LOGS",         "VPC flow logging enabled",                  "FAIL","medium",  "vpc"),
            ("RDS_ENCRYPTION",        "RDS instances encrypted at rest",           "PASS","high",    "rds"),
            ("KMS_CMK_ROTATION",      "KMS CMK rotation enabled",                 "FAIL","medium",  "kms"),
            ("GUARDDUTY_ENABLED",     "GuardDuty enabled",                        "FAIL","high",    "guardduty"),
            ("EC2_EBS_DEFAULT_ENCRYPTION","EBS default encryption enabled",        "PASS","medium",  "ec2"),
            ("IAM_PASSWORD_POLICY",   "IAM password policy meets requirements",    "FAIL","medium",  "iam"),
        ]
        return [
            CloudControl(control_id=cid, title=title, status=status,
                          severity=sev, service=svc, tool="prowler-mock")
            for cid, title, status, sev, svc in mock_checks
        ]

    # ── ScoutSuite ────────────────────────────────────────────────────────────
    def _run_scoutsuite(self) -> list:
        if not shutil.which("scout"):
            log.info("[CSPM] ScoutSuite not found — skipping secondary scan")
            return []

        out_dir  = self.output_dir / "scoutsuite"
        out_dir.mkdir(exist_ok=True)
        cmd = ["scout", self.provider, "--report-dir", str(out_dir),
               "--no-browser", "--quiet"]
        if self.provider == "aws":
            cmd += ["--profile", self.profile]

        console.print(f"[#00FFD4]  [SCOUTSUITE] {self.provider.upper()} audit...[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=1800)
        except Exception as e:
            log.debug(f"[CSPM] ScoutSuite: {e}")
        return []   # ScoutSuite generates HTML report directly

    def _aggregate(self, controls: list) -> PostureReport:
        report = PostureReport(
            provider    = self.provider,
            region      = self.region,
            total_checks= len(controls),
        )
        for c in controls:
            if c.status   == "PASS":    report.passed   += 1
            elif c.status == "FAIL":    report.failed   += 1
            elif c.status == "WARNING": report.warnings += 1
            report.by_severity[c.severity] = report.by_severity.get(c.severity,0) + 1
            report.by_service[c.service]   = report.by_service.get(c.service,0) + 1
            if c.status == "FAIL" and c.severity in ("critical","high"):
                report.critical_fails.append({
                    "id":          c.control_id,
                    "title":       c.title,
                    "severity":    c.severity,
                    "service":     c.service,
                    "resource":    c.resource,
                    "remediation": c.remediation,
                })
        total = max(len(controls), 1)
        report.compliance_score = round(report.passed / total * 100, 1)
        report.controls = [c.__dict__ for c in controls]
        return report

    def _print_report(self, report: PostureReport):
        sc_color = ("#FF003C" if report.compliance_score < 50
                    else "#FFD700" if report.compliance_score < 75 else "#00FFD4")
        console.print(
            f"\n  [bold #7B00FF]Cloud: {report.provider.upper()}[/bold #7B00FF] | "
            f"Score: [bold {sc_color}]{report.compliance_score}%[/bold {sc_color}] | "
            f"Checks: {report.total_checks} | "
            f"[bold #FF003C]Failed: {report.failed}[/bold #FF003C]"
        )

        table = Table(
            title="[bold #7B00FF]☁️  CLOUD POSTURE — Critical Failures[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Severity",    width=10)
        table.add_column("Service",     width=12)
        table.add_column("Control",     width=45)
        table.add_column("Resource",    width=30)

        SEV_COLOR = {"critical":"[bold #FF003C]","high":"[bold #FF8C00]",
                     "medium":"[bold #FFD700]"}
        for f in report.critical_fails[:15]:
            c = SEV_COLOR.get(f.get("severity",""), "[white]")
            e = c.replace("[","[/")
            table.add_row(
                f"{c}{f.get('severity','').upper()}{e}",
                f.get("service","")[:12],
                f.get("title","")[:45],
                f.get("resource","")[:30],
            )
        if report.critical_fails:
            console.print(table)

        # By service breakdown
        svc_table = Table(
            title="By Service", border_style="#1E1E1E", header_style="bold #555",
        )
        svc_table.add_column("Service", style="#00FFD4", width=15)
        svc_table.add_column("Issues",  width=8, justify="right")
        for svc, count in sorted(report.by_service.items(), key=lambda x:-x[1])[:8]:
            svc_table.add_row(svc, str(count))
        console.print(svc_table)

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  ☁️  Cloud Posture Manager — "
                       f"{self.provider.upper()} | {self.region}[/bold #7B00FF]")

        controls = self._run_prowler()
        self._run_scoutsuite()

        report = self._aggregate(controls)
        self._print_report(report)

        # Export JSON
        out = self.output_dir / f"posture_{self.provider}.json"
        out.write_text(json.dumps(report.__dict__, indent=2, default=str))

        console.print(f"[bold #00FFD4]  ✅ Cloud posture complete — "
                       f"score: {report.compliance_score}% | "
                       f"{report.failed} failures | "
                       f"{len(report.critical_fails)} critical[/bold #00FFD4]")
        return {
            "provider":         report.provider,
            "compliance_score": report.compliance_score,
            "total_checks":     report.total_checks,
            "passed":           report.passed,
            "failed":           report.failed,
            "critical_fails":   len(report.critical_fails),
            "by_severity":      report.by_severity,
            "by_service":       report.by_service,
            "json_report":      str(out),
        }
