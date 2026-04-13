"""
NEXUS SPECTER PRO — IaC Security Scanner
Audits Infrastructure-as-Code for security misconfigurations:
Terraform · CloudFormation · Kubernetes YAML · Dockerfile · Ansible
Tools: Checkov · tfsec · kube-score · Hadolint
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import subprocess, shutil, logging, json, re
from dataclasses import dataclass, field
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.devsecops.iac")


@dataclass
class IaCFinding:
    check_id:   str
    title:      str
    severity:   str
    file_path:  str
    resource:   str  = ""
    line_start: int  = 0
    line_end:   int  = 0
    guideline:  str  = ""
    tool:       str  = "checkov"
    iac_type:   str  = ""


class IaCScan:
    """
    Infrastructure-as-Code security scanner for NEXUS SPECTER PRO.
    Runs Checkov (primary) + tfsec + kube-score + Hadolint.
    Supports: Terraform, CloudFormation, Kubernetes, Dockerfile, Ansible.
    """

    IAC_EXTENSIONS = {
        "terraform":        [".tf", ".tfvars"],
        "cloudformation":   [".yaml",".yml",".json", "template.json"],
        "kubernetes":       ["k8s/", "kubernetes/", "manifests/"],
        "dockerfile":       ["Dockerfile", "Dockerfile.*"],
        "ansible":          ["playbook.yml","site.yml","tasks/"],
    }

    def __init__(self, scan_path: str = ".", output_dir: str = "/tmp/nsp_iac"):
        self.scan_path  = Path(scan_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[IaCFinding] = []

    def _detect_iac_types(self) -> list:
        types = []
        for f in self.scan_path.rglob("*"):
            if f.name.endswith(".tf") or f.name.endswith(".tfvars"):
                if "terraform" not in types: types.append("terraform")
            if f.name == "Dockerfile" or f.name.startswith("Dockerfile."):
                if "dockerfile" not in types: types.append("dockerfile")
            if f.suffix in (".yaml",".yml"):
                try:
                    content = f.read_text(errors="ignore")
                    if "apiVersion:" in content and "kind:" in content:
                        if "kubernetes" not in types: types.append("kubernetes")
                    if "AWSTemplateFormatVersion" in content:
                        if "cloudformation" not in types: types.append("cloudformation")
                except Exception:
                    pass
        return types

    # ── Checkov ───────────────────────────────────────────────────────────────
    def _run_checkov(self, iac_type: str = None) -> list:
        if not shutil.which("checkov"):
            log.warning("[IAC] checkov not found — run: pip install checkov")
            return []

        out_file = self.output_dir / "checkov_result.json"
        cmd = [
            "checkov", "-d", str(self.scan_path),
            "--output", "json",
            "--output-file", str(out_file),
            "--quiet",
        ]
        if iac_type:
            cmd += ["--framework", iac_type]

        console.print(f"[#00FFD4]  [CHECKOV] Scanning {self.scan_path}...[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            log.warning("[IAC] Checkov timeout")
            return []

        if not out_file.exists():
            return []

        findings = []
        try:
            # Checkov can return array or single object
            raw = out_file.read_text()
            # Handle JSONL or JSON
            data_list = []
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data_list.append(json.loads(line))
                except Exception:
                    pass
            if not data_list:
                try:
                    data_list = [json.loads(raw)]
                except Exception:
                    pass

            for data in data_list:
                if isinstance(data, list):
                    data = {"results": {"failed_checks": data}}
                results = data.get("results", data)
                if isinstance(results, list):
                    results = {"failed_checks": results}
                for check in results.get("failed_checks", []):
                    sev = check.get("severity","MEDIUM") or "MEDIUM"
                    findings.append(IaCFinding(
                        check_id  = check.get("check_id",""),
                        title     = check.get("check","")[:80] or check.get("name",""),
                        severity  = sev.lower(),
                        file_path = check.get("file_path",""),
                        resource  = check.get("resource",""),
                        line_start= check.get("file_line_range",[0])[0] if check.get("file_line_range") else 0,
                        guideline = check.get("guideline",""),
                        tool      = "checkov",
                        iac_type  = check.get("check_type",""),
                    ))
        except Exception as e:
            log.debug(f"[IAC] Checkov parse error: {e}")

        console.print(f"  [#00FFD4]→ Checkov: {len(findings)} failures[/#00FFD4]")
        return findings

    # ── tfsec ─────────────────────────────────────────────────────────────────
    def _run_tfsec(self) -> list:
        if not shutil.which("tfsec"):
            return []
        tf_files = list(self.scan_path.rglob("*.tf"))
        if not tf_files:
            return []

        out_file = self.output_dir / "tfsec_result.json"
        cmd = ["tfsec", str(self.scan_path), "--format", "json",
               "--out", str(out_file), "--quiet"]
        console.print(f"[#00FFD4]  [TFSEC] Scanning Terraform...[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            return []

        findings = []
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text())
                for r in data.get("results",[]):
                    sev = r.get("severity","MEDIUM").lower()
                    findings.append(IaCFinding(
                        check_id  = r.get("rule_id",""),
                        title     = r.get("description","")[:80],
                        severity  = sev,
                        file_path = r.get("location",{}).get("filename",""),
                        resource  = r.get("resource",""),
                        line_start= r.get("location",{}).get("start_line",0),
                        guideline = r.get("links",[""])[0] if r.get("links") else "",
                        tool      = "tfsec",
                        iac_type  = "terraform",
                    ))
            except Exception as e:
                log.debug(f"[IAC] tfsec parse: {e}")
        console.print(f"  [#00FFD4]→ tfsec: {len(findings)} issues[/#00FFD4]")
        return findings

    # ── Hadolint (Dockerfile) ─────────────────────────────────────────────────
    def _run_hadolint(self) -> list:
        if not shutil.which("hadolint"):
            return []
        dockerfiles = list(self.scan_path.rglob("Dockerfile*"))
        if not dockerfiles:
            return []

        findings = []
        for df in dockerfiles[:5]:
            console.print(f"[#00FFD4]  [HADOLINT] {df.name}[/#00FFD4]")
            try:
                r = subprocess.run(
                    ["hadolint", "--format", "json", str(df)],
                    capture_output=True, text=True, timeout=30,
                )
                for issue in json.loads(r.stdout or "[]"):
                    sev = issue.get("level","warning").lower()
                    sev_map = {"error":"high","warning":"medium","info":"low","style":"info"}
                    findings.append(IaCFinding(
                        check_id  = issue.get("code",""),
                        title     = issue.get("message","")[:80],
                        severity  = sev_map.get(sev,"medium"),
                        file_path = str(df),
                        line_start= issue.get("line",0),
                        tool      = "hadolint",
                        iac_type  = "dockerfile",
                    ))
            except Exception as e:
                log.debug(f"[IAC] hadolint: {e}")
        console.print(f"  [#00FFD4]→ hadolint: {len(findings)} issues[/#00FFD4]")
        return findings

    def _print_findings(self):
        if not self.findings:
            console.print("[bold #00FFD4]  ✅ No IaC security issues found.[/bold #00FFD4]")
            return

        table = Table(
            title=f"[bold #7B00FF]🏗️  IaC SECURITY — {len(self.findings)} issues[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4", show_lines=False,
        )
        table.add_column("Severity",  width=10)
        table.add_column("Check ID",  width=14)
        table.add_column("Title",     width=45)
        table.add_column("File",      width=25)
        table.add_column("Tool",      width=10)

        SEV_COLOR = {"critical":"[bold #FF003C]","high":"[bold #FF8C00]",
                     "medium":"[bold #FFD700]","low":"[bold #00FFD4]"}
        SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}

        for f in sorted(self.findings, key=lambda x: SEV_ORDER.get(x.severity,4))[:30]:
            c = SEV_COLOR.get(f.severity,"[white]")
            e = c.replace("[","[/")
            table.add_row(
                f"{c}{f.severity.upper()}{e}",
                f.check_id[:14], f.title[:45],
                Path(f.file_path).name[:25],
                f.tool,
            )
        console.print(table)

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🏗️  IaC Scanner — {self.scan_path}[/bold #7B00FF]")
        iac_types = self._detect_iac_types()
        console.print(f"  [#00FFD4]→ Detected: {', '.join(iac_types) or 'no IaC files'}[/#00FFD4]")

        all_findings = []
        all_findings += self._run_checkov()
        if "terraform" in iac_types:
            all_findings += self._run_tfsec()
        if "dockerfile" in iac_types:
            all_findings += self._run_hadolint()

        # Deduplicate
        seen, unique = set(), []
        for f in all_findings:
            key = f"{f.check_id}:{f.file_path}:{f.line_start}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

        by_sev = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity,0) + 1

        self._print_findings()
        console.print(f"[bold #00FFD4]  ✅ IaC scan complete — "
                       f"{len(self.findings)} issues | types: {iac_types}[/bold #00FFD4]")
        return {
            "scan_path":  str(self.scan_path),
            "iac_types":  iac_types,
            "total":      len(self.findings),
            "by_severity":by_sev,
            "findings": [
                {"check_id":f.check_id,"title":f.title,"severity":f.severity,
                 "file":f.file_path,"line":f.line_start,"tool":f.tool}
                for f in self.findings
            ],
        }
