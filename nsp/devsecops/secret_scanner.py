"""
NEXUS SPECTER PRO — Secret Scanner
Detects secrets, credentials, and sensitive data in source code and git history.
Tools: TruffleHog · Gitleaks · detect-secrets (Python)
Integrates with CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins).
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import subprocess, shutil, logging, json, re
from dataclasses import dataclass, field
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.devsecops.secrets")


# ── Built-in regex patterns (supplement external tools) ───────────────────────
BUILTIN_PATTERNS = {
    "AWS Access Key":         r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":         r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Anthropic API Key":      r"sk-ant-[A-Za-z0-9\-_]{95}",
    "OpenAI API Key":         r"sk-[A-Za-z0-9]{48}",
    "GitHub Token":           r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}",
    "Slack Token":            r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe Secret Key":      r"sk_live_[0-9a-zA-Z]{24}",
    "Google API Key":         r"AIza[0-9A-Za-z\-_]{35}",
    "Private RSA Key":        r"-----BEGIN RSA PRIVATE KEY-----",
    "Private EC Key":         r"-----BEGIN EC PRIVATE KEY-----",
    "SSH Private Key":        r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "JWT Token":              r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+",
    "Database URL":           r"(mysql|postgres|mongodb|redis):\/\/[^\"'\s]{8,}",
    "Password in Code":       r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "Generic Secret":         r"(?i)(secret|api_key|token)\s*[:=]\s*['\"][^'\"]{10,}['\"]",
    "Azure Storage Key":      r"DefaultEndpointsProtocol=https;AccountName=",
    "Hardcoded IP+Port":      r"(?<!\.)\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b",
}

# Files to skip (binaries, generated, etc.)
SKIP_EXTENSIONS = {
    ".png",".jpg",".jpeg",".gif",".ico",".svg",".pdf",".zip",".tar",".gz",
    ".pyc",".pyo",".class",".jar",".war",".exe",".dll",".so",".dylib",
    ".lock","package-lock.json","yarn.lock","Pipfile.lock",
}


@dataclass
class SecretFinding:
    secret_type:  str
    file_path:    str
    line_number:  int   = 0
    commit:       str   = ""
    author:       str   = ""
    redacted_val: str   = ""
    severity:     str   = "high"
    tool:         str   = "builtin"
    context:      str   = ""


class SecretScanner:
    """
    Secret detection engine for NEXUS SPECTER PRO.
    Scans: file system, git history, environment files.
    Primary tools: TruffleHog (git history) + Gitleaks (repo) + built-in regex.
    CI/CD integration: generates SARIF output for GitHub/GitLab.
    """

    def __init__(self, scan_path: str = ".",
                 output_dir: str = "/tmp/nsp_secrets",
                 scan_git_history: bool = True):
        self.scan_path        = Path(scan_path)
        self.output_dir       = Path(output_dir)
        self.scan_git_history = scan_git_history
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[SecretFinding] = []

    def _is_git_repo(self) -> bool:
        return (self.scan_path / ".git").exists()

    # ── TruffleHog ────────────────────────────────────────────────────────────
    def _run_trufflehog(self) -> list:
        if not shutil.which("trufflehog"):
            log.warning("[SECRETS] trufflehog not found — "
                        "install: pip install trufflehog3")
            return []
        findings = []
        out_file = self.output_dir / "trufflehog_results.json"

        if self._is_git_repo() and self.scan_git_history:
            cmd = ["trufflehog", "git",
                   f"file://{self.scan_path}",
                   "--json", "--no-update"]
        else:
            cmd = ["trufflehog", "filesystem",
                   str(self.scan_path), "--json", "--no-update"]

        console.print("[#00FFD4]  [TRUFFLEHOG] Scanning for secrets...[/#00FFD4]")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            for line in r.stdout.splitlines():
                try:
                    data = json.loads(line)
                    det  = data.get("SourceMetadata",{}).get("Data",{})
                    file_info = (det.get("Filesystem",{}) or
                                 det.get("Git",{}))
                    findings.append(SecretFinding(
                        secret_type = data.get("DetectorName","Unknown"),
                        file_path   = file_info.get("file","") or file_info.get("filename",""),
                        line_number = file_info.get("line",0),
                        commit      = file_info.get("commit",""),
                        author      = file_info.get("email",""),
                        redacted_val= data.get("Redacted","")[:40],
                        severity    = "critical",
                        tool        = "trufflehog",
                    ))
                except Exception:
                    pass
        except subprocess.TimeoutExpired:
            log.warning("[SECRETS] TruffleHog timeout")
        except Exception as e:
            log.debug(f"[SECRETS] TruffleHog: {e}")

        console.print(f"  [#00FFD4]→ TruffleHog: {len(findings)} secrets[/#00FFD4]")
        return findings

    # ── Gitleaks ──────────────────────────────────────────────────────────────
    def _run_gitleaks(self) -> list:
        if not shutil.which("gitleaks"):
            return []
        out_file = self.output_dir / "gitleaks_results.json"
        cmd = [
            "gitleaks", "detect",
            "--source", str(self.scan_path),
            "--report-format", "json",
            "--report-path",   str(out_file),
            "--no-banner",
        ]
        if not self._is_git_repo():
            cmd += ["--no-git"]

        console.print("[#00FFD4]  [GITLEAKS] Scanning...[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            return []
        except Exception as e:
            log.debug(f"[SECRETS] Gitleaks: {e}")
            return []

        findings = []
        if out_file.exists() and out_file.stat().st_size > 2:
            try:
                data = json.loads(out_file.read_text())
                for item in (data if isinstance(data,list) else []):
                    findings.append(SecretFinding(
                        secret_type = item.get("RuleID",""),
                        file_path   = item.get("File",""),
                        line_number = item.get("StartLine",0),
                        commit      = item.get("Commit",""),
                        author      = item.get("Author",""),
                        redacted_val= item.get("Secret","")[:20] + "...",
                        context     = item.get("Match","")[:80],
                        severity    = "high",
                        tool        = "gitleaks",
                    ))
            except Exception as e:
                log.debug(f"[SECRETS] Gitleaks parse: {e}")
        console.print(f"  [#00FFD4]→ Gitleaks: {len(findings)} secrets[/#00FFD4]")
        return findings

    # ── Built-in regex scanner ────────────────────────────────────────────────
    def _run_builtin(self) -> list:
        console.print("[#00FFD4]  [BUILTIN] Regex secret scan...[/#00FFD4]")
        findings = []
        for path in self.scan_path.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if any(skip in str(path) for skip in [".git","node_modules","__pycache__",".venv"]):
                continue
            try:
                content = path.read_text(errors="ignore")
                lines   = content.splitlines()
                for i, line in enumerate(lines, 1):
                    for secret_type, pattern in BUILTIN_PATTERNS.items():
                        matches = re.findall(pattern, line)
                        for match in matches:
                            val = match if isinstance(match,str) else match[0]
                            if len(val) < 8:
                                continue
                            # Skip obvious false positives
                            if any(fp in val.lower() for fp in
                                   ["example","test","placeholder","your_","xxxx","XXXX"]):
                                continue
                            findings.append(SecretFinding(
                                secret_type = secret_type,
                                file_path   = str(path.relative_to(self.scan_path)),
                                line_number = i,
                                redacted_val= val[:8] + "***" + val[-4:] if len(val)>12 else "***",
                                context     = line.strip()[:80],
                                severity    = ("critical" if "key" in secret_type.lower()
                                               or "rsa" in secret_type.lower()
                                               else "high"),
                                tool        = "builtin",
                            ))
            except Exception:
                pass
        console.print(f"  [#00FFD4]→ Builtin: {len(findings)} potential secrets[/#00FFD4]")
        return findings

    def _export_sarif(self) -> Path:
        """Export findings as SARIF v2.1.0 for CI/CD integration."""
        rules = [{"id":f.secret_type,"name":f.secret_type,
                  "shortDescription":{"text":f.secret_type}}
                 for f in self.findings]
        results = []
        for f in self.findings:
            results.append({
                "ruleId":  f.secret_type,
                "level":   "error" if f.severity=="critical" else "warning",
                "message": {"text": f"{f.secret_type} detected"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation":{"uri": f.file_path},
                        "region":{"startLine": f.line_number or 1},
                    }
                }],
            })
        sarif = {
            "$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version":"2.1.0",
            "runs": [{
                "tool":{"driver":{"name":"NEXUS SPECTER PRO — Secret Scanner",
                                   "version":"1.0","rules":rules}},
                "results": results,
            }],
        }
        out = self.output_dir / "secrets_sarif.json"
        out.write_text(json.dumps(sarif, indent=2))
        return out

    def _print_findings(self):
        if not self.findings:
            console.print("[bold #00FFD4]  ✅ No secrets detected.[/bold #00FFD4]")
            return
        table = Table(
            title=f"[bold #FF003C]🔑 SECRETS FOUND — {len(self.findings)}[/bold #FF003C]",
            border_style="#FF003C", header_style="bold #00FFD4", show_lines=True,
        )
        table.add_column("Type",     width=22)
        table.add_column("File",     width=30)
        table.add_column("Line",     width=6, justify="right")
        table.add_column("Severity", width=10)
        table.add_column("Tool",     width=12)
        table.add_column("Preview",  width=22)

        SEV_COLOR = {"critical":"[bold #FF003C]","high":"[bold #FF8C00]"}
        for f in self.findings[:25]:
            c = SEV_COLOR.get(f.severity,"[white]")
            e = c.replace("[","[/")
            table.add_row(
                f.secret_type[:22],
                Path(f.file_path).name[:30],
                str(f.line_number),
                f"{c}{f.severity.upper()}{e}",
                f.tool,
                f.redacted_val[:22],
            )
        console.print(table)

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🔑 Secret Scanner — {self.scan_path}[/bold #7B00FF]")
        all_findings = []
        all_findings += self._run_trufflehog()
        all_findings += self._run_gitleaks()
        all_findings += self._run_builtin()

        # Deduplicate
        seen, unique = set(), []
        for f in all_findings:
            key = f"{f.secret_type}:{f.file_path}:{f.line_number}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

        sarif_path = self._export_sarif()
        self._print_findings()

        crit_c = sum(1 for f in self.findings if f.severity=="critical")
        console.print(f"[bold #00FFD4]  ✅ Secret scan complete — "
                       f"{len(self.findings)} secrets | {crit_c} critical | "
                       f"SARIF: {sarif_path}[/bold #00FFD4]")
        return {
            "scan_path":    str(self.scan_path),
            "total_secrets":len(self.findings),
            "critical":     crit_c,
            "sarif_path":   str(sarif_path),
            "findings": [
                {"type":f.secret_type,"file":f.file_path,"line":f.line_number,
                 "severity":f.severity,"tool":f.tool,"commit":f.commit}
                for f in self.findings
            ],
        }
