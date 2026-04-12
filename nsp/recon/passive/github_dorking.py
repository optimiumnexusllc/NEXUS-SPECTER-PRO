"""
NEXUS SPECTER PRO — GitHub Dorking Engine
Passive secret detection in public GitHub repositories
Finds: API keys, credentials, tokens, private keys, config files, internal URLs
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import requests, logging, time, re, os, base64
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.recon.github")

# ── Secret patterns (regex) ──────────────────────────────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key":         r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":         r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":         r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Token":     r"ya29\.[0-9A-Za-z\-_]+",
    "GitHub Token":           r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}",
    "GitHub OAuth":           r"gho_[0-9a-zA-Z]{36}",
    "Slack Token":            r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Slack Webhook":          r"https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[a-zA-Z0-9]{24}",
    "Stripe API Key":         r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Twilio API Key":         r"SK[0-9a-fA-F]{32}",
    "SendGrid API Key":       r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Mailgun API Key":        r"key-[0-9a-zA-Z]{32}",
    "Heroku API Key":         r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Private RSA Key":        r"-----BEGIN RSA PRIVATE KEY-----",
    "Private EC Key":         r"-----BEGIN EC PRIVATE KEY-----",
    "Private PGP Key":        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "SSH Private Key":        r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "JWT Token":              r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*",
    "Database URL":           r"(mysql|postgres|mongodb|redis|sqlite):\/\/[^\"'\s]+",
    "JDBC Connection":        r"jdbc:(mysql|postgresql|oracle|mssql|sqlserver):\/\/[^\"'\s]+",
    "Password in Code":       r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    "API Key Generic":        r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][^'\"]{10,}['\"]",
    "Secret Generic":         r"(?i)(secret|token)\s*[=:]\s*['\"][^'\"]{10,}['\"]",
    "Bearer Token":           r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]+=*",
    "Basic Auth":             r"(?i)basic\s+[A-Za-z0-9+/]+=*",
    "NPM Token":              r"npm_[A-Za-z0-9]{36}",
    "Anthropic API Key":      r"sk-ant-[A-Za-z0-9\-_]{95}",
    "OpenAI API Key":         r"sk-[A-Za-z0-9]{48}",
    "Shodan API Key":         r"[A-Za-z0-9]{32}(?=.*shodan)",
    "Azure Storage Key":      r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "GCP Service Account":    r'"type":\s*"service_account"',
    "Internal IP":            r"(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+",
    "Internal Hostname":      r"(?i)(internal|intra|dev|staging|prod|uat)\.[a-z0-9\-]+\.[a-z]{2,}",
}

# ── GitHub Search dorks ──────────────────────────────────────────────────────
GITHUB_DORKS = [
    '{target} password',
    '{target} api_key',
    '{target} secret',
    '{target} token',
    '{target} credentials',
    '{target} config',
    '{target} .env',
    '{target} database_url',
    '{target} private_key',
    '{target} BEGIN RSA',
    '{target} smtp password',
    '{target} ftp password',
    '{target} ssh private',
    '{target} oauth',
    '{target} aws_access_key_id',
    '{target} "internal"',
    '{target} extension:yaml password',
    '{target} extension:json secret',
    '{target} extension:env DB_PASSWORD',
    '{target} filename:config.php',
    '{target} filename:.htpasswd',
    '{target} filename:wp-config.php',
]


@dataclass
class GitHubSecret:
    secret_type:  str
    secret_value: str
    file_path:    str
    repo:         str
    repo_url:     str
    commit:       str = ""
    line_number:  int = 0
    context:      str = ""
    severity:     str = "high"


class GitHubDorker:
    """
    GitHub passive dorking engine for NEXUS SPECTER PRO.
    Searches GitHub for exposed secrets, credentials, and sensitive information
    related to the target organization/domain.
    Uses GitHub REST API with smart rate limit handling.
    """

    GITHUB_API = "https://api.github.com"
    RATE_LIMIT_DELAY = 2.0

    def __init__(
        self,
        target:     str,
        org:        str = None,
        github_token: str = None,
        max_results: int = 100,
        output_dir:  str = "/tmp/nsp_github",
    ):
        self.target      = target
        self.org         = org or target.split(".")[0]
        self.token       = github_token or os.getenv("GITHUB_TOKEN", "")
        self.max_results = max_results
        self.output_dir  = output_dir
        self.secrets     = []
        self.headers = {
            "Accept":       "application/vnd.github.v3+json",
            "User-Agent":   "NSP-SPECTER-1.0",
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"
        else:
            log.warning("[GITHUB] No GitHub token — rate limited to 10 req/min. Set GITHUB_TOKEN env var.")

    def _gh_get(self, url: str, params: dict = None) -> Optional[dict]:
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=15)
            if resp.status_code == 403:
                log.warning("[GITHUB] Rate limited — sleeping 60s")
                time.sleep(60)
                return None
            if resp.status_code == 422:
                log.debug(f"[GITHUB] Unprocessable query — skipping")
                return None
            resp.raise_for_status()
            time.sleep(self.RATE_LIMIT_DELAY)
            return resp.json()
        except Exception as e:
            log.debug(f"[GITHUB] Request error: {e}")
            return None

    def search_code(self, query: str) -> list:
        """Search GitHub code for a given query."""
        url    = f"{self.GITHUB_API}/search/code"
        params = {"q": query, "per_page": 30}
        data   = self._gh_get(url, params)
        if not data:
            return []
        return data.get("items", [])

    def _decode_file_content(self, content_url: str) -> str:
        """Fetch and decode a file's content from GitHub API."""
        data = self._gh_get(content_url)
        if not data or "content" not in data:
            return ""
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _scan_content_for_secrets(self, content: str, file_path: str, repo: str, repo_url: str) -> list:
        """Scan file content for secret patterns."""
        found = []
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for secret_type, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, line)
                for match in matches:
                    val = match if isinstance(match, str) else match[0]
                    # Skip obvious false positives
                    if val in ("", "your_key_here", "xxxxxxxxxxxx", "XXXX", "example"):
                        continue
                    if len(val) < 8:
                        continue
                    found.append(GitHubSecret(
                        secret_type=secret_type,
                        secret_value=val[:60] + ("..." if len(val) > 60 else ""),
                        file_path=file_path,
                        repo=repo,
                        repo_url=repo_url,
                        line_number=i,
                        context=line.strip()[:120],
                        severity="critical" if any(k in secret_type.lower()
                                    for k in ["private key", "aws secret", "database"]) else "high",
                    ))
        return found

    def search_org_repos(self) -> list:
        """List all public repositories for the target organization."""
        console.print(f"[#00FFD4]  [GITHUB] Searching org repos: {self.org}[/#00FFD4]")
        url  = f"{self.GITHUB_API}/orgs/{self.org}/repos"
        data = self._gh_get(url, {"per_page": 100, "type": "public"})
        if isinstance(data, list):
            return data
        url2 = f"{self.GITHUB_API}/users/{self.org}/repos"
        data2 = self._gh_get(url2, {"per_page": 100})
        return data2 if isinstance(data2, list) else []

    def dork_search(self) -> list:
        """Run all GitHub dorks and scan results for secrets."""
        all_secrets = []
        console.print(f"[bold #7B00FF]  🐙 GitHub Dorking — target: {self.target} | org: {self.org}[/bold #7B00FF]")

        dorks_to_run = GITHUB_DORKS[:12] if not self.token else GITHUB_DORKS

        for dork_template in dorks_to_run:
            query = dork_template.format(target=self.target)
            console.print(f"[#00FFD4]  → Dork: {query[:60]}[/#00FFD4]")
            items = self.search_code(query)

            for item in items[:5]:
                file_path    = item.get("path", "")
                repo         = item.get("repository", {}).get("full_name", "")
                repo_url     = item.get("repository", {}).get("html_url", "")
                content_url  = item.get("url", "")

                content = self._decode_file_content(content_url)
                if content:
                    secrets = self._scan_content_for_secrets(content, file_path, repo, repo_url)
                    if secrets:
                        all_secrets.extend(secrets)
                        for s in secrets:
                            console.print(
                                f"  [bold #FF003C]⚡ {s.secret_type}[/bold #FF003C] "
                                f"in [#00FFD4]{repo}/{s.file_path}[/#00FFD4] "
                                f"(line {s.line_number})"
                            )

        self.secrets = all_secrets
        return all_secrets

    def scan_repo_files(self, repo_full_name: str) -> list:
        """Directly scan all files in a specific repository."""
        console.print(f"[#00FFD4]  [GITHUB] Scanning repo: {repo_full_name}[/#00FFD4]")
        url  = f"{self.GITHUB_API}/repos/{repo_full_name}/git/trees/HEAD"
        data = self._gh_get(url, {"recursive": 1})
        if not data:
            return []

        all_secrets = []
        sensitive_files = [
            ".env", "config.php", "wp-config.php", "settings.py", "database.yml",
            "credentials.json", "secrets.yaml", "key.pem", "id_rsa", ".htpasswd",
            "application.properties", "appsettings.json", "web.config",
        ]

        for tree_item in (data.get("tree") or []):
            fname = tree_item.get("path", "")
            if any(fname.endswith(sf) or sf in fname for sf in sensitive_files):
                content_url = f"{self.GITHUB_API}/repos/{repo_full_name}/contents/{fname}"
                content     = self._decode_file_content(content_url)
                if content:
                    secrets = self._scan_content_for_secrets(
                        content, fname, repo_full_name,
                        f"https://github.com/{repo_full_name}"
                    )
                    all_secrets.extend(secrets)
        return all_secrets

    def _print_results(self, secrets: list):
        if not secrets:
            console.print("[bold #00FFD4]  ✅ No secrets found in public GitHub repositories.[/bold #00FFD4]")
            return

        table = Table(
            title=f"[bold #7B00FF]🐙 GITHUB SECRETS FOUND — {len(secrets)}[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4", show_lines=True
        )
        table.add_column("Type",     style="#FF003C", width=22)
        table.add_column("Value",    style="white",   width=35)
        table.add_column("Repo",     style="#00FFD4", width=30)
        table.add_column("File",     style="#888",    width=25)
        table.add_column("Line",     style="#555",    width=6,  justify="right")
        table.add_column("Severity", width=10)

        sev_color = {"critical": "[bold #FF003C]", "high": "[bold #FF8C00]", "medium": "[bold #FFD700]"}
        for s in sorted(secrets, key=lambda x: x.severity):
            sc = sev_color.get(s.severity, "[white]")
            ec = sc.replace("[", "[/")
            table.add_row(
                s.secret_type[:22],
                s.secret_value[:35],
                s.repo[:30],
                s.file_path[-25:],
                str(s.line_number),
                f"{sc}{s.severity.upper()}{ec}",
            )
        console.print(table)

    def run(self) -> dict:
        """Full GitHub dorking run."""
        secrets = self.dork_search()

        # Also scan org repos directly
        repos = self.search_org_repos()
        console.print(f"[#00FFD4]  [GITHUB] Found {len(repos)} public repos for org: {self.org}[/#00FFD4]")
        for repo in repos[:5]:
            repo_name = repo.get("full_name", "")
            if repo_name:
                repo_secrets = self.scan_repo_files(repo_name)
                secrets.extend(repo_secrets)

        # Deduplicate
        seen = set()
        unique = []
        for s in secrets:
            key = f"{s.secret_type}:{s.secret_value[:20]}:{s.repo}"
            if key not in seen:
                seen.add(key)
                unique.append(s)

        self._print_results(unique)
        console.print(f"[bold #00FFD4]  ✅ GitHub dorking complete — {len(unique)} unique secrets found[/bold #00FFD4]")

        return {
            "target":        self.target,
            "org":           self.org,
            "total_secrets": len(unique),
            "secrets": [
                {
                    "type":      s.secret_type,
                    "value":     s.secret_value,
                    "repo":      s.repo,
                    "repo_url":  s.repo_url,
                    "file":      s.file_path,
                    "line":      s.line_number,
                    "severity":  s.severity,
                    "context":   s.context,
                }
                for s in unique
            ],
            "repos_scanned": [r.get("full_name","") for r in repos],
        }
