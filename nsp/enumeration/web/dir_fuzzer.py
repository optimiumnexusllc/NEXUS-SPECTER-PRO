"""
NEXUS SPECTER PRO — Directory Fuzzer
Orchestrates ffuf + Gobuster + feroxbuster for web content discovery.
Auto-selects best tool, manages wordlists, filters noise, and ranks findings.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import subprocess, shutil, logging, json, re
from pathlib import Path
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.enum.dir_fuzzer")


@dataclass
class FuzzResult:
    url:         str
    status_code: int
    size:        int
    words:       int = 0
    lines:       int = 0
    redirect_to: str = ""
    content_type:str = ""
    interesting: bool = False
    severity:    str = "info"


class DirFuzzer:
    """
    Multi-tool web directory & file fuzzer for NEXUS SPECTER PRO.
    Tool priority: ffuf (fastest) → feroxbuster → gobuster
    Features: smart filtering, extension fuzzing, vhost discovery, auto-calibration.
    """

    WORDLISTS = {
        "quick":   "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "medium":  "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
        "large":   "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
        "api":     "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "backup":  "/usr/share/seclists/Discovery/Web-Content/raft-medium-extensions.txt",
        "dirs":    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        # Fallback small built-in wordlist
        "builtin": None,
    }

    # Built-in minimal wordlist (fallback if seclists not installed)
    BUILTIN_WORDS = [
        "admin","login","dashboard","api","v1","v2","backup","config","upload",
        "uploads","files","images","static","assets","js","css","includes",
        "wp-admin","wp-login","phpmyadmin","manager","console","portal","test",
        ".git",".env","robots.txt","sitemap.xml","swagger","api-docs","graphql",
        "debug","info","status","health","metrics","actuator","readme","changelog",
        "backup.zip","backup.tar.gz","db.sql","dump.sql","config.php","wp-config.php",
    ]

    INTERESTING_PATTERNS = [
        r"\.git/?$", r"\.env$", r"\.bak$", r"\.sql$", r"\.zip$",
        r"backup", r"config", r"admin", r"login", r"dashboard",
        r"wp-admin", r"phpmyadmin", r"\.log$", r"debug", r"\.key$",
        r"swagger", r"graphql", r"api-docs", r"metrics", r"actuator",
    ]

    INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 401, 403}

    def __init__(
        self,
        target_url:   str,
        wordlist:     str = "medium",
        extensions:   list = None,
        threads:      int = 40,
        timeout:      int = 10,
        rate_limit:   int = 200,
        output_dir:   str = "/tmp/nsp_fuzzer",
        follow_redirects: bool = True,
        filter_status:list = None,
        user_agent:   str = None,
        cookies:      str = None,
        headers:      dict = None,
        proxy:        str = None,
    ):
        self.target_url      = target_url.rstrip("/")
        self.wordlist_key    = wordlist
        self.extensions      = extensions or ["php","asp","aspx","jsp","html","txt","bak","zip"]
        self.threads         = threads
        self.timeout         = timeout
        self.rate_limit      = rate_limit
        self.output_dir      = Path(output_dir)
        self.follow_redirects= follow_redirects
        self.filter_status   = filter_status or [404, 429, 500, 503]
        self.user_agent      = user_agent or "Mozilla/5.0 (NSP-SPECTER)"
        self.cookies         = cookies or ""
        self.headers         = headers or {}
        self.proxy           = proxy
        self.results: list[FuzzResult] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_wordlist(self) -> Path:
        """Find the best available wordlist."""
        wl_path = self.WORDLISTS.get(self.wordlist_key)
        if wl_path and Path(wl_path).exists():
            return Path(wl_path)
        # Try alternatives
        for key in ["quick","dirs"]:
            alt = self.WORDLISTS.get(key,"")
            if alt and Path(alt).exists():
                log.info(f"[FUZZER] Using fallback wordlist: {alt}")
                return Path(alt)
        # Write builtin
        builtin_path = self.output_dir / "nsp_builtin.txt"
        builtin_path.write_text("\n".join(self.BUILTIN_WORDS))
        log.warning(f"[FUZZER] No wordlist found — using built-in {len(self.BUILTIN_WORDS)}-word list")
        return builtin_path

    def _best_tool(self) -> str:
        for tool in ("ffuf", "feroxbuster", "gobuster"):
            if shutil.which(tool):
                return tool
        return ""

    # ── ffuf ────────────────────────────────────────────────────────────────
    def _run_ffuf(self, wordlist: Path) -> list:
        out_file  = self.output_dir / "ffuf_results.json"
        ext_str   = ",".join(self.extensions)
        filter_sc = ",".join(str(s) for s in self.filter_status)

        cmd = [
            "ffuf",
            "-u",       f"{self.target_url}/FUZZ",
            "-w",       str(wordlist),
            "-o",       str(out_file),
            "-of",      "json",
            "-t",       str(self.threads),
            "-timeout", str(self.timeout),
            "-rate",    str(self.rate_limit),
            "-fc",      filter_sc,
            "-H",       f"User-Agent: {self.user_agent}",
            "-e",       ext_str,
            "-mc",      "all",
            "-ac",      # auto-calibrate
        ]
        if self.cookies:
            cmd += ["-b", self.cookies]
        if self.proxy:
            cmd += ["-x", self.proxy]
        if self.follow_redirects:
            cmd += ["-r"]

        console.print(f"[#00FFD4]  [FFUF] Fuzzing {self.target_url} | "
                       f"wordlist: {wordlist.name} | threads: {self.threads}[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=1800)
        except subprocess.TimeoutExpired:
            log.warning("[FUZZER] ffuf timeout")

        return self._parse_ffuf_json(out_file)

    def _parse_ffuf_json(self, out_file: Path) -> list:
        results = []
        if not out_file.exists():
            return results
        try:
            data = json.loads(out_file.read_text())
            for r in data.get("results", []):
                results.append(FuzzResult(
                    url         = r.get("url",""),
                    status_code = r.get("status", 0),
                    size        = r.get("length", 0),
                    words       = r.get("words", 0),
                    lines       = r.get("lines", 0),
                    redirect_to = r.get("redirectlocation",""),
                    content_type= r.get("content-type",""),
                ))
        except Exception as e:
            log.debug(f"[FUZZER] ffuf parse error: {e}")
        return results

    # ── feroxbuster ─────────────────────────────────────────────────────────
    def _run_feroxbuster(self, wordlist: Path) -> list:
        out_file = self.output_dir / "ferox_results.json"
        ext_str  = ",".join(self.extensions)
        filter_sc= " ".join(f"--filter-status {s}" for s in self.filter_status)

        cmd = [
            "feroxbuster",
            "--url",     self.target_url,
            "--wordlist",str(wordlist),
            "--output",  str(out_file),
            "--json",
            "--threads", str(self.threads),
            "--timeout", str(self.timeout),
            "--rate-limit", str(self.rate_limit),
            "--extensions", ext_str,
            "--auto-tune",
            "--silent",
            "--user-agent", self.user_agent,
        ]
        for sc in self.filter_status:
            cmd += ["--filter-status", str(sc)]
        if self.cookies:
            cmd += ["--cookies", self.cookies]
        if self.proxy:
            cmd += ["--proxy", self.proxy]
        if self.follow_redirects:
            cmd += ["--redirects"]

        console.print(f"[#00FFD4]  [FEROXBUSTER] Fuzzing {self.target_url}[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=1800)
        except subprocess.TimeoutExpired:
            log.warning("[FUZZER] feroxbuster timeout")

        return self._parse_ferox_json(out_file)

    def _parse_ferox_json(self, out_file: Path) -> list:
        results = []
        if not out_file.exists():
            return results
        for line in out_file.read_text().splitlines():
            try:
                r = json.loads(line)
                if r.get("type") == "response":
                    results.append(FuzzResult(
                        url         = r.get("url",""),
                        status_code = r.get("status", 0),
                        size        = r.get("content_length", 0),
                        words       = r.get("word_count", 0),
                        lines       = r.get("line_count", 0),
                        redirect_to = r.get("redirects",[""])[-1] if r.get("redirects") else "",
                    ))
            except Exception:
                pass
        return results

    # ── gobuster ────────────────────────────────────────────────────────────
    def _run_gobuster(self, wordlist: Path) -> list:
        out_file  = self.output_dir / "gobuster_results.txt"
        ext_str   = ",".join(self.extensions)

        cmd = [
            "gobuster", "dir",
            "-u",  self.target_url,
            "-w",  str(wordlist),
            "-o",  str(out_file),
            "-t",  str(self.threads),
            "-x",  ext_str,
            "--timeout", f"{self.timeout}s",
            "-a",  self.user_agent,
            "-q",
        ]
        for sc in self.filter_status:
            cmd += ["--exclude-length", str(sc)]
        if self.cookies:
            cmd += ["-c", self.cookies]
        if self.proxy:
            cmd += ["--proxy", self.proxy]
        if self.follow_redirects:
            cmd += ["-r"]

        console.print(f"[#00FFD4]  [GOBUSTER] Fuzzing {self.target_url}[/#00FFD4]")
        try:
            subprocess.run(cmd, capture_output=True, timeout=1800)
        except subprocess.TimeoutExpired:
            log.warning("[FUZZER] gobuster timeout")

        return self._parse_gobuster_txt(out_file)

    def _parse_gobuster_txt(self, out_file: Path) -> list:
        results = []
        if not out_file.exists():
            return results
        for line in out_file.read_text().splitlines():
            m = re.match(r"(/\S+)\s+\(Status:\s+(\d+)\)", line)
            if m:
                path, sc = m.group(1), int(m.group(2))
                results.append(FuzzResult(
                    url         = f"{self.target_url}{path}",
                    status_code = sc,
                    size        = 0,
                ))
        return results

    # ── Post-processing ──────────────────────────────────────────────────────
    def _annotate(self, results: list) -> list:
        """Mark interesting results and assign severity."""
        for r in results:
            # Check interesting patterns
            for pat in self.INTERESTING_PATTERNS:
                if re.search(pat, r.url, re.IGNORECASE):
                    r.interesting = True
                    break
            # Severity
            if r.status_code == 200 and r.interesting:
                r.severity = "high"
            elif r.status_code == 200:
                r.severity = "medium"
            elif r.status_code in (401, 403):
                r.severity = "low"
            else:
                r.severity = "info"
        return results

    def _deduplicate(self, results: list) -> list:
        seen, unique = set(), []
        for r in results:
            if r.url not in seen:
                seen.add(r.url)
                unique.append(r)
        return unique

    def _print_results(self, results: list):
        interesting = [r for r in results if r.interesting]
        table = Table(
            title=f"[bold #7B00FF]🗂️  DIR FUZZ — {len(results)} paths | "
                  f"{len(interesting)} interesting[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Status", width=7,  justify="center")
        table.add_column("Size",   width=8,  justify="right")
        table.add_column("URL",    width=55)
        table.add_column("⭐",    width=5,  justify="center")

        SC_COLOR = {
            200:"[bold #00FFD4]", 201:"[bold #00FFD4]", 301:"[bold #FFD700]",
            302:"[bold #FFD700]", 401:"[bold #FF8C00]", 403:"[bold #FF8C00]",
        }
        shown = sorted(results, key=lambda r: (0 if r.interesting else 1,
                                                -r.status_code))[:60]
        for r in shown:
            sc_c = SC_COLOR.get(r.status_code, "[dim]")
            sc_e = sc_c.replace("[","[/")
            table.add_row(
                f"{sc_c}{r.status_code}{sc_e}",
                str(r.size),
                r.url[-55:],
                "⭐" if r.interesting else "",
            )
        console.print(table)

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🗂️  Dir Fuzzer — {self.target_url}[/bold #7B00FF]")
        wordlist = self._resolve_wordlist()
        tool     = self._best_tool()

        if not tool:
            log.error("[FUZZER] No fuzzing tool found (ffuf/feroxbuster/gobuster). "
                      "Install one to use this module.")
            return {"error": "no tool available", "total": 0}

        if tool == "ffuf":
            raw = self._run_ffuf(wordlist)
        elif tool == "feroxbuster":
            raw = self._run_feroxbuster(wordlist)
        else:
            raw = self._run_gobuster(wordlist)

        self.results = self._annotate(self._deduplicate(raw))
        self._print_results(self.results)

        interesting = [r for r in self.results if r.interesting]
        console.print(f"[bold #00FFD4]  ✅ Fuzzing complete — {len(self.results)} paths | "
                       f"tool: {tool} | wordlist: {wordlist.name}[/bold #00FFD4]")

        return {
            "target":      self.target_url,
            "tool":        tool,
            "wordlist":    str(wordlist),
            "total":       len(self.results),
            "interesting": len(interesting),
            "paths": [
                {"url": r.url, "status": r.status_code, "size": r.size,
                 "interesting": r.interesting, "severity": r.severity,
                 "redirect": r.redirect_to}
                for r in self.results
            ],
        }
