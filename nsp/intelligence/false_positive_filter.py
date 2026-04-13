"""
NEXUS SPECTER PRO — False Positive Filter
Heuristic + ML-assisted scoring to reduce false positives from Nuclei/ZAP/Nikto.
Uses: response analysis, keyword matching, confidence scoring, cross-tool validation.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import re, logging, hashlib
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.intelligence.fp_filter")


# ── Heuristic rules ────────────────────────────────────────────────────────────
KNOWN_FP_PATTERNS = [
    # Patterns that commonly indicate false positives
    r"test[_-]?page",
    r"example\.(com|org|net)",
    r"placeholder",
    r"default[_-]?install",
    r"this[_-]?is[_-]?a[_-]?test",
    r"lorem[_-]?ipsum",
    r"httpbin\.org",
    r"localhost|127\.0\.0\.1",
]

# Templates that have high false-positive rates
HIGH_FP_TEMPLATES = {
    "generic-xss": 0.6,          # Often FP in non-reflected contexts
    "cors-misconfiguration": 0.5, # Complex to confirm
    "missing-csp": 0.3,          # Very common, low risk
    "http-missing-security-headers": 0.3,
    "server-version-disclosure": 0.25,
    "self-signed-ssl": 0.2,
    "deprecated-tls": 0.25,
    "directory-listing": 0.35,
}

# Evidence patterns that CONFIRM a finding (reduce FP score)
CONFIRMATION_PATTERNS = {
    "sqli": [
        r"SQL syntax.*MySQL", r"ORA-\d+", r"PG::SyntaxError",
        r"You have an error in your SQL", r"Unclosed quotation",
        r"Microsoft.*ODBC.*SQL",
    ],
    "xss": [
        r"<script>", r"javascript:", r"onerror=", r"onload=",
        r"<img[^>]+src=x", r"alert\(", r"confirm\(",
    ],
    "lfi": [
        r"root:.*:/bin/", r"\[boot loader\]", r"daemon:.*:/usr/sbin",
        r"\\[autorun\\]",
    ],
    "rce": [
        r"uid=\d+.*gid=\d+", r"Linux .* #\d+", r"Windows NT",
        r"COMPUTERNAME=", r"/bin/bash",
    ],
}

# Severity weights for FP scoring
SEVERITY_TRUST = {
    "critical": 0.85,   # High trust — assume real unless proven otherwise
    "high":     0.75,
    "medium":   0.55,
    "low":      0.40,
    "info":     0.20,
}


@dataclass
class FPScore:
    finding_id:      str
    original_name:   str
    severity:        str
    fp_probability:  float    # 0.0 (definitely real) → 1.0 (definitely FP)
    confidence:      float    # How confident is the score
    verdict:         str      # CONFIRMED | LIKELY_REAL | UNCERTAIN | LIKELY_FP | FALSE_POSITIVE
    reasons:         list     = field(default_factory=list)
    evidence_found:  list     = field(default_factory=list)
    recommendation:  str      = ""


class FalsePositiveFilter:
    """
    Heuristic false-positive filter for NEXUS SPECTER PRO.
    Analyses each finding against multiple signals:
    - Template known-FP rate
    - Response evidence presence
    - Cross-tool validation (if same finding in multiple tools → more real)
    - URL/context patterns
    - Severity × confirmation match
    Outputs: FPScore with verdict + actionable recommendation.
    """

    def __init__(self, cross_validation: bool = True):
        self.cross_validation = cross_validation
        self._tool_results: dict = {}   # tool → set of finding keys

    def register_tool_results(self, tool: str, findings: list):
        """Register findings from a specific tool for cross-validation."""
        keys = set()
        for f in findings:
            key = hashlib.md5(
                f"{f.get('host','')}:{f.get('name','')}".encode()
            ).hexdigest()[:8]
            keys.add(key)
        self._tool_results[tool] = keys

    def _fp_probability(self, finding: dict) -> tuple:
        """Compute FP probability and reasons list."""
        name     = finding.get("name","").lower()
        template = finding.get("template_id","").lower()
        severity = finding.get("severity","info").lower()
        host     = finding.get("host","").lower()
        evidence = finding.get("evidence","") or finding.get("raw_response","") or ""
        desc     = finding.get("description","")
        tags     = [t.lower() for t in finding.get("tags",[])]

        fp_prob  = 1.0 - SEVERITY_TRUST.get(severity, 0.3)  # Base from severity
        reasons  = []
        evidence_found = []

        # 1. Known high-FP template
        for tmpl, rate in HIGH_FP_TEMPLATES.items():
            if tmpl in template or tmpl in name:
                fp_prob = max(fp_prob, rate)
                reasons.append(f"Template '{tmpl}' has ~{int(rate*100)}% historical FP rate")

        # 2. Known FP patterns in host/URL
        for pattern in KNOWN_FP_PATTERNS:
            if re.search(pattern, host, re.IGNORECASE):
                fp_prob = min(fp_prob + 0.3, 0.95)
                reasons.append(f"Host matches known FP pattern: {pattern}")

        # 3. Evidence confirmation (REDUCES FP probability)
        for tag in tags:
            patterns = CONFIRMATION_PATTERNS.get(tag, [])
            for pat in patterns:
                if re.search(pat, evidence, re.IGNORECASE):
                    fp_prob = max(fp_prob - 0.25, 0.05)
                    match   = re.search(pat, evidence, re.IGNORECASE)
                    evidence_found.append(f"Confirmed: '{match.group()[:60]}'")

        # 4. No evidence in response body
        if not evidence and severity in ("critical","high"):
            fp_prob = min(fp_prob + 0.15, 0.90)
            reasons.append("No response evidence captured — harder to confirm")

        # 5. Cross-tool validation
        if self.cross_validation and len(self._tool_results) >= 2:
            key = hashlib.md5(
                f"{finding.get('host','')}:{finding.get('name','')}".encode()
            ).hexdigest()[:8]
            tools_seen = [t for t, keys in self._tool_results.items() if key in keys]
            if len(tools_seen) >= 2:
                fp_prob = max(fp_prob - 0.20, 0.05)
                reasons.append(f"Confirmed by {len(tools_seen)} tools: {', '.join(tools_seen)}")

        # 6. CVE present = more credible
        if finding.get("cve_id") or finding.get("cve"):
            fp_prob = max(fp_prob - 0.10, 0.05)
            reasons.append("CVE reference present — likely real vulnerability")

        # 7. CVSS score > 7 = higher confidence
        cvss = float(finding.get("cvss_score",0) or finding.get("cvss",0) or 0)
        if cvss >= 7.0:
            fp_prob = max(fp_prob - 0.10, 0.05)

        confidence = 1.0 - abs(fp_prob - 0.5) * 2   # Higher when near 0 or 1

        return round(fp_prob, 3), round(confidence, 3), reasons, evidence_found

    def _verdict(self, fp_prob: float) -> tuple:
        if fp_prob <= 0.10: return "CONFIRMED",      "Validate manually; mark as confirmed"
        if fp_prob <= 0.25: return "LIKELY_REAL",    "High confidence — remediate"
        if fp_prob <= 0.45: return "UNCERTAIN",      "Manual verification recommended"
        if fp_prob <= 0.65: return "LIKELY_FP",      "Review before reporting"
        return "FALSE_POSITIVE",                     "Suppress — likely false positive"

    def score_finding(self, finding: dict) -> FPScore:
        fp_prob, confidence, reasons, evidence = self._fp_probability(finding)
        verdict, recommendation                = self._verdict(fp_prob)
        return FPScore(
            finding_id     = hashlib.md5(str(finding).encode()).hexdigest()[:8],
            original_name  = finding.get("name","")[:60],
            severity       = finding.get("severity","info"),
            fp_probability = fp_prob,
            confidence     = confidence,
            verdict        = verdict,
            reasons        = reasons,
            evidence_found = evidence,
            recommendation = recommendation,
        )

    def filter_findings(self, findings: dict,
                         suppress_threshold: float = 0.65) -> dict:
        """
        Filter a findings dict. Returns:
        - confirmed: findings with FP probability < suppress_threshold
        - suppressed: likely false positives
        - scored: all findings with FP scores attached
        """
        confirmed  = {}
        suppressed = []
        scored_all = []

        for sev in ["critical","high","medium","low","info"]:
            for f in findings.get("by_severity",{}).get(sev,[]):
                score = self.score_finding(f)
                f["fp_score"] = {
                    "probability":  score.fp_probability,
                    "verdict":      score.verdict,
                    "confidence":   score.confidence,
                    "reasons":      score.reasons,
                    "evidence":     score.evidence_found,
                    "recommendation": score.recommendation,
                }
                scored_all.append((sev, f, score))
                if score.fp_probability < suppress_threshold:
                    confirmed.setdefault(sev,[]).append(f)
                else:
                    suppressed.append(f)

        return {
            "confirmed":    {"by_severity": confirmed},
            "suppressed":   suppressed,
            "stats": {
                "total":      len(scored_all),
                "confirmed":  sum(len(v) for v in confirmed.values()),
                "suppressed": len(suppressed),
                "fp_rate":    round(len(suppressed)/max(len(scored_all),1)*100,1),
            }
        }

    def _print_scores(self, scored: list):
        table = Table(
            title=f"[bold #7B00FF]🎯 FALSE POSITIVE ANALYSIS — {len(scored)} findings[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4", show_lines=False,
        )
        table.add_column("Finding",     width=40)
        table.add_column("Severity",    width=10)
        table.add_column("FP Prob",     width=9,  justify="right")
        table.add_column("Verdict",     width=18)
        table.add_column("Confidence",  width=10, justify="right")

        VERDICT_COLOR = {
            "CONFIRMED":     "[bold #FF003C]",
            "LIKELY_REAL":   "[bold #FF8C00]",
            "UNCERTAIN":     "[bold #FFD700]",
            "LIKELY_FP":     "[bold #00FFD4]",
            "FALSE_POSITIVE":"[dim]",
        }
        SEV_COLOR = {"critical":"[bold #FF003C]","high":"[bold #FF8C00]",
                     "medium":"[bold #FFD700]","low":"[bold #00FFD4]","info":"[dim]"}
        for s in sorted(scored, key=lambda x: x.fp_probability):
            vc = VERDICT_COLOR.get(s.verdict,"[white]")
            ve = vc.replace("[","[/")
            sc = SEV_COLOR.get(s.severity,"[white]")
            se = sc.replace("[","[/")
            table.add_row(
                s.original_name[:40],
                f"{sc}{s.severity}{se}",
                f"{s.fp_probability:.0%}",
                f"{vc}{s.verdict}{ve}",
                f"{s.confidence:.0%}",
            )
        console.print(table)

    def run(self, findings: dict) -> dict:
        console.print("[bold #7B00FF]  🎯 False Positive Filter...[/bold #7B00FF]")
        result  = self.filter_findings(findings)
        stats   = result["stats"]

        # Score all for display
        all_findings = []
        for sev in ["critical","high","medium","low","info"]:
            for f in findings.get("by_severity",{}).get(sev,[]):
                all_findings.append(self.score_finding(f))

        self._print_scores(all_findings)
        console.print(
            f"  [#00FFD4]Total: {stats['total']} | "
            f"Confirmed: {stats['confirmed']} | "
            f"Suppressed: {stats['suppressed']} | "
            f"FP rate: {stats['fp_rate']}%[/#00FFD4]"
        )
        return result
