"""
NEXUS SPECTER PRO — CVSS 3.1 Scoring Engine
Full implementation: Base Score + Temporal Score + Environmental Score
CVSS v3.1 specification: https://www.first.org/cvss/specification-document
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import math, logging
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.reporting.cvss")


# ── CVSS 3.1 metric weights (FIRST specification) ──────────────────────────
BASE_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},   # Attack Vector
    "AC": {"L": 0.77, "H": 0.44},                           # Attack Complexity
    "PR": {
        "N": {"U": 0.85, "C": 0.85},                        # Scope Unchanged / Changed
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},                           # User Interaction
    "S":  {"U": 0.0,  "C": 0.0},                            # Scope (handled in formula)
    "C":  {"N": 0.00, "L": 0.22, "H": 0.56},               # Confidentiality
    "I":  {"N": 0.00, "L": 0.22, "H": 0.56},               # Integrity
    "A":  {"N": 0.00, "L": 0.22, "H": 0.56},               # Availability
}

TEMPORAL_METRICS = {
    "E":  {"X": 1.00, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.00},  # Exploit Code Maturity
    "RL": {"X": 1.00, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.00},  # Remediation Level
    "RC": {"X": 1.00, "U": 0.92, "R": 0.96, "C": 1.00},             # Report Confidence
}

ENVIRONMENTAL_METRICS = {
    "CR":  {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50},  # Confidentiality Req
    "IR":  {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50},  # Integrity Req
    "AR":  {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50},  # Availability Req
    # Modified base metrics (same weights as base)
    "MAV": {"X": None, "N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "MAC": {"X": None, "L": 0.77, "H": 0.44},
    "MUI": {"X": None, "N": 0.85, "R": 0.62},
    "MS":  {"X": None, "U": 0.0,  "C": 0.0},
    "MC":  {"X": None, "N": 0.00, "L": 0.22, "H": 0.56},
    "MI":  {"X": None, "N": 0.00, "L": 0.22, "H": 0.56},
    "MA":  {"X": None, "N": 0.00, "L": 0.22, "H": 0.56},
}

SEVERITY_RATINGS = [
    (9.0, 10.0, "Critical", "#FF003C"),
    (7.0,  8.9, "High",     "#FF8C00"),
    (4.0,  6.9, "Medium",   "#FFD700"),
    (0.1,  3.9, "Low",      "#00FFD4"),
    (0.0,  0.0, "None",     "#555555"),
]


@dataclass
class CVSSVector:
    # Base metrics (required)
    AV: str = "N"   # Attack Vector:        N=Network A=Adjacent L=Local P=Physical
    AC: str = "L"   # Attack Complexity:    L=Low H=High
    PR: str = "N"   # Privileges Required:  N=None L=Low H=High
    UI: str = "N"   # User Interaction:     N=None R=Required
    S:  str = "U"   # Scope:                U=Unchanged C=Changed
    C:  str = "N"   # Confidentiality:      N=None L=Low H=High
    I:  str = "N"   # Integrity:            N=None L=Low H=High
    A:  str = "N"   # Availability:         N=None L=Low H=High

    # Temporal metrics (optional)
    E:  str = "X"   # Exploit Code Maturity:  X=NotDefined U=Unproven P=ProofOfConcept F=Functional H=High
    RL: str = "X"   # Remediation Level:      X=NotDefined O=OfficialFix T=TemporaryFix W=Workaround U=Unavailable
    RC: str = "X"   # Report Confidence:      X=NotDefined U=Unknown R=Reasonable C=Confirmed

    # Environmental metrics (optional)
    CR:  str = "X"  # Confidentiality Req
    IR:  str = "X"  # Integrity Req
    AR:  str = "X"  # Availability Req
    MAV: str = "X"  # Modified Attack Vector
    MAC: str = "X"  # Modified Attack Complexity
    MPR: str = "X"  # Modified Privileges Required
    MUI: str = "X"  # Modified User Interaction
    MS:  str = "X"  # Modified Scope
    MC:  str = "X"  # Modified Confidentiality
    MI:  str = "X"  # Modified Integrity
    MA:  str = "X"  # Modified Availability


@dataclass
class CVSSScore:
    base_score:        float
    temporal_score:    float
    environmental_score: float
    base_severity:     str
    temporal_severity: str
    environmental_severity: str
    iss:               float   # Impact Sub-Score
    ess:               float   # Exploitability Sub-Score
    vector_string:     str
    breakdown:         dict = field(default_factory=dict)


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup function — rounds to 1 decimal place."""
    int_val = round(value * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000
    return math.floor(int_val / 10000) / 10.0 + 0.1


def _severity_rating(score: float) -> tuple:
    for lo, hi, label, color in SEVERITY_RATINGS:
        if lo <= score <= hi:
            return label, color
    return "None", "#555555"


class CVSSScorer:
    """
    CVSS 3.1 Scoring Engine — full Base + Temporal + Environmental calculation.
    Parses CVSS vector strings and calculates all three score types.
    Provides human-readable breakdowns for pentest reports.
    """

    def __init__(self, vector: CVSSVector = None, vector_string: str = None):
        if vector_string:
            self.vector = self._parse_vector_string(vector_string)
        else:
            self.vector = vector or CVSSVector()

    def _parse_vector_string(self, vs: str) -> CVSSVector:
        """Parse a CVSS 3.1 vector string into a CVSSVector object."""
        v = CVSSVector()
        # Strip prefix
        vs = vs.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")
        for part in vs.split("/"):
            if ":" not in part:
                continue
            k, val = part.split(":", 1)
            if hasattr(v, k):
                setattr(v, k, val)
        return v

    def _pr_weight(self, pr: str, scope: str) -> float:
        weights = BASE_METRICS["PR"].get(pr, {})
        if isinstance(weights, dict):
            return weights.get(scope, 0.0)
        return weights

    def calculate_base_score(self) -> tuple:
        """Calculate CVSS 3.1 Base Score. Returns (score, ISS, ESS)."""
        v = self.vector

        av  = BASE_METRICS["AV"].get(v.AV, 0.85)
        ac  = BASE_METRICS["AC"].get(v.AC, 0.77)
        pr  = self._pr_weight(v.PR, v.S)
        ui  = BASE_METRICS["UI"].get(v.UI, 0.85)
        c   = BASE_METRICS["C"].get(v.C, 0.0)
        i   = BASE_METRICS["I"].get(v.I, 0.0)
        a   = BASE_METRICS["A"].get(v.A, 0.0)

        # Impact Sub-Score (ISS)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Impact (with scope adjustment)
        if v.S == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Exploitability Sub-Score
        ess = 8.22 * av * ac * pr * ui

        if iss <= 0:
            base = 0.0
        else:
            if v.S == "U":
                base = _roundup(min(impact + ess, 10.0))
            else:
                base = _roundup(min(1.08 * (impact + ess), 10.0))

        return base, round(iss, 3), round(ess, 3)

    def calculate_temporal_score(self, base: float) -> float:
        """Calculate CVSS 3.1 Temporal Score."""
        v   = self.vector
        e   = TEMPORAL_METRICS["E"].get(v.E,   1.00)
        rl  = TEMPORAL_METRICS["RL"].get(v.RL, 1.00)
        rc  = TEMPORAL_METRICS["RC"].get(v.RC, 1.00)
        return _roundup(base * e * rl * rc)

    def calculate_environmental_score(self) -> float:
        """Calculate CVSS 3.1 Environmental Score."""
        v = self.vector

        # Use modified metrics where defined, fallback to base
        mav = (ENVIRONMENTAL_METRICS["MAV"].get(v.MAV) or BASE_METRICS["AV"].get(v.AV, 0.85))
        mac = (ENVIRONMENTAL_METRICS["MAC"].get(v.MAC) or BASE_METRICS["AC"].get(v.AC, 0.77))
        mpr_base = BASE_METRICS["PR"].get(v.MPR if v.MPR != "X" else v.PR, {})
        ms  = v.MS if v.MS != "X" else v.S
        mpr = mpr_base.get(ms, 0.62) if isinstance(mpr_base, dict) else mpr_base
        mui = (ENVIRONMENTAL_METRICS["MUI"].get(v.MUI) or BASE_METRICS["UI"].get(v.UI, 0.85))

        mc_val = (ENVIRONMENTAL_METRICS["MC"].get(v.MC) or BASE_METRICS["C"].get(v.C, 0.0))
        mi_val = (ENVIRONMENTAL_METRICS["MI"].get(v.MI) or BASE_METRICS["I"].get(v.I, 0.0))
        ma_val = (ENVIRONMENTAL_METRICS["MA"].get(v.MA) or BASE_METRICS["A"].get(v.A, 0.0))

        cr = ENVIRONMENTAL_METRICS["CR"].get(v.CR, 1.00)
        ir = ENVIRONMENTAL_METRICS["IR"].get(v.IR, 1.00)
        ar = ENVIRONMENTAL_METRICS["AR"].get(v.AR, 1.00)

        # Modified ISS
        miss = min(
            1 - (1 - mc_val * cr) * (1 - mi_val * ir) * (1 - ma_val * ar),
            0.915
        )

        if ms == "U":
            m_impact = 6.42 * miss
        else:
            m_impact = 7.52 * (miss - 0.029) - 3.25 * ((miss * 0.9731 - 0.02) ** 13)

        m_exploitability = 8.22 * mav * mac * mpr * mui

        e   = TEMPORAL_METRICS["E"].get(v.E,   1.00)
        rl  = TEMPORAL_METRICS["RL"].get(v.RL, 1.00)
        rc  = TEMPORAL_METRICS["RC"].get(v.RC, 1.00)

        if miss <= 0:
            env = 0.0
        else:
            if ms == "U":
                env = _roundup(_roundup(min(m_impact + m_exploitability, 10)) * e * rl * rc)
            else:
                env = _roundup(_roundup(min(1.08 * (m_impact + m_exploitability), 10)) * e * rl * rc)
        return env

    def build_vector_string(self) -> str:
        v = self.vector
        base = (f"CVSS:3.1/AV:{v.AV}/AC:{v.AC}/PR:{v.PR}/UI:{v.UI}"
                f"/S:{v.S}/C:{v.C}/I:{v.I}/A:{v.A}")
        temporal = ""
        if any(getattr(v, m) != "X" for m in ["E","RL","RC"]):
            temporal = f"/E:{v.E}/RL:{v.RL}/RC:{v.RC}"
        env = ""
        if any(getattr(v, m) != "X" for m in ["CR","IR","AR"]):
            env = f"/CR:{v.CR}/IR:{v.IR}/AR:{v.AR}"
        return base + temporal + env

    def score(self) -> CVSSScore:
        """Calculate and return all CVSS scores."""
        base, iss, ess = self.calculate_base_score()
        temporal       = self.calculate_temporal_score(base)
        environmental  = self.calculate_environmental_score()

        b_sev, _  = _severity_rating(base)
        t_sev, _  = _severity_rating(temporal)
        e_sev, _  = _severity_rating(environmental)

        v = self.vector
        breakdown = {
            "Attack Vector":        {"N":"Network","A":"Adjacent","L":"Local","P":"Physical"}.get(v.AV, v.AV),
            "Attack Complexity":    {"L":"Low","H":"High"}.get(v.AC, v.AC),
            "Privileges Required":  {"N":"None","L":"Low","H":"High"}.get(v.PR, v.PR),
            "User Interaction":     {"N":"None","R":"Required"}.get(v.UI, v.UI),
            "Scope":                {"U":"Unchanged","C":"Changed"}.get(v.S, v.S),
            "Confidentiality":      {"N":"None","L":"Low","H":"High"}.get(v.C, v.C),
            "Integrity":            {"N":"None","L":"Low","H":"High"}.get(v.I, v.I),
            "Availability":         {"N":"None","L":"Low","H":"High"}.get(v.A, v.A),
        }

        return CVSSScore(
            base_score=base, temporal_score=temporal,
            environmental_score=environmental,
            base_severity=b_sev, temporal_severity=t_sev,
            environmental_severity=e_sev,
            iss=iss, ess=ess,
            vector_string=self.build_vector_string(),
            breakdown=breakdown,
        )

    def print_score_card(self, name: str = "Vulnerability"):
        s = self.score()
        _, base_color = _severity_rating(s.base_score)
        _, temp_color = _severity_rating(s.temporal_score)
        _, env_color  = _severity_rating(s.environmental_score)

        table = Table(
            title=f"[bold #7B00FF]🎯 CVSS 3.1 — {name}[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Score Type",   style="#00FFD4", width=22)
        table.add_column("Score",        width=8,  justify="right")
        table.add_column("Severity",     width=12)
        table.add_column("Vector",       width=55)

        def sev_str(sev, color):
            return f"[bold {color}]{sev}[/bold {color}]"

        table.add_row("Base Score",        f"{s.base_score:.1f}",
                      sev_str(s.base_severity, base_color), s.vector_string)
        table.add_row("Temporal Score",    f"{s.temporal_score:.1f}",
                      sev_str(s.temporal_severity, temp_color), "")
        table.add_row("Environmental",     f"{s.environmental_score:.1f}",
                      sev_str(s.environmental_severity, env_color), "")
        table.add_row("Impact Sub-Score",  f"{s.iss:.3f}", "", "")
        table.add_row("Exploitability SS", f"{s.ess:.3f}", "", "")
        console.print(table)

        detail = Table(border_style="#1E1E1E", header_style="bold #555", show_header=False)
        detail.add_column("Metric", style="#00FFD4", width=22)
        detail.add_column("Value",  style="white",   width=20)
        for k, v_val in s.breakdown.items():
            detail.add_row(k, str(v_val))
        console.print(detail)
        return s

    @staticmethod
    def score_findings_batch(findings: list) -> list:
        """Score a list of findings dicts that have 'cvss_vector' keys."""
        scored = []
        for f in findings:
            vs = f.get("cvss_vector","") or f.get("vector","")
            if vs:
                try:
                    scorer  = CVSSScorer(vector_string=vs)
                    result  = scorer.score()
                    f["cvss_base"]        = result.base_score
                    f["cvss_temporal"]    = result.temporal_score
                    f["cvss_env"]         = result.environmental_score
                    f["cvss_severity"]    = result.base_severity.lower()
                    f["cvss_breakdown"]   = result.breakdown
                except Exception as e:
                    log.debug(f"[CVSS] Scoring error: {e}")
            scored.append(f)
        return scored

    @staticmethod
    def quick_score(av="N", ac="L", pr="N", ui="N", s="U",
                    c="H", i="H", a="H") -> float:
        """Quick helper — returns base score from individual metric strings."""
        scorer = CVSSScorer(vector=CVSSVector(AV=av,AC=ac,PR=pr,UI=ui,S=s,C=c,I=i,A=a))
        return scorer.calculate_base_score()[0]
