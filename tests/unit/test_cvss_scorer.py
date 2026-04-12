"""
NEXUS SPECTER PRO — CVSS Scorer Unit Tests
by OPTIMIUM NEXUS LLC
"""
import pytest
from nsp.reporting.cvss_scorer import CVSSScorer, CVSSVector, _roundup


class TestCVSSScorer:

    def test_critical_network_rce(self):
        """CVE-2021-44228 Log4Shell — expected ~10.0"""
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")
        scorer = CVSSScorer(vector=v)
        score, _, _ = scorer.calculate_base_score()
        assert score == 10.0

    def test_medium_auth_required(self):
        """Medium finding — network, low complexity, auth required"""
        v = CVSSVector(AV="N", AC="L", PR="L", UI="R", S="U", C="L", I="L", A="N")
        scorer = CVSSScorer(vector=v)
        score, _, _ = scorer.calculate_base_score()
        assert 4.0 <= score <= 6.9

    def test_vector_string_parse(self):
        vs = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        scorer = CVSSScorer(vector_string=vs)
        assert scorer.vector.AV == "N"
        assert scorer.vector.C  == "H"

    def test_no_impact_zero_score(self):
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N")
        scorer = CVSSScorer(vector=v)
        score, _, _ = scorer.calculate_base_score()
        assert score == 0.0

    def test_roundup(self):
        assert _roundup(4.02) == 4.1
        assert _roundup(4.00) == 4.0
        assert _roundup(9.99) == 10.0

    def test_temporal_reduces_score(self):
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        scorer = CVSSScorer(vector=v)
        scorer.vector.E  = "U"    # Unproven exploit
        scorer.vector.RL = "O"    # Official fix available
        scorer.vector.RC = "U"    # Unknown confidence
        base, _, _ = scorer.calculate_base_score()
        temporal   = scorer.calculate_temporal_score(base)
        assert temporal <= base

    def test_quick_score(self):
        score = CVSSScorer.quick_score(C="H", I="H", A="H")
        assert score >= 7.0

    def test_build_vector_string(self):
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        scorer = CVSSScorer(vector=v)
        vs = scorer.build_vector_string()
        assert vs.startswith("CVSS:3.1/")
        assert "AV:N" in vs
        assert "C:H" in vs
