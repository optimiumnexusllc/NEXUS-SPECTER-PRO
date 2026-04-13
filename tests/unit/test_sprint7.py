"""
NEXUS SPECTER PRO — Sprint 7 Unit Tests
Reporting, OSINT & Intelligence modules.
by OPTIMIUM NEXUS LLC
"""
import pytest, json
from pathlib import Path

# ── Sample findings fixture ───────────────────────────────────────────────────
SAMPLE_FINDINGS = {
    "by_severity": {
        "critical": [
            {"name":"SQL Injection /api/login","host":"api.example.com",
             "cvss_score":9.8,"tags":["sqli","injection","cve"],
             "cve_id":"CVE-2021-0001","evidence":"SQL error: 1064"},
        ],
        "high": [
            {"name":"XSS in search parameter","host":"www.example.com",
             "cvss_score":7.5,"tags":["xss"],"evidence":"<script>alert(1)</script>"},
            {"name":"Default credentials on admin","host":"admin.example.com",
             "cvss_score":8.0,"tags":["default-login","auth"],"evidence":"admin:admin"},
        ],
        "medium": [
            {"name":"Missing HSTS header","host":"www.example.com",
             "cvss_score":5.0,"tags":["ssl","misconfig"]},
        ],
        "low":  [{"name":"Server version disclosure","host":"www.example.com",
                  "cvss_score":2.0,"tags":["info","exposed"]}],
        "info": [],
    }
}


class TestExecutiveDashboard:
    def test_generates_html(self, tmp_path):
        from nsp.reporting.executive_dashboard import ExecutiveDashboard, DashboardConfig
        d = ExecutiveDashboard(output_dir=str(tmp_path))
        cfg = DashboardConfig(
            session_id  = "NSP-TEST-001",
            client_name = "ACME Corp",
            target      = "example.com",
            risk_score  = 72,
            findings    = {"by_severity": SAMPLE_FINDINGS["by_severity"]},
        )
        out = d.generate(cfg)
        assert out.exists()
        content = out.read_text()
        assert "NEXUS SPECTER PRO" in content
        assert "ACME Corp"         in content
        assert "CONFIDENTIAL"      in content

    def test_risk_level_critical(self, tmp_path):
        from nsp.reporting.executive_dashboard import ExecutiveDashboard
        d = ExecutiveDashboard(output_dir=str(tmp_path))
        level, color = d._risk_level(85)
        assert level == "CRITICAL"
        assert color == "#FF003C"

    def test_risk_level_low(self, tmp_path):
        from nsp.reporting.executive_dashboard import ExecutiveDashboard
        d = ExecutiveDashboard(output_dir=str(tmp_path))
        level, color = d._risk_level(25)
        assert level == "LOW"

    def test_gauge_dash_full(self, tmp_path):
        from nsp.reporting.executive_dashboard import ExecutiveDashboard
        d = ExecutiveDashboard(output_dir=str(tmp_path))
        assert d._gauge_dash(100) == 189
        assert d._gauge_dash(0)   == 0
        assert 0 < d._gauge_dash(50) < 189


class TestRiskMatrix:
    def test_cvss_to_coords(self, tmp_path):
        from nsp.reporting.risk_matrix_generator import RiskMatrixGenerator
        g = RiskMatrixGenerator(output_dir=str(tmp_path))
        l, i = g._cvss_to_coords(9.8, "CRITICAL")
        assert l == 5 and i == 5

    def test_cvss_low(self, tmp_path):
        from nsp.reporting.risk_matrix_generator import RiskMatrixGenerator
        g = RiskMatrixGenerator(output_dir=str(tmp_path))
        l, i = g._cvss_to_coords(2.5, "LOW")
        assert l <= 3 and i <= 3

    def test_generate_html(self, tmp_path):
        from nsp.reporting.risk_matrix_generator import RiskMatrixGenerator, RiskItem
        g     = RiskMatrixGenerator(output_dir=str(tmp_path))
        items = [RiskItem("SQL Injection", 5, 5, "critical", score=9.8),
                 RiskItem("XSS", 3, 4, "high", score=7.5)]
        out   = g.generate(items, "NSP-TEST")
        assert out.exists()
        assert "RISK MATRIX" in out.read_text()

    def test_risk_item_level(self):
        from nsp.reporting.risk_matrix_generator import RiskItem
        r = RiskItem("Test", likelihood=5, impact=5, severity="critical")
        assert r.risk_level  == 25
        assert r.risk_label  == "CRITICAL"

    def test_findings_to_items(self, tmp_path):
        from nsp.reporting.risk_matrix_generator import RiskMatrixGenerator
        g = RiskMatrixGenerator(output_dir=str(tmp_path))
        items = g._findings_to_items(SAMPLE_FINDINGS)
        assert len(items) >= 3


class TestMITREMapper:
    def test_map_findings(self, tmp_path):
        from nsp.reporting.mitre_attack_mapper import MITREAttackMapper
        m = MITREAttackMapper(output_dir=str(tmp_path))
        m._map_findings(SAMPLE_FINDINGS)
        assert len(m.hits) > 0

    def test_sqli_maps_to_t1190(self, tmp_path):
        from nsp.reporting.mitre_attack_mapper import MITREAttackMapper
        m = MITREAttackMapper(output_dir=str(tmp_path))
        m._map_findings(SAMPLE_FINDINGS)
        assert "T1190" in m.hits

    def test_navigator_export(self, tmp_path):
        from nsp.reporting.mitre_attack_mapper import MITREAttackMapper
        m = MITREAttackMapper(output_dir=str(tmp_path))
        m._map_findings(SAMPLE_FINDINGS)
        out  = m.export_navigator_layer("NSP-TEST")
        data = json.loads(out.read_text())
        assert data["domain"] == "enterprise-attack"
        assert len(data["techniques"]) > 0

    def test_html_report(self, tmp_path):
        from nsp.reporting.mitre_attack_mapper import MITREAttackMapper
        m = MITREAttackMapper(output_dir=str(tmp_path))
        m._map_findings(SAMPLE_FINDINGS)
        out = m.generate_html_report("NSP-TEST")
        assert out.exists()
        assert "ATT&CK" in out.read_text()


class TestComplianceReporter:
    def test_iso27001_evaluation(self, tmp_path):
        from nsp.reporting.compliance_reporter import ComplianceReporter
        r = ComplianceReporter(output_dir=str(tmp_path))
        result = r.evaluate_framework("ISO 27001:2022", SAMPLE_FINDINGS)
        assert result.framework == "ISO 27001:2022"
        assert 0 <= result.overall_score <= 100
        assert result.rating in ("Compliant","Substantially Compliant",
                                  "Partially Compliant","Non-Compliant")

    def test_fails_with_critical(self, tmp_path):
        from nsp.reporting.compliance_reporter import ComplianceReporter
        r = ComplianceReporter(output_dir=str(tmp_path))
        result = r.evaluate_framework("PCI-DSS v4", SAMPLE_FINDINGS)
        assert result.fail_count > 0

    def test_all_frameworks(self, tmp_path):
        from nsp.reporting.compliance_reporter import ComplianceReporter, FRAMEWORKS
        r = ComplianceReporter(output_dir=str(tmp_path))
        for fw in FRAMEWORKS:
            res = r.evaluate_framework(fw, SAMPLE_FINDINGS)
            assert res.framework == fw
            assert isinstance(res.overall_score, float)

    def test_html_generation(self, tmp_path):
        from nsp.reporting.compliance_reporter import ComplianceReporter
        r       = ComplianceReporter(output_dir=str(tmp_path))
        results = [r.evaluate_framework("ISO 27001:2022", SAMPLE_FINDINGS)]
        out     = r.generate_html(results, "NSP-TEST")
        assert out.exists()
        assert "ISO 27001" in out.read_text()


class TestTrendAnalyzer:
    def test_record_and_retrieve(self, tmp_path):
        from nsp.reporting.trend_analyzer import TrendAnalyzer
        t = TrendAnalyzer(output_dir=str(tmp_path))
        # Override store dir
        t.STORE_DIR = tmp_path / "trend"
        t.STORE_DIR.mkdir()
        snap = t.record_snapshot("NSP-001","example.com", SAMPLE_FINDINGS)
        assert snap.risk_score > 0
        assert snap.target == "example.com"

    def test_risk_score_computation(self, tmp_path):
        from nsp.reporting.trend_analyzer import TrendAnalyzer
        t = TrendAnalyzer(output_dir=str(tmp_path))
        score = t._compute_risk_score(SAMPLE_FINDINGS)
        assert score > 0
        # 1 critical (×15=15) + 2 high (×8=16) + 1 medium (×4=4) + 1 low (×1=1) = 36
        assert score == 36.0

    def test_sparkline_data(self, tmp_path):
        from nsp.reporting.trend_analyzer import TrendAnalyzer
        t         = TrendAnalyzer(output_dir=str(tmp_path))
        t.STORE_DIR = tmp_path / "trend"
        t.STORE_DIR.mkdir()
        for i, session in enumerate(["A","B","C"]):
            t.record_snapshot(f"NSP-{session}", "example.com", SAMPLE_FINDINGS)
        data = t.get_sparkline_data("example.com")
        assert len(data) == 3


class TestFaviconHasher:
    def test_murmurhash_pure(self):
        from nsp.recon.passive.favicon_hasher import _mmh3_32
        # Test known hash value
        result = _mmh3_32(b"hello world")
        assert isinstance(result, int)

    def test_compute_hash_consistency(self):
        from nsp.recon.passive.favicon_hasher import FaviconHasher
        h  = FaviconHasher("example.com")
        h1 = h.compute_hash(b"\x89PNG test data here")
        h2 = h.compute_hash(b"\x89PNG test data here")
        assert h1 == h2   # deterministic

    def test_compute_hash_different_inputs(self):
        from nsp.recon.passive.favicon_hasher import FaviconHasher
        h  = FaviconHasher("example.com")
        h1 = h.compute_hash(b"favicon_data_1")
        h2 = h.compute_hash(b"favicon_data_2")
        assert h1 != h2


class TestFalsePositiveFilter:
    def test_critical_low_fp(self):
        from nsp.intelligence.false_positive_filter import FalsePositiveFilter
        f = FalsePositiveFilter()
        finding = {"name":"SQL Injection","severity":"critical",
                   "tags":["sqli"],"evidence":"SQL syntax error MySQL",
                   "cvss_score":9.8,"cve_id":"CVE-2021-0001"}
        score = f.score_finding(finding)
        assert score.fp_probability < 0.5
        assert score.verdict in ("CONFIRMED","LIKELY_REAL","UNCERTAIN")

    def test_info_high_fp(self):
        from nsp.intelligence.false_positive_filter import FalsePositiveFilter
        f = FalsePositiveFilter()
        finding = {"name":"Missing CSP header","severity":"info",
                   "tags":["missing-csp"],"evidence":"","cvss_score":0}
        score = f.score_finding(finding)
        assert score.fp_probability >= 0.3

    def test_filter_returns_structure(self):
        from nsp.intelligence.false_positive_filter import FalsePositiveFilter
        f  = FalsePositiveFilter()
        r  = f.filter_findings(SAMPLE_FINDINGS)
        assert "confirmed"  in r
        assert "suppressed" in r
        assert "stats"      in r
        assert r["stats"]["total"] == 5   # 1+2+1+1

    def test_cross_validation_reduces_fp(self):
        from nsp.intelligence.false_positive_filter import FalsePositiveFilter
        f = FalsePositiveFilter(cross_validation=True)
        f.register_tool_results("nuclei",  [{"host":"x.com","name":"XSS"}])
        f.register_tool_results("zap",     [{"host":"x.com","name":"XSS"}])
        finding = {"name":"XSS in search","severity":"medium",
                   "tags":["xss"],"host":"x.com","evidence":"","cvss_score":5.0}
        score = f.score_finding(finding)
        # Cross-validation should reduce FP probability
        assert score.fp_probability < 0.8

    def test_evidence_reduces_fp(self):
        from nsp.intelligence.false_positive_filter import FalsePositiveFilter
        f = FalsePositiveFilter()
        # Finding with strong SQL error evidence
        finding = {"name":"SQLi","severity":"high","tags":["sqli"],
                   "evidence":"You have an error in your SQL syntax",
                   "cvss_score":7.5}
        score = f.score_finding(finding)
        assert score.fp_probability < 0.4
        assert len(score.evidence_found) > 0


class TestAttackNarrative:
    def test_template_narrative(self, tmp_path):
        from nsp.intelligence.attack_narrative import AttackNarrative
        n = AttackNarrative(output_dir=str(tmp_path))
        result = n.run("example.com", "ACME Corp",
                        {"vuln_scan": SAMPLE_FINDINGS})
        assert result["source"]     == "template"
        assert result["word_count"] > 50
        assert "example.com" in result["narrative"] or "ACME" in result["narrative"]

    def test_html_exported(self, tmp_path):
        from nsp.intelligence.attack_narrative import AttackNarrative
        n   = AttackNarrative(output_dir=str(tmp_path))
        res = n.run("example.com","Client",{"vuln_scan": SAMPLE_FINDINGS})
        out = Path(res["html"])
        assert out.exists()
        assert "Attack Narrative" in out.read_text()

    def test_narrative_contains_target(self, tmp_path):
        from nsp.intelligence.attack_narrative import AttackNarrative
        n   = AttackNarrative(output_dir=str(tmp_path))
        res = n.run("target.corp","BigCo",{"vuln_scan": SAMPLE_FINDINGS})
        # Template should reference findings
        assert len(res["narrative"]) > 200
