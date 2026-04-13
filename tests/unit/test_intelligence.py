"""
NEXUS SPECTER PRO — Intelligence Modules Unit Tests
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""
import pytest
from unittest.mock import patch, MagicMock


class TestThreatIntelEngine:

    def test_detect_type_ip(self):
        from nsp.intelligence.threat_intel_engine import ThreatIntelEngine
        eng = ThreatIntelEngine()
        assert eng._detect_type("192.168.1.1") == "ip"

    def test_detect_type_domain(self):
        from nsp.intelligence.threat_intel_engine import ThreatIntelEngine
        eng = ThreatIntelEngine()
        assert eng._detect_type("example.com") == "domain"

    def test_detect_type_url(self):
        from nsp.intelligence.threat_intel_engine import ThreatIntelEngine
        eng = ThreatIntelEngine()
        assert eng._detect_type("https://example.com/path") == "url"

    def test_detect_type_hash(self):
        from nsp.intelligence.threat_intel_engine import ThreatIntelEngine
        eng = ThreatIntelEngine()
        assert eng._detect_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_compute_score_zero(self):
        from nsp.intelligence.threat_intel_engine import ThreatIntelEngine, SourceResult
        eng = ThreatIntelEngine()
        sources = {"shodan": SourceResult("shodan", score=0),
                   "vt":     SourceResult("vt",     score=0)}
        score, level, _ = eng._compute_score(sources)
        assert score == 0.0
        assert level == "MINIMAL"

    def test_compute_score_critical(self):
        from nsp.intelligence.threat_intel_engine import ThreatIntelEngine, SourceResult
        eng = ThreatIntelEngine()
        sources = {"shodan": SourceResult("shodan", score=25),
                   "vt":     SourceResult("vt",     score=20),
                   "gn":     SourceResult("gn",     score=20),
                   "abuseipdb": SourceResult("abuseipdb", score=15)}
        score, level, _ = eng._compute_score(sources)
        assert level == "CRITICAL"

    def test_cache_save_load(self, tmp_path):
        from nsp.intelligence.threat_intel_engine import ThreatIntelEngine
        eng = ThreatIntelEngine(cache_dir=str(tmp_path))
        data = {"target": "1.2.3.4", "threat_score": 42.0,
                "queried_at": "2025-04-13T12:00:00"}
        eng._save_cache("1.2.3.4", data)
        loaded = eng._load_cache("1.2.3.4")
        assert loaded is not None
        assert loaded["threat_score"] == 42.0

    def test_confidence_high(self):
        from nsp.intelligence.threat_intel_engine import ThreatIntelEngine, SourceResult
        eng = ThreatIntelEngine()
        sources = {f"src{i}": SourceResult(f"src{i}", error="") for i in range(5)}
        assert eng._compute_confidence(sources) == "High"

    def test_confidence_low_all_errors(self):
        from nsp.intelligence.threat_intel_engine import ThreatIntelEngine, SourceResult
        eng = ThreatIntelEngine()
        sources = {"s1": SourceResult("s1", error="key missing")}
        assert eng._compute_confidence(sources) == "Low"


class TestCVECorrelator:

    def test_parse_nvd_record_empty(self):
        from nsp.intelligence.cve_correlator import CVECorrelator
        corr = CVECorrelator()
        record = corr._parse_nvd_record({"cve": {"id":"CVE-2021-44228",
                                                   "descriptions":[{"lang":"en","value":"Log4Shell"}],
                                                   "published":"2021-12-10T00:00:00",
                                                   "lastModified":"2022-01-01T00:00:00"}})
        assert record.cve_id == "CVE-2021-44228"
        assert "Log4Shell" in record.description

    def test_kev_loaded_structure(self):
        from nsp.intelligence.cve_correlator import CVECorrelator
        # Without network, kev_data should be empty dict or pre-populated from cache
        corr = CVECorrelator()
        assert isinstance(corr.kev_data, dict)

    def test_check_kev_not_in_kev(self):
        from nsp.intelligence.cve_correlator import CVECorrelator, CVERecord
        corr = CVECorrelator()
        corr.kev_data = {}  # empty
        rec = CVERecord(cve_id="CVE-2099-99999")
        rec = corr._check_kev(rec)
        assert rec.in_cisa_kev is False

    def test_check_kev_in_kev(self):
        from nsp.intelligence.cve_correlator import CVECorrelator, CVERecord
        corr = CVECorrelator()
        corr.kev_data = {"CVE-2021-44228": {"dueDate":"2021-12-24",
                                              "knownRansomwareCampaignUse":"Known"}}
        rec = CVERecord(cve_id="CVE-2021-44228")
        rec = corr._check_kev(rec)
        assert rec.in_cisa_kev is True
        assert rec.weaponization_score >= 5

    def test_compute_weaponization_immediate(self):
        from nsp.intelligence.cve_correlator import CVECorrelator, CVERecord
        corr   = CVECorrelator()
        record = CVERecord(cve_id="CVE-2021-44228", cvss_v3_score=10.0,
                           in_cisa_kev=True, exploit_available=True,
                           github_pocs=10, metasploit_module=True)
        record = corr._compute_weaponization(record)
        assert record.priority == "IMMEDIATE"
        assert record.weaponization_score == 10


class TestAttackGraph:

    def test_add_nodes_edges(self):
        from nsp.intelligence.attack_graph import AttackGraph, AttackNode, AttackEdge
        g = AttackGraph(output_dir="/tmp/nsp_test_graph")
        g.add_node(AttackNode("A", "Attacker", "attacker"))
        g.add_node(AttackNode("B", "Target",   "host"))
        g.add_edge(AttackEdge("A", "B", "exploits", weight=2))
        assert len(g.nodes) == 2
        assert len(g.edges_) == 1

    def test_demo_graph_builds(self):
        from nsp.intelligence.attack_graph import AttackGraph
        g = AttackGraph(output_dir="/tmp/nsp_test_graph")
        g._build_demo_graph()
        assert len(g.nodes) >= 4
        assert len(g.edges_) >= 4

    def test_attack_paths_found(self):
        from nsp.intelligence.attack_graph import AttackGraph
        g = AttackGraph(output_dir="/tmp/nsp_test_graph")
        g._build_demo_graph()
        paths = g.find_attack_paths()
        assert isinstance(paths, list)

    def test_export_d3_html(self, tmp_path):
        from nsp.intelligence.attack_graph import AttackGraph
        g = AttackGraph(output_dir=str(tmp_path))
        g._build_demo_graph()
        out = g.export_d3_html()
        assert out.exists()
        content = out.read_text()
        assert "NEXUS SPECTER PRO" in content
        assert "d3" in content.lower()

    def test_chokepoints(self):
        from nsp.intelligence.attack_graph import AttackGraph
        g = AttackGraph(output_dir="/tmp/nsp_test_graph")
        g._build_demo_graph()
        choke = g.find_chokepoints()
        assert isinstance(choke, list)

    def test_blast_radius(self):
        from nsp.intelligence.attack_graph import AttackGraph
        g = AttackGraph(output_dir="/tmp/nsp_test_graph")
        g._build_demo_graph()
        br = g.blast_radius("ATTACKER")
        assert "reachable_nodes" in br
        assert br["reachable_nodes"] >= 0


class TestIOCTracker:

    def test_detect_type_ip(self):
        from nsp.intelligence.ioc_tracker import IOCTracker
        t = IOCTracker(output_dir="/tmp/nsp_test_ioc")
        assert t.detect_type("192.168.1.1") == "ipv4"

    def test_detect_type_domain(self):
        from nsp.intelligence.ioc_tracker import IOCTracker
        t = IOCTracker(output_dir="/tmp/nsp_test_ioc")
        assert t.detect_type("evil.example.com") == "domain"

    def test_detect_type_sha256(self):
        from nsp.intelligence.ioc_tracker import IOCTracker
        t = IOCTracker(output_dir="/tmp/nsp_test_ioc")
        h = "a" * 64
        assert t.detect_type(h) == "sha256"

    def test_detect_type_cve(self):
        from nsp.intelligence.ioc_tracker import IOCTracker
        t = IOCTracker(output_dir="/tmp/nsp_test_ioc")
        assert t.detect_type("CVE-2021-44228") == "cve"

    def test_register_ttp_known(self):
        from nsp.intelligence.ioc_tracker import IOCTracker
        t = IOCTracker(output_dir="/tmp/nsp_test_ioc")
        t.register_ttp("mimikatz")
        assert "T1003.001" in t._ttp_map

    def test_register_ttp_unknown(self):
        from nsp.intelligence.ioc_tracker import IOCTracker
        t = IOCTracker(output_dir="/tmp/nsp_test_ioc")
        # Should not raise
        t.register_ttp("totally_unknown_ttp_xyz")
        assert "totally_unknown_ttp_xyz" not in t._ttp_map

    def test_threat_actor_matching(self):
        from nsp.intelligence.ioc_tracker import IOCTracker
        t = IOCTracker(output_dir="/tmp/nsp_test_ioc")
        # Register APT28-like TTPs
        for ttp in ["phishing","powershell","mimikatz","pass_the_hash"]:
            t.register_ttp(ttp)
        matches = t.match_threat_actors()
        assert isinstance(matches, list)
        assert len(matches) > 0
        # APT28 should score highest
        assert matches[0]["actor"] == "APT28"

    def test_navigator_export(self, tmp_path):
        from nsp.intelligence.ioc_tracker import IOCTracker
        t = IOCTracker(output_dir=str(tmp_path))
        t.register_ttp("mimikatz")
        t.register_ttp("kerberoasting")
        path = t.export_navigator_layer()
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["domain"] == "enterprise-attack"
        assert len(data["techniques"]) >= 2

    def test_ingest_iocs(self):
        from nsp.intelligence.ioc_tracker import IOCTracker
        t = IOCTracker(output_dir="/tmp/nsp_test_ioc")
        values = ["192.168.1.1","evil.com","CVE-2021-44228"]
        iocs = t.ingest(values, auto_enrich=False)
        assert len(iocs) == 3
        types = {i.ioc_type for i in iocs}
        assert "ipv4" in types
        assert "domain" in types
        assert "cve" in types


import json
