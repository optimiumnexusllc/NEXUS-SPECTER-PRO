"""
NEXUS SPECTER PRO — Sprint 8 Unit Tests
Automation & DevSecOps modules.
by OPTIMIUM NEXUS LLC
"""
import pytest, json
from pathlib import Path


class TestMissionScheduler:
    def test_add_schedule_preset(self, tmp_path):
        from nsp.automation.mission_scheduler import MissionScheduler
        s = MissionScheduler()
        s.STORE_PATH = tmp_path / "schedules.json"
        sched = s.add("Test Scan","example.com","black_box",preset="weekly")
        assert sched.schedule_id
        assert sched.target == "example.com"
        assert sched.interval_hours == 168 or sched.cron_expr

    def test_add_remove_schedule(self, tmp_path):
        from nsp.automation.mission_scheduler import MissionScheduler
        s = MissionScheduler()
        s.STORE_PATH = tmp_path / "schedules.json"
        sched = s.add("Test","target.com","black_box",interval_hours=24)
        sid   = sched.schedule_id
        assert sid in s._schedules
        s.remove(sid)
        assert sid not in s._schedules

    def test_enable_disable(self, tmp_path):
        from nsp.automation.mission_scheduler import MissionScheduler
        s = MissionScheduler()
        s.STORE_PATH = tmp_path / "schedules.json"
        sched = s.add("Test","target.com","black_box",interval_hours=12)
        s.disable(sched.schedule_id)
        assert not s._schedules[sched.schedule_id].enabled
        s.enable(sched.schedule_id)
        assert s._schedules[sched.schedule_id].enabled

    def test_stats(self, tmp_path):
        from nsp.automation.mission_scheduler import MissionScheduler
        s = MissionScheduler()
        s.STORE_PATH = tmp_path / "schedules.json"
        s.add("A","a.com","black_box",interval_hours=24)
        s.add("B","b.com","black_box",interval_hours=48)
        stats = s.get_stats()
        assert stats.total_schedules == 2
        assert stats.active_schedules == 2

    def test_presets_available(self):
        from nsp.automation.mission_scheduler import SCHEDULE_PRESETS
        assert "daily"   in SCHEDULE_PRESETS
        assert "weekly"  in SCHEDULE_PRESETS
        assert "monthly" in SCHEDULE_PRESETS


class TestParallelExecutor:
    def test_chunk_targets(self):
        from nsp.automation.parallel_executor import ParallelExecutor
        targets = list(range(120))
        chunks  = ParallelExecutor.chunk_targets(targets, 50)
        assert len(chunks) == 3
        assert len(chunks[0]) == 50
        assert len(chunks[2]) == 20

    def test_empty_targets(self):
        from nsp.automation.parallel_executor import ParallelExecutor
        ex = ParallelExecutor(max_concurrent=2)
        result = ex.run([])
        assert result.total == 0

    def test_run_with_mock_worker(self):
        import asyncio
        from nsp.automation.parallel_executor import ParallelExecutor

        async def mock_worker(target, **kw):
            await asyncio.sleep(0.01)
            return {"status":"success","target":target,
                    "session_id":f"MOCK-{target}","by_severity":{}}

        ex = ParallelExecutor(max_concurrent=3, target_timeout=10)
        targets = ["target1.com","target2.com","target3.com"]
        summary = ex.run(targets, worker=mock_worker)
        assert summary.total    == 3
        assert summary.succeeded == 3
        assert summary.failed   == 0


class TestAssetDiscovery:
    def test_register_new_asset(self, tmp_path):
        from nsp.automation.asset_discovery import AssetDiscovery
        d = AssetDiscovery("AcmeCorp","acme.com",output_dir=str(tmp_path))
        d.INVENTORY_DIR = tmp_path / "inv"
        d.INVENTORY_DIR.mkdir()
        asset = d._register("subdomain","app.acme.com","ct_logs",risk=15)
        assert asset.is_new is True
        assert asset.asset_type == "subdomain"

    def test_register_existing_not_new(self, tmp_path):
        from nsp.automation.asset_discovery import AssetDiscovery
        d = AssetDiscovery("AcmeCorp","acme.com",output_dir=str(tmp_path))
        d.INVENTORY_DIR = tmp_path / "inv"
        d.INVENTORY_DIR.mkdir()
        d._register("subdomain","app.acme.com","ct_logs")
        d._save_inventory()
        d._load_inventory()
        asset2 = d._register("subdomain","app.acme.com","ct_logs")
        assert asset2.is_new is False

    def test_inventory_summary(self, tmp_path):
        from nsp.automation.asset_discovery import AssetDiscovery
        d = AssetDiscovery("AcmeCorp","acme.com",output_dir=str(tmp_path))
        d.INVENTORY_DIR = tmp_path / "inv"
        d.INVENTORY_DIR.mkdir()
        d._register("subdomain","a.acme.com","ct")
        d._register("ip","1.2.3.4","shodan")
        summary = d.get_inventory_summary()
        assert summary["total_assets"] == 2
        assert summary["by_type"]["subdomain"] == 1
        assert summary["by_type"]["ip"] == 1


class TestChangeDetector:
    def test_fingerprint_stable(self):
        from nsp.automation.change_detector import ChangeDetector
        cd = ChangeDetector()
        f  = {"name":"SQL Injection","host":"example.com","severity":"critical"}
        fp1 = cd._fingerprint(f)
        fp2 = cd._fingerprint(f)
        assert fp1.sig == fp2.sig

    def test_compute_risk_score(self):
        from nsp.automation.change_detector import ChangeDetector
        cd = ChangeDetector()
        session = {"vuln_scan":{"by_severity":{
            "critical":[{}],"high":[{},{}],"medium":[{},{},{}],"low":[],"info":[]
        }}}
        # 1×15 + 2×8 + 3×4 = 15+16+12 = 43
        score = cd._compute_risk_score(session)
        assert score == 43.0

    def test_compare_detects_new(self, tmp_path):
        from nsp.automation.change_detector import ChangeDetector
        cd = ChangeDetector(output_dir=str(tmp_path))
        baseline = {"target":"t.com","vuln_scan":{"by_severity":{
            "critical":[],"high":[],"medium":[],"low":[],"info":[]
        }}}
        current  = {"target":"t.com","vuln_scan":{"by_severity":{
            "critical":[{"name":"SQLi","host":"t.com","severity":"critical"}],
            "high":[],"medium":[],"low":[],"info":[]
        }}}
        report = cd.compare(baseline, current, "base","curr")
        assert len(report.new_vulns)   == 1
        assert len(report.resolved_vulns) == 0
        assert report.new_critical    == 1
        assert report.risk_regression is True

    def test_compare_detects_resolved(self, tmp_path):
        from nsp.automation.change_detector import ChangeDetector
        cd = ChangeDetector(output_dir=str(tmp_path))
        baseline = {"target":"t.com","vuln_scan":{"by_severity":{
            "high":[{"name":"XSS","host":"t.com","severity":"high"}],
            "critical":[],"medium":[],"low":[],"info":[]
        }}}
        current = {"target":"t.com","vuln_scan":{"by_severity":{
            "critical":[],"high":[],"medium":[],"low":[],"info":[]
        }}}
        report = cd.compare(baseline, current)
        assert len(report.resolved_vulns) == 1
        assert report.direction == "improving"

    def test_save_load_snapshot(self, tmp_path):
        from nsp.automation.change_detector import ChangeDetector
        cd = ChangeDetector(output_dir=str(tmp_path))
        cd.SCAN_STORE = tmp_path / "snaps"
        cd.SCAN_STORE.mkdir()
        data = {"target":"t.com","vuln_scan":{"by_severity":{}}}
        cd.save_snapshot("NSP-001", data)
        loaded = cd.load_snapshot("NSP-001")
        assert loaded["target"] == "t.com"


class TestAlertEngine:
    def test_should_send_level_filter(self):
        from nsp.automation.alert_engine import AlertEngine, AlertConfig
        eng = AlertEngine(AlertConfig(min_level="warning", enabled=True))
        assert eng._should_send("critical") is True
        assert eng._should_send("warning")  is True
        assert eng._should_send("info")     is False

    def test_disabled_engine(self):
        from nsp.automation.alert_engine import AlertEngine, AlertConfig
        eng = AlertEngine(AlertConfig(enabled=False))
        assert eng._should_send("critical") is False

    def test_send_returns_alert(self):
        from nsp.automation.alert_engine import AlertEngine, AlertConfig
        # No channels configured → console only, no HTTP calls
        eng   = AlertEngine(AlertConfig(enabled=True))
        alert = eng.send("Test Alert","Test message","info")
        assert alert.title   == "Test Alert"
        assert alert.level   == "info"

    def test_mission_complete_alert(self):
        from nsp.automation.alert_engine import AlertEngine, AlertConfig
        eng = AlertEngine(AlertConfig(enabled=True, min_level="info"))
        alert = eng.mission_complete(
            "example.com","NSP-001",
            {"critical":0,"high":2,"medium":5,"low":3}
        )
        assert alert.level in ("warning","info","critical")
        assert "NSP-001" in alert.message


class TestSupplyChain:
    def test_detect_python_project(self, tmp_path):
        from nsp.devsecops.supply_chain_audit import SupplyChainAuditor
        (tmp_path/"requirements.txt").write_text("requests==2.28.0\nnumpy>=1.21.0\n")
        a = SupplyChainAuditor(project_path=str(tmp_path), output_dir=str(tmp_path/"out"))
        eco = a._detect_ecosystems()
        assert "python" in eco

    def test_detect_npm_project(self, tmp_path):
        from nsp.devsecops.supply_chain_audit import SupplyChainAuditor
        (tmp_path/"package.json").write_text('{"name":"test","dependencies":{"lodash":"4.17.0"}}')
        a = SupplyChainAuditor(project_path=str(tmp_path), output_dir=str(tmp_path/"out"))
        eco = a._detect_ecosystems()
        assert "npm" in eco

    def test_sbom_from_requirements(self, tmp_path):
        from nsp.devsecops.supply_chain_audit import SupplyChainAuditor
        (tmp_path/"requirements.txt").write_text("requests==2.28.0\nflask>=2.0.0\n")
        a = SupplyChainAuditor(project_path=str(tmp_path), output_dir=str(tmp_path/"out"))
        a._scan_python()
        assert len(a.sbom) >= 2

    def test_sbom_spdx_export(self, tmp_path):
        from nsp.devsecops.supply_chain_audit import SupplyChainAuditor, SBOMEntry
        a = SupplyChainAuditor(project_path=str(tmp_path), output_dir=str(tmp_path/"out"))
        a.sbom = [SBOMEntry("requests","2.28.0","PyPI"),
                  SBOMEntry("flask","2.0.0","PyPI")]
        out  = a._export_sbom_spdx()
        data = json.loads(out.read_text())
        assert data["spdxVersion"] == "SPDX-2.3"
        assert len(data["packages"]) == 2


class TestContainerScanner:
    def test_risk_score_zero(self, tmp_path):
        from nsp.devsecops.container_scanner import ContainerScanner, ContainerScanResult
        s = ContainerScanner(output_dir=str(tmp_path))
        r = ContainerScanResult(image="test:latest", by_severity={})
        assert s._compute_risk(r) == 0

    def test_risk_score_with_crits(self, tmp_path):
        from nsp.devsecops.container_scanner import ContainerScanner, ContainerScanResult
        s = ContainerScanner(output_dir=str(tmp_path))
        r = ContainerScanResult(image="test:latest",
                                 by_severity={"critical":3,"high":2})
        score = s._compute_risk(r)
        assert score == min(3*15 + 2*8, 100)

    def test_scan_multiple_empty(self, tmp_path):
        from nsp.devsecops.container_scanner import ContainerScanner
        s = ContainerScanner(output_dir=str(tmp_path))
        # With no tool installed, returns error dict
        results = s.scan_multiple(["busybox:latest"])
        assert isinstance(results, list)
        assert len(results) == 1


class TestIaCScanner:
    def test_detect_terraform(self, tmp_path):
        from nsp.devsecops.iac_scanner import IaCScan
        (tmp_path/"main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        scanner = IaCScan(scan_path=str(tmp_path), output_dir=str(tmp_path/"out"))
        types   = scanner._detect_iac_types()
        assert "terraform" in types

    def test_detect_dockerfile(self, tmp_path):
        from nsp.devsecops.iac_scanner import IaCScan
        (tmp_path/"Dockerfile").write_text("FROM ubuntu:20.04\nRUN apt-get update\n")
        scanner = IaCScan(scan_path=str(tmp_path), output_dir=str(tmp_path/"out"))
        types   = scanner._detect_iac_types()
        assert "dockerfile" in types

    def test_detect_kubernetes(self, tmp_path):
        from nsp.devsecops.iac_scanner import IaCScan
        (tmp_path/"deployment.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: test\n"
        )
        scanner = IaCScan(scan_path=str(tmp_path), output_dir=str(tmp_path/"out"))
        types   = scanner._detect_iac_types()
        assert "kubernetes" in types


class TestSecretScanner:
    def test_builtin_detects_aws_key(self, tmp_path):
        from nsp.devsecops.secret_scanner import SecretScanner
        test_file = tmp_path / "config.py"
        test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        s = SecretScanner(scan_path=str(tmp_path), output_dir=str(tmp_path/"out"))
        findings = s._run_builtin()
        assert len(findings) >= 1
        assert any("AWS" in f.secret_type for f in findings)

    def test_builtin_skips_false_positives(self, tmp_path):
        from nsp.devsecops.secret_scanner import SecretScanner
        test_file = tmp_path / "example.py"
        test_file.write_text('KEY = "your_api_key_here"\n')
        s = SecretScanner(scan_path=str(tmp_path), output_dir=str(tmp_path/"out"))
        findings = s._run_builtin()
        assert len(findings) == 0

    def test_sarif_export(self, tmp_path):
        from nsp.devsecops.secret_scanner import SecretScanner, SecretFinding
        s = SecretScanner(scan_path=str(tmp_path), output_dir=str(tmp_path/"out"))
        s.findings = [SecretFinding("AWS Access Key","config.py",10,"","","AKI***","critical","builtin")]
        out  = s._export_sarif()
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 1

    def test_skip_binary_files(self, tmp_path):
        from nsp.devsecops.secret_scanner import SecretScanner, SKIP_EXTENSIONS
        assert ".png"  in SKIP_EXTENSIONS
        assert ".pyc"  in SKIP_EXTENSIONS
        assert ".jar"  in SKIP_EXTENSIONS


class TestCloudPosture:
    def test_mock_prowler_results(self, tmp_path):
        from nsp.devsecops.cloud_posture import CloudPosture
        cp = CloudPosture(provider="aws", output_dir=str(tmp_path))
        results = cp._mock_prowler_results()
        assert len(results) > 0
        assert any(c.status == "FAIL" for c in results)
        assert any(c.status == "PASS" for c in results)

    def test_aggregate_score(self, tmp_path):
        from nsp.devsecops.cloud_posture import CloudPosture, CloudControl
        cp = CloudPosture(provider="aws", output_dir=str(tmp_path))
        controls = [
            CloudControl("C1","Check 1","PASS","medium","iam"),
            CloudControl("C2","Check 2","PASS","high","iam"),
            CloudControl("C3","Check 3","FAIL","critical","s3"),
            CloudControl("C4","Check 4","FAIL","high","ec2"),
        ]
        report = cp._aggregate(controls)
        assert report.passed  == 2
        assert report.failed  == 2
        assert report.compliance_score == 50.0
        assert len(report.critical_fails) == 2

    def test_run_returns_dict(self, tmp_path):
        from nsp.devsecops.cloud_posture import CloudPosture
        cp = CloudPosture(provider="aws", output_dir=str(tmp_path))
        # Prowler not installed → uses mock results
        result = cp.run()
        assert "compliance_score" in result
        assert "provider"         in result
        assert 0 <= result["compliance_score"] <= 100
