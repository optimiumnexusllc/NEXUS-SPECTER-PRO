"""
NEXUS SPECTER PRO — Session Manager Unit Tests
by OPTIMIUM NEXUS LLC
"""
import pytest
from pathlib import Path
from nsp.core.session_manager import SessionManager


@pytest.fixture
def sm(tmp_path):
    return SessionManager(db_url=None)


class TestSessionManager:

    def test_create_session(self, sm):
        s = sm.create("Test Mission", "example.com", "black_box")
        assert s.session_id.startswith("NSP-")
        assert s.target == "example.com"
        assert s.mode   == "black_box"
        assert s.status == "initialised"

    def test_get_session(self, sm):
        s   = sm.create("Test", "target.com", "gray_box")
        got = sm.get(s.session_id)
        assert got is not None
        assert got.session_id == s.session_id

    def test_update_session(self, sm):
        s = sm.create("Test", "target.com", "black_box")
        sm.update(s.session_id, status="running")
        got = sm.get(s.session_id)
        assert got.status == "running"

    def test_add_finding(self, sm):
        s = sm.create("Test", "target.com", "black_box")
        sm.add_finding(s.session_id, "high", {"name": "SQLi", "url": "/login"})
        got = sm.get(s.session_id)
        assert len(got.findings.get("high",[])) == 1

    def test_add_phase(self, sm):
        s = sm.create("Test", "target.com", "black_box")
        sm.add_phase(s.session_id, "recon", {"subdomains": ["a.com"]})
        got = sm.get(s.session_id)
        assert "recon" in got.phases_done

    def test_complete_session(self, sm):
        s = sm.create("Test", "target.com", "black_box")
        sm.complete(s.session_id)
        got = sm.get(s.session_id)
        assert got.status == "complete"

    def test_audit_log(self, sm):
        s = sm.create("Test", "target.com", "black_box")
        sm.note(s.session_id, "Found interesting endpoint")
        got = sm.get(s.session_id)
        assert len(got.notes) >= 1
        assert len(got.audit_log) >= 1
