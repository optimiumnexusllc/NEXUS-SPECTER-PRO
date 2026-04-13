"""
NEXUS SPECTER PRO — Dashboard API Integration Tests
Tests the FastAPI v2 backend endpoints end-to-end.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport


@pytest.fixture(scope="module")
def app():
    from dashboard.backend.main_v2 import app as _app
    return _app


@pytest.fixture(scope="module")
async def auth_headers(app):
    """Get JWT token and return auth headers."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/auth/login",
                         json={"username": "admin", "password": "nsp_admin_2025!"})
        if r.status_code == 200:
            token = r.json().get("access_token","")
            return {"Authorization": f"Bearer {token}"}
    return {}


class TestSystemEndpoints:
    async def test_health(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "operational"
        assert "NEXUS SPECTER PRO" in data["platform"]

    async def test_root(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/")
        assert r.status_code == 200
        assert r.json()["company"] == "OPTIMIUM NEXUS LLC"


class TestAuth:
    async def test_login_success(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/auth/login",
                             json={"username":"admin","password":"nsp_admin_2025!"})
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    async def test_login_wrong_password(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/auth/login",
                             json={"username":"admin","password":"wrong"})
        assert r.status_code == 401

    async def test_me_authenticated(self, app, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/auth/me", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["username"] == "admin"

    async def test_unauthorized_without_token(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/missions")
        assert r.status_code == 401


class TestMissions:
    async def test_list_missions_empty(self, app, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/missions", headers=auth_headers)
        assert r.status_code == 200
        assert "missions" in r.json()
        assert "total" in r.json()

    async def test_create_mission(self, app, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/missions", headers=auth_headers, json={
                "name":      "Test Mission",
                "target":    "example.com",
                "mode":      "black_box",
                "ai_assist": False,
            })
        assert r.status_code == 201
        data = r.json()
        assert data["target"] == "example.com"
        assert data["mode"]   == "black_box"
        assert data["id"].startswith("NSP-")
        return data["id"]

    async def test_get_mission(self, app, auth_headers):
        # Create first
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/missions", headers=auth_headers, json={
                "name":"Get Test","target":"gettest.com","mode":"gray_box"})
            mid = r.json()["id"]
            r2  = await c.get(f"/api/missions/{mid}", headers=auth_headers)
        assert r2.status_code == 200
        assert r2.json()["id"] == mid

    async def test_get_mission_not_found(self, app, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/missions/NSP-DOESNOTEXIST", headers=auth_headers)
        assert r.status_code == 404

    async def test_delete_mission(self, app, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r  = await c.post("/api/missions", headers=auth_headers,
                              json={"name":"Delete Me","target":"del.com","mode":"black_box"})
            mid = r.json()["id"]
            r2  = await c.delete(f"/api/missions/{mid}", headers=auth_headers)
        assert r2.status_code == 200
        assert r2.json()["status"] == "deleted"


class TestTargets:
    async def test_add_and_list_target(self, app, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/targets", headers=auth_headers, json={
                "host":"example.com","type":"domain","scope":"in"})
            assert r.status_code == 201
            tid = r.json()["id"]
            r2  = await c.get("/api/targets", headers=auth_headers)
        assert r2.status_code == 200
        assert any(t["id"] == tid for t in r2.json()["targets"])


class TestResults:
    async def test_add_and_filter_results(self, app, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Create a mission first
            rm = await c.post("/api/missions", headers=auth_headers,
                              json={"name":"RTest","target":"r.com","mode":"black_box"})
            mid = rm.json()["id"]

            # Add findings
            for sev in ["critical","high","medium"]:
                await c.post("/api/results", headers=auth_headers, json={
                    "mission_id":  mid,
                    "name":        f"Test {sev} finding",
                    "severity":    sev,
                    "host":        "r.com",
                    "description": f"Test {sev} vulnerability",
                    "tool":        "nuclei",
                })

            # List all
            r  = await c.get("/api/results", headers=auth_headers)
            # Filter by severity
            r2 = await c.get("/api/results?severity=critical", headers=auth_headers)

        assert r.status_code == 200
        assert r2.status_code == 200
        crits = r2.json()["results"]
        assert all(x["severity"] == "critical" for x in crits)


class TestStats:
    async def test_stats_structure(self, app, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/stats", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert "total_missions"  in data
        assert "total_findings"  in data
        assert "by_severity"     in data
        assert "platform"        in data
        assert data["platform"]["company"] == "OPTIMIUM NEXUS LLC"
