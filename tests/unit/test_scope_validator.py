"""
NEXUS SPECTER PRO — Scope Validator Unit Tests
by OPTIMIUM NEXUS LLC
"""
import pytest
from nsp.core.scope_validator import ScopeValidator, ScopeConfig


@pytest.fixture
def scope():
    cfg = ScopeConfig(
        client="Test Client",
        in_scope_domains=["*.example.com", "example.com", "api.target.org"],
        in_scope_ips=["192.168.1.0/24", "10.0.0.0/8"],
        out_scope_domains=["partner.example.com"],
        out_scope_ips=["192.168.1.254/32"],
    )
    return ScopeValidator(scope_config=cfg)


class TestScopeValidator:

    def test_in_scope_domain(self, scope):
        r = scope.check("app.example.com")
        assert r.in_scope is True

    def test_out_of_scope_domain(self, scope):
        r = scope.check("google.com")
        assert r.in_scope is False

    def test_explicit_out_of_scope(self, scope):
        r = scope.check("partner.example.com")
        assert r.in_scope is False

    def test_in_scope_ip(self, scope):
        r = scope.check("192.168.1.100")
        assert r.in_scope is True

    def test_out_of_scope_ip(self, scope):
        r = scope.check("192.168.1.254")
        assert r.in_scope is False

    def test_url_extraction(self, scope):
        r = scope.check("https://app.example.com/login")
        assert r.in_scope is True

    def test_wildcard_match(self, scope):
        r = scope.check("deep.nested.example.com")
        assert r.in_scope is True

    def test_no_scope_allows_all(self):
        validator = ScopeValidator()
        r = validator.check("anything.com")
        assert r.in_scope is True

    def test_assert_raises_on_oos(self, scope):
        with pytest.raises(ValueError, match="OUT OF SCOPE"):
            scope.assert_in_scope("google.com")

    def test_validate_list(self, scope):
        targets = ["app.example.com", "192.168.1.1", "google.com", "192.168.1.254"]
        approved, blocked = scope.validate_list(targets)
        assert "app.example.com" in approved
        assert "192.168.1.1"     in approved
        assert any("google.com"      in b[0] for b in blocked)
        assert any("192.168.1.254"   in b[0] for b in blocked)
