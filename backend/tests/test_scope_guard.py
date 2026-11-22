"""
BugHawk AI 2.0 — Scope Guardian Tests

Tests the deterministic scope validation engine.
Run: pytest tests/test_scope_guard.py -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.core.scope_guard import (
    ScopeGuardian, ScopeDecision, validate_target,
    _normalize_host, _is_ip_address, _is_valid_hostname, _host_matches_rule,
    ScopeRule,
)


# ---------------------------------------------------------------------------
# Normalization tests
# ---------------------------------------------------------------------------

class TestNormalization:
    def test_bare_hostname(self):
        ok, host, _ = _normalize_host("example.com")
        assert ok and host == "example.com"

    def test_https_url(self):
        ok, host, _ = _normalize_host("https://example.com/path?q=1")
        assert ok and host == "example.com"

    def test_http_url(self):
        ok, host, _ = _normalize_host("http://sub.example.com")
        assert ok and host == "sub.example.com"

    def test_host_with_port(self):
        ok, host, _ = _normalize_host("example.com:8080")
        assert ok and host == "example.com"

    def test_uppercase_normalized(self):
        ok, host, _ = _normalize_host("EXAMPLE.COM")
        assert ok and host == "example.com"

    def test_trailing_dot_stripped(self):
        ok, host, _ = _normalize_host("example.com.")
        assert ok and host == "example.com"

    def test_empty_string_rejected(self):
        ok, host, reason = _normalize_host("")
        assert not ok

    def test_unsupported_scheme_rejected(self):
        ok, host, reason = _normalize_host("ftp://example.com")
        assert not ok

    def test_whitespace_stripped(self):
        ok, host, _ = _normalize_host("  example.com  ")
        assert ok and host == "example.com"


# ---------------------------------------------------------------------------
# IP address detection
# ---------------------------------------------------------------------------

class TestIPDetection:
    def test_ipv4_detected(self):
        assert _is_ip_address("192.168.1.1") is True

    def test_ipv6_detected(self):
        assert _is_ip_address("2001:db8::1") is True

    def test_hostname_not_ip(self):
        assert _is_ip_address("example.com") is False

    def test_partial_ip_not_ip(self):
        assert _is_ip_address("192.168") is False


# ---------------------------------------------------------------------------
# Hostname validation
# ---------------------------------------------------------------------------

class TestHostnameValidation:
    def test_valid_hostname(self):
        assert _is_valid_hostname("example.com") is True

    def test_valid_subdomain(self):
        assert _is_valid_hostname("api.sub.example.com") is True

    def test_single_label_rejected(self):
        # Single-label hostnames (no dot) are invalid in our context
        assert _is_valid_hostname("localhost") is False

    def test_invalid_chars_rejected(self):
        assert _is_valid_hostname("example_com.test") is False

    def test_too_long_rejected(self):
        assert _is_valid_hostname("a" * 254 + ".com") is False


# ---------------------------------------------------------------------------
# Exact rule matching
# ---------------------------------------------------------------------------

class TestExactRuleMatching:
    def test_exact_match_allowed(self):
        rule = ScopeRule(raw="example.com")
        assert _host_matches_rule("example.com", rule) is True

    def test_subdomain_not_allowed_by_exact_rule(self):
        """This is the critical test: exact auth does NOT allow subdomains."""
        rule = ScopeRule(raw="example.com")
        assert _host_matches_rule("sub.example.com", rule) is False

    def test_different_domain_rejected(self):
        rule = ScopeRule(raw="example.com")
        assert _host_matches_rule("notexample.com", rule) is False

    def test_suffix_bypass_rejected(self):
        """example.com.attacker.test must NOT match example.com."""
        rule = ScopeRule(raw="example.com")
        assert _host_matches_rule("example.com.attacker.test", rule) is False


# ---------------------------------------------------------------------------
# Wildcard rule matching
# ---------------------------------------------------------------------------

class TestWildcardRuleMatching:
    def setup_method(self):
        self.rule = ScopeRule(raw="*.example.com")

    def test_root_domain_allowed_by_wildcard(self):
        """*.example.com should allow example.com itself."""
        assert _host_matches_rule("example.com", self.rule) is True

    def test_direct_subdomain_allowed(self):
        assert _host_matches_rule("sub.example.com", self.rule) is True

    def test_deep_subdomain_allowed(self):
        assert _host_matches_rule("api.sub.example.com", self.rule) is True

    def test_different_domain_rejected(self):
        assert _host_matches_rule("notexample.com", self.rule) is False

    def test_suffix_bypass_rejected(self):
        """example.com.attacker.test must NOT match *.example.com."""
        assert _host_matches_rule("example.com.attacker.test", self.rule) is False

    def test_partial_match_rejected(self):
        """myexample.com must NOT match *.example.com."""
        assert _host_matches_rule("myexample.com", self.rule) is False


# ---------------------------------------------------------------------------
# ScopeGuardian integration tests
# ---------------------------------------------------------------------------

class TestScopeGuardian:
    def test_exact_scope_allows_exact(self):
        guardian = ScopeGuardian(["example.com"])
        result = guardian.validate("example.com")
        assert result.is_allowed
        assert result.decision == ScopeDecision.ALLOWED

    def test_exact_scope_denies_subdomain(self):
        guardian = ScopeGuardian(["example.com"])
        result = guardian.validate("sub.example.com")
        assert not result.is_allowed
        assert result.decision == ScopeDecision.DENIED

    def test_wildcard_scope_allows_subdomain(self):
        guardian = ScopeGuardian(["*.example.com"])
        result = guardian.validate("sub.example.com")
        assert result.is_allowed

    def test_wildcard_scope_allows_root(self):
        guardian = ScopeGuardian(["*.example.com"])
        result = guardian.validate("example.com")
        assert result.is_allowed

    def test_wildcard_scope_denies_other_domain(self):
        guardian = ScopeGuardian(["*.example.com"])
        result = guardian.validate("notexample.com")
        assert not result.is_allowed

    def test_ip_rejected_without_explicit_authorization(self):
        guardian = ScopeGuardian(["example.com"])
        result = guardian.validate("192.168.1.1")
        assert not result.is_allowed

    def test_ip_allowed_when_explicitly_authorized(self):
        guardian = ScopeGuardian(["example.com"], authorized_ips={"192.168.1.1"})
        result = guardian.validate("192.168.1.1")
        assert result.is_allowed

    def test_stored_ip_scope_authorizes_exact_ip(self):
        guardian = ScopeGuardian.from_scope_values(["203.0.113.10", "example.com"])
        result = guardian.validate("203.0.113.10")
        assert result.is_allowed
        assert result.matched_rule == "203.0.113.10"

    def test_stored_ip_scope_rejects_neighbor(self):
        guardian = ScopeGuardian.from_scope_values(["203.0.113.10"])
        result = guardian.validate("203.0.113.11")
        assert not result.is_allowed
        assert result.decision == ScopeDecision.DENIED

    def test_hostname_rules_still_apply_beside_ip_scope(self):
        guardian = ScopeGuardian.from_scope_values(["203.0.113.10", "*.example.com"])
        assert guardian.validate("api.example.com").is_allowed
        assert not guardian.validate("other.test").is_allowed

    def test_malformed_input_marked_invalid(self):
        guardian = ScopeGuardian(["example.com"])
        result = guardian.validate("")
        assert result.decision == ScopeDecision.INVALID

    def test_audit_log_records_all_decisions(self):
        guardian = ScopeGuardian(["example.com"])
        guardian.validate("example.com")
        guardian.validate("other.com")
        guardian.validate("sub.example.com")
        log = guardian.get_audit_log()
        assert len(log) == 3

    def test_filter_authorized_keeps_only_allowed(self):
        guardian = ScopeGuardian(["*.example.com"])
        targets = ["sub.example.com", "other.com", "api.example.com", "192.168.1.1"]
        allowed = guardian.filter_authorized(targets)
        assert "sub.example.com" in allowed
        assert "api.example.com" in allowed
        assert "other.com" not in allowed
        assert "192.168.1.1" not in allowed

    def test_empty_scope_list_denies_everything(self):
        guardian = ScopeGuardian([])
        result = guardian.validate("example.com")
        assert not result.is_allowed

    def test_https_url_target_normalized(self):
        guardian = ScopeGuardian(["example.com"])
        result = guardian.validate("https://example.com/path?q=test")
        assert result.is_allowed

    def test_suffix_bypass_via_url(self):
        """https://evil.example.com.attacker.test should be rejected."""
        guardian = ScopeGuardian(["example.com"])
        result = guardian.validate("https://evil.example.com.attacker.test/")
        assert not result.is_allowed

    def test_mixed_scope_rules(self):
        """Test exact + wildcard rules together."""
        guardian = ScopeGuardian(["other.com", "*.example.com"])
        assert guardian.validate("other.com").is_allowed
        assert guardian.validate("sub.other.com").decision == ScopeDecision.DENIED
        assert guardian.validate("example.com").is_allowed
        assert guardian.validate("deep.sub.example.com").is_allowed

    def test_validate_many(self):
        guardian = ScopeGuardian(["example.com"])
        results = guardian.validate_many(["example.com", "other.com"])
        assert results[0].is_allowed
        assert not results[1].is_allowed


# ---------------------------------------------------------------------------
# Convenience function test
# ---------------------------------------------------------------------------

class TestValidateTarget:
    def test_convenience_function(self):
        result = validate_target("example.com", ["example.com"])
        assert result.is_allowed

    def test_convenience_function_denied(self):
        result = validate_target("other.com", ["example.com"])
        assert not result.is_allowed
