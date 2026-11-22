"""
BugHawk AI 2.0 — Scope Guardian
Deterministic security boundary for authorized target validation.

This module NEVER uses an LLM for scope decisions.
All authorization checks are pure Python logic.

Design:
- Exact hostname authorization: only the exact host is allowed.
- Wildcard authorization: *.example.com allows example.com and all subdomains.
- Suffix bypass prevention: notexample.com does not match *.example.com.
- IP address handling: rejected unless explicitly authorized.
- Malformed input: always rejected.

Audit log entry is created for every validation call.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class ScopeDecision(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    INVALID = "invalid"


@dataclass
class ScopeRule:
    """A single authorization rule."""
    raw: str
    is_wildcard: bool = False
    root_domain: str = ""  # e.g. "example.com" for *.example.com

    def __post_init__(self):
        self.raw = self.raw.strip().lower()
        if self.raw.startswith("*."):
            self.is_wildcard = True
            self.root_domain = self.raw[2:]  # strip "*."
        else:
            self.root_domain = self.raw


@dataclass
class ScopeValidationResult:
    """Result of a scope validation check."""
    decision: ScopeDecision
    target: str
    normalized_host: str
    matched_rule: Optional[str]
    reason: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def is_allowed(self) -> bool:
        return self.decision == ScopeDecision.ALLOWED


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_VALID_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


def _normalize_host(raw: str) -> Tuple[bool, str, str]:
    """
    Normalize a target string to a bare hostname.

    Returns (success, normalized_host, failure_reason).
    Accepts: bare hostnames, http(s):// URLs.
    Rejects: empty strings, paths without hosts, malformed inputs.
    """
    raw = raw.strip().lower()
    if not raw:
        return False, "", "Empty target"

    # If it looks like a URL, parse it
    if raw.startswith(("http://", "https://")):
        try:
            parsed = urlparse(raw)
            host = parsed.hostname or ""
        except Exception:
            return False, "", "Malformed URL"
    elif "://" in raw:
        return False, "", "Unsupported URL scheme"
    else:
        # Bare hostname or host:port
        host = raw.split(":")[0]  # strip port if present

    # Remove trailing dot (FQDN notation)
    host = host.rstrip(".")

    if not host:
        return False, "", "No hostname extracted"

    return True, host, ""


def _canonical_ip(value: str) -> Optional[str]:
    """Return the normalized IP, or None when the value is not an IP."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _is_ip_address(host: str) -> bool:
    """Return True if host is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_valid_hostname(host: str) -> bool:
    """Return True if host passes RFC-compliant hostname validation."""
    if len(host) > 253:
        return False
    return bool(_VALID_HOSTNAME_RE.match(host))


def _host_matches_rule(host: str, rule: ScopeRule) -> bool:
    """
    Check if host is authorized by rule.

    Exact rule "example.com":
        - Allows exactly "example.com".
        - Does NOT allow "sub.example.com".

    Wildcard rule "*.example.com":
        - Allows "example.com" (root itself).
        - Allows "sub.example.com".
        - Allows "api.sub.example.com".
        - Rejects "notexample.com".
        - Rejects "example.com.attacker.test".

    Suffix bypass prevention:
        - For wildcard *.example.com, host must either equal root_domain
          OR end with "." + root_domain (not just contain it).
    """
    if not rule.is_wildcard:
        # Exact match only
        return host == rule.root_domain

    # Wildcard: allow root domain itself
    if host == rule.root_domain:
        return True

    # Wildcard: allow any subdomain — MUST end with ".<root_domain>"
    return host.endswith("." + rule.root_domain)


# ---------------------------------------------------------------------------
# Scope Guardian class
# ---------------------------------------------------------------------------

class ScopeGuardian:
    """
    Deterministic scope validation engine.

    Instantiate with a list of authorized scope rules (strings).
    Call .validate(target) for each target before any action.
    """

    def __init__(self, authorized_scopes: List[str], authorized_ips: Optional[Set[str]] = None):
        self.rules: List[ScopeRule] = []
        self.authorized_ips: Set[str] = set()
        for ip in authorized_ips or set():
            canonical = _canonical_ip(ip)
            if canonical:
                self.authorized_ips.add(canonical)
        self._audit_log: List[ScopeValidationResult] = []

        for scope_str in authorized_scopes:
            scope_str = scope_str.strip().lower()
            if scope_str:
                self.rules.append(ScopeRule(raw=scope_str))

    @classmethod
    def from_scope_values(cls, scope_values: List[str]) -> "ScopeGuardian":
        """Build a guardian from stored scope strings.

        An exact IP scope authorizes that IP. Other values stay hostname rules.
        """
        hosts: List[str] = []
        ips: Set[str] = set()
        for raw in scope_values:
            text = (raw or "").strip()
            if not text:
                continue
            canonical = _canonical_ip(text)
            if canonical:
                ips.add(canonical)
            else:
                hosts.append(text)
        return cls(hosts, ips)

    def validate(self, target: str) -> ScopeValidationResult:
        """
        Validate a target against authorized scopes.
        Records an audit log entry regardless of decision.
        """
        # Step 1: Normalize
        ok, host, reason = _normalize_host(target)
        if not ok:
            result = ScopeValidationResult(
                decision=ScopeDecision.INVALID,
                target=target,
                normalized_host="",
                matched_rule=None,
                reason=f"Normalization failed: {reason}",
            )
            self._audit_log.append(result)
            return result

        # Step 2: IP address check. Only the canonical address is authorized.
        if _is_ip_address(host):
            host = _canonical_ip(host) or host
            if host in self.authorized_ips:
                result = ScopeValidationResult(
                    decision=ScopeDecision.ALLOWED,
                    target=target,
                    normalized_host=host,
                    matched_rule=host,
                    reason="IP address explicitly authorized",
                )
            else:
                result = ScopeValidationResult(
                    decision=ScopeDecision.DENIED,
                    target=target,
                    normalized_host=host,
                    matched_rule=None,
                    reason="IP address not in authorized IP list",
                )
            self._audit_log.append(result)
            return result

        # Step 3: Hostname format validation
        if not _is_valid_hostname(host):
            result = ScopeValidationResult(
                decision=ScopeDecision.INVALID,
                target=target,
                normalized_host=host,
                matched_rule=None,
                reason=f"Invalid hostname format: {host}",
            )
            self._audit_log.append(result)
            return result

        # Step 4: Match against rules (order: exact rules first, then wildcards)
        for rule in sorted(self.rules, key=lambda r: r.is_wildcard):
            if _host_matches_rule(host, rule):
                result = ScopeValidationResult(
                    decision=ScopeDecision.ALLOWED,
                    target=target,
                    normalized_host=host,
                    matched_rule=rule.raw,
                    reason=f"Matched scope rule: {rule.raw}",
                )
                self._audit_log.append(result)
                return result

        # Step 5: Denied
        result = ScopeValidationResult(
            decision=ScopeDecision.DENIED,
            target=target,
            normalized_host=host,
            matched_rule=None,
            reason=f"Host '{host}' does not match any authorized scope",
        )
        self._audit_log.append(result)
        return result

    def validate_many(self, targets: List[str]) -> List[ScopeValidationResult]:
        """Validate multiple targets. Returns one result per target."""
        return [self.validate(t) for t in targets]

    def filter_authorized(self, targets: List[str]) -> List[str]:
        """Return only targets that pass scope validation."""
        return [
            t for t in targets
            if self.validate(t).is_allowed
        ]

    def get_audit_log(self) -> List[ScopeValidationResult]:
        """Return a copy of the audit log."""
        return list(self._audit_log)

    def clear_audit_log(self) -> None:
        """Clear the in-memory audit log."""
        self._audit_log.clear()


# ---------------------------------------------------------------------------
# Convenience function for one-off validation
# ---------------------------------------------------------------------------

def validate_target(target: str, authorized_scopes: List[str]) -> ScopeValidationResult:
    """One-shot scope validation without maintaining a guardian instance."""
    guardian = ScopeGuardian(authorized_scopes)
    return guardian.validate(target)
