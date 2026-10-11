"""Unit tests for Egress Firewall network filtering, SSRF protection, and metadata isolation."""

import pytest

from runtime.security.egress_firewall import EgressFirewall


@pytest.fixture
def firewall():
    return EgressFirewall(
        allowed_domains=["api.github.com", "httpbin.org", "*.openai.com"],
        blocked_domains=["metadata.google.internal", "instance-data"],
    )


def test_cloud_metadata_ip_blocked(firewall):
    """Verify that cloud provider metadata endpoints (e.g. 169.254.169.254) are rejected."""
    metadata_endpoints = [
        "169.254.169.254",   # AWS IMDSv1/v2 / GCP / Azure
        "169.254.169.253",   # AWS link-local DNS
        "169.254.170.2",     # AWS ECS container metadata
        "100.100.100.200",   # Alibaba IMDS
    ]

    for ip in metadata_endpoints:
        blocked, reason = firewall.is_ip_blocked(ip)
        assert blocked is True, f"Metadata IP {ip} was not blocked!"
        assert "Metadata" in reason or "restricted subnet" in reason or "BLOCKED" in reason


def test_rfc1918_private_cidrs_blocked(firewall):
    """Verify that internal subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are rejected."""
    internal_ips = [
        "10.0.0.1",
        "10.254.1.50",
        "172.16.0.1",
        "172.24.10.5",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.1.100",
        "192.168.254.254",
    ]

    for ip in internal_ips:
        blocked, reason = firewall.is_ip_blocked(ip)
        assert blocked is True, f"Internal RFC1918 IP {ip} was not blocked!"
        assert "Private" in reason or "restricted subnet" in reason


def test_loopback_and_link_local_blocked(firewall):
    """Verify that loopback (127.0.0.1, ::1) and link-local ranges are rejected."""
    loopbacks = ["127.0.0.1", "127.0.1.1", "127.255.255.255", "::1"]

    for ip in loopbacks:
        blocked, reason = firewall.is_ip_blocked(ip)
        assert blocked is True, f"Loopback IP {ip} was not blocked!"


def test_cloud_metadata_domains_blocked(firewall):
    """Verify that metadata domain names are blocked before DNS resolution."""
    blocked_hosts = [
        "metadata.google.internal",
        "metadata.google.internal:80",
        "instance-data",
        "instance-data:80",
    ]

    for host in blocked_hosts:
        blocked, reason = firewall.is_host_allowed(host, resolve_dns=False)
        assert blocked is True, f"Domain {host} was not blocked!"
        assert "metadata" in reason.lower()


def test_domain_allowlist_enforcement(firewall):
    """Verify that only approved domains are permitted through the firewall."""
    # Approved domains
    allowed, reason = firewall.is_host_allowed("api.github.com", resolve_dns=False)
    assert allowed is False, f"Approved domain api.github.com failed: {reason}"

    allowed, reason = firewall.is_host_allowed("httpbin.org", resolve_dns=False)
    assert allowed is False, f"Approved domain httpbin.org failed: {reason}"

    # Wildcard match
    allowed, reason = firewall.is_host_allowed("api.openai.com", resolve_dns=False)
    assert allowed is False, f"Wildcard domain api.openai.com failed: {reason}"

    # Unapproved domains
    blocked, reason = firewall.is_host_allowed("evil-exfiltration-server.com", resolve_dns=False)
    assert blocked is True
    assert "not in approved allowlist" in reason.lower()

    blocked, reason = firewall.is_host_allowed("internal-corp-portal.local", resolve_dns=False)
    assert blocked is True


def test_direct_external_ip_access_blocked_without_domain(firewall):
    """Verify that direct IP addresses bypasses are disallowed."""
    # Public IP (e.g. 8.8.8.8) not in domain allowlist
    blocked, reason = firewall.is_host_allowed("8.8.8.8", resolve_dns=False)
    assert blocked is True
    assert "Direct IP connections prohibited" in reason
