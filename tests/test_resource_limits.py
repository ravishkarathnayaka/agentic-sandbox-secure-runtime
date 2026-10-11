"""Unit tests verifying resource limits, capability tokens, path containment, and audit integrity."""

import time

import pytest

from runtime.core.session import Session, WorkspaceSecurityError
from runtime.security.capability_gate import CapabilityGate, Permission, SecurityPolicyViolation
from runtime.telemetry.audit_trail import AuditTrail


def test_capability_token_lifecycle_and_verification():
    """Verify cryptographic capability token generation, signature checks, and tamper rejection."""
    gate = CapabilityGate(secret_key="test-secret-key-for-unit-testing-32b")

    token_str = gate.issue_token(
        agent_id="agent-007",
        permissions=[Permission.WASM_EXEC, Permission.FS_READ],
        ttl_seconds=10.0,
        allowed_domains=["api.github.com"],
        max_memory_mb=128,
        max_timeout_sec=5.0,
    )

    token = gate.verify_token(token_str)
    assert token.agent_id == "agent-007"
    assert token.has_permission(Permission.WASM_EXEC) is True
    assert token.has_permission(Permission.CONTAINER_EXEC) is False
    assert token.max_memory_mb == 128
    assert token.allowed_domains == ["api.github.com"]

    # Tampered signature detection
    tampered_token = token_str[:-4] + "ABCD"
    with pytest.raises(SecurityPolicyViolation) as exc_info:
        gate.verify_token(tampered_token)
    assert "signature verification failed" in str(exc_info.value).lower()


def test_capability_token_expiry():
    """Verify expired tokens are rejected."""
    gate = CapabilityGate(secret_key="test-secret-key-for-unit-testing-32b")
    short_token = gate.issue_token(
        agent_id="ephemeral-agent",
        permissions=[Permission.WASM_EXEC],
        ttl_seconds=0.05,
    )

    time.sleep(0.08)
    with pytest.raises(SecurityPolicyViolation) as exc_info:
        gate.verify_token(short_token)
    assert "expired" in str(exc_info.value).lower()


def test_capability_quota_enforcement():
    """Verify requested resource quotas exceeding token ceilings are blocked."""
    gate = CapabilityGate(secret_key="test-secret-key-for-unit-testing-32b")
    token_str = gate.issue_token(
        agent_id="constrained-agent",
        permissions=[Permission.WASM_EXEC],
        max_memory_mb=64,
        max_timeout_sec=2.0,
    )
    token = gate.verify_token(token_str)

    # Exceeding RAM cap
    with pytest.raises(SecurityPolicyViolation) as exc_info:
        gate.validate_execution(
            token=token,
            backend="wasm",
            requested_memory_mb=128,
        )
    assert "exceeds token cap" in str(exc_info.value).lower()

    # Exceeding Timeout cap
    with pytest.raises(SecurityPolicyViolation) as exc_info:
        gate.validate_execution(
            token=token,
            backend="wasm",
            requested_timeout_sec=5.0,
        )
    assert "exceeds token cap" in str(exc_info.value).lower()


def test_session_path_traversal_prevention(tmp_path):
    """Verify that path traversal attempts escaping the workspace are blocked."""
    session = Session(session_id="traversal_test", base_dir=tmp_path)
    session.create()

    # Safe write
    session.write_file("sub/file.txt", "safe data")
    assert session.read_file("sub/file.txt") == b"safe data"

    # Directory traversal attack attempts
    dangerous_paths = [
        "../outside.txt",
        "../../etc/passwd",
        "/absolute/root.txt",
        "subdir/../../../../escaped.txt",
    ]

    for attack_path in dangerous_paths:
        with pytest.raises(WorkspaceSecurityError):
            session.write_file(attack_path, "malicious payload")

    session.destroy()


def test_session_file_diffing(tmp_path):
    """Verify session tracks created, modified, and deleted files accurately."""
    session = Session(session_id="diff_test", base_dir=tmp_path)
    session.create()

    session.stage_files({"init.txt": "initial"})

    # Simulate workload mutations
    session.write_file("init.txt", "modified content")
    session.write_file("created.txt", "brand new file")

    diffs = session.compute_diffs()
    created_paths = [c["path"] for c in diffs["created"]]
    modified_paths = [m["path"] for m in diffs["modified"]]

    assert "created.txt" in created_paths
    assert "init.txt" in modified_paths

    session.destroy()


def test_audit_trail_tamper_evident_integrity(tmp_path):
    """Verify cryptographic SHA-256 hash chaining and tamper detection in audit logs."""
    log_file = tmp_path / "audit_test.jsonl"
    trail = AuditTrail(log_path=log_file)

    # Log sequential execution events
    e1 = trail.log_execution(
        session_id="s1",
        agent_id="a1",
        action="EXECUTE_WASM",
        backend="wasm",
        code="code 1",
        status="SUCCESS",
        exit_code=0,
    )

    e2 = trail.log_execution(
        session_id="s2",
        agent_id="a1",
        action="EXECUTE_CONTAINER",
        backend="container",
        code="code 2",
        status="SUCCESS",
        exit_code=0,
    )

    # Hash chaining assertions
    assert e2.prev_hash == e1.record_hash
    valid, msg = trail.verify_integrity()
    assert valid is True

    # Tampering test: Mutate record in buffer
    trail._buffer[0].status = "TAMPERED"
    valid, msg = trail.verify_integrity()
    assert valid is False
    assert "tampered" in msg.lower() or "mismatch" in msg.lower()
