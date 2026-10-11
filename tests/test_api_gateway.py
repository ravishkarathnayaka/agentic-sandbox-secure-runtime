"""Integration tests for FastAPI Gateway endpoints."""

import pytest
from fastapi.testclient import TestClient

from api.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_api_health_endpoint(client):
    """Verify system health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["wasm_backend_active"] is True
    assert "version" in data


def test_api_token_minting_and_execution_flow(client):
    """Verify end-to-end flow: minting token and executing Wasm code through REST API."""
    # 1. Mint capability token
    token_resp = client.post(
        "/v1/capabilities/token",
        json={
            "agent_id": "test-agent-api",
            "permissions": ["wasm:exec", "fs:read"],
            "ttl_seconds": 60.0,
            "max_memory_mb": 64,
            "max_timeout_sec": 5.0,
        },
    )
    assert token_resp.status_code == 200
    token_data = token_resp.json()
    token = token_data["token"]
    assert token is not None

    # 2. Execute Wasm arithmetic code
    wat_code = """(module
      (func $mul (param $a i32) (param $b i32) (result i32)
        local.get $a
        local.get $b
        i32.mul
      )
      (export "calculate" (func $mul))
    )"""

    exec_resp = client.post(
        "/v1/execute",
        json={
            "backend": "wasm",
            "code": wat_code,
            "capability_token": token,
            "format": "wat",
            "function_name": "calculate",
            "function_args": [6, 7],
        },
    )
    assert exec_resp.status_code == 200
    receipt = exec_resp.json()
    assert receipt["status"] == "SUCCESS"
    assert receipt["result_value"] == "42"
    assert receipt["exit_code"] == 0
    assert len(receipt["audit_hash"]) == 64


def test_api_unauthorized_execution_rejected(client):
    """Verify that execution requests with unauthorized backend permissions return policy violation."""
    # Mint token with only wasm:exec permission
    token_resp = client.post(
        "/v1/capabilities/token",
        json={
            "agent_id": "wasm-only-agent",
            "permissions": ["wasm:exec"],
            "ttl_seconds": 60.0,
        },
    )
    token = token_resp.json()["token"]

    # Attempt container execution
    exec_resp = client.post(
        "/v1/execute",
        json={
            "backend": "container",
            "code": "print('attack')",
            "capability_token": token,
            "format": "python",
        },
    )
    assert exec_resp.status_code == 200
    receipt = exec_resp.json()
    assert receipt["status"] == "POLICY_VIOLATION"
    assert receipt["exit_code"] == 126
    assert len(receipt["policy_violations"]) > 0


def test_api_audit_and_metrics_endpoints(client):
    """Verify querying audit trail and system metrics via API."""
    logs_resp = client.get("/v1/audit/logs?limit=10")
    assert logs_resp.status_code == 200
    logs_data = logs_resp.json()
    assert "count" in logs_data

    verify_resp = client.get("/v1/audit/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True

    metrics_resp = client.get("/metrics")
    assert metrics_resp.status_code == 200
    metrics_data = metrics_resp.json()
    assert "total_executions" in metrics_data
