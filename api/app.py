"""FastAPI Gateway Application for Secure Agent Sandbox Runtime."""

import logging
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from api.schemas import (
    AuditVerificationResponse,
    ExecutionReceiptResponse,
    ExecutionRequest,
    HealthStatusResponse,
    TokenIssueRequest,
    TokenIssueResponse,
)
from runtime.core.manager import SandboxManager
from runtime.security.capability_gate import Permission

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sandbox.gateway")

# Central sandbox manager singleton
manager = SandboxManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle startup and shutdown hooks."""
    logger.info("Initializing Agent Sandbox Runtime Gateway...")
    yield
    logger.info("Tearing down sandbox sessions and releasing resources...")
    manager.session_manager.cleanup_all()


app = FastAPI(
    title="Secure MicroVM & WebAssembly Execution Sandbox",
    description="Sub-second multi-tier isolated execution runtime for autonomous AI agents.",
    version="0.1.0",
    lifespan=lifespan,
)

# Cross-Origin Request configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthStatusResponse, tags=["System"])
async def health_check():
    """System health check endpoint verifying engine readiness."""
    docker_ready = manager.container_backend.get_docker_client() is not None
    return HealthStatusResponse(
        status="healthy",
        version="0.1.0",
        wasm_backend_active=True,
        container_backend_active=docker_ready,
        egress_firewall_active=True,
        active_sessions_count=len(manager.session_manager.list_sessions()),
    )


@app.post("/v1/capabilities/token", response_model=TokenIssueResponse, tags=["Security"])
async def mint_capability_token(req: TokenIssueRequest):
    """Issue a cryptographically signed capability token scoped to least-privilege permissions."""
    try:
        validated_perms = [Permission(p) for p in req.permissions]
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid permission specified: {e}",
        )

    token_str = manager.capability_gate.issue_token(
        agent_id=req.agent_id,
        permissions=validated_perms,
        ttl_seconds=req.ttl_seconds,
        allowed_domains=req.allowed_domains,
        max_memory_mb=req.max_memory_mb,
        max_timeout_sec=req.max_timeout_sec,
    )

    token_obj = manager.capability_gate.verify_token(token_str)

    return TokenIssueResponse(
        token=token_str,
        agent_id=token_obj.agent_id,
        expires_at=token_obj.expires_at,
        permissions=[p.value for p in token_obj.permissions],
        allowed_domains=token_obj.allowed_domains,
    )


@app.post("/v1/execute", response_model=ExecutionReceiptResponse, tags=["Execution"])
async def execute_isolated_code(req: ExecutionRequest):
    """Execute code payload inside the Wasm or hardened container tier."""
    receipt = manager.execute(
        backend=req.backend,
        code=req.code,
        capability_token=req.capability_token,
        format=req.format,
        session_id=req.session_id,
        files=req.files,
        env_vars=req.env_vars,
        timeout_seconds=req.timeout_seconds,
        memory_mb=req.memory_mb,
        allow_network=req.allow_network,
        requested_domains=req.requested_domains,
        function_name=req.function_name,
        function_args=req.function_args,
        retain_session=req.retain_session,
    )

    return ExecutionReceiptResponse(
        execution_id=receipt.execution_id,
        session_id=receipt.session_id,
        backend=receipt.backend,
        status=receipt.status,
        exit_code=receipt.exit_code,
        stdout=receipt.stdout,
        stderr=receipt.stderr,
        duration_ms=receipt.duration_ms,
        memory_consumed_bytes=receipt.memory_consumed_bytes,
        audit_hash=receipt.audit_hash,
        policy_violations=receipt.policy_violations,
        created_files=receipt.created_files,
        modified_files=receipt.modified_files,
        deleted_files=receipt.deleted_files,
        result_value=receipt.result_value,
    )


@app.get("/v1/sessions", response_model=List[str], tags=["Sessions"])
async def list_active_sessions():
    """List all currently active isolated session IDs."""
    return manager.session_manager.list_sessions()


@app.delete("/v1/sessions/{session_id}", tags=["Sessions"])
async def destroy_session(session_id: str):
    """Manually destroy and purge an ephemeral workspace session."""
    removed = manager.session_manager.remove_session(session_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found",
        )
    return {"message": f"Session '{session_id}' wiped successfully"}


@app.get("/v1/audit/logs", tags=["Telemetry"])
async def get_audit_trail(
    limit: int = Query(default=50, ge=1, le=500),
    session_id: Optional[str] = Query(default=None),
    violations_only: bool = Query(default=False),
):
    """Query recent tamper-evident execution audit logs."""
    events = manager.audit_trail.get_events(
        session_id=session_id,
        violations_only=violations_only,
        limit=limit,
    )
    return {"count": len(events), "events": [e.model_dump() for e in events]}


@app.get("/v1/audit/verify", response_model=AuditVerificationResponse, tags=["Telemetry"])
async def verify_audit_chain():
    """Verify cryptographic SHA-256 hash chaining across the audit trail."""
    valid, message = manager.audit_trail.verify_integrity()
    events = manager.audit_trail.get_events(limit=1000)
    return AuditVerificationResponse(
        valid=valid,
        message=message or "Integrity verified",
        record_count=len(events),
    )


@app.get("/metrics", tags=["System"])
async def get_system_metrics():
    """Return execution metrics and policy violation counters."""
    events = manager.audit_trail.get_events(limit=1000)
    violations = [e for e in events if e.policy_violations or e.status == "VIOLATION"]
    durations = [e.duration_ms for e in events if e.duration_ms > 0]
    avg_latency = (sum(durations) / len(durations)) if durations else 0.0

    return {
        "total_executions": len(events),
        "total_violations": len(violations),
        "active_sessions": len(manager.session_manager.list_sessions()),
        "average_duration_ms": round(avg_latency, 2),
    }
