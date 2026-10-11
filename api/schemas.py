"""Pydantic request and response schemas for Sandbox REST API."""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class ExecutionRequest(BaseModel):
    """Payload submitted by an AI Agent to execute isolated code."""
    backend: Literal["wasm", "container"] = Field(
        ..., description="Execution sandbox tier: 'wasm' or 'container'"
    )
    code: str = Field(..., description="Executable code string, WAT text, or Base64 wasm binary")
    capability_token: str = Field(..., description="Cryptographically signed capability token")
    format: Literal["wat", "wasm_b64", "python", "bash", "command"] = Field(
        default="python", description="Code payload format"
    )
    session_id: Optional[str] = Field(default=None, description="Optional persistent session identifier")
    files: Optional[Dict[str, str]] = Field(default=None, description="Files to stage into workspace {path: content}")
    env_vars: Optional[Dict[str, str]] = Field(default=None, description="Environment variables")
    timeout_seconds: Optional[float] = Field(default=None, description="Execution timeout cap in seconds")
    memory_mb: Optional[int] = Field(default=None, description="RAM limit in Megabytes")
    allow_network: bool = Field(default=False, description="Whether network egress is requested")
    requested_domains: Optional[List[str]] = Field(default=None, description="External domain destinations requested")
    function_name: Optional[str] = Field(default=None, description="Wasm exported function to call (optional)")
    function_args: Optional[List[Any]] = Field(default=None, description="Arguments to pass to Wasm function")
    retain_session: bool = Field(default=False, description="Retain session workspace after execution")


class ExecutionReceiptResponse(BaseModel):
    """Execution receipt documenting status, I/O, diffs, and cryptographic audit hash."""
    execution_id: str
    session_id: str
    backend: str
    status: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    memory_consumed_bytes: int
    audit_hash: str
    policy_violations: List[str] = Field(default_factory=list)
    created_files: List[Dict[str, Any]] = Field(default_factory=list)
    modified_files: List[Dict[str, Any]] = Field(default_factory=list)
    deleted_files: List[str] = Field(default_factory=list)
    result_value: Optional[str] = None


class TokenIssueRequest(BaseModel):
    """Request to mint a signed capability token for an agent."""
    agent_id: str = Field(..., description="Unique agent identifier")
    permissions: List[str] = Field(
        ...,
        description="Granted permissions (e.g. wasm:exec, container:exec, network:egress, fs:read, fs:write)"
    )
    ttl_seconds: float = Field(default=300.0, description="Token lifetime in seconds")
    allowed_domains: Optional[List[str]] = Field(default=None, description="Approved domain allowlist")
    max_memory_mb: Optional[int] = Field(default=None, description="Max RAM memory limit")
    max_timeout_sec: Optional[float] = Field(default=None, description="Max timeout limit")


class TokenIssueResponse(BaseModel):
    """Minted capability token response."""
    token: str
    agent_id: str
    expires_at: float
    permissions: List[str]
    allowed_domains: List[str]


class HealthStatusResponse(BaseModel):
    """Sandbox Gateway health status."""
    status: str
    version: str
    wasm_backend_active: bool
    container_backend_active: bool
    egress_firewall_active: bool
    active_sessions_count: int


class AuditVerificationResponse(BaseModel):
    """Integrity check response for the cryptographic audit chain."""
    valid: bool
    message: str
    record_count: int
