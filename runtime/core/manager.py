"""Sandbox Manager orchestrating full lifecycle, capability validation, and multi-tier execution."""

import logging
import sys
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from runtime.backends.container_backend import ContainerBackend, ContainerExecutionResult
from runtime.backends.wasm_backend import WasmBackend, WasmExecutionResult
from runtime.core.session import SessionManager
from runtime.security.capability_gate import (
    CapabilityGate,
    CapabilityToken,
    SecurityPolicyViolation,
)
from runtime.security.egress_firewall import EgressFirewall
from runtime.telemetry.audit_trail import AuditTrail, audit_logger

logger = logging.getLogger("sandbox.manager")


class UnifiedExecutionReceipt(BaseModel):
    """Normalized receipt returned to calling agents and client APIs."""
    execution_id: str
    session_id: str
    backend: str
    status: str  # "SUCCESS", "ERROR", "TIMEOUT", "POLICY_VIOLATION"
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    memory_consumed_bytes: int = 0
    audit_hash: str = ""
    policy_violations: List[str] = Field(default_factory=list)
    created_files: List[Dict[str, Any]] = Field(default_factory=list)
    modified_files: List[Dict[str, Any]] = Field(default_factory=list)
    deleted_files: List[str] = Field(default_factory=list)
    result_value: Optional[str] = None


class SandboxManager:
    """Central orchestrator for the two-tier agent execution sandbox."""

    def __init__(
        self,
        capability_gate: Optional[CapabilityGate] = None,
        wasm_backend: Optional[WasmBackend] = None,
        container_backend: Optional[ContainerBackend] = None,
        session_manager: Optional[SessionManager] = None,
        audit_trail: Optional[AuditTrail] = None,
        firewall: Optional[EgressFirewall] = None,
    ):
        self.capability_gate = capability_gate or CapabilityGate()
        self.wasm_backend = wasm_backend or WasmBackend()
        self.container_backend = container_backend or ContainerBackend()
        self.session_manager = session_manager or SessionManager()
        self.audit_trail = audit_trail or audit_logger
        self.firewall = firewall or EgressFirewall()

    def execute(
        self,
        backend: str,
        code: str | bytes,
        capability_token: str,
        format: str = "python",  # "wat", "wasm_b64", "python", "bash", "command"
        session_id: Optional[str] = None,
        files: Optional[Dict[str, str | bytes]] = None,
        env_vars: Optional[Dict[str, str]] = None,
        timeout_seconds: Optional[float] = None,
        memory_mb: Optional[int] = None,
        allow_network: bool = False,
        requested_domains: Optional[List[str]] = None,
        function_name: Optional[str] = None,
        function_args: Optional[List[Any]] = None,
        retain_session: bool = False,
    ) -> UnifiedExecutionReceipt:
        """Execute sandboxed agent workload with least-privilege verification and telemetry."""
        policy_violations: List[str] = []
        token_obj: Optional[CapabilityToken] = None
        agent_id = "unknown_agent"

        # 1. Capability Token Validation
        try:
            token_obj = self.capability_gate.verify_token(capability_token)
            agent_id = token_obj.agent_id
            self.capability_gate.validate_execution(
                token=token_obj,
                backend=backend,
                network_requested=allow_network,
                requested_domains=requested_domains,
                requested_memory_mb=memory_mb,
                requested_timeout_sec=timeout_seconds,
            )
        except SecurityPolicyViolation as e:
            policy_violations.append(str(e))
            event = self.audit_trail.log_execution(
                session_id=session_id or "unauthenticated",
                agent_id=agent_id,
                action="POLICY_VIOLATION",
                backend=backend,
                code=str(code)[:500] if isinstance(code, str) else "<binary>",
                status="VIOLATION",
                exit_code=126,
                policy_violations=policy_violations,
            )
            return UnifiedExecutionReceipt(
                execution_id=event.event_id,
                session_id=session_id or "unauthenticated",
                backend=backend,
                status="POLICY_VIOLATION",
                exit_code=126,
                stderr=f"Security Policy Violation: {str(e)}",
                audit_hash=event.record_hash,
                policy_violations=policy_violations,
            )

        # 2. Ephemeral Session Workspace Initialization
        session = self.session_manager.create_session(session_id=session_id)
        if files:
            session.stage_files(files)

        execution_status = "SUCCESS"
        exit_code = 0
        stdout = ""
        stderr = ""
        duration_ms = 0.0
        memory_consumed = 0
        result_value = None

        try:
            # 3. Execution Dispatch
            if backend == "wasm":
                is_wat = (format == "wat") or (isinstance(code, str) and code.strip().startswith("("))
                wasm_result: WasmExecutionResult = self.wasm_backend.execute(
                    code=code,
                    session=session,
                    function_name=function_name,
                    function_args=function_args,
                    timeout_seconds=timeout_seconds or token_obj.max_timeout_sec,
                    memory_limit_bytes=(memory_mb * 1024 * 1024) if memory_mb else None,
                    is_wat=is_wat,
                )
                stdout = wasm_result.stdout
                stderr = wasm_result.stderr
                exit_code = wasm_result.exit_code
                duration_ms = wasm_result.duration_ms
                result_value = wasm_result.result_value
                if wasm_result.timed_out:
                    execution_status = "TIMEOUT"
                elif not wasm_result.success:
                    execution_status = "ERROR"

            elif backend == "container":
                # Staging executable payload
                if format == "python":
                    session.write_file("main.py", code)
                    cmd = [sys.executable, "main.py"] if self.container_backend.get_docker_client() is None else ["python3", "/workspace/main.py"]
                elif format == "bash":
                    session.write_file("script.sh", code)
                    cmd = ["sh", "script.sh"] if self.container_backend.get_docker_client() is None else ["sh", "/workspace/script.sh"]
                elif format == "command":
                    cmd = code if isinstance(code, list) else code.split()
                else:
                    raise ValueError(f"Unsupported container payload format: {format}")

                container_result: ContainerExecutionResult = self.container_backend.execute(
                    command=cmd,
                    session=session,
                    timeout_seconds=timeout_seconds or token_obj.max_timeout_sec,
                    memory_mb=memory_mb or token_obj.max_memory_mb,
                    allow_network=allow_network,
                    env_vars=env_vars,
                )
                stdout = container_result.stdout
                stderr = container_result.stderr
                exit_code = container_result.exit_code
                duration_ms = container_result.duration_ms
                memory_consumed = container_result.memory_consumed_bytes
                if container_result.timed_out:
                    execution_status = "TIMEOUT"
                elif not container_result.success:
                    execution_status = "ERROR"
            else:
                raise ValueError(f"Unknown backend requested: {backend}")

        except Exception as e:
            execution_status = "ERROR"
            exit_code = 1
            stderr = f"{stderr}\nRuntime Error: {str(e)}".strip()
            logger.error(f"Execution error: {e}")

        # 4. File Diff Inspection & Telemetry Capture
        diffs = session.compute_diffs()

        # 5. Tamper-evident Audit Logging
        code_preview = str(code)[:500] if isinstance(code, str) else "<binary>"
        event = self.audit_trail.log_execution(
            session_id=session.session_id,
            agent_id=agent_id,
            action=f"EXECUTE_{backend.upper()}",
            backend=backend,
            code=code_preview,
            status=execution_status,
            exit_code=exit_code,
            duration_ms=duration_ms,
            memory_bytes=memory_consumed,
            file_diffs=diffs,
            policy_violations=policy_violations,
        )

        # 6. Session Teardown
        if not retain_session:
            self.session_manager.remove_session(session.session_id)

        return UnifiedExecutionReceipt(
            execution_id=event.event_id,
            session_id=session.session_id,
            backend=backend,
            status=execution_status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            memory_consumed_bytes=memory_consumed,
            audit_hash=event.record_hash,
            policy_violations=policy_violations,
            created_files=diffs.get("created", []),
            modified_files=diffs.get("modified", []),
            deleted_files=diffs.get("deleted", []),
            result_value=result_value,
        )
