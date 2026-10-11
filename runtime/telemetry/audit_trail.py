"""Tamper-evident audit trail with SHA-256 hash chaining for autonomous AI Agent executions."""

import hashlib
import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from runtime.config import settings

logger = logging.getLogger("sandbox.audit")


class AuditEvent(BaseModel):
    """Immutable audit record representing an execution or policy violation."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    session_id: str
    agent_id: str
    action: str  # e.g., "EXECUTE_WASM", "EXECUTE_CONTAINER", "POLICY_VIOLATION", "EGRESS_BLOCKED"
    backend: Optional[str] = None
    code_hash: Optional[str] = None
    status: str  # "SUCCESS", "FAILURE", "VIOLATION", "TIMEOUT"
    exit_code: int = 0
    duration_ms: float = 0.0
    memory_consumed_bytes: int = 0
    file_diffs: Dict[str, Any] = Field(default_factory=dict)
    policy_violations: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = "0" * 64
    record_hash: str = ""

    def compute_hash(self) -> str:
        """Compute tamper-evident SHA-256 digest over normalized record content."""
        payload = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "backend": self.backend,
            "code_hash": self.code_hash,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": round(self.duration_ms, 2),
            "memory_consumed_bytes": self.memory_consumed_bytes,
            "file_diffs": self.file_diffs,
            "policy_violations": sorted(self.policy_violations),
            "metadata": self.metadata,
            "prev_hash": self.prev_hash,
        }
        canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


class AuditTrail:
    """Thread-safe cryptographically chained audit logging facility."""

    def __init__(self, log_path: Optional[Path] = None, ring_buffer_size: int = 1000):
        self.log_path = log_path or settings.AUDIT_LOG_FILE
        self.ring_buffer_size = ring_buffer_size
        self._lock = threading.Lock()
        self._buffer: List[AuditEvent] = []
        self._latest_hash: str = "0" * 64
        self._load_latest_hash()

    def _load_latest_hash(self) -> None:
        """Restore latest hash from existing disk log if present."""
        if self.log_path and self.log_path.exists():
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    if lines:
                        last_line = lines[-1].strip()
                        if last_line:
                            record = json.loads(last_line)
                            self._latest_hash = record.get("record_hash", "0" * 64)
            except Exception as e:
                logger.error(f"Failed to read existing audit log for latest hash: {e}")

    def log_execution(
        self,
        session_id: str,
        agent_id: str,
        action: str,
        backend: Optional[str],
        code: Optional[str],
        status: str,
        exit_code: int = 0,
        duration_ms: float = 0.0,
        memory_bytes: int = 0,
        file_diffs: Optional[Dict[str, Any]] = None,
        policy_violations: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Construct, seal, hash-chain, and persist an audit event."""
        with self._lock:
            code_hash = (
                hashlib.sha256(code.encode("utf-8")).hexdigest() if code else None
            )

            event = AuditEvent(
                session_id=session_id,
                agent_id=agent_id,
                action=action,
                backend=backend,
                code_hash=code_hash,
                status=status,
                exit_code=exit_code,
                duration_ms=duration_ms,
                memory_consumed_bytes=memory_bytes,
                file_diffs=file_diffs or {},
                policy_violations=policy_violations or [],
                metadata=metadata or {},
                prev_hash=self._latest_hash,
            )

            # Seal record with calculated hash
            event.record_hash = event.compute_hash()
            self._latest_hash = event.record_hash

            # Maintain in-memory ring buffer
            self._buffer.append(event)
            if len(self._buffer) > self.ring_buffer_size:
                self._buffer.pop(0)

            # Persist to JSONL file
            self._persist_event(event)

            return event

    def _persist_event(self, event: AuditEvent) -> None:
        """Write single audit event line to disk."""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")
        except Exception as e:
            logger.error(f"Audit disk write failed: {e}")

    def get_events(
        self,
        session_id: Optional[str] = None,
        violations_only: bool = False,
        limit: int = 50,
    ) -> List[AuditEvent]:
        """Query recent audit events with optional filtering."""
        with self._lock:
            results = list(self._buffer)

        if session_id:
            results = [e for e in results if e.session_id == session_id]

        if violations_only:
            results = [e for e in results if len(e.policy_violations) > 0 or e.status == "VIOLATION"]

        results.reverse()
        return results[:limit]

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """Verify the cryptographic hash-chain across all stored events."""
        with self._lock:
            if not self._buffer:
                return True, "Audit log is empty (valid)"

            expected_prev = "0" * 64
            for idx, event in enumerate(self._buffer):
                if idx == 0:
                    expected_prev = event.prev_hash
                elif event.prev_hash != expected_prev:
                    return (
                        False,
                        f"Hash chain broken at event {event.event_id}: prev_hash mismatch",
                    )

                computed = event.compute_hash()
                if computed != event.record_hash:
                    return (
                        False,
                        f"Event {event.event_id} content tampered: computed {computed} != {event.record_hash}",
                    )

                expected_prev = event.record_hash

            return True, "Audit chain integrity verified successfully"


# Singleton instance
audit_logger = AuditTrail()
