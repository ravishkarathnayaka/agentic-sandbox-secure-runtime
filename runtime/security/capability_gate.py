"""Least-privilege Capability Gate for Autonomous AI Agents.

Validates signed capability tokens granting scoped execution rights:
- Memory limits
- Execution timeouts
- Network egress and domain allowlists
- File read/write permissions
- Sandbox runtime execution targets (Wasm vs Container)
"""

import base64
import hashlib
import hmac
import json
import time
import uuid
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field

from runtime.config import settings


class Permission(str, Enum):
    """Granular permissions granted to AI Agent workloads."""
    WASM_EXEC = "wasm:exec"
    CONTAINER_EXEC = "container:exec"
    FS_READ = "fs:read"
    FS_WRITE = "fs:write"
    NETWORK_EGRESS = "network:egress"
    SHELL_EXEC = "shell:exec"


class SecurityPolicyViolation(Exception):
    """Raised when an execution request violates the capability security policy."""
    def __init__(self, message: str, violation_code: str = "CAPABILITY_DENIED"):
        super().__init__(message)
        self.message = message
        self.violation_code = violation_code


class CapabilityToken(BaseModel):
    """Decoded capability token attributes."""
    token_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    issued_at: float = Field(default_factory=time.time)
    expires_at: float
    permissions: List[Permission]
    allowed_domains: List[str] = Field(default_factory=list)
    max_memory_mb: int = Field(default=settings.MAX_MEMORY_MB)
    max_timeout_sec: float = Field(default=settings.DEFAULT_TIMEOUT_SECONDS)

    def is_expired(self) -> bool:
        """Check if token lifetime has expired."""
        return time.time() > self.expires_at

    def has_permission(self, perm: Permission) -> bool:
        """Check if specific permission is granted."""
        return perm in self.permissions


class CapabilityGate:
    """Cryptographic validator and policy gate for execution tokens."""

    def __init__(self, secret_key: Optional[str] = None):
        self._secret_key = (secret_key or settings.SECRET_KEY).encode("utf-8")

    def _sign_payload(self, payload_bytes: bytes) -> str:
        """Generate HMAC-SHA256 signature."""
        sig = hmac.new(self._secret_key, payload_bytes, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

    def issue_token(
        self,
        agent_id: str,
        permissions: List[Permission],
        ttl_seconds: float = 300.0,
        allowed_domains: Optional[List[str]] = None,
        max_memory_mb: Optional[int] = None,
        max_timeout_sec: Optional[float] = None,
    ) -> str:
        """Issue a tamper-evident, cryptographically signed capability token."""
        now = time.time()
        token_data = {
            "token_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "issued_at": round(now, 3),
            "expires_at": round(now + ttl_seconds, 3),
            "permissions": [p.value if isinstance(p, Permission) else p for p in permissions],
            "allowed_domains": allowed_domains or [],
            "max_memory_mb": max_memory_mb or settings.MAX_MEMORY_MB,
            "max_timeout_sec": max_timeout_sec or settings.DEFAULT_TIMEOUT_SECONDS,
        }

        canonical_json = json.dumps(token_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        b64_payload = base64.urlsafe_b64encode(canonical_json).decode("utf-8").rstrip("=")
        signature = self._sign_payload(canonical_json)
        return f"{b64_payload}.{signature}"

    def verify_token(self, token_str: str) -> CapabilityToken:
        """Verify signature, expiry, and structure of a capability token."""
        if not token_str or "." not in token_str:
            raise SecurityPolicyViolation("Malformed capability token format", "TOKEN_MALFORMED")

        parts = token_str.strip().split(".")
        if len(parts) != 2:
            raise SecurityPolicyViolation("Invalid token segment count", "TOKEN_MALFORMED")

        b64_payload, signature = parts

        # Restore base64 padding
        pad_len = (4 - len(b64_payload) % 4) % 4
        padded_b64 = b64_payload + ("=" * pad_len)

        try:
            payload_bytes = base64.urlsafe_b64decode(padded_b64.encode("utf-8"))
        except Exception as e:
            raise SecurityPolicyViolation(f"Failed to decode token payload: {e}", "TOKEN_INVALID_BASE64")

        # Verify cryptographic signature
        expected_sig = self._sign_payload(payload_bytes)
        if not hmac.compare_digest(signature, expected_sig):
            raise SecurityPolicyViolation("Capability token signature verification failed", "SIGNATURE_MISMATCH")

        try:
            raw_data = json.loads(payload_bytes.decode("utf-8"))
        except Exception as e:
            raise SecurityPolicyViolation(f"Failed to parse token JSON: {e}", "TOKEN_INVALID_JSON")

        token = CapabilityToken(
            token_id=raw_data["token_id"],
            agent_id=raw_data["agent_id"],
            issued_at=raw_data["issued_at"],
            expires_at=raw_data["expires_at"],
            permissions=[Permission(p) for p in raw_data["permissions"]],
            allowed_domains=raw_data.get("allowed_domains", []),
            max_memory_mb=raw_data.get("max_memory_mb", settings.MAX_MEMORY_MB),
            max_timeout_sec=raw_data.get("max_timeout_sec", settings.DEFAULT_TIMEOUT_SECONDS),
        )

        if token.is_expired():
            raise SecurityPolicyViolation("Capability token has expired", "TOKEN_EXPIRED")

        return token

    def validate_execution(
        self,
        token: CapabilityToken,
        backend: str,
        network_requested: bool = False,
        requested_domains: Optional[List[str]] = None,
        requested_memory_mb: Optional[int] = None,
        requested_timeout_sec: Optional[float] = None,
    ) -> None:
        """Enforce strict capability boundaries prior to sandbox execution."""
        # Check backend authorization
        if backend == "wasm":
            if not token.has_permission(Permission.WASM_EXEC):
                raise SecurityPolicyViolation(
                    f"Agent '{token.agent_id}' lacks '{Permission.WASM_EXEC.value}' permission",
                    "PERMISSION_DENIED_WASM"
                )
        elif backend == "container":
            if not token.has_permission(Permission.CONTAINER_EXEC):
                raise SecurityPolicyViolation(
                    f"Agent '{token.agent_id}' lacks '{Permission.CONTAINER_EXEC.value}' permission",
                    "PERMISSION_DENIED_CONTAINER"
                )
        else:
            raise SecurityPolicyViolation(f"Unknown execution backend: {backend}", "INVALID_BACKEND")

        # Enforce resource quotas
        if requested_memory_mb and requested_memory_mb > token.max_memory_mb:
            raise SecurityPolicyViolation(
                f"Requested memory ({requested_memory_mb}MB) exceeds token cap ({token.max_memory_mb}MB)",
                "RESOURCE_QUOTA_EXCEEDED"
            )

        if requested_timeout_sec and requested_timeout_sec > token.max_timeout_sec:
            raise SecurityPolicyViolation(
                f"Requested timeout ({requested_timeout_sec}s) exceeds token cap ({token.max_timeout_sec}s)",
                "RESOURCE_QUOTA_EXCEEDED"
            )

        # Enforce network egress policy
        if network_requested:
            if not token.has_permission(Permission.NETWORK_EGRESS):
                raise SecurityPolicyViolation(
                    f"Agent '{token.agent_id}' requested network egress without '{Permission.NETWORK_EGRESS.value}' permission",
                    "PERMISSION_DENIED_NETWORK"
                )

            # Check domain allowlist
            if requested_domains:
                token_domains_lower = {d.lower() for d in token.allowed_domains}
                for domain in requested_domains:
                    if domain.lower() not in token_domains_lower:
                        raise SecurityPolicyViolation(
                            f"Domain '{domain}' is not in token allowed domains: {token.allowed_domains}",
                            "EGRESS_DOMAIN_UNAPPROVED"
                        )
