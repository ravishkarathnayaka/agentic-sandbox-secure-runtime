"""Runtime configuration and security policies for sandbox environments."""

import os
from pathlib import Path
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SandboxConfig(BaseSettings):
    """Central configuration for Sandboxed Execution Runtime."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # General Settings
    ENVIRONMENT: str = Field(default="production", description="Environment mode: development/production")
    SECRET_KEY: str = Field(
        default="sandbox-super-secure-production-hmac-key-min32bytes",
        description="HMAC secret key used for capability token verification"
    )

    # Resource Limits
    DEFAULT_TIMEOUT_SECONDS: float = Field(default=5.0, description="Default execution timeout")
    MAX_TIMEOUT_SECONDS: float = Field(default=30.0, description="Maximum allowed timeout")
    MAX_MEMORY_MB: int = Field(default=256, description="Container memory limit in Megabytes")
    CPU_QUOTA_VCPU: float = Field(default=0.5, description="CPU quota in virtual CPU shares")
    MAX_OUTPUT_BYTES: int = Field(default=1_048_576, description="Max stdout/stderr output size (1MB)")
    MAX_CONCURRENT_SESSIONS: int = Field(default=50, description="Max concurrent ephemeral sessions")

    # WebAssembly Constraints
    WASM_MAX_MEMORY_BYTES: int = Field(default=16 * 1024 * 1024, description="Max Wasm memory limit (16MB)")
    WASM_DEFAULT_FUEL: int = Field(default=50_000_000, description="Default fuel units allocated for Wasm")
    WASM_ENABLE_EPOCH_INTERRUPTION: bool = Field(default=True, description="Enable epoch-based time bounding")
    WASM_EPOCH_INTERVAL_MS: int = Field(default=10, description="Epoch ticker frequency in milliseconds")

    # Container Security Hardening
    CONTAINER_IMAGE: str = Field(default="sandbox-runner:latest", description="Hardened worker container image")
    CONTAINER_FALLBACK_IMAGE: str = Field(default="python:3.11-slim", description="Fallback base image if worker missing")
    CONTAINER_USER: str = Field(default="65534:65534", description="Unprivileged UID:GID (nobody:nogroup)")
    CONTAINER_READ_ONLY_ROOT: bool = Field(default=True, description="Enforce read-only root filesystem")
    CONTAINER_DROP_CAPABILITIES: List[str] = Field(default_factory=lambda: ["ALL"], description="Linux capabilities to drop")
    SECCOMP_PROFILE_PATH: Path = Field(
        default=Path(__file__).parent / "security" / "seccomp_profile.json",
        description="Path to strict seccomp profile"
    )

    # Egress Network Security Policy
    EGRESS_PROXY_HOST: str = Field(default="127.0.0.1", description="Egress filtering proxy host")
    EGRESS_PROXY_PORT: int = Field(default=8080, description="Egress filtering proxy listening port")
    DEFAULT_ALLOW_NETWORK: bool = Field(default=False, description="Default network isolation state")

    METADATA_IPS: List[str] = Field(
        default_factory=lambda: [
            "169.254.169.254",   # AWS / GCP / Azure IMDSv1/v2
            "169.254.169.253",   # AWS DNS/DHCP link-local
            "fd00:ec2::254",      # AWS IPv6 IMDS
            "100.100.100.200",   # Alibaba Cloud IMDS
            "169.254.170.2",     # AWS ECS container metadata
        ]
    )

    BLOCKED_CIDRS: List[str] = Field(
        default_factory=lambda: [
            "0.0.0.0/8",         # Broadcast / current network
            "10.0.0.0/8",        # RFC 1918 Private
            "100.64.0.0/10",     # Carrier-Grade NAT
            "127.0.0.0/8",       # Loopback IPv4
            "169.254.0.0/16",    # Link-Local (including IMDS)
            "172.16.0.0/12",     # RFC 1918 Private
            "192.0.0.0/24",      # IETF Protocol Assignments
            "192.0.2.0/24",      # TEST-NET-1
            "192.168.0.0/16",    # RFC 1918 Private
            "198.18.0.0/15",     # Network benchmark tests
            "198.51.100.0/24",   # TEST-NET-2
            "203.0.113.0/24",    # TEST-NET-3
            "224.0.0.0/4",       # Multicast
            "240.0.0.0/4",       # Reserved
            "::1/128",           # IPv6 Loopback
            "::/128",            # IPv6 Unspecified
            "fc00::/7",          # IPv6 Unique Local Address (ULA)
            "fe80::/10",         # IPv6 Link-Local
            "ff00::/8",          # IPv6 Multicast
        ]
    )

    BLOCKED_DOMAINS: List[str] = Field(
        default_factory=lambda: [
            "metadata.google.internal",
            "metadata.goog",
            "instance-data",
            "metadata",
            "localhost",
            "kubernetes.default.svc",
        ]
    )

    DEFAULT_ALLOWED_DOMAINS: List[str] = Field(
        default_factory=lambda: [
            "api.github.com",
            "httpbin.org",
            "huggingface.co",
            "pypi.org",
            "pythonhosted.org",
        ]
    )

    # Workspace & Telemetry
    WORKSPACE_BASE_DIR: Path = Field(
        default=Path(os.environ.get("SANDBOX_WORKSPACE_DIR", Path.cwd() / ".sandboxes")),
        description="Base directory for ephemeral session workspaces"
    )
    AUDIT_LOG_FILE: Path = Field(
        default=Path(os.environ.get("SANDBOX_AUDIT_LOG", Path.cwd() / "audit.jsonl")),
        description="Tamper-evident audit trail log destination"
    )
    REDIS_URL: str = Field(default="redis://localhost:6379/0", description="Redis cache/coordination connection string")


# Singleton instance
settings = SandboxConfig()
