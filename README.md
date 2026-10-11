<div align="center">

# Secure MicroVM & WebAssembly Execution Sandbox
### Hardened, Sub-Second Multi-Tenant Runtime for Autonomous AI Agents

[![CI Test Suite](https://github.com/ravishkarathnayaka/agentic-sandbox-secure-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/ravishkarathnayaka/agentic-sandbox-secure-runtime/actions/workflows/ci.yml)
[![Security Hardening](https://github.com/ravishkarathnayaka/agentic-sandbox-secure-runtime/actions/workflows/security-scan.yml/badge.svg)](https://github.com/ravishkarathnayaka/agentic-sandbox-secure-runtime/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![WebAssembly: Wasmtime](https://img.shields.io/badge/Wasm-Wasmtime%20v49-654FF0.svg)](https://wasmtime.dev/)
[![Docker Hardening](https://img.shields.io/badge/Isolation-Seccomp%20%7C%20cgroups-success.svg)](https://docs.docker.com/engine/security/seccomp/)

*A defense-in-depth execution substrate engineered for LLM agents running untrusted code, arbitrary tool invocations, and autonomous scripts.*

</div>

---

## 📑 Table of Contents
- [Executive Overview](#-executive-overview)
- [Two-Tier Isolation Architecture](#-two-tier-isolation-architecture)
- [Defense-in-Depth Security Matrix](#-defense-in-depth-security-matrix)
- [Threat Model Comparison](#-threat-model-comparison)
- [Repository Layout](#-repository-layout)
- [Local Quickstart ($0 Setup)](#-local-quickstart-0-setup)
- [Interactive API Walkthrough & Receipts](#-interactive-api-walkthrough--receipts)
- [Egress Network Firewall & SSRF Protection](#-egress-network-firewall--ssrf-protection)
- [Cryptographic Audit Trail](#-cryptographic-audit-trail)
- [Autonomous Agent Client Harness](#-autonomous-agent-client-harness)
- [Test Suite & Verification](#-test-suite--verification)

---

## 🚀 Executive Overview

Autonomous AI Agents (such as coding assistants, data analysts, and workflow automation agents) frequently generate and execute untrusted code in real-time. Traditional container setups suffer from several critical vulnerabilities:
1. **Slow Startup Latency**: Standard container cold starts take 500ms–2500ms, stalling fast interactive agent reasoning loops.
2. **Kernel Exploitation Surface**: Standard Docker containers share the host Linux kernel without strict syscall filtering, leaving host systems vulnerable to local privilege escalation (`ptrace`, `bpf`, `io_uring`, `userfaultfd`).
3. **SSRF & Metadata Theft**: Agents executing network tools can query AWS/GCP/Azure Instance Metadata Services (`169.254.169.254`) or internal subnets (`10.0.0.0/8`, `192.168.0.0/16`) to exfiltrate IAM role credentials and cloud tokens.
4. **Denial of Service (Resource Exhaustion)**: Runaway compute loops and memory fork bombs can crash host nodes.

**Agentic Sandbox Secure Runtime** addresses these challenges through a hardened **Two-Tier Sandboxing Engine**:
- **Tier 1 (Sub-Millisecond Wasm Sandbox)**: Compiled WebAssembly executed via `wasmtime-py` with zero host filesystem access, deterministic compute fuel limits, and explicit linear memory page bounding (~3ms execution overhead).
- **Tier 2 (Hardened Container Sandbox)**: Ephemeral worker containers locked down with custom Linux seccomp filters blocking 35+ exploit syscalls, dropping all capabilities (`cap_drop: ALL`), enforcing read-only root filesystems, unprivileged UID (`65534:65534`), and cgroup resource limits.
- **Egress Firewall Proxy**: All egress network traffic passes through an asynchronous proxy dropping private RFC 1918 CIDRs, link-local addresses, and cloud metadata endpoints while enforcing strict domain allowlists.

---

## 🏗 Two-Tier Isolation Architecture

```mermaid
flowchart TD
    subgraph Agent["Autonomous AI Agent Ecosystem"]
        A[Autonomous Agent / Tool Caller]
    end

    subgraph Gateway["Sandbox Gateway API (Port 8000)"]
        G[FastAPI Gateway]
        CG[Capability Gate<br/>• HMAC-SHA256 Token Validation<br/>• Scoped Permissions & TTL<br/>• Resource Quota Verification]
    end

    subgraph Telemetry["Tamper-Evident Telemetry"]
        AT[Cryptographic Audit Trail<br/>• SHA-256 Hash Chaining<br/>• File Mutation Diffs<br/>• Telemetry Receipt]
    end

    subgraph Tier1["Tier 1: WebAssembly Engine (~3ms Cold Start)"]
        Wasm[wasmtime-py Runtime]
        WasmMem[Linear Memory Bounds<br/>16MB Ceiling]
        WasmFuel[Deterministic Fuel<br/>Compute Kill Switch]
        WasmWasi[Isolated WASI<br/>Zero Host FS Access]
    end

    subgraph Tier2["Tier 2: Hardened Container Engine (~50ms Cold Start)"]
        Docker[Ephemeral Worker Container]
        Sec[Strict Seccomp Filter<br/>ptrace, bpf, mount, reboot, keyctl BLOCKED]
        Caps[cap_drop: ALL<br/>UID: 65534 nobody:nogroup]
        Cgroups[cgroups Quota<br/>0.5 vCPU | 256MB RAM]
        FS[Read-Only Rootfs<br/>Ephemeral /tmp tmpfs]
    end

    subgraph Network["Egress Security Layer"]
        Proxy[Egress Filtering Proxy (Port 8080)<br/>• DNS Rebinding Protection<br/>• Domain Allowlist Enforcement]
        Blackhole[DROP: 169.254.169.254<br/>DROP: RFC 1918 / Loopback]
        ExtNet((Approved External APIs<br/>e.g., api.github.com))
    end

    A -->|1. Request Token & Submit Code| G
    G --> CG
    CG -->|Wasm Exec Allowed| Wasm
    CG -->|Container Exec Allowed| Docker
    CG -.->|Policy Violation| AT

    Wasm --- WasmMem
    Wasm --- WasmFuel
    Wasm --- WasmWasi

    Docker --- Sec
    Docker --- Caps
    Docker --- Cgroups
    Docker --- FS

    Docker -->|Network Mode: Bridge| Proxy
    Proxy -->|Blocked Destination| Blackhole
    Proxy -->|Approved Domain| ExtNet

    Wasm -->|Execution Telemetry| AT
    Docker -->|Execution Telemetry| AT
    AT -->|Normalized Execution Receipt| G
    G -->|Receipt + Stdout + Diff| A
```

---

## 🛡 Defense-in-Depth Security Matrix

| Security Layer | WebAssembly Sandbox (Tier 1) | Container Sandbox (Tier 2) | Defense Rationale |
| :--- | :--- | :--- | :--- |
| **Startup Overhead** | **< 4 ms** | **~50–80 ms** | Micro-second fast turnaround for arithmetic, parsing, and reasoning steps. |
| **Host Filesystem Access** | **Zero Host Access** (Virtual WASI streams only) | **Ephemeral Session Mount** (`/workspace:rw`, Rootfs: `ro`) | Prevents directory traversal attacks and host corruption. |
| **Syscall Filtering** | No host kernel syscalls executed | **Linux Seccomp Filter** (`SCMP_ACT_ERRNO` on dangerous calls) | Blocks container breakout primitives (`ptrace`, `bpf`, `mount`, `reboot`, `keyctl`, `clone3`). |
| **Linux Capabilities** | Not applicable (Wasm userspace) | **`cap_drop: ["ALL"]`** | Strips `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE`, etc. |
| **User Identity** | Sandboxed user process | **`65534:65534` (nobody:nogroup)** | Prevents root escalation inside container boundaries. |
| **Memory Boundaries** | `Store.set_limits(memory_size=16MB)` | **256MB Cgroup Limit + Swap Disabled** | Prevents RAM exhaustion and host Out-Of-Memory (OOM) crashes. |
| **Compute Timeout** | **Fuel Units + Epoch Deadline Interruption** | **0.5 vCPU share + Hard Timeout Kill Switch** | Terminates infinite loops and CPU consumption attacks deterministically. |
| **Network Egress** | **Disabled** (Zero sockets initialized) | **Default: `none`**; Proxy filtered on approved domains | Blocks cloud metadata (`169.254.169.254`) and internal subnets. |

---

## ⚖ Threat Model Comparison

| Threat Vector / Scenario | Standard Docker (`docker run`) | MicroVM (e.g., Firecracker / gVisor) | WebAssembly (`wasmtime`) | **Our Two-Tier Architecture** |
| :--- | :---: | :---: | :---: | :---: |
| **Cold Start Latency** | 🐌 800ms – 2500ms | ⏳ 150ms – 300ms | ⚡ **1ms – 5ms** | ⚡ **< 5ms (Wasm) / ~60ms (Container)** |
| **Host Resource Footprint** | ~50MB per instance | ~30MB per VM | **< 2MB per Store** | **Ultra-lightweight multi-tenant** |
| **Kernel Exploit Surface (`ptrace`, `bpf`)** | ❌ Full Host Kernel Exposed | ✅ Intercepted by Hypervisor | ✅ No kernel access | ✅ **Hardened Seccomp + Wasm Zero Host Access** |
| **Cloud Metadata Exfiltration (SSRF)** | ❌ Vulnerable (Bridge has route to 169.254.169.254) | ⚠️ Requires custom host iptables | ✅ Zero network access | ✅ **Egress Firewall drops IMDS & RFC 1918** |
| **Arbitrary Python/C Tool Support** | ✅ Native | ✅ Native | ⚠️ Requires Wasm compilation | ✅ **Seamless Dual-Engine Routing** |
| **Tamper-Evident Auditability** | ❌ Ephemeral logs lost | ❌ Requires custom agent | ❌ Custom integration | ✅ **Built-in SHA-256 Hash Chained Audit Trail** |

---

## 📂 Repository Layout

```
├── .github/
│   └── workflows/
│       ├── ci.yml                 # Code linting (Ruff), type checks (Mypy), and Pytest
│       └── security-scan.yml      # Security scanning with Trivy and Gitleaks
├── docker/
│   ├── docker-compose.yml         # Local stack: Sandbox Gateway API, Redis, and Egress Filter Proxy
│   ├── gateway.Dockerfile         # Multi-stage image for Sandbox Gateway & Egress Proxy
│   ├── sandbox.Dockerfile         # Minimal, non-root hardened container base image (UID 65534)
│   └── .env.example               # Environment variables configuration template
├── runtime/
│   ├── __init__.py
│   ├── config.py                  # Resource limits (CPU quota, RAM caps, execution timeouts)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── manager.py             # Sandbox lifecycle orchestrator (creation, execution, teardown)
│   │   └── session.py             # Ephemeral workspace manager with isolated volume mounts & diffs
│   ├── backends/
│   │   ├── __init__.py
│   │   ├── wasm_backend.py        # Wasm execution engine using wasmtime-py with isolated memory limits
│   │   └── container_backend.py   # Container runner applying seccomp profiles, drop-capabilities & limits
│   ├── security/
│   │   ├── __init__.py
│   │   ├── seccomp_profile.json   # Strict seccomp filter blocking ptrace, bpf, mount, reboot, keyctl
│   │   ├── capability_gate.py     # Least-privilege permission token validator (HMAC-SHA256)
│   │   └── egress_firewall.py     # Network proxy blocking internal CIDRs (RFC 1918) & cloud metadata
│   └── telemetry/
│       ├── __init__.py
│       └── audit_trail.py         # Cryptographic SHA-256 hash-chained audit trail & file diff tracking
├── api/
│   ├── __init__.py
│   ├── app.py                     # FastAPI interface for agents to request isolated code execution
│   └── schemas.py                 # Pydantic models for execution requests and receipts
├── agent_client/
│   ├── __init__.py
│   └── sample_agent.py            # Reference autonomous agent executing tools through the sandbox
├── tests/
│   ├── __init__.py
│   ├── test_api_gateway.py        # API integration tests (health, tokens, execute, audit)
│   ├── test_wasm_backend.py       # Memory limits, deterministic fuel exhaustion, and epoch timeouts
│   ├── test_seccomp_isolation.py  # Syscall filter validation & container hardening flags
│   ├── test_egress_firewall.py    # Metadata IP, RFC 1918, and domain allowlist rejection
│   └── test_resource_limits.py    # Token quota enforcement, path traversal defense & audit integrity
├── pyproject.toml                 # Package configuration, Ruff & Pytest settings
├── requirements.txt               # Locked production & test dependencies
└── README.md                      # Architecture documentation & setup guide
```

---

## 💻 Local Quickstart ($0 Setup)

### 1. Prerequisites
- Python 3.10+
- Docker & Docker Compose (optional for Container worker execution)

### 2. Installation
```bash
# Clone repository
git clone https://github.com/ravishkarathnayaka/agentic-sandbox-secure-runtime.git
cd agentic-sandbox-secure-runtime

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Automated Tests
```bash
pytest tests/ -v
```
Output:
```text
tests/test_api_gateway.py::test_api_health_endpoint PASSED               [  4%]
tests/test_api_gateway.py::test_api_token_minting_and_execution_flow PASSED [  8%]
tests/test_api_gateway.py::test_api_unauthorized_execution_rejected PASSED [ 12%]
tests/test_api_gateway.py::test_api_audit_and_metrics_endpoints PASSED   [ 16%]
tests/test_egress_firewall.py::test_cloud_metadata_ip_blocked PASSED     [ 20%]
tests/test_egress_firewall.py::test_rfc1918_private_cidrs_blocked PASSED [ 25%]
tests/test_egress_firewall.py::test_loopback_and_link_local_blocked PASSED [ 29%]
tests/test_egress_firewall.py::test_cloud_metadata_domains_blocked PASSED [ 33%]
tests/test_egress_firewall.py::test_domain_allowlist_enforcement PASSED  [ 37%]
tests/test_egress_firewall.py::test_direct_external_ip_access_blocked_without_domain PASSED [ 41%]
tests/test_resource_limits.py::test_capability_token_lifecycle_and_verification PASSED [ 45%]
tests/test_resource_limits.py::test_capability_token_expiry PASSED       [ 50%]
tests/test_resource_limits.py::test_capability_quota_enforcement PASSED  [ 54%]
tests/test_resource_limits.py::test_session_path_traversal_prevention PASSED [ 58%]
tests/test_resource_limits.py::test_session_file_diffing PASSED          [ 62%]
tests/test_resource_limits.py::test_audit_trail_tamper_evident_integrity PASSED [ 66%]
tests/test_seccomp_isolation.py::test_seccomp_profile_validity_and_structure PASSED [ 70%]
tests/test_seccomp_isolation.py::test_dangerous_syscalls_explicitly_blocked PASSED [ 75%]
tests/test_seccomp_isolation.py::test_container_hardening_flags_applied PASSED [ 79%]
tests/test_wasm_backend.py::test_wasm_basic_arithmetic PASSED            [ 83%]
tests/test_wasm_backend.py::test_wasm_fuel_exhaustion_infinite_loop PASSED [ 87%]
tests/test_wasm_backend.py::test_wasm_memory_limit_exceeded PASSED       [ 91%]
tests/test_wasm_backend.py::test_wasm_zero_host_filesystem_access PASSED [ 95%]
tests/test_wasm_backend.py::test_wasm_epoch_timeout_termination PASSED   [100%]
============================== 24 passed in 1.08s ==============================
```

### 4. Running Locally via Docker Compose
```bash
cd docker
docker compose up -d --build
```
The services will be active on:
- **Sandbox Gateway API**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **Egress Firewall Proxy**: `http://localhost:8080`
- **Redis State Cache**: `localhost:6379`

---

## 🔌 Interactive API Walkthrough & Receipts

### Step 1: Mint a Least-Privilege Capability Token
Autonomous agents must authenticate tool execution requests using cryptographically signed capability tokens with scoped permissions:

```bash
curl -X POST "http://localhost:8000/v1/capabilities/token" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-alpha-001",
    "permissions": ["wasm:exec", "container:exec", "fs:write"],
    "ttl_seconds": 300,
    "max_memory_mb": 128,
    "max_timeout_sec": 5.0
  }'
```

**Response**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJ...HMAC_SIGNATURE",
  "agent_id": "agent-alpha-001",
  "expires_at": 1791739500.5,
  "permissions": ["wasm:exec", "container:exec", "fs:write"],
  "allowed_domains": []
}
```

---

### Step 2: Execute High-Speed Math in WebAssembly (Tier 1)
```bash
curl -X POST "http://localhost:8000/v1/execute" \
  -H "Content-Type: application/json" \
  -d '{
    "backend": "wasm",
    "code": "(module (func $add (param $a i32) (param $b i32) (result i32) local.get $a local.get $b i32.add) (export \"calculate\" (func $add)))",
    "capability_token": "<YOUR_TOKEN>",
    "format": "wat",
    "function_name": "calculate",
    "function_args": [17, 25]
  }'
```

**Execution Receipt**:
```json
{
  "execution_id": "d00ec25a-9879-52ca-a42e-131bc873216d",
  "session_id": "sbx_f0a823b1c8e9",
  "backend": "wasm",
  "status": "SUCCESS",
  "exit_code": 0,
  "stdout": "",
  "stderr": "",
  "duration_ms": 3.84,
  "memory_consumed_bytes": 65536,
  "audit_hash": "8f01a443ea0b5e76a6cf17f7dcb1ea0c69d6c703b0704407b46e382d61c6b54a",
  "policy_violations": [],
  "created_files": [],
  "result_value": "42"
}
```

---

### Step 3: Execute Python Tool with Workspace File Tracking (Tier 2)
```bash
curl -X POST "http://localhost:8000/v1/execute" \
  -H "Content-Type: application/json" \
  -d '{
    "backend": "container",
    "code": "import json\nstats = {\"mean\": 23.1, \"samples\": 100}\nwith open(\"stats.json\", \"w\") as f:\n    json.dump(stats, f)\nprint(\"Analysis completed successfully\")",
    "capability_token": "<YOUR_TOKEN>",
    "format": "python"
  }'
```

**Execution Receipt**:
```json
{
  "execution_id": "18a992bc-6ef4-4f1b-8e2b-f63b49c719e2",
  "session_id": "sbx_a1c93b749d01",
  "backend": "container",
  "status": "SUCCESS",
  "exit_code": 0,
  "stdout": "Analysis completed successfully\n",
  "stderr": "",
  "duration_ms": 64.21,
  "memory_consumed_bytes": 14680064,
  "audit_hash": "2bc994fa103ef8013e8b0b5711a967f0c1e48227b3b9b47cf0845371ad52b618",
  "policy_violations": [],
  "created_files": [
    {
      "path": "stats.json",
      "size_bytes": 33,
      "hash": "c07519171b3e94a82194ad9d6fc19d453bf54d3bbd31e9c20a9dc637b526d113"
    }
  ],
  "result_value": null
}
```

---

## 🌐 Egress Network Firewall & SSRF Protection

When network access is requested by an agent, the egress firewall verifies each destination host before relaying traffic:

1. **Cloud Metadata IP Blocking**:
   Requests to AWS/GCP/Azure IMDS endpoints (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) are blocked with HTTP `403 Forbidden`.
2. **Private RFC 1918 CIDR Blocking**:
   Subnets `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` are rejected.
3. **Loopback & Link-Local Defense**:
   `127.0.0.0/8`, `::1/128`, and `169.254.0.0/16` are blocked.
4. **Anti-SSRF & DNS Rebinding Protection**:
   Hostnames are resolved against DNS in real-time. If a resolved IP address maps to any blocked subnet, the connection is dropped immediately prior to socket initialization.
5. **Strict Domain Allowlisting**:
   Only explicitly approved domains (e.g. `api.github.com`, `httpbin.org`) are permitted.

---

## 🔒 Cryptographic Audit Trail

Every lifecycle event and execution receipt is recorded into a tamper-evident audit log (`audit.jsonl`). Each record contains:
- Unique `event_id` and ISO-8601 UTC timestamp.
- SHA-256 digest of executed code payload.
- File mutations (created, modified, deleted) with file sizes and SHA-256 hashes.
- `prev_hash`: SHA-256 digest of preceding audit event.
- `record_hash`: Canonical SHA-256 digest sealing the current entry.

### Integrity Verification Endpoint
```bash
curl "http://localhost:8000/v1/audit/verify"
```
```json
{
  "valid": true,
  "message": "Audit chain integrity verified successfully",
  "record_count": 28
}
```
If an adversary or infected container tampers with any historical record in the log file, `verify_integrity()` detects the break in the hash chain and pinpoints the corrupted event.

---

## 🤖 Autonomous Agent Client Harness

A reference autonomous agent harness is included in `agent_client/sample_agent.py`. It simulates a real agent workflow executing multiple tool types:
- Fast mathematical evaluation in WebAssembly.
- Dataset statistics in Container with workspace file mutation diffing.
- Web scraping to approved domains.
- Adversarial SSRF attack against `169.254.169.254` demonstrating containment.

Run the demonstration harness:
```bash
python -m agent_client.sample_agent
```

Output:
```text
======================================================================
[AGENT] AUTONOMOUS AI AGENT SANDBOX HARNESS
Target Gateway: http://localhost:8000 (or In-Process fallback)
======================================================================

[Step 1] Requesting Wasm execution for fast factorial calculation...
  Status:       SUCCESS
  Result Value: 120 (Factorial of 5 = 120)
  Duration:     4.01 ms (sub-millisecond Wasm startup)
  Audit Hash:   8f01a443ea0b5e76...

[Step 2] Executing Python Data Analysis in Hardened Container Tier...
  Status:       SUCCESS
  Stdout:       Calculated dataset summary: Mean = 23.10
  Created Files:[{'path': 'main.py', 'size_bytes': 386, 'hash': '...'}, {'path': 'summary_report.json', 'size_bytes': 81, 'hash': '...'}]
  Duration:     65.63 ms

[Step 3] Executing Network Web Scraper to Approved Domain (httpbin.org)...
  Status:       SUCCESS
  Output:       Successfully retrieved query params: {'agent': 'sandbox'}

[Step 4] Adversarial Attempt: Trying to access AWS/GCP IMDS (169.254.169.254)...
  Status:       POLICY_VIOLATION
  Violations:   ["Domain '169.254.169.254' is not in token allowed domains: ['httpbin.org']"]
  Outcome:      BLOCKED BY EGRESS FIREWALL & CAPABILITY GATE!

======================================================================
[SUCCESS] ALL AGENT SANDBOX HARNESS CHECKS COMPLETED
======================================================================
```

---

## 🧪 Test Suite & Verification

The test suite requires zero specialized hardware, running locally on Linux, macOS, or Windows for **$0**, and executing cleanly in standard GitHub Actions CI runner environments:

```bash
# Run pytest with code coverage
pytest tests/ -v --cov=runtime --cov=api

# Run Ruff code quality linter
ruff check runtime/ api/ agent_client/ tests/
```

### Test Coverage Highlights
- `tests/test_wasm_backend.py`: Wasm WAT compilation, deterministic compute fuel exhaustion, memory ceiling enforcement (16MB), epoch interruption timeouts, and zero host filesystem access.
- `tests/test_seccomp_isolation.py`: JSON seccomp structure, validation of 35+ blocked syscalls (`ptrace`, `bpf`, `mount`, `reboot`, `keyctl`, `clone3`), and container options (`cap_drop: ALL`, `user: 65534`, `read_only`).
- `tests/test_egress_firewall.py`: Cloud metadata endpoints (`169.254.169.254`), RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks, metadata hostnames, and domain allowlist enforcement.
- `tests/test_resource_limits.py`: Cryptographic capability token minting, HMAC signature verification, expiry checks, quota caps, directory traversal prevention (`../` attacks), file mutation diffing, and audit hash chain integrity.
- `tests/test_api_gateway.py`: Health checks, capability token minting, execution dispatch, policy violation handling, audit log queries, and metrics.

---

## 📄 License
This project is licensed under the terms of the [MIT License](LICENSE).
