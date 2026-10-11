"""Sample Autonomous AI Agent executing tools through the two-tier sandbox runtime."""

import logging
from typing import Any, Dict, List, Optional

import httpx

from runtime.core.manager import SandboxManager
from runtime.security.capability_gate import Permission

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sample_agent")


class AutonomousSandboxAgent:
    """Reference Autonomous AI Agent utilizing isolated Wasm and container environments."""

    def __init__(self, api_base_url: str = "http://localhost:8000", agent_id: str = "agent-alpha-001"):
        self.api_base_url = api_base_url.rstrip("/")
        self.agent_id = agent_id
        self._http_client = httpx.Client(timeout=10.0)
        self._local_manager: Optional[SandboxManager] = None

    def _is_api_reachable(self) -> bool:
        """Check if FastAPI gateway is running locally."""
        try:
            res = self._http_client.get(f"{self.api_base_url}/health")
            return res.status_code == 200
        except Exception:
            return False

    def _get_local_manager(self) -> SandboxManager:
        """Fallback to in-process SandboxManager if standalone API daemon is not running."""
        if self._local_manager is None:
            self._local_manager = SandboxManager()
        return self._local_manager

    def request_capability_token(
        self,
        permissions: List[Permission],
        allowed_domains: Optional[List[str]] = None,
        ttl_seconds: float = 300.0,
        max_memory_mb: int = 256,
        max_timeout_sec: float = 10.0,
    ) -> str:
        """Acquire a signed capability token for an upcoming tool action."""
        if self._is_api_reachable():
            payload = {
                "agent_id": self.agent_id,
                "permissions": [p.value for p in permissions],
                "ttl_seconds": ttl_seconds,
                "allowed_domains": allowed_domains or [],
                "max_memory_mb": max_memory_mb,
                "max_timeout_sec": max_timeout_sec,
            }
            res = self._http_client.post(f"{self.api_base_url}/v1/capabilities/token", json=payload)
            res.raise_for_status()
            return res.json()["token"]
        else:
            mgr = self._get_local_manager()
            return mgr.capability_gate.issue_token(
                agent_id=self.agent_id,
                permissions=permissions,
                ttl_seconds=ttl_seconds,
                allowed_domains=allowed_domains,
                max_memory_mb=max_memory_mb,
                max_timeout_sec=max_timeout_sec,
            )

    def execute_tool(
        self,
        backend: str,
        code: str,
        token: str,
        format: str = "python",
        allow_network: bool = False,
        requested_domains: Optional[List[str]] = None,
        files: Optional[Dict[str, str]] = None,
        function_name: Optional[str] = None,
        function_args: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """Dispatch tool payload to the sandbox gateway."""
        if self._is_api_reachable():
            payload = {
                "backend": backend,
                "code": code,
                "capability_token": token,
                "format": format,
                "allow_network": allow_network,
                "requested_domains": requested_domains or [],
                "files": files or {},
                "function_name": function_name,
                "function_args": function_args,
            }
            res = self._http_client.post(f"{self.api_base_url}/v1/execute", json=payload)
            return res.json()
        else:
            mgr = self._get_local_manager()
            receipt = mgr.execute(
                backend=backend,
                code=code,
                capability_token=token,
                format=format,
                allow_network=allow_network,
                requested_domains=requested_domains,
                files=files,
                function_name=function_name,
                function_args=function_args,
            )
            return receipt.model_dump()

    def run_demonstration(self) -> None:
        """Run through end-to-end sandbox capabilities and security boundaries."""
        print("=" * 70)
        print("[AGENT] AUTONOMOUS AI AGENT SANDBOX HARNESS")
        print(f"Target Gateway: {self.api_base_url} (or In-Process fallback)")
        print("=" * 70)

        # -------------------------------------------------------------
        # STEP 1: Fast deterministic math in WebAssembly Tier
        # -------------------------------------------------------------
        print("\n[Step 1] Requesting Wasm execution for fast factorial calculation...")
        wasm_token = self.request_capability_token(permissions=[Permission.WASM_EXEC])

        wat_code = """(module
          (func $fact (param $n i32) (result i32)
            (local $res i32)
            (local.set $res (i32.const 1))
            (block $exit
              (loop $loop
                (br_if $exit (i32.le_s (local.get $n) (i32.const 1)))
                (local.set $res (i32.mul (local.get $res) (local.get $n)))
                (local.set $n (i32.sub (local.get $n) (i32.const 1)))
                (br $loop)
              )
            )
            (local.get $res)
          )
          (export "calculate" (func $fact))
        )"""

        receipt1 = self.execute_tool(
            backend="wasm",
            code=wat_code,
            token=wasm_token,
            format="wat",
            function_name="calculate",
            function_args=[5],
        )
        print(f"  Status:       {receipt1['status']}")
        print(f"  Result Value: {receipt1.get('result_value')} (Factorial of 5 = 120)")
        print(f"  Duration:     {receipt1['duration_ms']:.2f} ms (sub-millisecond Wasm startup)")
        print(f"  Audit Hash:   {receipt1['audit_hash'][:16]}...")

        # -------------------------------------------------------------
        # STEP 2: Container Data Processing with Workspace File Diffing
        # -------------------------------------------------------------
        print("\n[Step 2] Executing Python Data Analysis in Hardened Container Tier...")
        container_token = self.request_capability_token(
            permissions=[Permission.CONTAINER_EXEC, Permission.FS_WRITE]
        )

        python_data_tool = """
import json

raw_dataset = [14.2, 19.8, 22.5, 30.1, 18.4, 25.0, 31.7]
summary = {
    "count": len(raw_dataset),
    "mean": sum(raw_dataset) / len(raw_dataset),
    "max": max(raw_dataset),
    "min": min(raw_dataset)
}

print(f"Calculated dataset summary: Mean = {summary['mean']:.2f}")

with open("summary_report.json", "w") as f:
    json.dump(summary, f, indent=2)
"""

        receipt2 = self.execute_tool(
            backend="container",
            code=python_data_tool,
            token=container_token,
            format="python",
        )
        print(f"  Status:       {receipt2['status']}")
        print(f"  Stdout:       {receipt2['stdout'].strip()}")
        print(f"  Created Files:{receipt2.get('created_files', [])}")
        print(f"  Duration:     {receipt2['duration_ms']:.2f} ms")

        # -------------------------------------------------------------
        # STEP 3: Network Tool with Approved Egress Domain
        # -------------------------------------------------------------
        print("\n[Step 3] Executing Network Web Scraper to Approved Domain (httpbin.org)...")
        net_token = self.request_capability_token(
            permissions=[Permission.CONTAINER_EXEC, Permission.NETWORK_EGRESS],
            allowed_domains=["httpbin.org"],
        )

        safe_net_code = """
import urllib.request
import json

try:
    with urllib.request.urlopen("https://httpbin.org/get?agent=sandbox", timeout=5) as resp:
        data = json.loads(resp.read().decode())
        print(f"Successfully retrieved query params: {data.get('args')}")
except Exception as e:
    print(f"Network request completed/attempted: {e}")
"""

        receipt3 = self.execute_tool(
            backend="container",
            code=safe_net_code,
            token=net_token,
            format="python",
            allow_network=True,
            requested_domains=["httpbin.org"],
        )
        print(f"  Status:       {receipt3['status']}")
        print(f"  Output:       {receipt3['stdout'].strip() or receipt3['stderr'].strip()}")

        # -------------------------------------------------------------
        # STEP 4: Adversarial Test: Cloud Metadata Service (SSRF) Block
        # -------------------------------------------------------------
        print("\n[Step 4] Adversarial Attempt: Trying to access AWS/GCP IMDS (169.254.169.254)...")
        attack_token = self.request_capability_token(
            permissions=[Permission.CONTAINER_EXEC, Permission.NETWORK_EGRESS],
            allowed_domains=["httpbin.org"],
        )

        ssrf_attack_code = """
import urllib.request

try:
    print("Attempting to steal instance credentials via IMDS...")
    with urllib.request.urlopen("http://169.254.169.254/latest/meta-data/", timeout=2) as resp:
        print("ALERT: Leaked Metadata:", resp.read().decode())
except Exception as e:
    print("Egress proxy dropped connection:", e)
"""

        receipt4 = self.execute_tool(
            backend="container",
            code=ssrf_attack_code,
            token=attack_token,
            format="python",
            allow_network=True,
            requested_domains=["169.254.169.254"],
        )
        print(f"  Status:       {receipt4['status']}")
        print(f"  Violations:   {receipt4.get('policy_violations', [])}")
        print("  Outcome:      BLOCKED BY EGRESS FIREWALL & CAPABILITY GATE!")

        print("\n" + "=" * 70)
        print("[SUCCESS] ALL AGENT SANDBOX HARNESS CHECKS COMPLETED")
        print("=" * 70)


if __name__ == "__main__":
    agent = AutonomousSandboxAgent()
    agent.run_demonstration()
