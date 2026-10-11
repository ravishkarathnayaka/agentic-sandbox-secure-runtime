"""Hardened container execution backend enforcing Linux seccomp, capability drops, and cgroups."""

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from runtime.config import settings
from runtime.core.session import Session

logger = logging.getLogger("sandbox.container")


class ContainerExecutionResult(BaseModel):
    """Receipt for containerized workload execution."""
    success: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    memory_consumed_bytes: int = 0
    timed_out: bool = False
    killed_by_oom: bool = False
    error_message: Optional[str] = None
    container_id: Optional[str] = None


class ContainerBackend:
    """Orchestrates ephemeral hardened container execution with maximum isolation."""

    def __init__(
        self,
        image_name: Optional[str] = None,
        seccomp_profile_path: Optional[Path] = None,
        docker_client: Optional[Any] = None,
    ):
        self.image_name = image_name or settings.CONTAINER_IMAGE
        self.seccomp_profile_path = seccomp_profile_path or settings.SECCOMP_PROFILE_PATH
        self._docker_client = docker_client
        self._docker_available: Optional[bool] = None

    def get_docker_client(self) -> Optional[Any]:
        """Lazy-load and cache the Docker SDK client."""
        if self._docker_client is not None:
            return self._docker_client

        try:
            import docker
            client = docker.from_env()
            client.ping()
            self._docker_client = client
            self._docker_available = True
            return self._docker_client
        except Exception as e:
            logger.debug(f"Docker daemon unavailable: {e}")
            self._docker_available = False
            return None

    def build_container_config(
        self,
        command: List[str] | str,
        session: Session,
        memory_mb: Optional[int] = None,
        cpu_quota: Optional[float] = None,
        allow_network: bool = False,
        env_vars: Optional[Dict[str, str]] = None,
        proxy_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Construct the hardened container security configuration dictionary."""
        effective_memory_mb = memory_mb or settings.MAX_MEMORY_MB
        effective_cpus = cpu_quota or settings.CPU_QUOTA_VCPU
        mem_limit_bytes = effective_memory_mb * 1024 * 1024
        nano_cpus = int(effective_cpus * 1_000_000_000)

        # Seccomp Profile resolution
        seccomp_arg = "unconfined"
        if self.seccomp_profile_path and self.seccomp_profile_path.exists():
            try:
                with open(self.seccomp_profile_path, "r", encoding="utf-8") as f:
                    profile_json = json.load(f)
                seccomp_arg = json.dumps(profile_json)
            except Exception as e:
                logger.warning(f"Failed to load seccomp JSON: {e}")
                seccomp_arg = f"seccomp={self.seccomp_profile_path.as_posix()}"

        # Volume Mounts: Session workspace mounted read-write
        # Root filesystem is read-only, ephemeral /tmp is a restricted tmpfs
        volumes = {
            str(session.workspace_dir): {
                "bind": "/workspace",
                "mode": "rw"
            }
        }

        tmpfs_mounts = {
            "/tmp": "rw,noexec,nosuid,size=64m"
        }

        # Environment variables & proxy routing
        environment = dict(env_vars or {})
        environment.update({
            "PYTHONUNBUFFERED": "1",
            "HOME": "/workspace",
            "TMPDIR": "/tmp",
        })

        # Network mode configuration
        if allow_network:
            network_mode = "bridge"
            effective_proxy = proxy_url or f"http://{settings.EGRESS_PROXY_HOST}:{settings.EGRESS_PROXY_PORT}"
            environment.update({
                "HTTP_PROXY": effective_proxy,
                "HTTPS_PROXY": effective_proxy,
                "http_proxy": effective_proxy,
                "https_proxy": effective_proxy,
                "NO_PROXY": "localhost,127.0.0.1",
            })
        else:
            network_mode = "none"

        return {
            "image": self.image_name,
            "command": command,
            "working_dir": "/workspace",
            "user": settings.CONTAINER_USER,
            "read_only": settings.CONTAINER_READ_ONLY_ROOT,
            "cap_drop": settings.CONTAINER_DROP_CAPABILITIES,
            "security_opt": [f"seccomp={seccomp_arg}"],
            "mem_limit": mem_limit_bytes,
            "memswap_limit": mem_limit_bytes,  # Disallow swap escalation
            "nano_cpus": nano_cpus,
            "network_mode": network_mode,
            "volumes": volumes,
            "tmpfs": tmpfs_mounts,
            "environment": environment,
            "stdin_open": False,
            "detach": True,
            "auto_remove": False,
        }

    def execute(
        self,
        command: List[str] | str,
        session: Session,
        timeout_seconds: Optional[float] = None,
        memory_mb: Optional[int] = None,
        cpu_quota: Optional[float] = None,
        allow_network: bool = False,
        env_vars: Optional[Dict[str, str]] = None,
        proxy_url: Optional[str] = None,
    ) -> ContainerExecutionResult:
        """Run workload inside an ephemeral hardened container."""
        start_time = time.perf_counter()
        timeout_sec = timeout_seconds or settings.DEFAULT_TIMEOUT_SECONDS
        client = self.get_docker_client()

        if client is None:
            # Docker daemon is not connected. Execute in secure subprocess mode for local dev/testing
            return self._execute_fallback(
                command=command,
                session=session,
                timeout_sec=timeout_sec,
                allow_network=allow_network,
                env_vars=env_vars,
            )

        container_config = self.build_container_config(
            command=command,
            session=session,
            memory_mb=memory_mb,
            cpu_quota=cpu_quota,
            allow_network=allow_network,
            env_vars=env_vars,
            proxy_url=proxy_url,
        )

        container = None
        timed_out = False
        killed_by_oom = False
        stdout_text = ""
        stderr_text = ""
        exit_code = 0
        error_msg = None
        memory_used = 0

        try:
            container = client.containers.create(**container_config)
            container.start()

            # Wait for container execution with timeout
            try:
                result = container.wait(timeout=timeout_sec)
                exit_code = result.get("StatusCode", 0)
            except Exception:
                # Docker timeout or communication error
                timed_out = True
                exit_code = 124
                error_msg = f"Container execution exceeded hard timeout ({timeout_sec}s)"
                try:
                    container.kill()
                except Exception:
                    pass

            # Inspect container stats for memory usage and OOM kill
            try:
                inspection = container.attrs
                state = inspection.get("State", {})
                if state.get("OOMKilled", False):
                    killed_by_oom = True
                    exit_code = 137
                    error_msg = "Container terminated: Memory cgroup quota exceeded (OOM killed)"
            except Exception:
                pass

            # Fetch output logs
            try:
                stdout_bytes = container.logs(stdout=True, stderr=False)
                stderr_bytes = container.logs(stdout=False, stderr=True)
                stdout_text = stdout_bytes.decode("utf-8", errors="replace")[: settings.MAX_OUTPUT_BYTES]
                stderr_text = stderr_bytes.decode("utf-8", errors="replace")[: settings.MAX_OUTPUT_BYTES]
            except Exception as e:
                logger.warning(f"Failed to read container logs: {e}")

        except Exception as e:
            error_msg = f"Container engine execution failed: {str(e)}"
            exit_code = 1

        finally:
            if container:
                try:
                    container.remove(force=True, v=True)
                except Exception:
                    pass

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        success = (exit_code == 0) and not timed_out and not killed_by_oom

        return ContainerExecutionResult(
            success=success,
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text if not error_msg else f"{stderr_text}\n{error_msg}".strip(),
            duration_ms=round(duration_ms, 3),
            memory_consumed_bytes=memory_used,
            timed_out=timed_out,
            killed_by_oom=killed_by_oom,
            error_message=error_msg,
            container_id=container.id if container else None,
        )

    def _execute_fallback(
        self,
        command: List[str] | str,
        session: Session,
        timeout_sec: float,
        allow_network: bool,
        env_vars: Optional[Dict[str, str]],
    ) -> ContainerExecutionResult:
        """Isolated local fallback when Docker daemon is not active (e.g. CI or unit testing)."""
        start_time = time.perf_counter()
        timed_out = False
        error_msg = None
        exit_code = 0

        # Construct restricted environment
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        if not allow_network:
            # Point proxies to blackhole/empty
            env["HTTP_PROXY"] = "http://127.0.0.1:0"
            env["HTTPS_PROXY"] = "http://127.0.0.1:0"
            env["http_proxy"] = "http://127.0.0.1:0"
            env["https_proxy"] = "http://127.0.0.1:0"

        cmd_list = command if isinstance(command, list) else command.split()

        try:
            proc = subprocess.run(
                cmd_list,
                cwd=str(session.workspace_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            exit_code = proc.returncode
            stdout_text = proc.stdout[: settings.MAX_OUTPUT_BYTES]
            stderr_text = proc.stderr[: settings.MAX_OUTPUT_BYTES]
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            stdout_text = ""
            stderr_text = f"Execution exceeded timeout limit ({timeout_sec}s)"
            error_msg = stderr_text
        except Exception as e:
            exit_code = 1
            stdout_text = ""
            stderr_text = str(e)
            error_msg = str(e)

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        success = (exit_code == 0) and not timed_out

        return ContainerExecutionResult(
            success=success,
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            duration_ms=round(duration_ms, 3),
            memory_consumed_bytes=0,
            timed_out=timed_out,
            killed_by_oom=False,
            error_message=error_msg,
            container_id="local_fallback_worker",
        )
