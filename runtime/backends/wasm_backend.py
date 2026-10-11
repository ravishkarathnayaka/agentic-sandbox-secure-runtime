"""Hardened WebAssembly execution engine using wasmtime-py with isolated memory limits and deterministic compute bounds."""

import base64
import logging
import threading
import time
from typing import Any, List, Optional

from pydantic import BaseModel
from wasmtime import (
    Config,
    Engine,
    Linker,
    Module,
    Store,
    Trap,
    WasiConfig,
    WasmtimeError,
    wat2wasm,
)

from runtime.config import settings
from runtime.core.session import Session

logger = logging.getLogger("sandbox.wasm")


class WasmExecutionResult(BaseModel):
    """Execution receipt details for WebAssembly tasks."""
    success: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    fuel_consumed: int = 0
    result_value: Optional[str] = None
    error_message: Optional[str] = None
    timed_out: bool = False
    memory_exceeded: bool = False


class WasmBackend:
    """Isolated, sub-second WebAssembly execution runtime."""

    def __init__(
        self,
        max_memory_bytes: Optional[int] = None,
        default_fuel: Optional[int] = None,
        enable_epoch_interruption: bool = True,
    ):
        self.max_memory_bytes = max_memory_bytes or settings.WASM_MAX_MEMORY_BYTES
        self.default_fuel = default_fuel or settings.WASM_DEFAULT_FUEL
        self.enable_epoch_interruption = enable_epoch_interruption

        # Initialize Wasmtime Engine with strict security hardening
        self._config = Config()
        self._config.consume_fuel = True
        if self.enable_epoch_interruption:
            self._config.epoch_interruption = True

        self.engine = Engine(self._config)

    def _compile_module(self, code_or_bytes: str | bytes, is_wat: bool = False) -> Module:
        """Compile WAT text or Wasm binary into a validated Wasmtime Module."""
        if isinstance(code_or_bytes, str):
            code_str = code_or_bytes.strip()
            # Check if input is Base64 encoded wasm binary
            if not is_wat and not code_str.startswith("(") and len(code_str) % 4 == 0:
                try:
                    wasm_bytes = base64.b64decode(code_str)
                    return Module(self.engine, wasm_bytes)
                except Exception:
                    pass
            # Compile WAT text representation
            wasm_bytes = wat2wasm(code_str)
            return Module(self.engine, wasm_bytes)
        elif isinstance(code_or_bytes, bytes):
            return Module(self.engine, code_or_bytes)
        else:
            raise ValueError("Wasm payload must be string (WAT/Base64) or raw bytes")

    def execute(
        self,
        code: str | bytes,
        session: Session,
        function_name: Optional[str] = None,
        function_args: Optional[List[Any]] = None,
        fuel: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        memory_limit_bytes: Optional[int] = None,
        is_wat: bool = False,
    ) -> WasmExecutionResult:
        """Execute sandboxed WebAssembly with strict memory and deterministic CPU bounds."""
        start_time = time.perf_counter()
        allocated_fuel = fuel or self.default_fuel
        allocated_mem = memory_limit_bytes or self.max_memory_bytes
        timeout_sec = timeout_seconds or settings.DEFAULT_TIMEOUT_SECONDS

        store = Store(self.engine)
        store.set_fuel(allocated_fuel)
        store.set_limits(
            memory_size=allocated_mem,
            instances=1,
            tables=1,
            memories=1,
        )

        # WASI Configuration: Strict zero host access
        # Only route stdout and stderr to the ephemeral session log files
        wasi = WasiConfig()
        wasi.stdout_file = str(session.stdout_path)
        wasi.stderr_file = str(session.stderr_path)
        if session.stdin_path.exists() and session.stdin_path.stat().st_size > 0:
            wasi.stdin_file = str(session.stdin_path)
        store.set_wasi(wasi)

        linker = Linker(self.engine)
        linker.define_wasi()

        # Epoch interruption timer for hard wall-clock bounds
        epoch_cancelled = threading.Event()
        epoch_timer: Optional[threading.Timer] = None
        if self.enable_epoch_interruption:
            store.set_epoch_deadline(1)

            def tick_epoch():
                if not epoch_cancelled.is_set():
                    self.engine.increment_epoch()

            epoch_timer = threading.Timer(timeout_sec, tick_epoch)
            epoch_timer.daemon = True
            epoch_timer.start()

        timed_out = False
        memory_exceeded = False
        error_msg = None
        result_value = None
        exit_code = 0
        success = False

        try:
            module = self._compile_module(code, is_wat=is_wat)
            instance = linker.instantiate(store, module)

            # Determine entrypoint
            target_func = None
            if function_name:
                target_func = instance.exports(store).get(function_name)
                if not target_func:
                    raise ValueError(f"Exported function '{function_name}' not found in module")
            else:
                # Default to WASI _start, or main, or run, or first export
                exports = instance.exports(store)
                for candidate in ["_start", "main", "run", "calculate", "entry"]:
                    if candidate in exports:
                        target_func = exports[candidate]
                        break

            if target_func:
                args = function_args or []
                res = target_func(store, *args)
                result_value = str(res) if res is not None else None
            else:
                # If no function is invoked, module instantiation itself succeeded
                result_value = "Module instantiated successfully"

            success = True

        except (WasmtimeError, Trap, Exception) as e:
            err_str = str(e)
            error_msg = err_str

            if "fuel" in err_str.lower():
                timed_out = True
                error_msg = f"Deterministic compute limit reached: fuel exhausted ({allocated_fuel} units)"
                exit_code = 124
            elif "epoch" in err_str.lower() or "deadline" in err_str.lower() or "interrupt" in err_str.lower():
                timed_out = True
                error_msg = f"Execution timed out after {timeout_sec}s (epoch deadline exceeded)"
                exit_code = 124
            elif "memory" in err_str.lower() or "grow" in err_str.lower() or "exceeded limit" in err_str.lower():
                memory_exceeded = True
                error_msg = f"WebAssembly memory ceiling exceeded ({allocated_mem} bytes)"
                exit_code = 137
            else:
                exit_code = 1
                logger.debug(f"Wasm execution trap: {err_str}")

        finally:
            if epoch_timer:
                epoch_cancelled.set()
                epoch_timer.cancel()

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Calculate consumed fuel
        fuel_remaining = 0
        try:
            fuel_remaining = store.get_fuel()
        except Exception:
            pass
        fuel_consumed = max(0, allocated_fuel - fuel_remaining)

        stdout_content = session.read_stdout()
        stderr_content = session.read_stderr()

        return WasmExecutionResult(
            success=success,
            exit_code=exit_code,
            stdout=stdout_content,
            stderr=stderr_content if not error_msg else f"{stderr_content}\n{error_msg}".strip(),
            duration_ms=round(duration_ms, 3),
            fuel_consumed=fuel_consumed,
            result_value=result_value,
            error_message=error_msg,
            timed_out=timed_out,
            memory_exceeded=memory_exceeded,
        )
