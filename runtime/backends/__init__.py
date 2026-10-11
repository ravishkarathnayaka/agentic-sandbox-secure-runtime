"""Execution backends for Wasm and Hardened Containers."""

from runtime.backends.container_backend import ContainerBackend, ContainerExecutionResult
from runtime.backends.wasm_backend import WasmBackend, WasmExecutionResult

__all__ = [
    "WasmBackend",
    "WasmExecutionResult",
    "ContainerBackend",
    "ContainerExecutionResult",
]
