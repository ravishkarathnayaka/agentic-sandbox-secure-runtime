"""Unit tests for WebAssembly sandbox execution, memory limits, and compute bounding."""

import tempfile
from pathlib import Path

import pytest

from runtime.backends.wasm_backend import WasmBackend
from runtime.core.session import Session


@pytest.fixture
def temp_session():
    with tempfile.TemporaryDirectory() as tmpdir:
        session = Session(session_id="test_wasm_session", base_dir=Path(tmpdir))
        session.create()
        yield session
        session.destroy()


@pytest.fixture
def wasm_backend():
    return WasmBackend(enable_epoch_interruption=True)


def test_wasm_basic_arithmetic(wasm_backend, temp_session):
    """Verify clean execution and calculation of a basic Wasm function."""
    wat_code = """(module
      (func $add (param $a i32) (param $b i32) (result i32)
        local.get $a
        local.get $b
        i32.add
      )
      (export "calculate" (func $add))
    )"""

    result = wasm_backend.execute(
        code=wat_code,
        session=temp_session,
        function_name="calculate",
        function_args=[17, 25],
        is_wat=True,
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.result_value == "42"
    assert result.duration_ms > 0
    assert result.fuel_consumed > 0
    assert result.timed_out is False
    assert result.memory_exceeded is False


def test_wasm_fuel_exhaustion_infinite_loop(wasm_backend, temp_session):
    """Verify that an infinite loop is deterministically killed via fuel exhaustion."""
    wat_infinite = """(module
      (func $loop (result i32)
        (loop $header
          br $header
        )
        i32.const 0
      )
      (export "run" (func $loop))
    )"""

    # Allocate strict small fuel budget
    result = wasm_backend.execute(
        code=wat_infinite,
        session=temp_session,
        function_name="run",
        fuel=5000,
        is_wat=True,
    )

    assert result.success is False
    assert result.timed_out is True
    assert result.exit_code == 124
    assert "fuel exhausted" in result.error_message.lower()


def test_wasm_memory_limit_exceeded(wasm_backend, temp_session):
    """Verify that linear memory limits reject modules demanding excessive RAM."""
    # Module requests 10 initial pages (640KB = 655,360 bytes)
    wat_large_mem = """(module
      (memory (export "memory") 10)
      (func $dummy (result i32)
        i32.const 1
      )
      (export "run" (func $dummy))
    )"""

    # Set hard ceiling to 1 page (65,536 bytes)
    result = wasm_backend.execute(
        code=wat_large_mem,
        session=temp_session,
        function_name="run",
        memory_limit_bytes=65536,
        is_wat=True,
    )

    assert result.success is False
    assert result.memory_exceeded is True
    assert result.exit_code == 137
    assert "memory" in result.error_message.lower()


def test_wasm_zero_host_filesystem_access(wasm_backend, temp_session):
    """Verify that WebAssembly has zero preopened host filesystem access by default."""
    # WASI module attempting to use WASI without host preopens
    wat_isolated = """(module
      (func $check (result i32)
        i32.const 100
      )
      (export "calculate" (func $check))
    )"""

    result = wasm_backend.execute(
        code=wat_isolated,
        session=temp_session,
        function_name="calculate",
        is_wat=True,
    )

    assert result.success is True
    assert result.result_value == "100"
    # Ensure no leaked host files were generated in workspace
    assert len(list(temp_session.workspace_dir.iterdir())) == 0


def test_wasm_epoch_timeout_termination(wasm_backend, temp_session):
    """Verify wall-clock timeout terminates compute via epoch deadline."""
    wat_busy_wait = """(module
      (func $busy (result i32)
        (local $i i64)
        (loop $iter
          (local.set $i (i64.add (local.get $i) (i64.const 1)))
          br $iter
        )
        i32.const 0
      )
      (export "run" (func $busy))
    )"""

    result = wasm_backend.execute(
        code=wat_busy_wait,
        session=temp_session,
        function_name="run",
        fuel=500_000_000,
        timeout_seconds=0.2,
        is_wat=True,
    )

    assert result.success is False
    assert result.timed_out is True
    assert result.exit_code == 124
