# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Sandbox overhead benchmark workloads."""

from __future__ import annotations

from pysymex.sandbox import (
    ExecutionStatus,
    ResourceLimits,
    SandboxConfig,
    SecureSandbox,
)
from pysymex.sandbox.bridge.cache import clear_module_extraction_cache
from pysymex.sandbox.bridge.module import extract_module

_NOOP_SOURCE = "value = 1 + 1\n"
_MODULE_SOURCE = b"""
CONSTANT = 7

def target(x: int) -> int:
    if x > 0:
        return x + CONSTANT
    return CONSTANT - x
""".strip()


def _bridge_config() -> dict[str, object]:
    """Return conservative sandbox bridge benchmark limits."""
    return {
        "timeout_seconds": 5.0,
        "cpu_seconds": 5,
        "memory_mb": 256,
        "max_output_bytes": 64 * 1024,
    }


def _sandbox_benchmark_config() -> SandboxConfig:
    """Return sandbox config for strong-backend overhead measurement."""
    return SandboxConfig(
        limits=ResourceLimits(
            timeout_seconds=5.0,
            cpu_seconds=5,
            memory_mb=256,
            max_output_bytes=64 * 1024,
        ),
    )


def bench_sandbox_strong_setup() -> dict[str, int]:
    """Measure sandbox context setup and cleanup overhead."""
    with SecureSandbox(_sandbox_benchmark_config()) as sandbox:
        if not sandbox.is_active:
            raise RuntimeError("Sandbox did not become active during setup benchmark")
    return {"instructions": 1, "paths": 0, "solver_calls": 0}


def bench_sandbox_strong_execute_noop() -> dict[str, int]:
    """Measure sandbox setup plus execution of a tiny deterministic Python workload."""
    with SecureSandbox(_sandbox_benchmark_config()) as sandbox:
        result = sandbox.execute_code(_NOOP_SOURCE, filename="sandbox_noop.py")
    if result.status is not ExecutionStatus.SUCCESS:
        detail = result.error_message or result.get_combined_output().strip()
        raise RuntimeError(f"Sandbox noop execution failed: {detail}")
    return {"instructions": 1, "paths": 0, "solver_calls": 0}


def bench_sandbox_extract_module_cold() -> dict[str, int]:
    """Measure cold sandbox bridge module extraction with cache disabled."""
    clear_module_extraction_cache()
    blob = extract_module(
        _MODULE_SOURCE,
        "sandbox_benchmark_target.py",
        sandbox_config=_bridge_config(),
        use_cache=False,
    )
    if not blob.get_function_blob("target").payload:
        raise RuntimeError("Sandbox extraction benchmark produced an empty target payload")
    return {"instructions": 1, "paths": 0, "solver_calls": 0}


def bench_sandbox_extract_module_cached() -> dict[str, int]:
    """Measure process-local cache-hit overhead for sandbox bridge module extraction."""
    blob = extract_module(
        _MODULE_SOURCE,
        "sandbox_benchmark_target.py",
        sandbox_config=_bridge_config(),
        use_cache=True,
    )
    if not blob.get_function_blob("target").payload:
        raise RuntimeError("Sandbox cached extraction benchmark produced an empty target payload")
    return {"instructions": 1, "paths": 0, "solver_calls": 0}
