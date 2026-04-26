# pysymex: Python Symbolic Execution & Formal Verification
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

"""WebAssembly-based isolation backend (placeholder).

This backend is intended to run Python code inside a WASM runtime
for hardware-level memory isolation.  A full implementation would
use ``wasmtime`` with a pre-compiled RustPython or Pyodide module.

**Current status**: Falls back to subprocess isolation with the
hardened harness.  Capability reporting is **honest** — it only
claims capabilities that are actually enforced.

Requirements:
    - wasmtime>=14.0.0  (pip install wasmtime)
"""

from __future__ import annotations

import subprocess
import time
from typing import TYPE_CHECKING

from ..errors import SandboxSetupError
from ..types import ExecutionStatus, SandboxResult, SecurityCapabilities
from . import IsolationBackend
from .harness import HARNESS_FILENAME, generate_harness_script

if TYPE_CHECKING:
    from ..types import SandboxConfig


class WasmBackend(IsolationBackend):
    """WebAssembly-based isolation backend (placeholder).

    This backend is **not yet fully implemented**.  It falls back to
    subprocess isolation with the hardened harness.  Capability
    reporting is honest: only ``process_isolation`` and
    ``filesystem_jail`` are claimed, because the WASM runtime is
    not yet wired in.

    When fully implemented, this would provide:
    - Memory isolation (WASM linear memory model)
    - No system calls without explicit WASI imports
    - Fuel metering (instruction counting)
    - Deterministic execution
    """

    def __init__(self, config: SandboxConfig) -> None:
        super().__init__(config)
        self._process: subprocess.Popen[bytes] | None = None

    @property
    def is_available(self) -> bool:
        """Check if wasmtime is available."""
        try:
            import wasmtime  # type: ignore[reportUnusedImport]  # Import to check availability

            return True
        except ImportError:
            return False

    def get_capabilities(self) -> SecurityCapabilities:
        """Report *actually enforced* capabilities (honest)."""

        return SecurityCapabilities(
            process_isolation=True,
            filesystem_jail=True,
            network_blocking=False,
            syscall_filtering=False,
            memory_limits=False,
            cpu_limits=False,
            process_limits=False,
        )

    def setup(self) -> None:
        """Create jail directory."""
        try:
            self._jail_path = self._create_jail()
            self._is_setup = True
        except Exception as exc:
            self.cleanup()
            raise SandboxSetupError(f"Failed to create jail: {exc}") from exc

    def cleanup(self) -> None:
        """Clean up resources."""
        if self._process is not None:
            try:
                self._process.kill()
                self._process.wait(timeout=5.0)
            except Exception:
                pass
            self._process = None

        self._destroy_jail()
        self._is_setup = False

    def execute(
        self,
        code: bytes,
        filename: str,
        input_data: bytes,
        extra_files: dict[str, bytes],
    ) -> SandboxResult:
        """Execute code (subprocess fallback until WASM is implemented)."""
        if not self._is_setup or self._jail_path is None:
            raise SandboxSetupError("Backend not set up")

        self._populate_jail(code, filename, extra_files)

        harness = generate_harness_script(
            blocked_modules=self.config.harness_blocked_modules,
            allowed_imports=self.config.harness_allowed_imports,
            restrict_builtins=self.config.harness_restrict_builtins,
            install_audit_hook=self.config.harness_install_audit_hook,
            block_ast_imports=self.config.harness_block_ast_imports,
        )
        harness_path = self._jail_path / HARNESS_FILENAME
        harness_path.write_text(harness, encoding="utf-8")

        cmd: list[str] = [
            *self._python_cmd(),
            str(harness_path),
            filename,
        ]
        env = self._clean_environment()

        start_time = time.perf_counter()
        timeout = self.config.limits.timeout_seconds

        try:
            self._process = subprocess.Popen(
                cmd,
                stdin=(subprocess.PIPE if input_data else subprocess.DEVNULL),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self._jail_path),
                env=env,
            )

            stdout, stderr = self._process.communicate(
                input=input_data or None,
                timeout=timeout,
            )

            wall_time = (time.perf_counter() - start_time) * 1000
            status = (
                ExecutionStatus.SUCCESS if self._process.returncode == 0 else ExecutionStatus.FAILED
            )

            return SandboxResult(
                status=status,
                exit_code=self._process.returncode,
                stdout=stdout[: self.config.limits.max_output_bytes],
                stderr=stderr[: self.config.limits.max_output_bytes],
                wall_time_ms=wall_time,
            )

        except subprocess.TimeoutExpired:
            stdout, stderr = self._kill_and_drain()
            wall_time = (time.perf_counter() - start_time) * 1000
            return SandboxResult(
                status=ExecutionStatus.TIMEOUT,
                exit_code=None,
                stdout=stdout[: self.config.limits.max_output_bytes],
                stderr=stderr[: self.config.limits.max_output_bytes],
                wall_time_ms=wall_time,
                error_message=f"Execution timed out after {timeout}s",
            )

        except Exception as exc:
            wall_time = (time.perf_counter() - start_time) * 1000
            return SandboxResult(
                status=ExecutionStatus.CRASH,
                exit_code=None,
                wall_time_ms=wall_time,
                error_message=str(exc),
            )

        finally:
            self._process = None

    def _kill_and_drain(self) -> tuple[bytes, bytes]:
        if self._process is not None:
            self._process.kill()
            return self._process.communicate()
        return b"", b""


__all__ = ["WasmBackend"]
