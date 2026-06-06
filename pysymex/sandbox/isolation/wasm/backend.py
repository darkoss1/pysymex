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

"""WebAssembly/WASI isolation backend for sandboxed extraction."""

from __future__ import annotations

from importlib import import_module
from importlib.util import find_spec
from pathlib import Path
import time
from typing import TYPE_CHECKING, Any, Final

from pysymex.logger import get_logger

from ...errors import SandboxSetupError
from ...path_policy import validate_sandbox_filename
from ...types import ExecutionStatus, SandboxResult, SecurityCapabilities
from ..base import IsolationBackend
from ..constants import HARNESS_FILENAME
from ..harness import generate_harness_script
from .runtime import has_wasm_runtime_support, resolve_wasm_python_module

if TYPE_CHECKING:
    from ...types import SandboxConfig

_STDIN_FILENAME: Final[str] = "_pysymex_stdin.bin"
_STDOUT_FILENAME: Final[str] = "_pysymex_stdout.bin"
_STDERR_FILENAME: Final[str] = "_pysymex_stderr.bin"

logger = get_logger(__name__)


class WasmBackend(IsolationBackend):
    """WebAssembly/WASI backend built on wasmtime."""

    def __init__(self, config: SandboxConfig) -> None:
        """Initialize the WebAssembly sandbox backend."""
        super().__init__(config)
        self._wasm_python_module: Path | None = None

    @property
    def is_available(self) -> bool:
        """Check whether wasmtime and a WASI Python artifact are available."""
        return has_wasm_runtime_support(self.config)

    def get_capabilities(self) -> SecurityCapabilities:
        """Report the WASI capabilities this backend enforces when available."""
        return SecurityCapabilities(
            process_isolation=True,
            filesystem_jail=True,
            network_blocking=True,
            syscall_filtering=True,
            memory_limits=True,
            cpu_limits=True,
            process_limits=True,
        )

    def setup(self) -> None:
        """Create the jail after verifying strong WASM prerequisites."""
        if find_spec("wasmtime") is None:
            logger.warning("WASM sandbox backend is unavailable because wasmtime is missing")
            raise SandboxSetupError(
                "WASM sandbox backend requires the optional 'wasmtime' package. "
                "Install pysymex[sandbox] or configure another strong backend."
            )

        wasm_python = resolve_wasm_python_module(self.config)
        if wasm_python is None:
            logger.warning(
                "WASM sandbox backend is unavailable because no WASI Python module exists"
            )
            raise SandboxSetupError(
                "WASM sandbox backend requires a WASI Python module. "
                "Set SandboxConfig.wasm_python_module to a CPython-compatible "
                "WASI Python artifact."
            )

        self._wasm_python_module = wasm_python
        super().setup()
        logger.verbose("WASM sandbox jail created with module %s", wasm_python)

    def execute(
        self,
        code: bytes,
        filename: str,
        input_data: bytes,
        extra_files: dict[str, bytes],
    ) -> SandboxResult:
        """Execute target code inside the configured WASI Python runtime."""
        if not self._is_setup or self._jail_path is None or self._wasm_python_module is None:
            raise SandboxSetupError("WASM backend is not set up")

        self._validate_target_filename(filename)
        self._populate_jail(code, filename, extra_files)

        harness = generate_harness_script()
        harness_path = self._jail_path / HARNESS_FILENAME
        harness_path.write_text(harness, encoding="utf-8")

        stdin_path = self._jail_path / _STDIN_FILENAME
        stdout_path = self._jail_path / _STDOUT_FILENAME
        stderr_path = self._jail_path / _STDERR_FILENAME
        stdin_path.write_bytes(input_data)
        stdout_path.write_bytes(b"")
        stderr_path.write_bytes(b"")

        start_time = time.perf_counter()
        try:
            exit_code = self._run_wasi_python(
                argv=["python", "-I", "-B", HARNESS_FILENAME, filename],
                stdin_path=stdin_path,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            )
            wall_time = (time.perf_counter() - start_time) * 1000
            stdout, stdout_exceeded = self._read_capped_output(stdout_path)
            stderr, stderr_exceeded = self._read_capped_output(stderr_path)
            if stdout_exceeded or stderr_exceeded:
                logger.warning("WASM sandbox output exceeded configured limit")
                return SandboxResult(
                    status=ExecutionStatus.SECURITY_VIOLATION,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    wall_time_ms=wall_time,
                    error_message="WASM sandbox output exceeded configured limit",
                    blocked_operations=["output-limit"],
                )

            return SandboxResult(
                status=ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                wall_time_ms=wall_time,
            )
        except SandboxSetupError:
            raise
        except Exception as exc:
            wall_time = (time.perf_counter() - start_time) * 1000
            stdout, _ = self._read_capped_output(stdout_path)
            stderr, _ = self._read_capped_output(stderr_path)
            status = self._status_from_wasmtime_exception(exc)
            blocked_operations = (
                [status.name.lower()]
                if status
                in {
                    ExecutionStatus.TIMEOUT,
                    ExecutionStatus.MEMORY_EXCEEDED,
                    ExecutionStatus.CPU_EXCEEDED,
                    ExecutionStatus.SECURITY_VIOLATION,
                }
                else []
            )
            logger.warning(
                "WASM sandbox execution failed with status %s", status.name, exc_info=True
            )
            return SandboxResult(
                status=status,
                exit_code=None,
                stdout=stdout,
                stderr=stderr,
                wall_time_ms=wall_time,
                error_message=str(exc),
                blocked_operations=blocked_operations,
            )

    def _run_wasi_python(
        self,
        *,
        argv: list[str],
        stdin_path: Path,
        stdout_path: Path,
        stderr_path: Path,
    ) -> int:
        """Instantiate the WASI Python module and call ``_start``."""
        if self._jail_path is None or self._wasm_python_module is None:
            raise SandboxSetupError("WASM backend is not set up")

        wasmtime = self._load_wasmtime()
        config = wasmtime.Config()
        self._enable_fuel(config)
        engine = wasmtime.Engine(config)
        store = wasmtime.Store(engine)
        self._configure_store_limits(store)
        self._configure_store_fuel(store)

        wasi_config = wasmtime.WasiConfig()
        wasi_config.argv = argv
        wasi_config.env = sorted(self.config.environment.items())
        wasi_config.stdin_file = str(stdin_path)
        wasi_config.stdout_file = str(stdout_path)
        wasi_config.stderr_file = str(stderr_path)
        wasi_config.preopen_dir(str(self._jail_path), ".")
        store.set_wasi(wasi_config)

        linker = wasmtime.Linker(engine)
        linker.define_wasi()
        module = wasmtime.Module.from_file(engine, str(self._wasm_python_module))
        instance = linker.instantiate(store, module)
        exports = instance.exports(store)
        try:
            start = exports["_start"]
        except (KeyError, TypeError) as exc:
            logger.warning("WASI Python module does not export _start")
            raise SandboxSetupError("WASI Python module does not export _start") from exc

        try:
            start(store)
        except Exception as exc:
            exit_code = self._extract_wasi_exit_code(exc)
            if exit_code is not None:
                return exit_code
            raise
        return 0

    @staticmethod
    def _load_wasmtime() -> Any:
        """Load and return the wasmtime module."""
        if find_spec("wasmtime") is None:
            logger.warning("WASM sandbox backend requires wasmtime")
            raise SandboxSetupError("WASM sandbox backend requires wasmtime")
        return import_module("wasmtime")

    @staticmethod
    def _enable_fuel(config: Any) -> None:
        """Enable wasmtime fuel metering."""
        try:
            config.consume_fuel = True
        except Exception as exc:
            logger.warning("wasmtime runtime does not support fuel metering", exc_info=True)
            raise SandboxSetupError("wasmtime runtime does not support fuel metering") from exc

    def _configure_store_limits(self, store: Any) -> None:
        """Apply configured memory limits to a wasmtime store."""
        set_limits = getattr(store, "set_limits", None)
        if not callable(set_limits):
            logger.warning("wasmtime runtime does not expose memory limits")
            raise SandboxSetupError("wasmtime runtime does not expose memory limits")
        memory_bytes = max(1, self.config.limits.memory_mb) * 1024 * 1024
        set_limits(
            memory_size=memory_bytes,
            instances=1,
            memories=4,
            tables=16,
            table_elements=1_000_000,
        )

    def _configure_store_fuel(self, store: Any) -> None:
        """Configure fuel allocation on a wasmtime store."""
        fuel = self._fuel_for_limits()
        set_fuel = getattr(store, "set_fuel", None)
        if callable(set_fuel):
            set_fuel(fuel)
            return
        add_fuel = getattr(store, "add_fuel", None)
        if callable(add_fuel):
            add_fuel(fuel)
            return
        logger.warning("wasmtime runtime does not expose fuel controls")
        raise SandboxSetupError("wasmtime runtime does not expose fuel controls")

    def _fuel_for_limits(self) -> int:
        """Calculate wasmtime fuel from configured CPU and timeout limits."""
        seconds = max(float(self.config.limits.cpu_seconds), self.config.limits.timeout_seconds)
        return max(1_000_000, int(seconds * 50_000_000))

    @staticmethod
    def _extract_wasi_exit_code(exc: Exception) -> int | None:
        """Extract a numeric WASI exit status from a trap or exception."""
        for attr in ("code", "status", "exit_code"):
            value = getattr(exc, attr, None)
            if isinstance(value, int):
                return value
        name = type(exc).__name__.lower()
        if "exit" not in name:
            return None
        text = str(exc)
        for token in text.replace(":", " ").replace("=", " ").split():
            try:
                return int(token)
            except ValueError:
                continue
        return 1

    @staticmethod
    def _status_from_wasmtime_exception(exc: Exception) -> ExecutionStatus:
        """Map a wasmtime trap or runtime exception to an execution status."""
        text = f"{type(exc).__name__}: {exc}".lower()
        if "fuel" in text or "interrupt" in text or "timeout" in text:
            return ExecutionStatus.TIMEOUT
        if "memory" in text or "out of bounds" in text:
            return ExecutionStatus.MEMORY_EXCEEDED
        if "wasi" in text or "permission" in text or "capability" in text:
            return ExecutionStatus.SECURITY_VIOLATION
        return ExecutionStatus.CRASH

    def _read_capped_output(self, path: Path) -> tuple[bytes, bool]:
        """Read output bytes from a file up to the configured limit."""
        limit = self.config.limits.max_output_bytes
        try:
            size = path.stat().st_size
        except OSError:
            logger.debug("Failed to inspect WASM sandbox output file: %s", path, exc_info=True)
            return b"", False
        with path.open("rb") as fh:
            data = fh.read(limit)
        return data, size > limit

    @staticmethod
    def _validate_target_filename(filename: str) -> None:
        """Validate the target filename under the sandbox path policy."""
        try:
            validate_sandbox_filename(filename, context="WASM sandbox target filename")
        except ValueError as exc:
            raise SandboxSetupError(
                f"Invalid WASM sandbox target filename: {filename!r}: {exc}"
            ) from exc


__all__ = ["WasmBackend"]
