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

"""Native AppContainer process launch and pipe I/O."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from pysymex.logger import get_logger

from ....errors import SandboxSetupError
from ....types import ExecutionStatus
from .shared import NativeProcessResult
from ..native.api import (
    INFINITE,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    WindowsNativeApi,
    WindowsProcessHandles,
)

if TYPE_CHECKING:
    from ....types import SandboxConfig

logger = get_logger(__name__)


class WindowsNativeProcessMixin:
    """Mixin for running commands inside an AppContainer and Job Object."""

    if TYPE_CHECKING:
        config: SandboxConfig
        _appcontainer_sid: int | None
        _jail_path: Path | None
        _job_handle: int | None
        _runtime_path: Path | None
        _win32: WindowsNativeApi | None

        def _appcontainer_environment(self) -> dict[str, str]: ...

    def _run_native_process(
        self,
        command: list[str],
        *,
        input_data: bytes,
        output_limit: int | None = None,
    ) -> NativeProcessResult:
        """Run a command in the AppContainer and collect bounded output.

        Args:
            command: Argument vector for the AppContainer child process.
            input_data: Bytes written to the child's standard input.
            output_limit: Optional override for the captured stdout/stderr byte
                budget. When omitted, the caller's configured
                ``max_output_bytes`` applies. Trusted, pysymex-generated probes
                (such as the setup self-check) pass a fixed internal budget so a
                tightened ``max_output_bytes`` cannot misclassify their own
                bounded diagnostic output as an output-limit violation.
        """
        if (
            self._win32 is None
            or self._jail_path is None
            or self._job_handle is None
            or self._appcontainer_sid is None
        ):
            raise SandboxSetupError("Windows AppContainer backend is not set up")

        effective_limit = (
            output_limit if output_limit is not None else self.config.limits.max_output_bytes
        )
        stdin_pipe = self._win32.create_pipe_pair()
        stdout_pipe = self._win32.create_pipe_pair()
        stderr_pipe = self._win32.create_pipe_pair()
        parent_handles = [
            stdin_pipe.write,
            stdout_pipe.read,
            stderr_pipe.read,
        ]
        child_handles = [
            stdin_pipe.read,
            stdout_pipe.write,
            stderr_pipe.write,
        ]
        stdout_limit = effective_limit
        stderr_limit = self._stderr_capture_limit(effective_limit)
        process_info: WindowsProcessHandles | None = None
        stdin_thread: threading.Thread | None = None
        start = time.perf_counter()
        stdout = bytearray()
        stderr = bytearray()
        stdout_exceeded = threading.Event()
        stderr_exceeded = threading.Event()

        try:
            for handle in parent_handles:
                self._win32.set_non_inheritable(handle)

            application = command[0]
            process_info = self._win32.create_process(
                application=application,
                command=command,
                cwd=self._appcontainer_process_cwd(),
                environment=self._appcontainer_environment(),
                appcontainer_sid=self._appcontainer_sid,
                job_handle=self._job_handle,
                stdin_read=stdin_pipe.read,
                stdout_write=stdout_pipe.write,
                stderr_write=stderr_pipe.write,
            )

            for handle in child_handles:
                self._win32.close_handle(handle)
            stdin_pipe.read = 0
            stdout_pipe.write = 0
            stderr_pipe.write = 0

            stdout_thread = threading.Thread(
                target=_read_pipe,
                args=(
                    stdout_pipe.read,
                    stdout,
                    stdout_limit,
                    stdout_exceeded,
                ),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=_read_pipe,
                args=(
                    stderr_pipe.read,
                    stderr,
                    stderr_limit,
                    stderr_exceeded,
                ),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            stdout_pipe.read = 0
            stderr_pipe.read = 0

            stdin_thread = threading.Thread(
                target=_write_pipe,
                args=(stdin_pipe.write, input_data),
                daemon=True,
            )
            stdin_thread.start()
            stdin_pipe.write = 0

            self._win32.resume_thread(process_info.thread)
            wait_ms = max(1, int(self.config.limits.timeout_seconds * 1000))
            wait_result = self._win32.wait(process_info.process, wait_ms)
            if wait_result == WAIT_TIMEOUT:
                logger.warning(
                    "Windows AppContainer sandbox timed out after %ss",
                    self.config.limits.timeout_seconds,
                )
                self._win32.terminate_job(self._job_handle)
                self._win32.wait(process_info.process, INFINITE)
                status = ExecutionStatus.TIMEOUT
                exit_code = None
                error_message = f"Execution timed out after {self.config.limits.timeout_seconds}s"
            elif wait_result == WAIT_OBJECT_0:
                exit_code = self._win32.get_exit_code(process_info.process)
                status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
                error_message = None
            else:
                raise SandboxSetupError(f"WaitForSingleObject failed with result {wait_result}")

            stdin_thread.join(timeout=2.0)
            stdout_thread.join(timeout=2.0)
            stderr_thread.join(timeout=2.0)
            wall_ms = (time.perf_counter() - start) * 1000
            stdout_bytes = bytes(stdout)
            stderr_bytes = self._strip_staged_python_startup_warning(bytes(stderr))
            blocked_operations: tuple[str, ...] = ()
            if (
                stdout_exceeded.is_set()
                or stderr_exceeded.is_set()
                or len(stdout_bytes) > effective_limit
                or len(stderr_bytes) > effective_limit
            ):
                logger.warning("Windows AppContainer sandbox output exceeded configured limit")
                status = ExecutionStatus.SECURITY_VIOLATION
                error_message = "Windows AppContainer sandbox output exceeded configured limit"
                blocked_operations = ("output-limit",)
            return NativeProcessResult(
                status=status,
                exit_code=exit_code,
                stdout=stdout_bytes[:effective_limit],
                stderr=stderr_bytes[:effective_limit],
                wall_time_ms=wall_ms,
                error_message=error_message,
                blocked_operations=blocked_operations,
            )
        except Exception:
            logger.warning("Windows AppContainer native process failed", exc_info=True)
            if process_info is not None:
                self._win32.terminate_job(self._job_handle)
            raise
        finally:
            if process_info is not None:
                self._win32.close_handle(process_info.thread)
                self._win32.close_handle(process_info.process)
            for handle in (
                stdin_pipe.read,
                stdin_pipe.write,
                stdout_pipe.read,
                stdout_pipe.write,
                stderr_pipe.read,
                stderr_pipe.write,
            ):
                self._win32.close_handle(handle)

    def _stderr_capture_limit(self, limit: int) -> int:
        """Return the stderr cap including the removable staged-runtime warning."""
        if self._runtime_path is None:
            return limit
        python_executable = self._runtime_path / "python.exe"
        startup_warning = f"Failed to find real location of {python_executable}\r\n".encode()
        return limit + len(startup_warning)

    def _strip_staged_python_startup_warning(self, stderr: bytes) -> bytes:
        """Remove the staged Python location lookup warning from stderr."""
        if self._runtime_path is None:
            return stderr

        python_executable = self._runtime_path / "python.exe"
        warning = f"Failed to find real location of {python_executable}\n".encode()
        if stderr.startswith(warning):
            return stderr[len(warning) :]

        windows_warning = f"Failed to find real location of {python_executable}\r\n".encode()
        if stderr.startswith(windows_warning):
            return stderr[len(windows_warning) :]
        return stderr

    def _appcontainer_process_cwd(self) -> Path:
        """Return the staged runtime directory used as process cwd."""
        if self._runtime_path is None:
            raise SandboxSetupError("Windows AppContainer Python runtime is not staged")
        return self._runtime_path


def _read_pipe(
    handle: int,
    target: bytearray,
    limit: int,
    exceeded: threading.Event,
) -> None:
    """Read a pipe into ``target`` until EOF or the byte limit is reached."""
    import msvcrt

    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
    with os.fdopen(fd, "rb", closefd=True) as stream:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            remaining = max(0, limit - len(target))
            if remaining:
                target.extend(chunk[:remaining])
            if len(chunk) > remaining:
                exceeded.set()


def _write_pipe(handle: int, data: bytes) -> None:
    """Write bytes to a Windows pipe handle."""
    import msvcrt

    fd = msvcrt.open_osfhandle(handle, 0)
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            if data:
                stream.write(data)
    except (BrokenPipeError, OSError):
        return
