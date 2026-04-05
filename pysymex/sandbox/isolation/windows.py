# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Windows Job Object-based isolation backend.

This backend uses Windows Job Objects to provide **enforced** resource
limits and process control on Windows 10+ systems.

Security layers:
    - Job Object with configured memory, CPU, and process limits
    - ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` — child dies when sandbox
      exits, even on crash
    - Hardened harness (modern MetaPathFinder + restricted builtins)
    - Sanitised environment (no ``PYTHONPATH`` / credential leakage)
    - ``CREATE_NEW_PROCESS_GROUP`` — separate signal domain

Requirements:
    - Windows 10 or later
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
import time
from typing import TYPE_CHECKING

from .._errors import SandboxSetupError
from .._types import ExecutionStatus, SandboxResult, SecurityCapabilities
from . import IsolationBackend
from ._harness import HARNESS_FILENAME, generate_harness_script

if TYPE_CHECKING:
    from .._types import SandboxConfig


_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: int = 0x00002000
_JOB_OBJECT_LIMIT_PROCESS_MEMORY: int = 0x00000100
_JOB_OBJECT_LIMIT_JOB_MEMORY: int = 0x00000200
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS: int = 0x00000008
_JOB_OBJECT_LIMIT_JOB_TIME: int = 0x00000004
_JOB_OBJECT_UILIMIT_HANDLES: int = 0x00000001
_JOB_OBJECT_UILIMIT_READCLIPBOARD: int = 0x00000002
_JOB_OBJECT_UILIMIT_WRITECLIPBOARD: int = 0x00000004
_JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: int = 0x00000008
_JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: int = 0x00000010
_JOB_OBJECT_UILIMIT_GLOBALATOMS: int = 0x00000020
_JOB_OBJECT_UILIMIT_DESKTOP: int = 0x00000040
_JOB_OBJECT_UILIMIT_EXITWINDOWS: int = 0x00000080
_CREATE_SUSPENDED: int = 0x00000004
_TH32CS_SNAPTHREAD: int = 0x00000004
_THREAD_SUSPEND_RESUME: int = 0x0002

_JobObjectExtendedLimitInformation: int = 9


class WindowsJobBackend(IsolationBackend):
    """Windows Job Object-based isolation backend.

    This backend provides isolation on Windows using:

    1. **Job Objects with enforced limits**: memory cap, CPU time cap,
       active-process cap, and automatic kill-on-close.
    2. **Hardened harness**: modern MetaPathFinder, sys.modules scrub,
       restricted builtins, AST pre-screening.
    3. **Sanitised environment**: minimal env dict, no credential / path
       leakage.
    4. **Filesystem jail**: ephemeral temp directory.
    """

    def __init__(self, config: SandboxConfig) -> None:
        super().__init__(config)
        self._job_handle: int | None = None
        self._process: subprocess.Popen[bytes] | None = None

    @property
    def is_available(self) -> bool:
        """Check if Windows Job Objects are available."""
        if sys.platform != "win32":
            return False
        try:
            import platform

            return int(platform.release()) >= 10
        except Exception:
            return False

    def get_capabilities(self) -> SecurityCapabilities:
        """Windows Job Objects provide good resource control."""
        return SecurityCapabilities(
            process_isolation=True,
            filesystem_jail=True,
            network_blocking=False,
            syscall_filtering=False,
            memory_limits=True,
            cpu_limits=True,
            process_limits=True,
        )

    def setup(self) -> None:
        """Create filesystem jail and configured Job Object."""
        if not self.is_available:
            raise SandboxSetupError("Windows Job Objects not available")
        try:
            self._jail_path = self._create_jail()
            self._job_handle = self._create_configured_job_object()
            self._is_setup = True
        except Exception as exc:
            self.cleanup()
            raise SandboxSetupError(f"Failed to set up sandbox: {exc}") from exc

    def cleanup(self) -> None:
        """Clean up Job Object and jail directory."""
        if self._process is not None:
            try:
                self._process.kill()
                self._process.wait(timeout=5.0)
            except Exception:
                pass
            self._process = None

        if self._job_handle is not None:
            try:
                if sys.platform == "win32":
                    ctypes.windll.kernel32.CloseHandle(self._job_handle)
            except Exception:
                pass
            self._job_handle = None

        self._destroy_jail()
        self._is_setup = False

    def execute(
        self,
        code: bytes,
        filename: str,
        input_data: bytes,
        extra_files: dict[str, bytes],
    ) -> SandboxResult:
        """Execute code with Job Object isolation."""
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
            creation_flags = 0
            started_suspended = False
            if sys.platform == "win32":
                base_flags = subprocess.CREATE_NEW_PROCESS_GROUP
                try:
                    self._process = subprocess.Popen(
                        cmd,
                        stdin=(subprocess.PIPE if input_data else subprocess.DEVNULL),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=str(self._jail_path),
                        env=env,
                        creationflags=(base_flags | _CREATE_SUSPENDED),
                    )
                    started_suspended = True
                except OSError:
                    self._process = subprocess.Popen(
                        cmd,
                        stdin=(subprocess.PIPE if input_data else subprocess.DEVNULL),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=str(self._jail_path),
                        env=env,
                        creationflags=base_flags,
                    )
            else:
                self._process = subprocess.Popen(
                    cmd,
                    stdin=(subprocess.PIPE if input_data else subprocess.DEVNULL),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=str(self._jail_path),
                    env=env,
                    creationflags=creation_flags,
                )

            self._assign_to_job()
            if started_suspended:
                self._resume_process_main_thread()

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
            if self._process is not None:
                try:
                    self._process.kill()
                    self._process.communicate(timeout=2.0)
                except Exception:
                    pass
            wall_time = (time.perf_counter() - start_time) * 1000
            return SandboxResult(
                status=ExecutionStatus.CRASH,
                exit_code=None,
                wall_time_ms=wall_time,
                error_message=str(exc),
            )

        finally:
            self._process = None

    def _create_configured_job_object(self) -> int | None:
        """Create a Job Object with **enforced** resource limits."""
        if sys.platform != "win32":
            return None

        kernel32 = ctypes.windll.kernel32
        job: int = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise SandboxSetupError("Failed to create Job Object")

        limits = self.config.limits

        from ctypes.wintypes import DWORD, LARGE_INTEGER

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", LARGE_INTEGER),
                ("PerJobUserTimeLimit", LARGE_INTEGER),
                ("LimitFlags", DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", DWORD),
                ("SchedulingClass", DWORD),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        limit_flags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | _JOB_OBJECT_LIMIT_JOB_MEMORY
        )
        if limits.cpu_seconds > 0:
            limit_flags |= _JOB_OBJECT_LIMIT_JOB_TIME

        per_job_time = limits.cpu_seconds * 10_000_000
        memory_bytes = max(1, limits.memory_mb) * 1024 * 1024

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        if limits.cpu_seconds > 0:
            info.BasicLimitInformation.PerJobUserTimeLimit = per_job_time

        info.BasicLimitInformation.LimitFlags = limit_flags
        info.BasicLimitInformation.ActiveProcessLimit = limits.max_processes
        info.ProcessMemoryLimit = memory_bytes
        info.JobMemoryLimit = memory_bytes

        ok: int = kernel32.SetInformationJobObject(
            job,
            _JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            kernel32.CloseHandle(job)
            raise SandboxSetupError("Failed to configure Job Object limits")

        _JobObjectBasicUIRestrictions = 4
        ui_flags = (
            _JOB_OBJECT_UILIMIT_HANDLES
            | _JOB_OBJECT_UILIMIT_READCLIPBOARD
            | _JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | _JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | _JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | _JOB_OBJECT_UILIMIT_GLOBALATOMS
            | _JOB_OBJECT_UILIMIT_DESKTOP
            | _JOB_OBJECT_UILIMIT_EXITWINDOWS
        )
        ui_buf = ctypes.c_uint32(ui_flags)
        ok_ui: int = kernel32.SetInformationJobObject(
            job,
            _JobObjectBasicUIRestrictions,
            ctypes.byref(ui_buf),
            ctypes.sizeof(ui_buf),
        )
        if not ok_ui:
            ui_buf = ctypes.c_uint32(0)
            ok_ui = kernel32.SetInformationJobObject(
                job,
                _JobObjectBasicUIRestrictions,
                ctypes.byref(ui_buf),
                ctypes.sizeof(ui_buf),
            )
            if not ok_ui:
                kernel32.CloseHandle(job)
                raise SandboxSetupError("Failed to configure Job Object UI restrictions")

        return job

    def _assign_to_job(self) -> None:
        """Assign the child process to the Job Object."""
        if sys.platform != "win32" or self._job_handle is None or self._process is None:
            raise SandboxSetupError("Job Object handle or process is unavailable")

        kernel32 = ctypes.windll.kernel32
        handle = int(self._process._handle)  # type: ignore[union-attr]
        ok: int = kernel32.AssignProcessToJobObject(self._job_handle, handle)
        if not ok:
            raise SandboxSetupError("Failed to assign process to Job Object")

    def _resume_process_main_thread(self) -> None:
        """Resume process after it has been safely attached to the Job Object."""
        if sys.platform != "win32" or self._process is None:
            raise SandboxSetupError("Process is unavailable for ResumeThread")

        kernel32 = ctypes.windll.kernel32

        class THREADENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_uint32),
                ("cntUsage", ctypes.c_uint32),
                ("th32ThreadID", ctypes.c_uint32),
                ("th32OwnerProcessID", ctypes.c_uint32),
                ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", ctypes.c_uint32),
            ]

        snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot in (0, -1):
            raise SandboxSetupError("Failed to capture thread snapshot")

        thread_entry = THREADENTRY32()
        thread_entry.dwSize = ctypes.sizeof(THREADENTRY32)
        found = False

        try:
            ok: int = kernel32.Thread32First(snapshot, ctypes.byref(thread_entry))
            while ok:
                if int(thread_entry.th32OwnerProcessID) == int(self._process.pid):
                    thread_handle = kernel32.OpenThread(
                        _THREAD_SUSPEND_RESUME,
                        False,
                        int(thread_entry.th32ThreadID),
                    )
                    if not thread_handle:
                        raise SandboxSetupError("Failed to open suspended process thread")
                    try:
                        resume_result: int = kernel32.ResumeThread(thread_handle)
                        if resume_result == 0xFFFFFFFF:
                            raise SandboxSetupError("Failed to resume suspended process thread")
                    finally:
                        kernel32.CloseHandle(thread_handle)
                    found = True
                    break
                ok = kernel32.Thread32Next(snapshot, ctypes.byref(thread_entry))
        finally:
            kernel32.CloseHandle(snapshot)

        if not found:
            raise SandboxSetupError("No suspended thread found for child process")

    def _kill_and_drain(self) -> tuple[bytes, bytes]:
        if self._process is not None:
            self._process.kill()
            return self._process.communicate()
        return b"", b""


__all__ = ["WindowsJobBackend"]
