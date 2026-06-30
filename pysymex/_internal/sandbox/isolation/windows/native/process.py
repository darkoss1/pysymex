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

"""Win32 AppContainer process creation helpers."""

from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes
from typing import TYPE_CHECKING, Any

from pysymex._internal.sandbox.errors import SandboxSetupError

from .attributes import NativeAttributeMixin
from .shared import (
    CREATE_NO_WINDOW,
    CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT,
    STARTF_USESTDHANDLES,
    ProcessInformation,
    StartupInfoExW,
    WindowsProcessHandles,
)

if TYPE_CHECKING:
    from pathlib import Path


class NativeProcessCreationMixin(NativeAttributeMixin):
    """Mixin for creating AppContainer child processes."""

    if TYPE_CHECKING:
        kernel32: Any
        securitybase: Any

        def assign_to_job(self, job_handle: int, process_handle: int) -> None: ...

        def close_handle(self, handle: int | None) -> None: ...

        def last_error_message(self, operation: str) -> str: ...

        def verify_appcontainer_token(
            self,
            process_handle: int,
            *,
            expected_appcontainer_sid: int | None = None,
        ) -> None: ...

    def create_process(
        self,
        *,
        application: str,
        command: list[str],
        cwd: Path,
        environment: dict[str, str],
        appcontainer_sid: int,
        job_handle: int,
        stdin_read: int,
        stdout_write: int,
        stderr_write: int,
    ) -> WindowsProcessHandles:
        """Spawn a suspended AppContainer process with inherited pipe handles."""
        attributes = self._create_attribute_list(
            appcontainer_sid=appcontainer_sid,
            inherited_handles=(stdin_read, stdout_write, stderr_write),
        )
        startup = StartupInfoExW()
        startup.StartupInfo.cb = ctypes.sizeof(StartupInfoExW)
        startup.StartupInfo.lpDesktop = "winsta0\\default"
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = wintypes.HANDLE(stdin_read)
        startup.StartupInfo.hStdOutput = wintypes.HANDLE(stdout_write)
        startup.StartupInfo.hStdError = wintypes.HANDLE(stderr_write)
        startup.lpAttributeList = attributes.ptr

        process_info = ProcessInformation()
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        env_block = _make_environment_block(environment)
        env_buffer = ctypes.create_unicode_buffer(env_block)
        try:
            ok = self.kernel32.CreateProcessW(
                application,
                command_line,
                None,
                None,
                True,
                (
                    EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW
                    | CREATE_SUSPENDED
                ),
                env_buffer,
                str(cwd),
                ctypes.byref(startup),
                ctypes.byref(process_info),
            )
            if not ok:
                raise SandboxSetupError(self.last_error_message("CreateProcessW"))
            process_handle = int(process_info.hProcess)
            self.assign_to_job(job_handle, process_handle)
            self.verify_appcontainer_token(
                process_handle,
                expected_appcontainer_sid=appcontainer_sid,
            )
            return WindowsProcessHandles(
                process=process_handle,
                thread=int(process_info.hThread),
                process_id=int(process_info.dwProcessId),
                thread_id=int(process_info.dwThreadId),
            )
        except Exception:
            if process_info.hProcess:
                self.kernel32.TerminateProcess(process_info.hProcess, 1)
                self.close_handle(int(process_info.hProcess))
            if process_info.hThread:
                self.close_handle(int(process_info.hThread))
            raise
        finally:
            self.kernel32.DeleteProcThreadAttributeList(attributes.ptr)
            self._free_derived_capabilities(attributes)


WindowsNativeProcessMixin = NativeProcessCreationMixin


def _make_environment_block(environment: dict[str, str]) -> str:
    """Convert an environment dictionary to a Win32 Unicode block."""
    entries = [f"{key}={value}" for key, value in sorted(environment.items())]
    return "\0".join(entries) + "\0\0"
