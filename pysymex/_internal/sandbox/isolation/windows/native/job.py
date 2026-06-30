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

"""Win32 Job Object configuration for AppContainer children."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import TYPE_CHECKING, Any

from pysymex._internal.sandbox.errors import SandboxSetupError

from .shared import (
    JOB_OBJECT_BASIC_UI_RESTRICTIONS_CLASS,
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_JOB_TIME,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS,
    JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
    JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
)


class WindowsNativeJobMixin:
    """Mixin for configuring Win32 Job Object resource boundaries."""

    if TYPE_CHECKING:
        kernel32: Any

        def close_handle(self, handle: int | None) -> None: ...

    def create_configured_job_object(
        self,
        *,
        memory_mb: int,
        cpu_seconds: int,
        active_process_limit: int,
    ) -> int:
        """Create a Job Object and apply memory, CPU, and process limits."""
        job: int = int(self.kernel32.CreateJobObjectW(None, None))
        if not job:
            msg = "Failed to create Windows AppContainer Job Object"
            raise SandboxSetupError(msg)

        class _IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class _JobObjectBasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _JobObjectExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _JobObjectBasicLimitInformation),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        # Kill-on-close and active-process limits are the process-tree escape boundary.
        limit_flags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_MEMORY
        )
        if cpu_seconds > 0:
            limit_flags |= JOB_OBJECT_LIMIT_JOB_TIME

        info = _JobObjectExtendedLimitInformation()
        if cpu_seconds > 0:
            info.BasicLimitInformation.PerJobUserTimeLimit = cpu_seconds * 10_000_000
        info.BasicLimitInformation.LimitFlags = limit_flags
        info.BasicLimitInformation.ActiveProcessLimit = active_process_limit

        memory_bytes = max(1, memory_mb) * 1024 * 1024
        info.ProcessMemoryLimit = memory_bytes
        info.JobMemoryLimit = memory_bytes

        ok = int(
            self.kernel32.SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                ctypes.byref(info),
                ctypes.sizeof(info),
            ),
        )
        if not ok:
            self.close_handle(job)
            msg = "Failed to configure Windows AppContainer Job Object limits"
            raise SandboxSetupError(msg)

        ui_flags = (
            JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_EXITWINDOWS
        )
        ui_buf = ctypes.c_uint32(ui_flags)
        ok_ui = int(
            self.kernel32.SetInformationJobObject(
                job,
                JOB_OBJECT_BASIC_UI_RESTRICTIONS_CLASS,
                ctypes.byref(ui_buf),
                ctypes.sizeof(ui_buf),
            ),
        )
        if not ok_ui:
            ui_buf = ctypes.c_uint32(0)
            ok_ui = int(
                self.kernel32.SetInformationJobObject(
                    job,
                    JOB_OBJECT_BASIC_UI_RESTRICTIONS_CLASS,
                    ctypes.byref(ui_buf),
                    ctypes.sizeof(ui_buf),
                ),
            )
            if not ok_ui:
                self.close_handle(job)
                msg = "Failed to configure Windows AppContainer Job Object UI restrictions"
                raise SandboxSetupError(
                    msg,
                )

        return job
