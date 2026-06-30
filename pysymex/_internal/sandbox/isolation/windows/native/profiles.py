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

"""Win32 AppContainer profile and SID management."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import TYPE_CHECKING, Any

from pysymex._internal.sandbox.errors import SandboxSetupError

from .shared import (
    HANDLE_FLAG_INHERIT,
    HRESULT_ERROR_ALREADY_EXISTS,
    S_OK,
    SecurityAttributes,
    WindowsPipePair,
)


class WindowsNativeProfileMixin:
    """Mixin managing AppContainer profiles, SIDs, and standard handles."""

    if TYPE_CHECKING:
        advapi32: Any
        kernel32: Any
        userenv: Any

        def last_error_message(self, operation: str) -> str: ...

        @staticmethod
        def _unsigned_hresult(hr: int) -> int: ...

    def create_or_derive_profile(self, profile_name: str) -> int:
        """Create an AppContainer profile or derive its existing SID pointer."""
        sid = wintypes.LPVOID()
        hr = int(
            self.userenv.CreateAppContainerProfile(
                profile_name,
                "pysymex sandbox",
                "pysymex untrusted extraction sandbox",
                None,
                0,
                ctypes.byref(sid),
            ),
        )
        if hr == S_OK and sid.value:
            return int(sid.value)

        if self._unsigned_hresult(hr) != HRESULT_ERROR_ALREADY_EXISTS:
            msg = (
                f"CreateAppContainerProfile failed with HRESULT 0x{self._unsigned_hresult(hr):08x}"
            )
            raise SandboxSetupError(
                msg,
            )

        derived = wintypes.LPVOID()
        derive_hr = int(
            self.userenv.DeriveAppContainerSidFromAppContainerName(
                profile_name,
                ctypes.byref(derived),
            ),
        )
        if derive_hr != S_OK or not derived.value:
            msg = (
                "DeriveAppContainerSidFromAppContainerName failed with "
                f"HRESULT 0x{self._unsigned_hresult(derive_hr):08x}"
            )
            raise SandboxSetupError(
                msg,
            )
        return int(derived.value)

    def delete_profile(self, profile_name: str) -> None:
        """Delete an AppContainer profile."""
        self.userenv.DeleteAppContainerProfile(profile_name)

    def free_sid(self, sid: int | None) -> None:
        """Free a SID pointer when one was allocated."""
        if sid:
            self.advapi32.FreeSid(wintypes.LPVOID(sid))

    def _local_free(self, ptr: int | None) -> None:
        """Free a Win32 local heap allocation when present."""
        if ptr:
            self.kernel32.LocalFree(wintypes.HLOCAL(ptr))

    def sid_to_string(self, sid: int) -> str:
        """Format a SID pointer as a string."""
        sid_string = wintypes.LPWSTR()
        ok = self.advapi32.ConvertSidToStringSidW(
            wintypes.LPVOID(sid),
            ctypes.byref(sid_string),
        )
        if not ok or sid_string.value is None:
            raise SandboxSetupError(self.last_error_message("ConvertSidToStringSidW"))
        try:
            return str(sid_string.value)
        finally:
            sid_string_ptr = ctypes.cast(sid_string, ctypes.c_void_p)
            self._local_free(sid_string_ptr.value)

    def create_pipe_pair(self) -> WindowsPipePair:
        """Create an inheritable anonymous pipe pair."""
        attrs = SecurityAttributes()
        attrs.nLength = ctypes.sizeof(SecurityAttributes)
        attrs.lpSecurityDescriptor = None
        attrs.bInheritHandle = True

        read_handle = wintypes.HANDLE()
        write_handle = wintypes.HANDLE()
        ok = self.kernel32.CreatePipe(
            ctypes.byref(read_handle),
            ctypes.byref(write_handle),
            ctypes.byref(attrs),
            0,
        )
        if not ok or not read_handle.value or not write_handle.value:
            raise SandboxSetupError(self.last_error_message("CreatePipe"))
        return WindowsPipePair(read=int(read_handle.value), write=int(write_handle.value))

    def set_non_inheritable(self, handle: int) -> None:
        """Mark a handle as non-inheritable."""
        ok = self.kernel32.SetHandleInformation(
            wintypes.HANDLE(handle),
            HANDLE_FLAG_INHERIT,
            0,
        )
        if not ok:
            raise SandboxSetupError(self.last_error_message("SetHandleInformation"))

    def close_handle(self, handle: int | None) -> None:
        """Close an open Windows handle when present."""
        if handle:
            self.kernel32.CloseHandle(wintypes.HANDLE(handle))

    def wait(self, handle: int, timeout_ms: int) -> int:
        """Wait for a handle and return the Win32 wait status."""
        return int(self.kernel32.WaitForSingleObject(wintypes.HANDLE(handle), timeout_ms))

    def terminate_job(self, job_handle: int, exit_code: int = 1) -> None:
        """Terminate a Job Object with the provided exit code."""
        self.kernel32.TerminateJobObject(wintypes.HANDLE(job_handle), exit_code)

    def resume_thread(self, thread_handle: int) -> None:
        result = int(self.kernel32.ResumeThread(wintypes.HANDLE(thread_handle)))
        if result == 0xFFFFFFFF:
            raise SandboxSetupError(self.last_error_message("ResumeThread"))

    def assign_to_job(self, job_handle: int, process_handle: int) -> None:
        """Assign a process handle to a Job Object handle."""
        ok = self.kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(job_handle),
            wintypes.HANDLE(process_handle),
        )
        if not ok:
            raise SandboxSetupError(self.last_error_message("AssignProcessToJobObject"))

    def get_exit_code(self, process_handle: int) -> int:
        """Retrieve the current exit code for a process handle."""
        exit_code = wintypes.DWORD()
        ok = self.kernel32.GetExitCodeProcess(
            wintypes.HANDLE(process_handle),
            ctypes.byref(exit_code),
        )
        if not ok:
            raise SandboxSetupError(self.last_error_message("GetExitCodeProcess"))
        return int(exit_code.value)
