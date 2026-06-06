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

"""Typed Win32 API facade for native AppContainer isolation."""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Any

from ....errors import SandboxSetupError
from .job import WindowsNativeJobMixin
from .last_error import get_windows_last_error
from .process import WindowsNativeProcessMixin
from .profiles import WindowsNativeProfileMixin
from .shared import (
    INFINITE,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    ProcessInformation,
    SecurityAttributes,
    SidAndAttributes,
    StartupInfoExW,
    WindowsPipePair,
    WindowsProcessHandles,
)
from .tokens import WindowsNativeTokenMixin


class WindowsNativeApi(
    WindowsNativeProfileMixin,
    WindowsNativeTokenMixin,
    WindowsNativeProcessMixin,
    WindowsNativeJobMixin,
):
    """Typed wrapper around the Win32 calls used by the AppContainer backend."""

    def __init__(self) -> None:
        """Initialize Windows DLL function pointers and configurations."""
        if sys.platform != "win32":
            raise SandboxSetupError("Windows AppContainer backend requires win32")

        self.kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi32: Any = ctypes.WinDLL("advapi32", use_last_error=True)
        self.userenv: Any = ctypes.WinDLL("userenv", use_last_error=True)
        self.securitybase: Any = ctypes.WinDLL(
            "api-ms-win-security-base-l1-2-0",
            use_last_error=True,
        )
        self._configure_prototypes()

    @staticmethod
    def has_required_apis() -> bool:
        """Return whether the required Win32 API exports are available."""
        if sys.platform != "win32":
            return False
        try:
            userenv = ctypes.WinDLL("userenv", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            securitybase = ctypes.WinDLL("api-ms-win-security-base-l1-2-0", use_last_error=True)
        except OSError:
            return False
        return (
            all(
                hasattr(userenv, name)
                for name in (
                    "CreateAppContainerProfile",
                    "DeleteAppContainerProfile",
                    "DeriveAppContainerSidFromAppContainerName",
                )
            )
            and all(
                hasattr(ctypes.WinDLL("advapi32", use_last_error=True), name)
                for name in ("EqualSid",)
            )
            and all(
                hasattr(kernel32, name)
                for name in (
                    "AssignProcessToJobObject",
                    "CreateJobObjectW",
                    "InitializeProcThreadAttributeList",
                    "SetInformationJobObject",
                    "UpdateProcThreadAttribute",
                    "DeleteProcThreadAttributeList",
                )
            )
            and hasattr(securitybase, "DeriveCapabilitySidsFromName")
        )

    def _configure_prototypes(self) -> None:
        """Configure argument types and return values for loaded Win32 DLL functions."""
        self.userenv.CreateAppContainerProfile.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.POINTER(SidAndAttributes),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
        ]
        self.userenv.CreateAppContainerProfile.restype = ctypes.c_long

        self.userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.LPVOID),
        ]
        self.userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long

        self.userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
        self.userenv.DeleteAppContainerProfile.restype = ctypes.c_long

        self.advapi32.ConvertSidToStringSidW.argtypes = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        self.advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

        self.advapi32.FreeSid.argtypes = [wintypes.LPVOID]
        self.advapi32.FreeSid.restype = wintypes.LPVOID

        self.advapi32.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self.advapi32.OpenProcessToken.restype = wintypes.BOOL

        self.advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.advapi32.GetTokenInformation.restype = wintypes.BOOL

        self.advapi32.GetSidSubAuthorityCount.argtypes = [wintypes.LPVOID]
        self.advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(wintypes.BYTE)

        self.advapi32.GetSidSubAuthority.argtypes = [wintypes.LPVOID, wintypes.DWORD]
        self.advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)

        self.advapi32.EqualSid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
        self.advapi32.EqualSid.restype = wintypes.BOOL

        self.kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        self.kernel32.LocalFree.restype = wintypes.HLOCAL

        self.securitybase.DeriveCapabilitySidsFromName.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.POINTER(wintypes.LPVOID)),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.POINTER(wintypes.LPVOID)),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.securitybase.DeriveCapabilitySidsFromName.restype = wintypes.BOOL

        self.kernel32.GetCurrentProcess.argtypes = []
        self.kernel32.GetCurrentProcess.restype = wintypes.HANDLE

        self.kernel32.InitializeProcThreadAttributeList.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL

        self.kernel32.UpdateProcThreadAttribute.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.c_size_t,
            wintypes.LPVOID,
            ctypes.c_size_t,
            wintypes.LPVOID,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL

        self.kernel32.DeleteProcThreadAttributeList.argtypes = [wintypes.LPVOID]
        self.kernel32.DeleteProcThreadAttributeList.restype = None

        self.kernel32.CreateProcessW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.LPCWSTR,
            ctypes.POINTER(StartupInfoExW),
            ctypes.POINTER(ProcessInformation),
        ]
        self.kernel32.CreateProcessW.restype = wintypes.BOOL

        self.kernel32.CreatePipe.argtypes = [
            ctypes.POINTER(wintypes.HANDLE),
            ctypes.POINTER(wintypes.HANDLE),
            ctypes.POINTER(SecurityAttributes),
            wintypes.DWORD,
        ]
        self.kernel32.CreatePipe.restype = wintypes.BOOL

        self.kernel32.SetHandleInformation.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        self.kernel32.SetHandleInformation.restype = wintypes.BOOL

        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL

        self.kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel32.WaitForSingleObject.restype = wintypes.DWORD

        self.kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel32.TerminateJobObject.restype = wintypes.BOOL

        self.kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel32.TerminateProcess.restype = wintypes.BOOL

        self.kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        self.kernel32.ResumeThread.restype = wintypes.DWORD

        self.kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

        self.kernel32.GetExitCodeProcess.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.kernel32.GetExitCodeProcess.restype = wintypes.BOOL

        self.kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        self.kernel32.CreateJobObjectW.restype = wintypes.HANDLE

        self.kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        self.kernel32.SetInformationJobObject.restype = wintypes.BOOL

    def last_error_message(self, operation: str) -> str:
        """Format the last Win32 thread error for one operation."""
        error = get_windows_last_error()
        return f"{operation} failed with Windows error {error}"

    @staticmethod
    def _unsigned_hresult(hr: int) -> int:
        """Convert a signed HRESULT value to its unsigned representation."""
        return hr & 0xFFFFFFFF


def has_windows_native_appcontainer_support() -> bool:
    """Return whether native Windows AppContainer APIs are available."""
    return WindowsNativeApi.has_required_apis()


__all__ = [
    "INFINITE",
    "WAIT_OBJECT_0",
    "WAIT_TIMEOUT",
    "WindowsNativeApi",
    "WindowsPipePair",
    "WindowsProcessHandles",
    "has_windows_native_appcontainer_support",
]
