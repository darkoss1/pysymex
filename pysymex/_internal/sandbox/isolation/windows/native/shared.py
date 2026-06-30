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

"""Win32 constants and ctypes structures for AppContainer isolation."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from typing import Final

S_OK: Final[int] = 0

HRESULT_ERROR_ALREADY_EXISTS: Final[int] = 0x800700B7

ERROR_INSUFFICIENT_BUFFER: Final[int] = 122

ERROR_INVALID_PARAMETER: Final[int] = 87

EXTENDED_STARTUPINFO_PRESENT: Final[int] = 0x00080000

CREATE_UNICODE_ENVIRONMENT: Final[int] = 0x00000400

CREATE_NO_WINDOW: Final[int] = 0x08000000

CREATE_SUSPENDED: Final[int] = 0x00000004

STARTF_USESTDHANDLES: Final[int] = 0x00000100

HANDLE_FLAG_INHERIT: Final[int] = 0x00000001

WAIT_OBJECT_0: Final[int] = 0x00000000

WAIT_TIMEOUT: Final[int] = 0x00000102

INFINITE: Final[int] = 0xFFFFFFFF

TOKEN_QUERY: Final[int] = 0x0008

TOKEN_IS_APPCONTAINER: Final[int] = 29

TOKEN_CAPABILITIES: Final[int] = 30

TOKEN_APPCONTAINER_SID: Final[int] = 31

TOKEN_IS_LESS_PRIVILEGED_APPCONTAINER: Final[int] = 46

TOKEN_INTEGRITY_LEVEL: Final[int] = 25

SECURITY_MANDATORY_LOW_RID: Final[int] = 0x00001000

SE_GROUP_ENABLED: Final[int] = 0x00000004

PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: Final[int] = 0x0002000F

PROC_THREAD_ATTRIBUTE_HANDLE_LIST: Final[int] = 0x00020002

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: Final[int] = 0x00020009

PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: Final[int] = 0x00020007

PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON: Final[int] = 0x00000001 << 32

PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: Final[int] = 0x00000001

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final[int] = 0x00002000

JOB_OBJECT_LIMIT_PROCESS_MEMORY: Final[int] = 0x00000100

JOB_OBJECT_LIMIT_JOB_MEMORY: Final[int] = 0x00000200

JOB_OBJECT_LIMIT_ACTIVE_PROCESS: Final[int] = 0x00000008

JOB_OBJECT_LIMIT_JOB_TIME: Final[int] = 0x00000004

JOB_OBJECT_UILIMIT_HANDLES: Final[int] = 0x00000001

JOB_OBJECT_UILIMIT_READCLIPBOARD: Final[int] = 0x00000002

JOB_OBJECT_UILIMIT_WRITECLIPBOARD: Final[int] = 0x00000004

JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: Final[int] = 0x00000008

JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: Final[int] = 0x00000010

JOB_OBJECT_UILIMIT_GLOBALATOMS: Final[int] = 0x00000020

JOB_OBJECT_UILIMIT_DESKTOP: Final[int] = 0x00000040

JOB_OBJECT_UILIMIT_EXITWINDOWS: Final[int] = 0x00000080

JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: Final[int] = 9

JOB_OBJECT_BASIC_UI_RESTRICTIONS_CLASS: Final[int] = 4


@dataclass(slots=True, frozen=True)
class WindowsProcessHandles:
    """Container for Windows process and thread handles and identifiers."""

    process: int
    thread: int
    process_id: int
    thread_id: int


class SecurityAttributes(ctypes.Structure):
    """Ctypes structure representing SECURITY_ATTRIBUTES."""

    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class StartupInfoW(ctypes.Structure):
    """Ctypes structure representing STARTUPINFOW."""

    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class StartupInfoExW(ctypes.Structure):
    """Ctypes structure representing STARTUPINFOEXW."""

    _fields_ = [
        ("StartupInfo", StartupInfoW),
        ("lpAttributeList", wintypes.LPVOID),
    ]


class ProcessInformation(ctypes.Structure):
    """Ctypes structure representing PROCESS_INFORMATION."""

    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class SidAndAttributes(ctypes.Structure):
    """Ctypes structure representing SID_AND_ATTRIBUTES."""

    _fields_ = [
        ("Sid", wintypes.LPVOID),
        ("Attributes", wintypes.DWORD),
    ]


class SecurityCapabilitiesStruct(ctypes.Structure):
    """Ctypes structure representing SECURITY_CAPABILITIES."""

    _fields_ = [
        ("AppContainerSid", wintypes.LPVOID),
        ("Capabilities", ctypes.POINTER(SidAndAttributes)),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class TokenMandatoryLabel(ctypes.Structure):
    """Ctypes structure representing TOKEN_MANDATORY_LABEL."""

    _fields_ = [("Label", SidAndAttributes)]


class TokenAppContainerInformation(ctypes.Structure):
    """Ctypes structure representing TOKEN_APPCONTAINER_INFORMATION."""

    _fields_ = [("TokenAppContainer", wintypes.LPVOID)]


@dataclass(slots=True)
class WindowsPipePair:
    """Dataclass representing read and write handles for a pipe pair."""

    read: int
    write: int


@dataclass(slots=True)
class AttributeList:
    """Container mapping ProcThreadAttribute memory pointers and Sid allocations."""

    buffer: ctypes.Array[ctypes.c_char]
    ptr: wintypes.LPVOID
    capabilities: SecurityCapabilitiesStruct
    capability_array: ctypes.Array[SidAndAttributes]
    capability_sids: tuple[int, ...]
    capability_sid_arrays: tuple[int, ...]
    capability_group_sids: tuple[int, ...]
    capability_group_sid_arrays: tuple[int, ...]
    handle_array: object
    mitigation_policy: ctypes.c_ulonglong
    all_application_packages_policy: ctypes.c_uint32
