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
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ....errors import SandboxSetupError
from ..appcontainer.shared import LPAC_CAPABILITY_NAMES
from .last_error import get_windows_last_error
from .shared import (
    CREATE_NO_WINDOW,
    CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT,
    ERROR_INSUFFICIENT_BUFFER,
    EXTENDED_STARTUPINFO_PRESENT,
    PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
    PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    SE_GROUP_ENABLED,
    AttributeList,
    ProcessInformation,
    SecurityCapabilitiesStruct,
    SidAndAttributes,
    STARTF_USESTDHANDLES,
    StartupInfoExW,
    WindowsProcessHandles,
)


class WindowsNativeProcessMixin:
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

    def _create_attribute_list(
        self,
        *,
        appcontainer_sid: int,
        inherited_handles: tuple[int, int, int],
    ) -> AttributeList:
        """Build a process attribute list for handles and security capabilities."""
        attribute_count = 4
        size = ctypes.c_size_t(0)
        self.kernel32.InitializeProcThreadAttributeList(
            None, attribute_count, 0, ctypes.byref(size)
        )
        if get_windows_last_error() != ERROR_INSUFFICIENT_BUFFER:
            raise SandboxSetupError(self.last_error_message("InitializeProcThreadAttributeList"))

        attribute_buffer = ctypes.create_string_buffer(size.value)
        attribute_ptr = ctypes.cast(attribute_buffer, wintypes.LPVOID)
        ok = self.kernel32.InitializeProcThreadAttributeList(
            attribute_ptr,
            attribute_count,
            0,
            ctypes.byref(size),
        )
        if not ok:
            raise SandboxSetupError(self.last_error_message("InitializeProcThreadAttributeList"))

        (
            capability_array,
            capability_sids,
            capability_sid_arrays,
            capability_group_sids,
            capability_group_sid_arrays,
        ) = self._derive_lpac_capabilities()

        capabilities = SecurityCapabilitiesStruct()
        capabilities.AppContainerSid = wintypes.LPVOID(appcontainer_sid)
        capabilities.Capabilities = capability_array
        capabilities.CapabilityCount = len(capability_sids)
        capabilities.Reserved = 0
        self._update_attribute(
            attribute_ptr,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            ctypes.byref(capabilities),
            ctypes.sizeof(capabilities),
        )

        handle_array_type = wintypes.HANDLE * len(inherited_handles)
        handle_array = handle_array_type(*(wintypes.HANDLE(handle) for handle in inherited_handles))
        self._update_attribute(
            attribute_ptr,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            ctypes.byref(handle_array),
            ctypes.sizeof(handle_array),
        )

        mitigation_policy = ctypes.c_ulonglong(
            PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
        )
        self._update_attribute(
            attribute_ptr,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            ctypes.byref(mitigation_policy),
            ctypes.sizeof(mitigation_policy),
        )

        all_application_packages_policy = ctypes.c_uint32(
            PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
        )
        self._update_attribute(
            attribute_ptr,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            ctypes.byref(all_application_packages_policy),
            ctypes.sizeof(all_application_packages_policy),
        )

        return AttributeList(
            buffer=attribute_buffer,
            ptr=attribute_ptr,
            capabilities=capabilities,
            capability_array=capability_array,
            capability_sids=capability_sids,
            capability_sid_arrays=capability_sid_arrays,
            capability_group_sids=capability_group_sids,
            capability_group_sid_arrays=capability_group_sid_arrays,
            handle_array=handle_array,
            mitigation_policy=mitigation_policy,
            all_application_packages_policy=all_application_packages_policy,
        )

    def _derive_lpac_capabilities(
        self,
    ) -> tuple[
        ctypes.Array[SidAndAttributes],
        tuple[int, ...],
        tuple[int, ...],
        tuple[int, ...],
        tuple[int, ...],
    ]:
        """Build the SID arrays used for AppContainer and LPAC capabilities."""
        capability_sids: list[int] = []
        capability_sid_arrays: list[int] = []
        capability_group_sids: list[int] = []
        capability_group_sid_arrays: list[int] = []
        try:
            for capability_name in LPAC_CAPABILITY_NAMES:
                group_sids = ctypes.POINTER(wintypes.LPVOID)()
                group_count = wintypes.DWORD()
                sids = ctypes.POINTER(wintypes.LPVOID)()
                sid_count = wintypes.DWORD()
                ok = self.securitybase.DeriveCapabilitySidsFromName(
                    capability_name,
                    ctypes.byref(group_sids),
                    ctypes.byref(group_count),
                    ctypes.byref(sids),
                    ctypes.byref(sid_count),
                )
                if not ok:
                    raise SandboxSetupError(self.last_error_message("DeriveCapabilitySidsFromName"))
                capability_group_sid_arrays.append(
                    int(ctypes.cast(group_sids, ctypes.c_void_p).value or 0)
                )
                capability_sid_arrays.append(int(ctypes.cast(sids, ctypes.c_void_p).value or 0))
                capability_group_sids.extend(
                    int(group_sids[index]) for index in range(int(group_count.value))
                )
                capability_sids.extend(int(sids[index]) for index in range(int(sid_count.value)))
        except Exception:
            self._free_sid_pointers(
                (
                    *capability_group_sids,
                    *capability_sids,
                    *capability_group_sid_arrays,
                    *capability_sid_arrays,
                )
            )
            raise

        if not capability_sids:
            raise SandboxSetupError("LPAC capability derivation returned no capability SIDs")

        capability_array_type = SidAndAttributes * len(capability_sids)
        capability_array = capability_array_type()
        for index, sid in enumerate(capability_sids):
            capability_array[index].Sid = wintypes.LPVOID(sid)
            capability_array[index].Attributes = SE_GROUP_ENABLED
        return (
            capability_array,
            tuple(capability_sids),
            tuple(capability_sid_arrays),
            tuple(capability_group_sids),
            tuple(capability_group_sid_arrays),
        )

    def _free_derived_capabilities(self, attributes: AttributeList) -> None:
        """Free memory allocated for derived capability SIDs."""
        self._free_sid_pointers(
            (
                *attributes.capability_group_sids,
                *attributes.capability_sids,
                *attributes.capability_group_sid_arrays,
                *attributes.capability_sid_arrays,
            )
        )

    def _free_sid_pointers(self, pointers: tuple[int, ...]) -> None:
        """Free allocated SID pointers."""
        for pointer in pointers:
            if pointer:
                self.kernel32.LocalFree(wintypes.HLOCAL(pointer))

    def _update_attribute(
        self,
        attribute_ptr: wintypes.LPVOID,
        attribute: int,
        value: object,
        size: int,
    ) -> None:
        """Insert one mapping into a PROC_THREAD_ATTRIBUTE_LIST."""
        ok = self.kernel32.UpdateProcThreadAttribute(
            attribute_ptr,
            0,
            attribute,
            value,
            size,
            None,
            None,
        )
        if not ok:
            raise SandboxSetupError(self.last_error_message("UpdateProcThreadAttribute"))


def _make_environment_block(environment: dict[str, str]) -> str:
    """Convert an environment dictionary to a Win32 Unicode block."""
    entries = [f"{key}={value}" for key, value in sorted(environment.items())]
    return "\0".join(entries) + "\0\0"
