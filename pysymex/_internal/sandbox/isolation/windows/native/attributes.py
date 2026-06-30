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

"""Win32 process attribute-list construction for AppContainer launch."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import TYPE_CHECKING, Any

from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.windows.appcontainer.shared import LPAC_CAPABILITY_NAMES

from .errors import get_windows_last_error
from .shared import (
    ERROR_INSUFFICIENT_BUFFER,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
    PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON,
    SE_GROUP_ENABLED,
    AttributeList,
    SecurityCapabilitiesStruct,
    SidAndAttributes,
)


class NativeAttributeMixin:
    """Mixin for LPAC capability derivation and launch attribute construction."""

    if TYPE_CHECKING:
        kernel32: Any
        securitybase: Any

        def last_error_message(self, operation: str) -> str: ...

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
            None,
            attribute_count,
            0,
            ctypes.byref(size),
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
            PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON,
        )
        self._update_attribute(
            attribute_ptr,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            ctypes.byref(mitigation_policy),
            ctypes.sizeof(mitigation_policy),
        )

        all_application_packages_policy = ctypes.c_uint32(
            PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
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
                    int(ctypes.cast(group_sids, ctypes.c_void_p).value or 0),
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
                ),
            )
            raise

        if not capability_sids:
            msg = "LPAC capability derivation returned no capability SIDs"
            raise SandboxSetupError(msg)

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
            ),
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
