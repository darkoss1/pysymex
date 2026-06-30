import ctypes
from collections.abc import Callable
from ctypes import wintypes
from typing import Any, cast

import pytest

from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.windows.native.process import WindowsNativeProcessMixin
from pysymex._internal.sandbox.isolation.windows.native.shared import (
    ERROR_INSUFFICIENT_BUFFER,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
    PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON,
    SE_GROUP_ENABLED,
    AttributeList,
    SidAndAttributes,
)


def _set_ctypes_last_error(error: int) -> None:
    setter = getattr(ctypes, "set_last_error", None)
    assert callable(setter)
    cast(Callable[[int], None], setter)(error)


class _FakeKernel32:
    def __init__(self) -> None:
        self.attribute_counts: list[int] = []

    def InitializeProcThreadAttributeList(
        self,
        attribute_list: object | None,
        attribute_count: int,
        flags: int,
        size: Any,
    ) -> int:
        assert flags == 0
        self.attribute_counts.append(attribute_count)
        ctypes.cast(size, ctypes.POINTER(ctypes.c_size_t)).contents.value = 128
        if attribute_list is None:
            _set_ctypes_last_error(ERROR_INSUFFICIENT_BUFFER)
            return 0
        _set_ctypes_last_error(0)
        return 1


class _NativeProcessForTest(WindowsNativeProcessMixin):
    def __init__(self) -> None:
        self.kernel32 = _FakeKernel32()
        self.updated_attributes: list[tuple[int, int]] = []

    def last_error_message(self, operation: str) -> str:
        return f"{operation} failed"

    def create_attribute_list_for_test(self) -> AttributeList:
        return self._create_attribute_list(
            appcontainer_sid=1234,
            inherited_handles=(10, 11, 12),
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
        capability_array_type = SidAndAttributes * 1
        capability_array = capability_array_type()
        capability_array[0].Sid = wintypes.LPVOID(2222)
        capability_array[0].Attributes = SE_GROUP_ENABLED
        return capability_array, (2222,), (), (), ()

    def _update_attribute(
        self,
        attribute_ptr: wintypes.LPVOID,
        attribute: int,
        value: object,
        size: int,
    ) -> None:
        if not attribute_ptr:
            raise SandboxSetupError("missing attribute list")
        self.updated_attributes.append((attribute, size))
        _ = value


@pytest.mark.skipif(
    not hasattr(ctypes, "get_last_error") or not hasattr(ctypes, "set_last_error"),
    reason="Win32 last-error APIs are unavailable",
)
@pytest.mark.timeout(30)
def test_appcontainer_launch_attributes_include_lpac_opt_out_and_mitigation() -> None:
    native = _NativeProcessForTest()

    attributes = native.create_attribute_list_for_test()

    assert native.kernel32.attribute_counts == [4, 4]
    assert [attribute for attribute, _ in native.updated_attributes] == [
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    ]
    assert attributes.capabilities.CapabilityCount == 1
    assert attributes.capability_array[0].Sid == 2222
    assert attributes.mitigation_policy.value == (
        PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
    )
    assert attributes.all_application_packages_policy.value == (
        PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
    )
    assert native.updated_attributes[-2][1] == ctypes.sizeof(ctypes.c_ulonglong)
    assert native.updated_attributes[-1][1] == ctypes.sizeof(ctypes.c_uint32)
