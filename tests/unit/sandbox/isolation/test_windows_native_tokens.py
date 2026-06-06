import ctypes
from ctypes import wintypes
from typing import Any

import pytest

from pysymex.sandbox.errors import SandboxSetupError
from pysymex.sandbox.isolation.windows.native.last_error import set_windows_last_error
from pysymex.sandbox.isolation.windows.native.shared import (
    ERROR_INVALID_PARAMETER,
    TOKEN_IS_LESS_PRIVILEGED_APPCONTAINER,
)
from pysymex.sandbox.isolation.windows.native.tokens import WindowsNativeTokenMixin


class _FakeAdvapi32:
    def __init__(self, *, is_lpac: int, query_supported: bool = True) -> None:
        self.is_lpac = is_lpac
        self.query_supported = query_supported
        self.requested_classes: list[int] = []

    def GetTokenInformation(
        self,
        token: wintypes.HANDLE,
        token_information_class: int,
        token_information: Any,
        token_information_length: int,
        return_length: Any,
    ) -> int:
        assert token.value == 1234
        assert token_information_class == TOKEN_IS_LESS_PRIVILEGED_APPCONTAINER
        assert token_information_length == ctypes.sizeof(wintypes.DWORD)
        self.requested_classes.append(token_information_class)
        if not self.query_supported:
            set_windows_last_error(ERROR_INVALID_PARAMETER)
            return 0
        ctypes.cast(token_information, ctypes.POINTER(wintypes.DWORD)).contents.value = self.is_lpac
        ctypes.cast(return_length, ctypes.POINTER(wintypes.DWORD)).contents.value = ctypes.sizeof(
            wintypes.DWORD
        )
        return 1


class _TokenVerifierForTest(WindowsNativeTokenMixin):
    def __init__(self, *, is_lpac: int, query_supported: bool = True) -> None:
        self.advapi32 = _FakeAdvapi32(is_lpac=is_lpac, query_supported=query_supported)

    def last_error_message(self, operation: str) -> str:
        return f"{operation} failed"

    def verify_lpac_for_test(self) -> None:
        self._verify_lpac(1234)


@pytest.mark.timeout(30)
def test_lpac_token_verification_requires_lpac_token_information() -> None:
    verifier = _TokenVerifierForTest(is_lpac=1)

    verifier.verify_lpac_for_test()

    assert verifier.advapi32.requested_classes == [TOKEN_IS_LESS_PRIVILEGED_APPCONTAINER]


@pytest.mark.timeout(30)
def test_lpac_token_verification_rejects_regular_appcontainer() -> None:
    verifier = _TokenVerifierForTest(is_lpac=0)

    with pytest.raises(SandboxSetupError, match="not LPAC-backed"):
        verifier.verify_lpac_for_test()


@pytest.mark.skipif(
    not hasattr(ctypes, "set_last_error"),
    reason="Win32 last-error APIs are unavailable",
)
@pytest.mark.timeout(30)
def test_lpac_token_verification_defers_to_behavioral_check_when_query_is_unsupported() -> None:
    verifier = _TokenVerifierForTest(is_lpac=0, query_supported=False)

    verifier.verify_lpac_for_test()

    assert verifier.advapi32.requested_classes == [TOKEN_IS_LESS_PRIVILEGED_APPCONTAINER]
