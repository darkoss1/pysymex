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

"""Win32 token verification helpers for AppContainer children."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import TYPE_CHECKING, Any

from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.windows.appcontainer.shared import LPAC_CAPABILITY_NAMES

from .errors import get_windows_last_error
from .shared import (
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_PARAMETER,
    SECURITY_MANDATORY_LOW_RID,
    TOKEN_APPCONTAINER_SID,
    TOKEN_CAPABILITIES,
    TOKEN_INTEGRITY_LEVEL,
    TOKEN_IS_APPCONTAINER,
    TOKEN_IS_LESS_PRIVILEGED_APPCONTAINER,
    TOKEN_QUERY,
    TokenAppContainerInformation,
    TokenMandatoryLabel,
)


class NativeTokenMixin:
    """Mixin class for verifying security tokens of sandboxed processes."""

    if TYPE_CHECKING:
        advapi32: Any

        def close_handle(self, handle: int | None) -> None: ...

        def last_error_message(self, operation: str) -> str: ...

    def verify_appcontainer_token(
        self,
        process_handle: int,
        *,
        expected_appcontainer_sid: int | None = None,
    ) -> None:
        """Run assertions to confirm AppContainer sandboxing is active."""
        token = wintypes.HANDLE()
        ok = self.advapi32.OpenProcessToken(
            wintypes.HANDLE(process_handle),
            TOKEN_QUERY,
            ctypes.byref(token),
        )
        if not ok or not token.value:
            raise SandboxSetupError(self.last_error_message("OpenProcessToken"))
        try:
            is_appcontainer = wintypes.DWORD()
            returned = wintypes.DWORD()
            ok = self.advapi32.GetTokenInformation(
                token,
                TOKEN_IS_APPCONTAINER,
                ctypes.byref(is_appcontainer),
                ctypes.sizeof(is_appcontainer),
                ctypes.byref(returned),
            )
            if not ok:
                raise SandboxSetupError(self.last_error_message("GetTokenInformation"))
            if int(is_appcontainer.value) != 1:
                msg = "Created process token is not AppContainer-backed"
                raise SandboxSetupError(msg)
            self._verify_lpac(int(token.value))
            self._verify_low_integrity(int(token.value))
            self._verify_appcontainer_sid(
                int(token.value),
                expected_appcontainer_sid=expected_appcontainer_sid,
            )
            self._verify_expected_capability_count(int(token.value))
        finally:
            self.close_handle(int(token.value))

    def _verify_lpac(self, token: int) -> None:
        """Confirm LPAC token properties are active."""
        is_lpac = wintypes.DWORD()
        returned = wintypes.DWORD()
        ok = self.advapi32.GetTokenInformation(
            wintypes.HANDLE(token),
            TOKEN_IS_LESS_PRIVILEGED_APPCONTAINER,
            ctypes.byref(is_lpac),
            ctypes.sizeof(is_lpac),
            ctypes.byref(returned),
        )
        if not ok:
            if get_windows_last_error() == ERROR_INVALID_PARAMETER:
                return
            raise SandboxSetupError(self.last_error_message("GetTokenInformation(TokenIsLPAC)"))
        if int(is_lpac.value) != 1:
            msg = "Created process token is not LPAC-backed"
            raise SandboxSetupError(msg)

    def _verify_appcontainer_sid(
        self,
        token: int,
        *,
        expected_appcontainer_sid: int | None,
    ) -> None:
        """Check AppContainer SID matches the expected value."""
        returned = wintypes.DWORD()
        self.advapi32.GetTokenInformation(
            wintypes.HANDLE(token),
            TOKEN_APPCONTAINER_SID,
            None,
            0,
            ctypes.byref(returned),
        )
        if get_windows_last_error() != ERROR_INSUFFICIENT_BUFFER:
            raise SandboxSetupError(self.last_error_message("GetTokenInformation(TokenAppSid)"))

        buf = ctypes.create_string_buffer(int(returned.value))
        ok = self.advapi32.GetTokenInformation(
            wintypes.HANDLE(token),
            TOKEN_APPCONTAINER_SID,
            ctypes.byref(buf),
            int(returned.value),
            ctypes.byref(returned),
        )
        if not ok:
            raise SandboxSetupError(self.last_error_message("GetTokenInformation(TokenAppSid)"))

        info = ctypes.cast(
            ctypes.byref(buf),
            ctypes.POINTER(TokenAppContainerInformation),
        ).contents
        if not info.TokenAppContainer:
            msg = "Created process token has no AppContainer SID"
            raise SandboxSetupError(msg)
        if expected_appcontainer_sid is not None and not self.advapi32.EqualSid(
            info.TokenAppContainer,
            wintypes.LPVOID(expected_appcontainer_sid),
        ):
            msg = "Created process AppContainer SID does not match profile"
            raise SandboxSetupError(msg)

    def _verify_expected_capability_count(self, token: int) -> None:
        """Confirm capability token counts."""
        returned = wintypes.DWORD()
        self.advapi32.GetTokenInformation(
            wintypes.HANDLE(token),
            TOKEN_CAPABILITIES,
            None,
            0,
            ctypes.byref(returned),
        )
        if get_windows_last_error() != ERROR_INSUFFICIENT_BUFFER:
            raise SandboxSetupError(
                self.last_error_message("GetTokenInformation(TokenCapabilities)"),
            )

        buf = ctypes.create_string_buffer(int(returned.value))
        ok = self.advapi32.GetTokenInformation(
            wintypes.HANDLE(token),
            TOKEN_CAPABILITIES,
            ctypes.byref(buf),
            int(returned.value),
            ctypes.byref(returned),
        )
        if not ok:
            raise SandboxSetupError(
                self.last_error_message("GetTokenInformation(TokenCapabilities)"),
            )

        group_count = ctypes.cast(ctypes.byref(buf), ctypes.POINTER(wintypes.DWORD)).contents.value
        if int(group_count) != len(LPAC_CAPABILITY_NAMES):
            msg = "Created process token has unexpected AppContainer capability count"
            raise SandboxSetupError(
                msg,
            )

    def _verify_low_integrity(self, token: int) -> None:
        """Confirm integrity level is low."""
        returned = wintypes.DWORD()
        self.advapi32.GetTokenInformation(
            wintypes.HANDLE(token),
            TOKEN_INTEGRITY_LEVEL,
            None,
            0,
            ctypes.byref(returned),
        )
        if get_windows_last_error() != ERROR_INSUFFICIENT_BUFFER:
            raise SandboxSetupError(self.last_error_message("GetTokenInformation(TokenIL)"))

        buf = ctypes.create_string_buffer(int(returned.value))
        ok = self.advapi32.GetTokenInformation(
            wintypes.HANDLE(token),
            TOKEN_INTEGRITY_LEVEL,
            ctypes.byref(buf),
            int(returned.value),
            ctypes.byref(returned),
        )
        if not ok:
            raise SandboxSetupError(self.last_error_message("GetTokenInformation(TokenIL)"))

        label = ctypes.cast(ctypes.byref(buf), ctypes.POINTER(TokenMandatoryLabel)).contents
        sid = label.Label.Sid
        count_ptr = self.advapi32.GetSidSubAuthorityCount(sid)
        if not count_ptr:
            msg = "Could not inspect process integrity SID"
            raise SandboxSetupError(msg)
        count = int(count_ptr.contents.value)
        if count <= 0:
            msg = "Process integrity SID has no subauthorities"
            raise SandboxSetupError(msg)
        rid_ptr = self.advapi32.GetSidSubAuthority(sid, count - 1)
        if not rid_ptr:
            msg = "Could not inspect process integrity RID"
            raise SandboxSetupError(msg)
        if int(rid_ptr.contents.value) > SECURITY_MANDATORY_LOW_RID:
            msg = "AppContainer process is not low/untrusted integrity"
            raise SandboxSetupError(msg)
