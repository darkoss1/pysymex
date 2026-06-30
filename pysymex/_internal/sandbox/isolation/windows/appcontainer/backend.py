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

"""Native Windows AppContainer isolation backend."""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

from pysymex._internal.config.sandbox.types import SecurityCapabilities
from pysymex._internal.logging.root import get_logger
from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.base import IsolationBackend
from pysymex._internal.sandbox.isolation.constants import HARNESS_FILENAME
from pysymex._internal.sandbox.isolation.harness.generator import generate_harness_script
from pysymex._internal.sandbox.isolation.windows.appcontainer.runtime.runtime_cache import (
    WindowsRuntimeCacheMixin,
)
from pysymex._internal.sandbox.isolation.windows.appcontainer.selfcheck.checks import (
    WindowsSelfCheckMixin,
)
from pysymex._internal.sandbox.isolation.windows.native.api import (
    WindowsNativeApi,
    has_windows_native_appcontainer_support,
)
from pysymex._internal.sandbox.types import SandboxResult

from .acl import AclEnvironmentMixin, make_profile_name
from .process import AppContainerProcessMixin

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.config.sandbox.types import SandboxConfig

logger = get_logger(__name__)


class AppContainerBackend(
    WindowsRuntimeCacheMixin,
    WindowsSelfCheckMixin,
    AppContainerProcessMixin,
    AclEnvironmentMixin,
    IsolationBackend,
):
    """Strong native Windows backend using AppContainer plus Job Objects."""

    def __init__(self, config: SandboxConfig) -> None:
        """Initialize the Windows AppContainer backend."""
        super().__init__(config)
        self._win32: WindowsNativeApi | None = None
        self._profile_name: str | None = None
        self._appcontainer_sid: int | None = None
        self._appcontainer_sid_string: str | None = None
        self._runtime_path: Path | None = None
        self._job_handle: int | None = None
        self._security_verified: bool = False

    @property
    def is_available(self) -> bool:
        """Return whether required AppContainer process APIs are present."""
        return has_windows_appcontainer_support()

    def get_capabilities(self) -> SecurityCapabilities:
        """Report only capabilities verified by setup's AppContainer launch."""
        verified = self._is_setup and self._security_verified
        return SecurityCapabilities(
            process_isolation=verified,
            filesystem_jail=verified,
            network_blocking=verified,
            syscall_filtering=False,
            memory_limits=verified,
            cpu_limits=verified,
            process_limits=verified,
        )

    def setup(self) -> None:
        """Create AppContainer profile, jail ACLs, Job Object, and self-check."""
        if not self.is_available:
            logger.warning("Windows AppContainer APIs are unavailable")
            msg = "Windows AppContainer APIs are not available"
            raise SandboxSetupError(msg)

        self._security_verified = False
        self._win32 = WindowsNativeApi()
        self._profile_name = make_profile_name()
        try:
            self._appcontainer_sid = self._win32.create_or_derive_profile(self._profile_name)
            self._appcontainer_sid_string = self._win32.sid_to_string(self._appcontainer_sid)
            super().setup()
            if self._jail_path is None:
                msg = "Windows AppContainer jail was not created"
                raise SandboxSetupError(msg)
            self._job_handle = self._create_configured_job_object()
            self._stage_python_runtime()
            self._grant_jail_access()
            self._verify_launch_and_security_boundary()
            self._security_verified = True
            logger.verbose(
                "Windows AppContainer sandbox verified for profile %s",
                self._profile_name,
            )
        except Exception as exc:
            logger.warning("Failed to set up Windows AppContainer sandbox", exc_info=True)
            self.cleanup()
            if isinstance(exc, SandboxSetupError):
                raise
            msg = f"Failed to set up Windows AppContainer sandbox: {exc}"
            raise SandboxSetupError(
                msg,
            ) from exc

    def cleanup(self) -> None:
        """Clean up AppContainer resources and Job Object state."""
        profile_name = self._profile_name
        win32 = self._win32
        sid = self._appcontainer_sid
        try:
            super().cleanup()
        finally:
            if win32 is not None and self._job_handle is not None:
                win32.close_handle(self._job_handle)
            if win32 is not None:
                win32.free_sid(sid)
                if profile_name is not None:
                    win32.delete_profile(profile_name)
            self._win32 = None
            self._profile_name = None
            self._appcontainer_sid = None
            self._appcontainer_sid_string = None
            self._runtime_path = None
            self._job_handle = None
            self._security_verified = False
            logger.verbose("Windows AppContainer sandbox resources cleaned")

    def reset_workspace(self) -> None:
        """Remove transient target files while preserving the shared Python runtime cache."""
        if not self._is_setup or self._jail_path is None:
            msg = "Windows AppContainer backend is not set up"
            raise SandboxSetupError(msg)

        runtime_path = self._runtime_path.resolve() if self._runtime_path is not None else None
        jail_path = self._jail_path.resolve()
        for child in self._jail_path.iterdir():
            child_resolved = child.resolve()
            if runtime_path is not None and child_resolved == runtime_path:
                continue
            if child_resolved != jail_path and jail_path not in child_resolved.parents:
                msg = f"Refusing to reset path outside AppContainer jail: {child}"
                raise SandboxSetupError(
                    msg,
                )
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

    @staticmethod
    def effective_active_process_limit(max_processes: int) -> int:
        """Force AppContainer harnesses to be the only process in their Job Object."""
        _ = max_processes
        return 1

    def _create_configured_job_object(self) -> int:
        """Create the AppContainer Job Object resource and process-spawn boundary."""
        if self._win32 is None:
            msg = "Windows AppContainer Win32 API wrapper is unavailable"
            raise SandboxSetupError(msg)
        limits = self.config.limits
        return self._win32.create_configured_job_object(
            memory_mb=limits.memory_mb,
            cpu_seconds=limits.cpu_seconds,
            active_process_limit=self.effective_active_process_limit(limits.max_processes),
        )

    def execute(
        self,
        code: bytes,
        filename: str,
        input_data: bytes,
        extra_files: dict[str, bytes],
    ) -> SandboxResult:
        """Execute code in the AppContainer-backed Python harness."""
        if (
            not self._is_setup
            or self._jail_path is None
            or self._job_handle is None
            or self._appcontainer_sid is None
            or self._win32 is None
        ):
            msg = "Windows AppContainer backend is not set up"
            raise SandboxSetupError(msg)

        self._populate_jail(code, filename, extra_files)
        harness = generate_harness_script()
        harness_path = self._jail_path / HARNESS_FILENAME
        harness_path.write_text(harness, encoding="utf-8")

        result = self._run_native_process(
            [*self._runtime_python_cmd(), str(harness_path), filename],
            input_data=input_data,
        )
        return SandboxResult(
            status=result.status,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            wall_time_ms=result.wall_time_ms,
            error_message=result.error_message,
            blocked_operations=list(result.blocked_operations),
        )


def has_windows_appcontainer_support() -> bool:
    """Return whether required native AppContainer APIs are present."""
    return has_windows_native_appcontainer_support()
