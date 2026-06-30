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

"""Windows ACL and environment helpers for AppContainer isolation."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

from pysymex._internal.logging.root import get_logger
from pysymex._internal.sandbox.errors import SandboxSetupError

from .shared import (
    ALL_APPLICATION_PACKAGES_SID,
    ALL_RESTRICTED_APPLICATION_PACKAGES_SID,
)

if TYPE_CHECKING:
    from pysymex._internal.config.sandbox.types import SandboxConfig

logger = get_logger(__name__)


class AclEnvironmentMixin:
    """Mixin for ACL setup and AppContainer environment construction."""

    if TYPE_CHECKING:
        config: SandboxConfig
        _appcontainer_sid_string: str | None
        _jail_path: Path | None
        _runtime_path: Path | None

    def _grant_jail_access(self) -> None:
        """Grant modification rights on the jail path to the AppContainer SID."""
        if self._jail_path is None or self._appcontainer_sid_string is None:
            msg = "AppContainer jail or SID is unavailable"
            raise SandboxSetupError(msg)
        self._run_icacls(
            [
                str(self._jail_path),
                "/grant",
                f"*{self._appcontainer_sid_string}:(OI)(CI)M",
                "/T",
                "/C",
            ],
            context="grant AppContainer access to sandbox jail",
        )

    def _grant_runtime_cache_access(self, runtime_path: Path, *, recursive: bool) -> None:
        """Grant runtime RX access and deny write/mutation permissions."""
        traversal_args = ["/T"] if recursive else []
        for sid in (ALL_APPLICATION_PACKAGES_SID, ALL_RESTRICTED_APPLICATION_PACKAGES_SID):
            self._run_icacls(
                [
                    str(runtime_path),
                    "/deny",
                    f"*{sid}:(OI)(CI)(W,D,DC,WDAC,WO)",
                    *traversal_args,
                    "/C",
                ],
                context="deny AppContainer mutation access to runtime cache",
            )
            self._run_icacls(
                [
                    str(runtime_path),
                    "/grant",
                    f"*{sid}:(OI)(CI)RX",
                    *traversal_args,
                    "/C",
                ],
                context="grant AppContainer read/execute access to runtime cache",
            )
        if self._appcontainer_sid_string is not None:
            self._run_icacls(
                [
                    str(runtime_path),
                    "/grant",
                    f"*{self._appcontainer_sid_string}:(OI)(CI)RX",
                    *traversal_args,
                    "/C",
                ],
                context="grant LPAC package read/execute access to runtime cache",
            )

    def _run_icacls(self, args: list[str], *, context: str) -> None:
        """Run ``icacls.exe`` and raise setup errors on failure."""
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        icacls = Path(system_root) / "System32" / "icacls.exe"
        if not icacls.is_file():
            logger.warning("icacls.exe is required to %s", context)
            msg = f"icacls.exe is required to {context}"
            raise SandboxSetupError(msg)
        completed = subprocess.run(
            [str(icacls), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            logger.warning("Failed to %s", context)
            msg = f"Failed to {context}: {completed.stderr.strip() or completed.stdout.strip()}"
            raise SandboxSetupError(
                msg,
            )

    def _appcontainer_environment(self) -> dict[str, str]:
        """Construct the sanitized environment for the AppContainer process."""
        if self._jail_path is None or self._runtime_path is None:
            msg = "AppContainer jail or Python runtime is unavailable"
            raise SandboxSetupError(msg)

        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        system_drive = Path(system_root).drive or "C:"
        path_entries = [
            str(self._runtime_path),
            str(self._runtime_path / "DLLs"),
            str(Path(system_root) / "System32"),
        ]
        return {
            f"={self._jail_path.drive or system_drive}": str(self._jail_path),
            "SystemRoot": system_root,
            "SystemDrive": system_drive,
            "ComSpec": str(Path(system_root) / "System32" / "cmd.exe"),
            "PATH": os.pathsep.join(path_entries),
            "TEMP": str(self._jail_path),
            "TMP": str(self._jail_path),
            "USERPROFILE": str(self._jail_path),
            "APPDATA": str(self._jail_path),
            "LOCALAPPDATA": str(self._jail_path),
            "HOMEDRIVE": self._jail_path.drive or system_drive,
            "HOMEPATH": "\\",
            "PYSYMEX_SANDBOX_JAIL": str(self._jail_path),
            "PYTHONHOME": str(self._runtime_path),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }


def make_profile_name() -> str:
    """Generate a unique AppContainer profile name capped at 64 characters."""
    token = f"{os.getpid()}-{time.time_ns() % 1_000_000_000}"
    return f"pysymex-sandbox-{token}"[:64]
