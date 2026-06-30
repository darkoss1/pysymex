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

"""AppContainer launch and hostile-operation self-checks."""

from __future__ import annotations

import json
import os
import socket
import time
from typing import TYPE_CHECKING, cast

from pysymex._internal.logging.root import get_logger
from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.windows.appcontainer.shared import (
    ALL_APPLICATION_PACKAGES_SID,
    SELF_CHECK_OUTPUT_LIMIT,
    NativeProcessResult,
)
from pysymex._internal.sandbox.types import ExecutionStatus

from .code import build_combined_self_check_code

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)


class WindowsSelfCheckMixin:
    """Mixin providing AppContainer self-check execution and validation."""

    if TYPE_CHECKING:
        _jail_path: Path | None
        _runtime_path: Path | None

        def _run_native_process(
            self,
            command: list[str],
            *,
            input_data: bytes,
            output_limit: int | None = None,
        ) -> NativeProcessResult: ...

        def _runtime_python_cmd(self) -> list[str]: ...

        def _run_icacls(self, args: list[str], *, context: str) -> None: ...

    def _verify_launch_and_security_boundary(self) -> None:
        """Run launch and hostile security probes in one AppContainer child process."""
        if self._jail_path is None or self._runtime_path is None:
            msg = "AppContainer jail or Python runtime is unavailable"
            raise SandboxSetupError(msg)

        denied_file = self._jail_path.parent / f"{self._jail_path.name}_denied_probe.txt"
        denied_file.write_text("pysymex-denied", encoding="utf-8")
        lpac_probe_file = self._jail_path.parent / f"{self._jail_path.name}_lpac_probe.txt"
        lpac_probe_file.write_text("pysymex-lpac-denied", encoding="utf-8")
        try:
            self._run_icacls(
                [
                    str(lpac_probe_file),
                    "/grant",
                    f"*{ALL_APPLICATION_PACKAGES_SID}:R",
                    "/C",
                ],
                context="grant regular AppContainer-only LPAC probe access",
            )
        except Exception:
            for path in (denied_file, lpac_probe_file):
                try:
                    path.unlink()
                except OSError:
                    logger.debug("Sandbox probe cleanup failed during setup error", exc_info=True)
            raise
        registry_probe_key = f"Software\\pysymex_sandbox_probe_{os.getpid()}_{time.time_ns()}"
        registry_probe_value = "secret"
        registry_probe_secret = f"pysymex-registry-denied-{time.time_ns()}"
        try:
            import winreg

            key = winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                registry_probe_key,
                0,
                winreg.KEY_SET_VALUE,
            )
            try:
                winreg.SetValueEx(
                    key,
                    registry_probe_value,
                    0,
                    winreg.REG_SZ,
                    registry_probe_secret,
                )
            finally:
                winreg.CloseKey(key)
        except OSError as exc:
            for path in (denied_file, lpac_probe_file):
                try:
                    path.unlink()
                except OSError:
                    logger.debug("Sandbox probe cleanup failed during setup error", exc_info=True)
            logger.warning("Failed to create Windows registry self-check key", exc_info=True)
            msg = f"Failed to create Windows registry self-check key: {exc}"
            raise SandboxSetupError(
                msg,
            ) from exc

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                host, port = listener.getsockname()
                result = self._run_native_process(
                    [
                        *self._runtime_python_cmd(),
                        "-c",
                        build_combined_self_check_code(
                            expected_profile=str(self._jail_path),
                            expected_pythonhome=str(self._runtime_path),
                            denied_file=str(denied_file),
                            lpac_probe_file=str(lpac_probe_file),
                            registry_probe_key=registry_probe_key,
                            registry_probe_value=registry_probe_value,
                            registry_probe_secret=registry_probe_secret,
                            network_host=str(host),
                            network_port=int(port),
                        ),
                    ],
                    input_data=b"",
                    output_limit=SELF_CHECK_OUTPUT_LIMIT,
                )
            self._validate_combined_self_check(result)
        finally:
            try:
                denied_file.unlink()
            except OSError:
                logger.debug("Sandbox denied-file cleanup failed", exc_info=True)
            try:
                lpac_probe_file.unlink()
            except OSError:
                logger.debug("Sandbox LPAC probe cleanup failed", exc_info=True)
            try:
                import winreg

                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_probe_key)
            except OSError:
                logger.debug("Sandbox registry probe key cleanup failed", exc_info=True)

    def _validate_combined_self_check(self, result: NativeProcessResult) -> None:
        """Validate stdout and status from the combined self-check run."""
        if result.status is not ExecutionStatus.SUCCESS:
            logger.warning("Windows AppContainer combined self-check failed")
            self._raise_self_check_failed("combined", result)
        if result.exit_code != 0:
            logger.warning("Windows AppContainer combined self-check escaped")
            self._raise_self_check_failed("combined", result)
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        try:
            payload_obj: object = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("Windows AppContainer combined self-check produced invalid JSON")
            self._raise_self_check_failed("combined-protocol", result)
            return
        if not isinstance(payload_obj, dict):
            self._raise_self_check_failed("combined-protocol", result)
            return
        payload = cast("dict[str, object]", payload_obj)
        failures = self._self_check_string_list(payload.get("failures"))
        missing = self._self_check_string_list(payload.get("missing"))
        if failures is None or missing is None:
            self._raise_self_check_failed("combined-protocol", result)
            return
        if failures or missing:
            logger.warning(
                "Windows AppContainer combined self-check reported failures=%s missing=%s",
                failures,
                missing,
            )
            self._raise_self_check_failed("combined", result)

    @staticmethod
    def _self_check_string_list(value: object) -> list[str] | None:
        """Return ``value`` as a string list when it has that exact shape."""
        if not isinstance(value, list):
            return None
        items = cast("list[object]", value)
        strings: list[str] = []
        for item in items:
            if not isinstance(item, str):
                return None
            strings.append(item)
        return strings

    def _raise_self_check_failed(self, name: str, result: NativeProcessResult) -> None:
        """Raise a formatted self-check failure for one check name."""
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        msg = (
            "Windows AppContainer security self-check failed: "
            f"{name}, status={result.status.name}, exit_code={result.exit_code}, "
            f"stdout={stdout!r}, stderr={stderr!r}"
        )
        raise SandboxSetupError(
            msg,
        )
