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

"""Generated-harness launch and result collection for Linux namespace isolation."""

from __future__ import annotations

import subprocess
import time
from typing import TYPE_CHECKING

from pysymex._internal.logging.root import get_logger
from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.constants import HARNESS_FILENAME
from pysymex._internal.sandbox.isolation.harness.generator import generate_harness_script
from pysymex._internal.sandbox.types import ExecutionStatus, SandboxResult

from .shared import LINUX_LAUNCHER_FILENAME

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from pysymex._internal.config.sandbox.types import SandboxConfig


logger = get_logger(__name__)


class LinuxExecutionMixin:
    """Execute staged target code inside a Linux namespace jail."""

    if TYPE_CHECKING:
        config: SandboxConfig

        @property
        def jail_path(self) -> Path | None: ...

        _child_pid: int | None
        _is_setup: bool

        def _validate_target_filename(self, filename: str) -> None: ...

        def _validate_extra_file_paths(
            self,
            filename: str,
            extra_files: dict[str, bytes],
        ) -> None: ...

        def _find_unshare(self) -> str | None: ...

        def _should_enable_seccomp(self) -> bool: ...

        def _clean_environment(self) -> dict[str, str]: ...

        def _supports_root_jail(self) -> bool: ...

        def _root_jail_python_cmd(self) -> list[str]: ...

        def _python_cmd(self) -> list[str]: ...

        def _populate_jail(
            self,
            code: bytes,
            filename: str,
            extra_files: dict[str, bytes],
        ) -> None: ...

        @staticmethod
        def _generate_launcher_script() -> str: ...

        def _generate_nproc_preamble(self) -> str: ...

        def _root_jail_unshare_cmd(
            self,
            unshare_cmd: str,
            harness_args: list[str],
        ) -> list[str]: ...

        def _make_preexec_fn(self) -> Callable[[], None]: ...

        @staticmethod
        def _classify_exit(returncode: int) -> ExecutionStatus: ...

        @staticmethod
        def _kill_child_process_group(pid: int) -> None: ...

    def execute(
        self,
        code: bytes,
        filename: str,
        input_data: bytes,
        extra_files: dict[str, bytes],
    ) -> SandboxResult:
        """Execute code in isolated namespaces."""
        jail_path = self.jail_path
        if not self._is_setup or jail_path is None:
            msg = "Backend not set up"
            raise SandboxSetupError(msg)

        self._validate_target_filename(filename)
        self._validate_extra_file_paths(filename, extra_files)
        unshare_cmd = self._find_unshare()
        if unshare_cmd is None:
            logger.warning("Linux namespace isolation requires util-linux unshare")
            msg = "Linux namespace isolation requires util-linux unshare"
            raise SandboxSetupError(msg)
        enable_seccomp = self._should_enable_seccomp()
        env = self._clean_environment()
        has_root_jail = self._supports_root_jail()
        python_cmd = self._root_jail_python_cmd() if has_root_jail else self._python_cmd()

        self._populate_jail(code, filename, extra_files)

        harness = f"{self._generate_nproc_preamble()}{generate_harness_script()}"
        harness_path = jail_path / HARNESS_FILENAME
        harness_path.write_text(harness, encoding="utf-8")
        if enable_seccomp:
            launcher_path = jail_path / LINUX_LAUNCHER_FILENAME
            launcher_path.write_text(self._generate_launcher_script(), encoding="utf-8")

        harness_args = [
            *python_cmd,
            *(
                [LINUX_LAUNCHER_FILENAME, HARNESS_FILENAME]
                if enable_seccomp
                else [HARNESS_FILENAME]
            ),
            filename,
        ]
        cmd = (
            self._root_jail_unshare_cmd(unshare_cmd, harness_args)
            if has_root_jail
            else [
                unshare_cmd,
                "--user",
                "--map-root-user",
                "--mount",
                "--pid",
                "--fork",
                "--net",
                "--ipc",
                *harness_args,
            ]
        )

        start_time = time.perf_counter()
        timeout = self.config.limits.timeout_seconds
        process: subprocess.Popen[bytes] | None = None

        try:
            process = subprocess.Popen(
                cmd,
                stdin=(subprocess.PIPE if input_data else subprocess.DEVNULL),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(jail_path),
                env=env,
                preexec_fn=self._make_preexec_fn(),
            )

            self._child_pid = process.pid

            stdout, stderr = process.communicate(
                input=input_data or None,
                timeout=timeout,
            )

            wall_time = (time.perf_counter() - start_time) * 1000
            status = self._classify_exit(process.returncode)

            return SandboxResult(
                status=status,
                exit_code=process.returncode,
                stdout=stdout[: self.config.limits.max_output_bytes],
                stderr=stderr[: self.config.limits.max_output_bytes],
                wall_time_ms=wall_time,
            )

        except subprocess.TimeoutExpired:
            logger.warning("Linux namespace sandbox timed out after %ss", timeout)
            stdout, stderr = b"", b""
            if process is not None:
                self._kill_child_process_group(process.pid)
                stdout, stderr = process.communicate()
            wall_time = (time.perf_counter() - start_time) * 1000
            return SandboxResult(
                status=ExecutionStatus.TIMEOUT,
                exit_code=None,
                stdout=stdout[: self.config.limits.max_output_bytes],
                stderr=stderr[: self.config.limits.max_output_bytes],
                wall_time_ms=wall_time,
                error_message=f"Execution timed out after {timeout}s",
            )

        except Exception as exc:
            logger.warning("Linux namespace sandbox crashed", exc_info=True)
            wall_time = (time.perf_counter() - start_time) * 1000
            return SandboxResult(
                status=ExecutionStatus.CRASH,
                exit_code=None,
                wall_time_ms=wall_time,
                error_message=str(exc),
            )

        finally:
            self._child_pid = None
