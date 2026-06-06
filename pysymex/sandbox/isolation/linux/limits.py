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

"""Apply child-process resource limits and classify Linux process exits.

The mixin in this module supplies process-group cleanup and a pre-exec
callback used by the Linux namespace backend before it launches the generated
sandbox harness.
"""

from __future__ import annotations

import os
import signal
from collections.abc import Callable
from typing import TYPE_CHECKING

from pysymex.logger import get_logger

from ...types import ExecutionStatus

if TYPE_CHECKING:
    from ...types import SandboxConfig

_SIGKILL = int(getattr(signal, "SIGKILL", getattr(signal, "SIGTERM", 9)))
_SIGSYS = int(getattr(signal, "SIGSYS", _SIGKILL))
_SIGXCPU = int(getattr(signal, "SIGXCPU", _SIGKILL))

logger = get_logger(__name__)


class LinuxProcessLimitsMixin:
    """Provide Linux child cleanup, pre-exec hardening, and exit classification.

    The owning backend supplies `config.limits`. The generated pre-exec
    callback runs in the child process and attempts to establish a new session,
    enable `PR_SET_NO_NEW_PRIVS`, and set required resource limits before
    execution of the launcher or harness.
    """

    if TYPE_CHECKING:
        config: SandboxConfig

    @staticmethod
    def _kill_child_process_group(pid: int) -> None:
        """Kill the whole launcher process group, falling back to the direct child."""
        try:
            getpgid = getattr(os, "getpgid")
            killpg = getattr(os, "killpg")
            pgid = getpgid(pid)
            killpg(pgid, _SIGKILL)
        except (AttributeError, OSError, ProcessLookupError):
            try:
                os.kill(pid, _SIGKILL)
            except OSError:
                logger.debug("Sandbox child SIGKILL failed during teardown", exc_info=True)
        try:
            os.waitpid(pid, 0)
        except (OSError, ChildProcessError):
            logger.debug("Sandbox child waitpid failed during teardown", exc_info=True)

    def _make_preexec_fn(self):
        """Create a preexec_fn that sets a process group, no_new_privs, and rlimits.

        This function runs in the *child* process immediately after
        ``fork()`` and before ``exec()``.
        """
        limits = self.config.limits

        def _apply_restrictions() -> None:
            """Apply child-session, no-new-privileges, and rlimit settings."""
            import ctypes
            import resource

            setsid = getattr(os, "setsid", None)
            if callable(setsid):
                setsid()

            _PR_SET_NO_NEW_PRIVS = 38
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            rc = libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            if rc != 0:
                err = ctypes.get_errno()
                raise OSError(err, "prctl(PR_SET_NO_NEW_PRIVS) failed")

            setrlimit_candidate = getattr(resource, "setrlimit", None)
            setrlimit_fn: Callable[[int, tuple[int, int]], object] | None = None
            if callable(setrlimit_candidate):
                setrlimit_fn = setrlimit_candidate

            def _set_limit(
                limit_name: str,
                soft: int,
                hard: int,
                *,
                strict_error: str | None = None,
            ) -> None:
                """Apply one available rlimit or fail when it is required."""
                if setrlimit_fn is None:
                    if strict_error is not None:
                        raise OSError(strict_error)
                    return

                limit_value = getattr(resource, limit_name, None)
                if not isinstance(limit_value, int):
                    if strict_error is not None:
                        raise OSError(strict_error)
                    return

                try:
                    setrlimit_fn(limit_value, (soft, hard))
                except (OSError, ValueError) as exc:
                    if strict_error is not None:
                        raise OSError(strict_error) from exc

            mem_bytes = limits.memory_mb * 1024 * 1024
            _set_limit(
                "RLIMIT_AS",
                mem_bytes,
                mem_bytes,
                strict_error=f"Failed to enforce RLIMIT_AS={mem_bytes}",
            )
            _set_limit(
                "RLIMIT_CPU",
                limits.cpu_seconds,
                limits.cpu_seconds,
                strict_error=f"Failed to enforce RLIMIT_CPU={limits.cpu_seconds}",
            )
            _set_limit(
                "RLIMIT_NPROC",
                limits.max_processes,
                limits.max_processes,
                strict_error=f"Failed to enforce RLIMIT_NPROC={limits.max_processes}",
            )
            fsize = limits.max_file_size_mb * 1024 * 1024
            _set_limit(
                "RLIMIT_FSIZE",
                fsize,
                fsize,
                strict_error=f"Failed to enforce RLIMIT_FSIZE={fsize}",
            )
            _set_limit(
                "RLIMIT_NOFILE",
                limits.max_file_descriptors,
                limits.max_file_descriptors,
                strict_error=(f"Failed to enforce RLIMIT_NOFILE={limits.max_file_descriptors}"),
            )
            _set_limit("RLIMIT_CORE", 0, 0, strict_error="Failed to enforce RLIMIT_CORE=0")

        return _apply_restrictions

    @staticmethod
    def _classify_exit(returncode: int) -> ExecutionStatus:
        """Map child exit code / signal to an ExecutionStatus."""
        if returncode == 0:
            return ExecutionStatus.SUCCESS
        if returncode in {-_SIGKILL, -_SIGSYS}:
            return ExecutionStatus.SECURITY_VIOLATION
        if returncode == -_SIGXCPU:
            return ExecutionStatus.CPU_EXCEEDED
        return ExecutionStatus.FAILED
