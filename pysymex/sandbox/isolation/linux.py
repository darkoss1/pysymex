# pysymex: Python Symbolic Execution & Formal Verification
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

"""Linux namespace and seccomp-based isolation backend.

This is the most secure backend for Linux systems.  It uses:
    - User namespaces (unprivileged, no root required)
    - Mount namespaces (filesystem isolation)
    - Network namespaces (complete network isolation)
    - PID namespaces (process isolation)
    - seccomp-bpf via ``PR_SET_NO_NEW_PRIVS`` + ``PR_SET_SECCOMP``
    - ``rlimit`` resource constraints (memory, CPU, fds, fsize)

Requirements:
    - Linux kernel 3.8+ for user namespaces
    - /proc/sys/kernel/unprivileged_userns_clone = 1
"""

from __future__ import annotations

import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from ..errors import SandboxSetupError
from ..types import ExecutionStatus, SandboxResult, SecurityCapabilities
from . import IsolationBackend
from .harness import HARNESS_FILENAME, generate_harness_script

if TYPE_CHECKING:
    from ..types import SandboxConfig


_SYSCALL_ALLOWLIST_X86_64: frozenset[int] = frozenset(
    {
        0,
        1,
        2,
        3,
        5,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        17,
        21,
        28,
        35,
        60,
        72,
        79,
        89,
        97,
        102,
        104,
        107,
        108,
        110,
        158,
        202,
        204,
        217,
        218,
        228,
        231,
        234,
        257,
        262,
        273,
        302,
        318,
        332,
        334,
        435,
        439,
    }
)

_SIGKILL = int(getattr(signal, "SIGKILL", getattr(signal, "SIGTERM", 9)))
_SIGXCPU = int(getattr(signal, "SIGXCPU", _SIGKILL))


class LinuxNamespaceBackend(IsolationBackend):
    """Linux namespace-based isolation backend.

    This backend provides the strongest isolation available on Linux
    without root privileges.  It creates:

    1. User namespace: maps to unprivileged user inside sandbox
    2. Mount namespace: private mount tree (via ``unshare --root``)
    3. PID namespace: child becomes PID 1, can't see host processes
    4. Network namespace: empty network stack, no connectivity
    5. IPC namespace: separate IPC objects

    Additionally applies:
    - ``PR_SET_NO_NEW_PRIVS``
    - ``rlimit`` resource constraints
    """

    def __init__(self, config: SandboxConfig) -> None:
        super().__init__(config)
        self._child_pid: int | None = None

    @property
    def is_available(self) -> bool:
        """Check if user namespaces are available."""
        if sys.platform != "linux":
            return False
        if shutil.which("unshare") is None:
            return False
        try:
            with open("/proc/sys/kernel/unprivileged_userns_clone") as fh:
                return fh.read().strip() == "1"
        except FileNotFoundError:
            return True
        except Exception:
            return False

    def get_capabilities(self) -> SecurityCapabilities:
        """Linux namespaces provide all security capabilities."""
        has_unshare: bool = shutil.which("unshare") is not None
        has_root_jail = has_unshare and self._supports_unshare_root()
        return SecurityCapabilities(
            process_isolation=True,
            filesystem_jail=has_root_jail,
            network_blocking=has_unshare,
            syscall_filtering=has_unshare and self._should_enable_seccomp(),
            memory_limits=True,
            cpu_limits=True,
            process_limits=True,
        )

    def setup(self) -> None:
        """Create the filesystem jail."""
        if not self.is_available:
            raise SandboxSetupError(
                "Linux namespace isolation is not available. "
                "Require unshare and /proc/sys/kernel/unprivileged_userns_clone=1"
            )
        try:
            self._jail_path = self._create_jail()
            self._is_setup = True
        except Exception as exc:
            self.cleanup()
            raise SandboxSetupError(f"Failed to create jail: {exc}") from exc

    def cleanup(self) -> None:
        """Clean up jail and kill any child processes."""
        if self._child_pid is not None:
            try:
                os.kill(self._child_pid, _SIGKILL)
                os.waitpid(self._child_pid, 0)
            except (OSError, ChildProcessError):
                pass
            self._child_pid = None

        self._destroy_jail()
        self._is_setup = False

    def execute(
        self,
        code: bytes,
        filename: str,
        input_data: bytes,
        extra_files: dict[str, bytes],
    ) -> SandboxResult:
        """Execute code in isolated namespaces."""
        if not self._is_setup or self._jail_path is None:
            raise SandboxSetupError("Backend not set up")

        self._populate_jail(code, filename, extra_files)
        enable_seccomp = self._should_enable_seccomp()

        harness = generate_harness_script(
            blocked_modules=self.config.harness_blocked_modules,
            allowed_imports=self.config.harness_allowed_imports,
            restrict_builtins=self.config.harness_restrict_builtins,
            install_audit_hook=self.config.harness_install_audit_hook,
            block_ast_imports=self.config.harness_block_ast_imports,
            install_seccomp=enable_seccomp,
            seccomp_allowlist=tuple(_SYSCALL_ALLOWLIST_X86_64),
        )
        harness_path = self._jail_path / HARNESS_FILENAME
        harness_path.write_text(harness, encoding="utf-8")

        python_cmd = self._python_cmd()
        env = self._clean_environment()
        has_root_jail = self._supports_unshare_root()

        if self.config.harness_install_audit_hook and not has_root_jail:
            raise SandboxSetupError(
                "Linux strict profile requires unshare --root support "
                "for filesystem jail enforcement"
            )

        if self.config.harness_install_audit_hook and not enable_seccomp:
            raise SandboxSetupError("Linux strict profile requires seccomp support on x86_64")

        cmd: list[str] = [
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            *(["--root", str(self._jail_path)] if has_root_jail else []),
            "--pid",
            "--fork",
            "--net",
            "--ipc",
            *python_cmd,
            HARNESS_FILENAME,
            filename,
        ]

        start_time = time.perf_counter()
        timeout = self.config.limits.timeout_seconds
        process: subprocess.Popen[bytes] | None = None

        try:
            process = subprocess.Popen(
                cmd,
                stdin=(subprocess.PIPE if input_data else subprocess.DEVNULL),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self._jail_path),
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
            stdout, stderr = b"", b""
            if process is not None:
                process.kill()
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
            wall_time = (time.perf_counter() - start_time) * 1000
            return SandboxResult(
                status=ExecutionStatus.CRASH,
                exit_code=None,
                wall_time_ms=wall_time,
                error_message=str(exc),
            )

        finally:
            self._child_pid = None

    @staticmethod
    def _supports_unshare_root() -> bool:
        """Return True when util-linux unshare supports --root."""
        try:
            proc = subprocess.run(
                ["unshare", "--help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
        except Exception:
            return False
        return "--root" in (proc.stdout or "")

    def _should_enable_seccomp(self) -> bool:
        """Enable seccomp for strict/untrusted profile on supported hosts."""
        machine = platform.machine().lower()
        is_x86_64 = machine in {"x86_64", "amd64"}
        return self.config.harness_install_audit_hook and is_x86_64

    def _make_preexec_fn(self):
        """Create a preexec_fn that sets no_new_privs and rlimits.

        This function runs in the *child* process immediately after
        ``fork()`` and before ``exec()``.
        """
        limits = self.config.limits

        def _apply_restrictions() -> None:
            import ctypes
            import resource

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
            _set_limit("RLIMIT_AS", mem_bytes, mem_bytes)
            _set_limit("RLIMIT_CPU", limits.cpu_seconds, limits.cpu_seconds)
            _set_limit(
                "RLIMIT_NPROC",
                limits.max_processes,
                limits.max_processes,
                strict_error=f"Failed to enforce RLIMIT_NPROC={limits.max_processes}",
            )
            fsize = limits.max_file_size_mb * 1024 * 1024
            _set_limit("RLIMIT_FSIZE", fsize, fsize)
            _set_limit(
                "RLIMIT_NOFILE",
                limits.max_file_descriptors,
                limits.max_file_descriptors,
            )
            _set_limit("RLIMIT_CORE", 0, 0)

        return _apply_restrictions

    @staticmethod
    def _classify_exit(returncode: int) -> ExecutionStatus:
        """Map child exit code / signal to an ExecutionStatus."""
        if returncode == 0:
            return ExecutionStatus.SUCCESS
        if returncode == -_SIGKILL:
            return ExecutionStatus.MEMORY_EXCEEDED
        if returncode == -_SIGXCPU:
            return ExecutionStatus.CPU_EXCEEDED
        return ExecutionStatus.FAILED


__all__ = ["LinuxNamespaceBackend"]
