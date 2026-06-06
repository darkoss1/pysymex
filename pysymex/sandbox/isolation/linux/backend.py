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

"""Execute staged target code through the Linux namespace backend.

This module owns Linux backend setup, jail population, generated-harness
launch, and result collection while delegating resource-limit and optional
seccomp-launcher behavior to focused mixins.
"""

from __future__ import annotations

from collections.abc import Sequence
import shutil
import subprocess
import sys
import sysconfig
import time
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from pysymex.logger import get_logger

from ...errors import SandboxSetupError
from ...path_policy import validate_extra_file_path, validate_sandbox_filename
from ...types import ExecutionStatus, SandboxResult, SecurityCapabilities
from ..base import IsolationBackend
from ..constants import HARNESS_FILENAME
from ..harness import generate_harness_script
from .launcher import LinuxSeccompMixin
from .limits import LinuxProcessLimitsMixin
from .shared import LINUX_LAUNCHER_FILENAME, UNSHARE_SEARCH_PATH

if TYPE_CHECKING:
    from ...types import SandboxConfig

logger = get_logger(__name__)

_ROOT_JAIL_READONLY_MOUNTS = ("/usr/bin", "/usr/lib64")
_ROOT_JAIL_LIBRARY_PATHS = ("/usr/local/lib", "/usr/lib", "/lib", "/usr/lib64", "/lib64")
_ROOT_JAIL_BOOTSTRAP_SCRIPT = """
_jail=$1
_chroot=$2
_mount=$3
_mkdir=$4
_ln=$5
_ld_library_path=$6
shift 6
"$_mkdir" -p "$_jail/tmp"
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    _src=$1
    shift
    _dst="${_jail}${_src}"
    "$_mkdir" -p "$_dst"
    "$_mount" --bind "$_src" "$_dst"
    "$_mount" -o remount,bind,ro "$_dst"
done
"$_ln" -sfn usr/bin "$_jail/bin"
"$_ln" -sfn usr/lib "$_jail/lib"
"$_ln" -sfn usr/lib64 "$_jail/lib64"
if [ "$#" -eq 0 ]; then
    echo "linux-sandbox: missing chroot command delimiter" >&2
    exit 127
fi
shift
cd "$_jail"
unset LD_LIBRARY_PATH
exec "$_chroot" "$_jail" /bin/sh -eu -c '
_ld_library_path=$1
shift
export LD_LIBRARY_PATH="$_ld_library_path"
exec "$@"
' pysymex-linux-root-jail-inner "$_ld_library_path" "$@"
""".strip()


def _host_multiarch_library_paths() -> tuple[PurePosixPath, ...]:
    """Return host multiarch library dirs that should precede generic lib dirs."""
    multiarch = sysconfig.get_config_var("MULTIARCH")
    if not isinstance(multiarch, str) or not multiarch:
        return ()
    return (PurePosixPath(f"/usr/lib/{multiarch}"),)


def _host_python_stdlib_paths() -> tuple[PurePosixPath, ...]:
    """Return host Python stdlib directories needed by isolated interpreter startup."""
    paths: list[PurePosixPath] = []
    value = sysconfig.get_path("stdlib")
    if value:
        candidate = PurePosixPath(value)
        if candidate.is_absolute():
            paths.append(candidate)
    return tuple(paths)


class LinuxNamespaceBackend(LinuxSeccompMixin, LinuxProcessLimitsMixin, IsolationBackend):
    """Linux namespace-based isolation backend."""

    def __init__(self, config: SandboxConfig) -> None:
        """Initialize Linux sandbox state for a supplied configuration.

        Args:
            config: Sandbox settings controlling limits and harness options.
        """
        super().__init__(config)
        self._child_pid: int | None = None

    @property
    def is_available(self) -> bool:
        """Check if user namespaces are available."""
        if sys.platform != "linux":
            return False
        if self._find_unshare() is None:
            return False
        try:
            with open("/proc/sys/kernel/unprivileged_userns_clone") as fh:
                return fh.read().strip() == "1"
        except FileNotFoundError:
            return True
        except Exception:
            logger.debug("Failed to inspect Linux user namespace availability", exc_info=True)
            return False

    def get_capabilities(self) -> SecurityCapabilities:
        """Linux namespaces provide all security capabilities."""
        has_namespaces = self.is_available
        has_root_jail = has_namespaces and self._supports_root_jail()
        has_seccomp = has_namespaces and self._should_enable_seccomp()
        return SecurityCapabilities(
            process_isolation=has_namespaces,
            filesystem_jail=has_root_jail,
            network_blocking=has_namespaces,
            syscall_filtering=has_seccomp,
            memory_limits=True,
            cpu_limits=True,
            process_limits=True,
        )

    def setup(self) -> None:
        """Create the filesystem jail."""
        if not self.is_available:
            logger.warning("Linux namespace isolation is unavailable")
            raise SandboxSetupError(
                "Linux namespace isolation is not available. "
                "Require unshare and /proc/sys/kernel/unprivileged_userns_clone=1"
            )
        try:
            self._jail_path = self._create_jail()
            self._is_setup = True
            logger.verbose("Linux namespace sandbox jail created at %s", self._jail_path)
        except Exception as exc:
            logger.warning("Failed to create Linux namespace sandbox jail", exc_info=True)
            self.cleanup()
            raise SandboxSetupError(f"Failed to create jail: {exc}") from exc

    def cleanup(self) -> None:
        """Clean up jail and kill any child processes."""
        if self._child_pid is not None:
            self._kill_child_process_group(self._child_pid)
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

        self._validate_target_filename(filename)
        self._validate_extra_file_paths(filename, extra_files)
        unshare_cmd = self._find_unshare()
        if unshare_cmd is None:
            logger.warning("Linux namespace isolation requires util-linux unshare")
            raise SandboxSetupError("Linux namespace isolation requires util-linux unshare")
        enable_seccomp = self._should_enable_seccomp()
        env = self._clean_environment()
        has_root_jail = self._supports_root_jail()
        python_cmd = self._root_jail_python_cmd() if has_root_jail else self._python_cmd()

        self._populate_jail(code, filename, extra_files)

        harness = generate_harness_script()
        harness_path = self._jail_path / HARNESS_FILENAME
        harness_path.write_text(harness, encoding="utf-8")
        if enable_seccomp:
            launcher_path = self._jail_path / LINUX_LAUNCHER_FILENAME
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

    @staticmethod
    def _find_unshare() -> str | None:
        """Resolve util-linux unshare from trusted system paths only."""
        return shutil.which("unshare", path=UNSHARE_SEARCH_PATH)

    @staticmethod
    def _supports_unshare_root() -> bool:
        """Return True when util-linux unshare supports --root."""
        unshare_cmd = LinuxNamespaceBackend._find_unshare()
        if unshare_cmd is None:
            return False
        try:
            proc = subprocess.run(
                [unshare_cmd, "--help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                env={"PATH": UNSHARE_SEARCH_PATH, "LANG": "C.UTF-8"},
            )
        except Exception:
            logger.debug("Failed to inspect unshare --root support", exc_info=True)
            return False
        return "--root" in (proc.stdout or "")

    def _supports_root_jail(self) -> bool:
        """Return True when root-jail setup can run this Python runtime."""
        if not self._supports_unshare_root():
            return False
        python_exe = self._root_jail_python_path()
        runtime_root = self._root_jail_runtime_mount_root(python_exe)
        if runtime_root is None:
            return False
        return self._is_under_any_posix_path(python_exe, self._root_jail_readonly_mounts())

    def _root_jail_unshare_cmd(self, unshare_cmd: str, harness_args: list[str]) -> list[str]:
        """Build a root-jail command that mounts a read-only Python runtime first."""
        if self._jail_path is None:
            raise SandboxSetupError("Linux namespace jail is unavailable")
        chroot_cmd = self._find_trusted_tool("chroot")
        mount_cmd = self._find_trusted_tool("mount")
        mkdir_cmd = self._find_trusted_tool("mkdir")
        ln_cmd = self._find_trusted_tool("ln")
        if chroot_cmd is None or mount_cmd is None or mkdir_cmd is None or ln_cmd is None:
            raise SandboxSetupError("Linux namespace root jail requires chroot, mount, mkdir, and ln")
        readonly_mounts = self._root_jail_readonly_mounts()
        return [
            unshare_cmd,
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--fork",
            "--net",
            "--ipc",
            "/bin/sh",
            "-eu",
            "-c",
            _ROOT_JAIL_BOOTSTRAP_SCRIPT,
            "pysymex-linux-root-jail",
            str(self._jail_path),
            chroot_cmd,
            mount_cmd,
            mkdir_cmd,
            ln_cmd,
            self._root_jail_library_path(readonly_mounts),
            *readonly_mounts,
            "--",
            *harness_args,
        ]

    def _root_jail_python_cmd(self) -> list[str]:
        """Return a Python command path that exists after read-only runtime mounts."""
        python_exe = self._root_jail_python_path()
        if not self._is_under_any_posix_path(python_exe, self._root_jail_readonly_mounts()):
            raise SandboxSetupError(
                "Linux namespace root jail requires a Python executable under a mounted "
                "read-only runtime root"
            )
        return [python_exe.as_posix(), "-I", "-B"]

    def _root_jail_python_path(self) -> PurePosixPath:
        """Resolve the Python executable path used inside the Linux root jail."""
        configured = self.config.python_executable
        if configured is not None:
            raw_executable = configured
        else:
            base_executable = getattr(sys, "_base_executable", "")
            raw_executable = base_executable if isinstance(base_executable, str) else ""
            if not raw_executable:
                raw_executable = sys.executable

        if raw_executable.startswith("/"):
            return PurePosixPath(raw_executable)
        return PurePosixPath(Path(raw_executable).expanduser().resolve().as_posix())

    def _root_jail_readonly_mounts(self) -> tuple[str, ...]:
        """Return read-only host paths mounted into the Linux root jail."""
        mounts: list[str] = []
        for candidate in _ROOT_JAIL_READONLY_MOUNTS:
            self._append_unique_posix_path(mounts, PurePosixPath(candidate))
        python_exe = self._root_jail_python_path()
        runtime_root = self._root_jail_runtime_mount_root(python_exe)
        if runtime_root is not None and not self._is_under_any_posix_path(python_exe, mounts):
            self._append_unique_posix_path(mounts, runtime_root)
        for candidate in _host_python_stdlib_paths():
            self._append_unique_posix_path(mounts, candidate)
        for candidate in _host_multiarch_library_paths():
            self._append_unique_posix_path(mounts, candidate)
        return tuple(mounts)

    def _root_jail_library_path(self, readonly_mounts: tuple[str, ...]) -> str:
        """Build the loader search path for mounted Python runtime libraries."""
        library_paths: list[str] = []
        for candidate in _host_multiarch_library_paths():
            self._append_unique_posix_path(library_paths, candidate)
        for candidate in _ROOT_JAIL_LIBRARY_PATHS:
            self._append_unique_posix_path(library_paths, PurePosixPath(candidate))
        python_exe = self._root_jail_python_path()
        runtime_root = self._root_jail_runtime_mount_root(python_exe)
        if runtime_root is not None:
            for candidate in self._root_jail_runtime_library_paths(runtime_root):
                if self._is_under_any_posix_path(candidate, readonly_mounts):
                    self._append_unique_posix_path(library_paths, candidate)
        return ":".join(library_paths)

    @staticmethod
    def _root_jail_runtime_mount_root(python_exe: PurePosixPath) -> PurePosixPath | None:
        """Return the narrow runtime root needed to expose ``python_exe`` in chroot."""
        if not python_exe.is_absolute() or python_exe.parent.name != "bin":
            return None
        prefix = python_exe.parent.parent
        if prefix == PurePosixPath("/usr"):
            return python_exe.parent
        return prefix

    @staticmethod
    def _root_jail_runtime_library_paths(
        runtime_root: PurePosixPath,
    ) -> tuple[PurePosixPath, ...]:
        """Return likely shared-library directories for a mounted Python runtime."""
        if runtime_root.name == "bin":
            prefix = runtime_root.parent
        else:
            prefix = runtime_root
        return (prefix / "lib", prefix / "lib64")

    @staticmethod
    def _find_trusted_tool(name: str) -> str | None:
        """Resolve a trusted Linux setup tool from fixed system paths."""
        return shutil.which(name, path=UNSHARE_SEARCH_PATH)

    @staticmethod
    def _is_under_path(path: Path, parent: Path) -> bool:
        try:
            path.relative_to(parent)
        except ValueError:
            return False
        return True

    @staticmethod
    def _is_under_any_posix_path(path: PurePosixPath, parents: Sequence[str]) -> bool:
        for parent in parents:
            try:
                path.relative_to(PurePosixPath(parent))
            except ValueError:
                continue
            return True
        return False

    @staticmethod
    def _append_unique_posix_path(
        paths: list[str],
        candidate: PurePosixPath,
    ) -> None:
        candidate_text = candidate.as_posix()
        if candidate_text not in paths:
            paths.append(candidate_text)

    @staticmethod
    def _validate_target_filename(filename: str) -> None:
        """Reject target filenames that could escape the jail or alter launcher flags."""
        try:
            validate_sandbox_filename(filename, context="Linux sandbox target filename")
        except ValueError as exc:
            raise SandboxSetupError(
                f"Invalid Linux sandbox target filename: {filename!r}: {exc}"
            ) from exc

    @staticmethod
    def _validate_extra_file_paths(filename: str, extra_files: dict[str, bytes]) -> None:
        """Reject supplementary files that can shadow trusted Linux sandbox files."""
        reserved_root_names = frozenset({filename, HARNESS_FILENAME, LINUX_LAUNCHER_FILENAME})
        safe_chars = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
        for rel_path in extra_files:
            try:
                normalized = validate_extra_file_path(
                    str(rel_path),
                    context="Linux sandbox extra file path",
                )
            except ValueError as exc:
                raise SandboxSetupError(
                    f"Invalid Linux sandbox extra file path: {rel_path!r}: {exc}"
                ) from exc
            parts = normalized.split("/")
            if (
                not parts
                or any(part.startswith(("-", ".")) for part in parts)
                or any(not all(ch in safe_chars for ch in part) for part in parts)
            ):
                raise SandboxSetupError(f"Invalid Linux sandbox extra file path: {rel_path!r}")
            normalized = "/".join(parts)
            if normalized in reserved_root_names:
                raise SandboxSetupError(
                    f"Linux sandbox extra file path shadows reserved file: {rel_path!r}"
                )


__all__ = ["LinuxNamespaceBackend"]
