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

"""Root-jail command and runtime mount helpers for the Linux namespace backend."""

from __future__ import annotations

import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from pysymex._internal.logging.root import get_logger
from pysymex._internal.sandbox.errors import SandboxSetupError

from .shared import UNSHARE_SEARCH_PATH

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.config.sandbox.types import SandboxConfig


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


class LinuxRootJailMixin:
    """Build root-jail commands and runtime mount metadata for Linux isolation."""

    if TYPE_CHECKING:
        config: SandboxConfig

        @property
        def jail_path(self) -> Path | None: ...

        def _find_unshare(self) -> str | None: ...

    def _supports_unshare_root(self) -> bool:
        """Return True when util-linux unshare supports --root."""
        unshare_cmd = self._find_unshare()
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
        jail_path = self.jail_path
        if jail_path is None:
            msg = "Linux namespace jail is unavailable"
            raise SandboxSetupError(msg)
        chroot_cmd = self._find_trusted_tool("chroot")
        mount_cmd = self._find_trusted_tool("mount")
        mkdir_cmd = self._find_trusted_tool("mkdir")
        ln_cmd = self._find_trusted_tool("ln")
        if chroot_cmd is None or mount_cmd is None or mkdir_cmd is None or ln_cmd is None:
            msg = "Linux namespace root jail requires chroot, mount, mkdir, and ln"
            raise SandboxSetupError(
                msg,
            )
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
            str(jail_path),
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
            msg = (
                "Linux namespace root jail requires a Python executable under a mounted "
                "read-only runtime root"
            )
            raise SandboxSetupError(
                msg,
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
        prefix = runtime_root.parent if runtime_root.name == "bin" else runtime_root
        return (prefix / "lib", prefix / "lib64")

    @staticmethod
    def _find_trusted_tool(name: str) -> str | None:
        """Resolve a trusted Linux setup tool from fixed system paths."""
        return shutil.which(name, path=UNSHARE_SEARCH_PATH)

    @staticmethod
    def _is_under_any_posix_path(path: PurePosixPath, parents: Sequence[str]) -> bool:
        """Return whether ``path`` is below any trusted POSIX parent."""
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
        """Append a POSIX path string if it is not already present."""
        candidate_text = candidate.as_posix()
        if candidate_text not in paths:
            paths.append(candidate_text)
