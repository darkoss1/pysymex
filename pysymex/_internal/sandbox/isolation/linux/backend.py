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

"""Linux namespace backend setup, availability, and path-policy enforcement."""

from __future__ import annotations

import shutil
import sys
from typing import TYPE_CHECKING

from pysymex._internal.config.sandbox.types import SecurityCapabilities
from pysymex._internal.logging.root import get_logger
from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.base import IsolationBackend
from pysymex._internal.sandbox.isolation.constants import HARNESS_FILENAME
from pysymex._internal.sandbox.paths import validate_extra_file_path, validate_sandbox_filename

from .execution import LinuxExecutionMixin
from .jail import LinuxRootJailMixin
from .launcher import LinuxSeccompMixin
from .limits import LinuxProcessLimitsMixin
from .shared import LINUX_LAUNCHER_FILENAME, UNSHARE_SEARCH_PATH

if TYPE_CHECKING:
    from pysymex._internal.config.sandbox.types import SandboxConfig

logger = get_logger(__name__)


class LinuxNamespaceBackend(
    LinuxExecutionMixin,
    LinuxRootJailMixin,
    LinuxSeccompMixin,
    LinuxProcessLimitsMixin,
    IsolationBackend,
):
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
            msg = (
                "Linux namespace isolation is not available. "
                "Require unshare and /proc/sys/kernel/unprivileged_userns_clone=1"
            )
            raise SandboxSetupError(
                msg,
            )
        try:
            self._jail_path = self._create_jail()
            self._is_setup = True
            logger.verbose("Linux namespace sandbox jail created at %s", self._jail_path)
        except Exception as exc:
            logger.warning("Failed to create Linux namespace sandbox jail", exc_info=True)
            self.cleanup()
            msg = f"Failed to create jail: {exc}"
            raise SandboxSetupError(msg) from exc

    def cleanup(self) -> None:
        """Clean up jail and kill any child processes."""
        if self._child_pid is not None:
            self._kill_child_process_group(self._child_pid)
            self._child_pid = None

        self._destroy_jail()
        self._is_setup = False

    def _find_unshare(self) -> str | None:
        """Resolve util-linux unshare from trusted system paths only."""
        return shutil.which("unshare", path=UNSHARE_SEARCH_PATH)

    def _validate_target_filename(self, filename: str) -> None:
        """Reject target filenames that could escape the jail or alter launcher flags."""
        try:
            validate_sandbox_filename(filename, context="Linux sandbox target filename")
        except ValueError as exc:
            msg = f"Invalid Linux sandbox target filename: {filename!r}: {exc}"
            raise SandboxSetupError(
                msg,
            ) from exc

    def _validate_extra_file_paths(self, filename: str, extra_files: dict[str, bytes]) -> None:
        """Reject supplementary files that can shadow trusted Linux sandbox files."""
        reserved_root_names = frozenset((filename, HARNESS_FILENAME, LINUX_LAUNCHER_FILENAME))
        safe_chars = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
        for rel_path in extra_files:
            try:
                normalized = validate_extra_file_path(
                    str(rel_path),
                    context="Linux sandbox extra file path",
                )
            except ValueError as exc:
                msg = f"Invalid Linux sandbox extra file path: {rel_path!r}: {exc}"
                raise SandboxSetupError(
                    msg,
                ) from exc
            parts = normalized.split("/")
            if (
                not parts
                or any(part.startswith(("-", ".")) for part in parts)
                or any(not all(ch in safe_chars for ch in part) for part in parts)
            ):
                msg = f"Invalid Linux sandbox extra file path: {rel_path!r}"
                raise SandboxSetupError(msg)
            normalized = "/".join(parts)
            if normalized in reserved_root_names:
                msg = f"Linux sandbox extra file path shadows reserved file: {rel_path!r}"
                raise SandboxSetupError(
                    msg,
                )
