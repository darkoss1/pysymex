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

"""Runtime result and status types for sandbox execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


def _default_blocked_entries() -> list[str]:
    """Return default empty blocked-entry list."""
    return []


def _default_output_files() -> dict[str, bytes]:
    """Return default empty output-file mapping."""
    return {}


class SandboxBackendStrength(Enum):
    """Backend strength classification after availability or setup checks."""

    STRONG = auto()
    """Backend satisfies the strong sandbox capability contract."""

    EXPERIMENTAL = auto()
    """Backend has partial isolation but must not be treated as strong."""

    UNAVAILABLE = auto()
    """Backend is unavailable or has not been set up."""


class ExecutionStatus(Enum):
    """Status codes for sandbox execution results."""

    SUCCESS = auto()
    """Execution completed normally with exit code 0."""

    FAILED = auto()
    """Execution completed but with non-zero exit code."""

    TIMEOUT = auto()
    """Execution was killed due to timeout."""

    MEMORY_EXCEEDED = auto()
    """Execution was killed due to memory limit."""

    CPU_EXCEEDED = auto()
    """Execution was killed due to CPU time limit."""

    SECURITY_VIOLATION = auto()
    """Execution attempted a blocked operation (syscall, network, etc.)."""

    CRASH = auto()
    """Execution crashed unexpectedly (segfault, etc.)."""

    SETUP_ERROR = auto()
    """Sandbox setup failed before execution could begin."""


@dataclass
class SandboxResult:
    """Result of sandbox execution.

    Contains execution status, outputs, resource usage telemetry,
    and security event information.
    """

    status: ExecutionStatus
    """Overall execution status."""

    exit_code: int | None = None
    """Process exit code (None if killed or setup failed)."""

    stdout: bytes = b""
    """Captured standard output."""

    stderr: bytes = b""
    """Captured standard error."""

    wall_time_ms: float = 0.0
    """Wall-clock execution time in milliseconds."""

    cpu_time_ms: float = 0.0
    """CPU time used in milliseconds."""

    peak_memory_bytes: int = 0
    """Peak memory usage in bytes."""

    blocked_syscalls: list[str] = field(default_factory=_default_blocked_entries)
    """List of syscalls that were blocked by seccomp (Linux only)."""

    blocked_operations: list[str] = field(default_factory=_default_blocked_entries)
    """List of operations that were blocked (network, filesystem, etc.)."""

    error_message: str | None = None
    """Error message if execution failed."""

    error_traceback: str | None = None
    """Python traceback if available."""

    output_files: dict[str, bytes] = field(default_factory=_default_output_files)
    """Files created by the sandboxed code (relative path -> content)."""

    @property
    def succeeded(self) -> bool:
        """Check if execution succeeded (status SUCCESS and exit code 0)."""
        return self.status == ExecutionStatus.SUCCESS and self.exit_code == 0

    @property
    def was_killed(self) -> bool:
        """Check if process was killed (timeout, OOM, security violation)."""
        return self.status in (
            ExecutionStatus.TIMEOUT,
            ExecutionStatus.MEMORY_EXCEEDED,
            ExecutionStatus.CPU_EXCEEDED,
            ExecutionStatus.SECURITY_VIOLATION,
        )

    def get_stdout_text(self, encoding: str = "utf-8") -> str:
        """Decode stdout as text."""
        return self.stdout.decode(encoding, errors="replace")

    def get_stderr_text(self, encoding: str = "utf-8") -> str:
        """Decode stderr as text."""
        return self.stderr.decode(encoding, errors="replace")

    def get_combined_output(self, encoding: str = "utf-8") -> str:
        """Get combined stdout and stderr as text."""
        return self.get_stdout_text(encoding) + self.get_stderr_text(encoding)
