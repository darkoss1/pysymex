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

"""Type definitions for the sandbox module.

This module contains all dataclasses, enums, and type definitions
used throughout the sandbox system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path


def _default_environment() -> dict[str, str]:
    """Return default empty environment mapping."""
    return {}


def _default_blocked_entries() -> list[str]:
    """Return default empty blocked-entry list."""
    return []


def _default_output_files() -> dict[str, bytes]:
    """Return default empty output-file mapping."""
    return {}


class SandboxBackend(Enum):
    """Available sandbox isolation backends.

    Each backend provides different isolation mechanisms based on
    the underlying operating system capabilities.
    """

    LINUX_NAMESPACE = auto()
    """Linux seccomp-bpf + user namespaces. Most secure on Linux."""

    WINDOWS_JOB = auto()
    """Windows Job Objects + process mitigations."""

    WASM = auto()
    """WebAssembly runtime (wasmtime). Cross-platform fallback."""

    SUBPROCESS = auto()
    """Basic subprocess isolation. Minimum security, maximum compatibility."""


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


@dataclass(frozen=True, slots=True)
class SecurityCapabilities:
    """Describes the security capabilities of an isolation backend.

    Each boolean field indicates whether a specific isolation
    mechanism is *actively enforced* (not merely attempted).
    """

    process_isolation: bool = False
    """Code runs in a separate OS process."""

    filesystem_jail: bool = False
    """Filesystem access is confined to an ephemeral directory."""

    network_blocking: bool = False
    """Network access is denied at the OS level (not just Python)."""

    syscall_filtering: bool = False
    """System calls are filtered via seccomp-bpf or equivalent."""

    memory_limits: bool = False
    """Memory consumption is capped by the OS."""

    cpu_limits: bool = False
    """CPU time is capped by the OS."""

    process_limits: bool = False
    """Child process / thread creation is capped by the OS."""


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Resource limits for sandbox execution.

    All limits have secure defaults. Values of 0 mean unlimited
    (not recommended for untrusted code).
    """

    timeout_seconds: float = 30.0
    """Wall-clock timeout in seconds."""

    cpu_seconds: int = 30
    """CPU time limit in seconds (may exceed wall time for I/O-bound code)."""

    memory_mb: int = 256
    """Maximum memory (address space) in megabytes."""

    max_processes: int = 1
    """Maximum number of processes/threads. Set to 1 to prevent fork bombs."""

    max_file_descriptors: int = 32
    """Maximum open file descriptors."""

    max_file_size_mb: int = 16
    """Maximum size of any single file created."""

    max_output_bytes: int = 1024 * 1024
    """Maximum stdout + stderr combined (1 MB default)."""


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    """Configuration for sandbox execution.

    All security-critical settings have safe defaults. The only
    setting that can be adjusted without security implications
    is the resource limits.

    Attributes:
        limits: Resource limits (CPU, memory, time, etc.)
        backend: Which isolation backend to use (auto-detect if None)
        working_directory: Custom working directory (creates temp if None)
        environment: Environment variables for the sandboxed process
        python_executable: Path to Python interpreter (uses sys.executable)
        capture_output: Whether to capture stdout/stderr
        allow_stdin: Whether to allow stdin input
        harness_blocked_modules: Modules to block inside the harness.
            ``None`` → use ``SANDBOX_BLOCKED_MODULES`` from ``_constants``.
            An explicit ``frozenset`` overrides the default (pass an empty
            set to disable module blocking while retaining OS-level isolation).
        harness_restrict_builtins: Whether to restrict builtins (exec,
            eval, compile, open, …) inside the harness namespace.
    """

    limits: ResourceLimits = field(default_factory=ResourceLimits)
    backend: SandboxBackend | None = None
    working_directory: Path | None = None
    environment: dict[str, str] = field(default_factory=_default_environment)
    python_executable: str | None = None
    capture_output: bool = True
    allow_stdin: bool = False

    harness_blocked_modules: frozenset[str] | None = None
    harness_allowed_imports: frozenset[str] | None = None
    harness_restrict_builtins: bool = True
    harness_install_audit_hook: bool = True
    harness_block_ast_imports: bool = True

    allow_weak_backends: bool = False

    required_capabilities: SecurityCapabilities | None = None

    _block_network: bool = field(default=True, repr=False)
    _block_filesystem: bool = field(default=True, repr=False)
    _block_process_spawn: bool = field(default=True, repr=False)

    def __post_init__(self) -> None:
        """Enforce security invariants after initialization."""

        object.__setattr__(self, "_block_network", True)
        object.__setattr__(self, "_block_filesystem", True)
        object.__setattr__(self, "_block_process_spawn", True)


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
