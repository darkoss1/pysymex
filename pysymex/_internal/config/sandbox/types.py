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

"""Sandbox configuration schema and secure defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def _default_environment() -> dict[str, str]:
    """Return default empty environment mapping."""
    return {}


class SandboxBackend(Enum):
    """Available sandbox isolation backends."""

    LINUX_NAMESPACE = auto()
    """Linux seccomp-bpf + user namespaces. Most secure on Linux."""

    WINDOWS_APPCONTAINER = auto()
    """Windows AppContainer process with deny-by-default capabilities."""


@dataclass(frozen=True, slots=True)
class SecurityCapabilities:
    """Describes security capabilities required from or reported by an isolation backend."""

    process_isolation: bool = False
    """Code runs in a separate OS process."""

    filesystem_jail: bool = False
    """Filesystem access is confined to an ephemeral directory."""

    network_blocking: bool = False
    """Network access is denied at the OS level."""

    syscall_filtering: bool = False
    """System calls are filtered via seccomp-bpf or equivalent."""

    memory_limits: bool = False
    """Memory consumption is capped by the OS."""

    cpu_limits: bool = False
    """CPU time is capped by the OS."""

    process_limits: bool = False
    """Child process or thread creation is capped by the OS."""


@dataclass(frozen=True, slots=True)
class SandboxResourceLimits:
    """Resource limits for sandbox execution."""

    timeout_seconds: float = 30.0
    """Wall-clock timeout in seconds."""

    cpu_seconds: int = 30
    """CPU time limit in seconds."""

    memory_mb: int = 512
    """Maximum memory in megabytes."""

    max_processes: int = 4
    """Maximum number of processes or threads."""

    max_file_descriptors: int = 32
    """Maximum open file descriptors."""

    max_file_size_mb: int = 16
    """Maximum size of any single file created."""

    max_output_bytes: int = 1024 * 1024
    """Maximum stdout plus stderr combined."""

    max_result_bytes: int = 10 * 1024 * 1024
    """Maximum serialized sandbox result payload accepted by the host."""


ResourceLimits = SandboxResourceLimits


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    """Configuration for sandbox execution.

    Security-critical block flags are forced on after initialization so caller
    overrides cannot accidentally weaken the sandbox boundary.
    """

    limits: SandboxResourceLimits = field(default_factory=SandboxResourceLimits)
    backend: SandboxBackend | None = None
    working_directory: Path | None = None
    environment: dict[str, str] = field(default_factory=_default_environment)
    python_executable: str | None = None
    capture_output: bool = True
    allow_stdin: bool = False
    required_capabilities: SecurityCapabilities | None = None
    _block_network: bool = field(default=True, repr=False)
    _block_filesystem: bool = field(default=True, repr=False)
    _block_process_spawn: bool = field(default=True, repr=False)

    def __post_init__(self) -> None:
        """Enforce security invariants after initialization."""
        object.__setattr__(self, "_block_network", True)
        object.__setattr__(self, "_block_filesystem", True)
        object.__setattr__(self, "_block_process_spawn", True)
