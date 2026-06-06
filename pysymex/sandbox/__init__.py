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

"""Secure sandbox execution module for pysymex.

This module provides hardened isolation for executing untrusted code.
It uses multiple layers of defence including process isolation,
filesystem jailing, network blocking, resource limits, syscall
filtering (seccomp-bpf), and a hardened in-process harness.

Usage::

    from pysymex.sandbox import SecureSandbox, SandboxConfig

    config = SandboxConfig()
    with SecureSandbox(config) as sandbox:
        result = sandbox.execute(file_path)
        if result.succeeded:
            print(result.get_stdout_text())

Security Model:
    - Code executes in a separate process (not just exec())
    - Network isolation when a strong backend is active (Linux namespaces,
      Windows AppContainer, or WASI)
    - Filesystem jailed to ephemeral temp directory
    - Strict resource limits (CPU, memory, processes)
    - Syscall filtering where supported (Linux seccomp-bpf on x86_64)
"""

from __future__ import annotations

from .errors import (
    ExecutionTimeout,
    ResourceExhaustedError,
    ResourceLimitError,
    SandboxCleanupError,
    SandboxError,
    SandboxExecutionError,
    SandboxProtocolError,
    SandboxResourceError,
    SandboxSecurityError,
    SandboxSetupError,
    SandboxTimeoutError,
    SecurityError,
    SecurityViolationError,
)
from .types import (
    ExecutionStatus,
    ResourceLimits,
    SandboxBackend,
    SandboxBackendStrength,
    SandboxConfig,
    SandboxResult,
    SecurityCapabilities,
)


from .runner import SandboxRunner, SecureSandbox
from .validation import (
    PathTraversalError,
    SecurityConfig,
    sanitize_function_name,
    validate_bounds,
    validate_config,
    validate_path,
)

__all__ = [
    "ExecutionStatus",
    "ExecutionTimeout",
    "PathTraversalError",
    "ResourceExhaustedError",
    "ResourceLimitError",
    "ResourceLimits",
    "SandboxBackend",
    "SandboxBackendStrength",
    "SandboxCleanupError",
    "SandboxConfig",
    "SandboxError",
    "SandboxExecutionError",
    "SandboxProtocolError",
    "SandboxResourceError",
    "SandboxSecurityError",
    "SandboxResult",
    "SandboxRunner",
    "SandboxSetupError",
    "SandboxTimeoutError",
    "SecureSandbox",
    "SecurityCapabilities",
    "SecurityConfig",
    "SecurityError",
    "SecurityViolationError",
    "sanitize_function_name",
    "validate_bounds",
    "validate_config",
    "validate_path",
]
