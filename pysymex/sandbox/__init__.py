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
    - Complete network isolation (namespaces / Job Objects)
    - Filesystem jailed to ephemeral temp directory
    - Strict resource limits (CPU, memory, processes)
    - Syscall filtering where supported (Linux seccomp-bpf)
    - Hardened harness with modern MetaPathFinder, restricted builtins,
      sys.modules scrubbing, and AST pre-screening
"""

from __future__ import annotations

from .errors import (
    ResourceExhaustedError,
    SandboxCleanupError,
    SandboxError,
    SandboxSetupError,
    SandboxTimeoutError,
    SecurityViolationError,
)
from .types import (
    ExecutionStatus,
    ResourceLimits,
    SandboxBackend,
    SandboxConfig,
    SandboxResult,
    SecurityCapabilities,
)


from .execution import (
    ExecutionTimeout,
    ResourceLimitError,
    SecurityError,
    create_sandbox_namespace,
    get_hardened_builtins,
    get_safe_builtins,
    hardened_exec,
    make_restricted_import,
    resource_limits,
    safe_exec,
    timeout_context,
)
from .execution import (
    ResourceLimitError as ExecutionResourceLimitError,
)
from .execution import (
    SecurityError as ExecutionSecurityError,
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
    "ExecutionResourceLimitError",
    "ExecutionSecurityError",
    "ExecutionStatus",
    "ExecutionTimeout",
    "PathTraversalError",
    "ResourceExhaustedError",
    "ResourceLimitError",
    "ResourceLimits",
    "SandboxBackend",
    "SandboxCleanupError",
    "SandboxConfig",
    "SandboxError",
    "SandboxResult",
    "SandboxRunner",
    "SandboxSetupError",
    "SandboxTimeoutError",
    "SecureSandbox",
    "SecurityCapabilities",
    "SecurityConfig",
    "SecurityError",
    "SecurityViolationError",
    "create_sandbox_namespace",
    "get_hardened_builtins",
    "get_safe_builtins",
    "hardened_exec",
    "make_restricted_import",
    "resource_limits",
    "safe_exec",
    "sanitize_function_name",
    "timeout_context",
    "validate_bounds",
    "validate_config",
    "validate_path",
]
