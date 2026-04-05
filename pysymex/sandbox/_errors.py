# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Exception classes for the sandbox module.

All sandbox-related errors derive from SandboxError, allowing
callers to catch all sandbox issues with a single exception type.
"""

from __future__ import annotations


class SandboxError(Exception):
    """Base exception for all sandbox-related errors.

    This is the root of the sandbox exception hierarchy. Catching
    this exception will catch all sandbox-specific errors.
    """

    pass


class SandboxSetupError(SandboxError):
    """Raised when sandbox environment cannot be created.

    This indicates a problem with the host system configuration,
    missing dependencies, or insufficient permissions to create
    the sandbox environment.
    """

    pass


class SandboxTimeoutError(SandboxError):
    """Raised when sandbox execution exceeds time limit.

    The sandboxed process was killed due to exceeding the
    configured timeout.
    """

    def __init__(self, timeout_seconds: float, message: str | None = None) -> None:
        self.timeout_seconds = timeout_seconds
        msg = message or f"Sandbox execution timed out after {timeout_seconds}s"
        super().__init__(msg)


class SecurityViolationError(SandboxError):
    """Raised when sandboxed code attempts a forbidden operation.

    This indicates the sandboxed code tried to perform an operation
    that was blocked by the security policy (e.g., network access,
    forbidden syscall, filesystem escape attempt).
    """

    def __init__(
        self,
        operation: str,
        details: str | None = None,
    ) -> None:
        self.operation = operation
        self.details = details
        msg = f"Security violation: attempted {operation}"
        if details:
            msg += f" ({details})"
        super().__init__(msg)


class ResourceExhaustedError(SandboxError):
    """Raised when sandboxed code exceeds resource limits.

    This indicates the sandboxed code was killed due to exceeding
    memory, CPU, or other resource limits.
    """

    def __init__(
        self,
        resource: str,
        limit: int | float,
        unit: str = "",
    ) -> None:
        self.resource = resource
        self.limit = limit
        self.unit = unit
        msg = f"Resource exhausted: {resource} exceeded limit of {limit}{unit}"
        super().__init__(msg)


class SandboxCleanupError(SandboxError):
    """Raised when sandbox cleanup fails.

    This is a non-fatal error indicating that temporary files
    or processes could not be cleaned up properly. The execution
    itself may have succeeded.
    """

    pass
