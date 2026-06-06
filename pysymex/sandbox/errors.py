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

"""Define process-sandbox and in-process restriction exception families.

`SandboxError` is the root for isolation-backend and bridge failures.
`ExecutionTimeout` and `SecurityError` remain separate in-process execution
errors used by Python-level validation and policy helpers.
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


class SandboxExecutionError(SandboxError):
    """Raised when sandboxed code or a sandbox worker fails at runtime."""

    pass


class SandboxResourceError(SandboxError):
    """Raised when a sandbox execution exceeds a resource or size limit."""

    pass


class SandboxProtocolError(SandboxError):
    """Raised when untrusted sandbox output violates the host protocol."""

    pass


class SandboxSecurityError(SandboxError):
    """Raised when a sandbox security invariant is violated or denied."""

    pass


class SandboxTimeoutError(SandboxResourceError):
    """Raised when sandbox execution exceeds time limit.

    The sandboxed process was killed due to exceeding the
    configured timeout.
    """

    def __init__(self, timeout_seconds: float, message: str | None = None) -> None:
        """Store the configured timeout and initialize the error message.

        Args:
            timeout_seconds: Timeout limit associated with the failed
                execution.
            message: Explicit error message. When omitted, a message is
                constructed from `timeout_seconds`.
        """
        self.timeout_seconds = timeout_seconds
        msg = message or f"Sandbox execution timed out after {timeout_seconds}s"
        super().__init__(msg)


class SecurityViolationError(SandboxSecurityError):
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
        """Store the denied operation and construct a diagnostic message.

        Args:
            operation: Operation rejected by sandbox policy.
            details: Optional contextual information appended to the message.
        """
        self.operation = operation
        self.details = details
        msg = f"Security violation: attempted {operation}"
        if details:
            msg += f" ({details})"
        super().__init__(msg)


class ResourceExhaustedError(SandboxResourceError):
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
        """Store exceeded resource metadata and construct the message.

        Args:
            resource: Resource whose configured bound was exceeded.
            limit: Configured limiting value.
            unit: Optional unit suffix appended to the limiting value.
        """
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


class ExecutionTimeout(Exception):
    """Raised when in-process sandbox execution times out."""

    pass


class SecurityError(Exception):
    """Raised when a security check fails in the in-process sandbox."""

    pass


class ResourceLimitError(SecurityError):
    """Raised when in-process sandbox resource limits are exceeded."""

    pass
