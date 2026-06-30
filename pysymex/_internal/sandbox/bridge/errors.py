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

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.config.sandbox.types import SandboxConfig


def sandbox_result_error(result: object, config: SandboxConfig, default_message: str) -> Exception:
    """Map a sandbox worker result to the host-side exception hierarchy.

    Args:
        result: Candidate sandbox result object to classify.
        config: Sandbox configuration supplying the timeout value for timeout
            exceptions.
        default_message: Message used when the result has no textual
            diagnostic or does not satisfy the result protocol.

    Returns:
        A protocol, timeout, resource, security, setup, or generic execution
        exception selected from the result type and execution status.

    Notes:
        This function constructs an exception for its caller to raise; it does
        not raise or execute sandboxed code itself.

    """
    from pysymex._internal.sandbox.errors import (
        SandboxExecutionError,
        SandboxProtocolError,
        SandboxResourceError,
        SandboxSecurityError,
        SandboxSetupError,
        SandboxTimeoutError,
    )
    from pysymex._internal.sandbox.types import ExecutionStatus, SandboxResult

    if not isinstance(result, SandboxResult):
        return SandboxProtocolError(default_message)

    message = (
        result.error_message
        or result.get_stderr_text().strip()
        or result.get_stdout_text().strip()
        or default_message
    )
    if result.status is ExecutionStatus.TIMEOUT:
        return SandboxTimeoutError(config.limits.timeout_seconds, message=message)
    if result.status in {
        ExecutionStatus.MEMORY_EXCEEDED,
        ExecutionStatus.CPU_EXCEEDED,
    }:
        return SandboxResourceError(message)
    if result.status is ExecutionStatus.SECURITY_VIOLATION:
        return SandboxSecurityError(message)
    if result.status is ExecutionStatus.SETUP_ERROR:
        return SandboxSetupError(message)
    return SandboxExecutionError(message)
