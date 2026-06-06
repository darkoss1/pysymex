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

"""Public exception aliases for user-facing API boundaries."""

from __future__ import annotations

from pysymex.resources.models import AnalysisTimeoutError
from pysymex.resources.models import LimitExceeded
from pysymex.resources.models import TimeoutError as ResourceTimeoutError
from pysymex.sandbox import ExecutionTimeout
from pysymex.sandbox import PathTraversalError
from pysymex.sandbox import ResourceExhaustedError
from pysymex.sandbox import ResourceLimitError
from pysymex.sandbox import SandboxError
from pysymex.sandbox import SandboxExecutionError
from pysymex.sandbox import SandboxProtocolError
from pysymex.sandbox import SandboxResourceError
from pysymex.sandbox import SandboxSecurityError
from pysymex.sandbox import SandboxSetupError
from pysymex.sandbox import SandboxTimeoutError
from pysymex.sandbox import SecurityError
from pysymex.sandbox import SecurityViolationError

__all__ = [
    "AnalysisTimeoutError",
    "ExecutionTimeout",
    "LimitExceeded",
    "PathTraversalError",
    "ResourceExhaustedError",
    "ResourceLimitError",
    "ResourceTimeoutError",
    "SandboxError",
    "SandboxExecutionError",
    "SandboxProtocolError",
    "SandboxResourceError",
    "SandboxSecurityError",
    "SandboxSetupError",
    "SandboxTimeoutError",
    "SecurityError",
    "SecurityViolationError",
]
