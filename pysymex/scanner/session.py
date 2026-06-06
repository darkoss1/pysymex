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

"""Scanner session context.

Part of the execution state management. Holds task-local scan session context
used to track current limits, cancellation tokens, and overall scanning status
across asynchronous tasks or execution loops.
"""

from __future__ import annotations

import contextvars

from pysymex.scanner.types import ScanSession

# Task-local context variable storing the active ScanSession.
session_var: contextvars.ContextVar[ScanSession | None] = contextvars.ContextVar(
    "session_var",
    default=None,
)
