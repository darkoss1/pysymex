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

"""Concurrency analysis with Z3-backed constraint solving.

Provides thread-interleaving modelling, happens-before graph construction,
and Z3-powered detection of data races, deadlocks, atomicity violations,
race conditions, await cycles, and lock-ordering problems.
"""

from __future__ import annotations

from .enums import (
    ConcurrencyIssueKind,
    MemoryOrder,
    OperationKind,
    ThreadState,
)
from .happens_before import HappensBeforeGraph
from .models import (
    ConcurrencyIssue,
    MemoryOperation,
    Thread,
)
from .schedules import (
    RaceCheckResult,
    RaceCheckStatus,
    ScheduleSearchResult,
    ScheduleSearchStatus,
)

from .analyzer import (
    ConcurrencyAnalyzer,
)

__all__ = [
    "ConcurrencyAnalyzer",
    "ConcurrencyIssue",
    "ConcurrencyIssueKind",
    "HappensBeforeGraph",
    "MemoryOperation",
    "MemoryOrder",
    "OperationKind",
    "RaceCheckResult",
    "RaceCheckStatus",
    "ScheduleSearchResult",
    "ScheduleSearchStatus",
    "Thread",
    "ThreadState",
]
