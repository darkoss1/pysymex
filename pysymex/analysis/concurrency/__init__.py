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

"""Concurrency Analysis with Z3.
This module provides comprehensive concurrency analysis using Z3 SMT solver
for mathematical proofs of thread safety. Covers:
- Thread interleaving model
- Race condition detection
- Deadlock analysis
- Data race detection
- Atomicity violation detection
- Memory ordering issues
- Happens-before relationships
"""

from __future__ import annotations

from .types import (
    ConcurrencyIssue,
    ConcurrencyIssueKind,
    HappensBeforeGraph,
    MemoryOperation,
    MemoryOrder,
    OperationKind,
    Thread,
    ThreadState,
)

from .core import (
    ConcurrencyAnalyzer,
    LockOrderChecker,
    ThreadSafetyChecker,
)

__all__ = [
    "ConcurrencyAnalyzer",
    "ConcurrencyIssue",
    "ConcurrencyIssueKind",
    "HappensBeforeGraph",
    "LockOrderChecker",
    "MemoryOperation",
    "ThreadSafetyChecker",
    "MemoryOrder",
    "OperationKind",
    "Thread",
    "ThreadState",
]
