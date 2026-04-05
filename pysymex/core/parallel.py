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

"""Parallel path exploration for pysymex.

This module provides multi-threaded symbolic execution with:
- Work-stealing task queues
- State partitioning
- Thread-safe result aggregation
- Configurable parallelism
- Process-based file parallelism (bypasses GIL)

Split into:
- parallel_types: dataclasses, enums, type-only definitions
- parallel_core: logic classes (queues, merging, solvers, verifiers)
"""

from pysymex.core.parallel_core import ConstraintPartitioner as ConstraintPartitioner
from pysymex.core.parallel_core import ParallelExplorer as ParallelExplorer
from pysymex.core.parallel_core import ParallelSolver as ParallelSolver
from pysymex.core.parallel_core import (
    ProcessParallelVerifier as ProcessParallelVerifier,
)
from pysymex.core.parallel_core import StateMerger as StateMerger
from pysymex.core.parallel_core import WorkQueue as WorkQueue
from pysymex.core.parallel_types import ExplorationConfig as ExplorationConfig
from pysymex.core.parallel_types import ExplorationResult as ExplorationResult
from pysymex.core.parallel_types import ExplorationStrategy as ExplorationStrategy
from pysymex.core.parallel_types import PathResult as PathResult
from pysymex.core.parallel_types import StateSignature as StateSignature
from pysymex.core.parallel_types import WorkItem as WorkItem

__all__ = [
    "ConstraintPartitioner",
    "ExplorationConfig",
    "ExplorationResult",
    "ExplorationStrategy",
    "ParallelExplorer",
    "ParallelSolver",
    "PathResult",
    "ProcessParallelVerifier",
    "StateMerger",
    "StateSignature",
    "WorkItem",
    "WorkQueue",
]
