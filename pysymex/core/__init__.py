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

"""Lazy public exports for symbolic state, solver, memory, and analysis types."""

from __future__ import annotations

from typing import TYPE_CHECKING
from pysymex.deps import ensure_z3_ready
from pysymex.lazy import lazy_dir, lazy_getattr
from pysymex.core.exports import EXPORTS as _EXPORTS
from pysymex.core.exports import NON_Z3_EXPORTS as _NON_Z3_EXPORTS

if TYPE_CHECKING:
    from pysymex.core.types.base import SymbolicType, SymbolicNoneType as SymbolicNone
    from pysymex.core.types.scalars.values import SymbolicValue, AnySymbolic
    from pysymex.core.types.scalars.strings import SymbolicString
    from pysymex.core.types.containers.lists import SymbolicList
    from pysymex.core.types.containers.dicts import SymbolicDict
    from pysymex.core.state.record import VMState
    from pysymex.core.solver.engine.incremental import IncrementalSolver
    from pysymex.core.memory.heap.state import MemoryState
    from pysymex.core.memory.heap.store import SymbolicHeap
    from pysymex.core.memory.types import HeapObject
    from pysymex.core.types.advanced_float import (
        AdvancedSymbolicFloat,
    )
    from pysymex.core.solver.floats.analysis import (
        AccuracyAnalyzer,
        FloatAnalyzer,
    )
    from pysymex.config.floats import (
        FloatConfig,
        FloatPrecision,
    )
    from pysymex.core.types.numeric.float import SymbolicFloat
    from pysymex.core.solver.partitioning import ConstraintPartitioner, ParallelSolver
    from pysymex.core.solver.constraints.contradictions import quick_contradiction_check
    from pysymex.core.solver.constraints.simplification import simplify_constraints
    from pysymex.core.solver.constraints.subsumption import remove_subsumed
    from pysymex.core.solver.unsat import (
        UnsatCoreResult,
        extract_unsat_core,
        prune_with_core,
    )
    from pysymex.core.exceptions.analyzer.core import ExceptionAnalyzer
    from pysymex.core.exceptions.objects import ExceptionHandler, SymbolicException
    from pysymex.core.exceptions.state import ExceptionState
    from pysymex.core.types.havoc import (
        HavocValue,
        is_havoc,
        has_havoc,
    )
    from pysymex.resources.degradation import (
        GracefulDegradation,
        PartialResult,
        create_partial_result,
        timeout_context,
    )
    from pysymex.resources.models import (
        AnalysisTimeoutError,
        LimitExceeded,
        ResourceLimits,
        ResourceSnapshot,
        ResourceType,
        TimeoutError,
    )
    from pysymex.resources.tracker import ResourceTracker

try:
    ensure_z3_ready()
    _z3_import_error: RuntimeError | None = None
except RuntimeError as exc:
    _z3_import_error = exc


def __getattr__(name: str) -> object:
    """Load a registered export on demand after dependency readiness checks.

    Raises:
        AttributeError: If ``name`` is not a registered public export.
        RuntimeError: If a Z3-dependent export is requested without usable Z3.
    """
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

    if _z3_import_error is not None and name not in _NON_Z3_EXPORTS:
        raise RuntimeError(str(_z3_import_error)) from _z3_import_error

    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Return available global and lazily exported names for introspection."""
    return lazy_dir(_EXPORTS, globals())


__all__ = [
    "AccuracyAnalyzer",
    "AdvancedSymbolicFloat",
    "AnalysisTimeoutError",
    "AnySymbolic",
    "ConstraintPartitioner",
    "ExceptionHandler",
    "ExceptionAnalyzer",
    "ExceptionState",
    "FloatAnalyzer",
    "FloatConfig",
    "FloatPrecision",
    "GracefulDegradation",
    "HavocValue",
    "HeapObject",
    "IncrementalSolver",
    "LimitExceeded",
    "MemoryState",
    "ParallelSolver",
    "PartialResult",
    "ResourceLimits",
    "ResourceSnapshot",
    "ResourceTracker",
    "ResourceType",
    "SymbolicDict",
    "SymbolicException",
    "SymbolicFloat",
    "SymbolicHeap",
    "SymbolicList",
    "SymbolicNone",
    "SymbolicString",
    "SymbolicType",
    "SymbolicValue",
    "TimeoutError",
    "UnsatCoreResult",
    "VMState",
    "create_partial_result",
    "extract_unsat_core",
    "has_havoc",
    "is_havoc",
    "prune_with_core",
    "quick_contradiction_check",
    "remove_subsumed",
    "simplify_constraints",
    "timeout_context",
]
