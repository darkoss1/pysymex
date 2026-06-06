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

"""Lazy export targets for :mod:`pysymex.core`."""

from __future__ import annotations

EXPORTS: dict[str, tuple[str, str]] = {
    "SymbolicType": ("pysymex.core.types.base", "SymbolicType"),
    "SymbolicValue": ("pysymex.core.types.scalars.values", "SymbolicValue"),
    "SymbolicString": ("pysymex.core.types.scalars.strings", "SymbolicString"),
    "SymbolicList": ("pysymex.core.types.containers.lists", "SymbolicList"),
    "SymbolicDict": ("pysymex.core.types.containers.dicts", "SymbolicDict"),
    "SymbolicNone": ("pysymex.core.types.base", "SymbolicNoneType"),
    "AnySymbolic": ("pysymex.core.types.scalars.values", "AnySymbolic"),
    "VMState": ("pysymex.core.state.record", "VMState"),
    "IncrementalSolver": ("pysymex.core.solver.engine.incremental", "IncrementalSolver"),
    "HeapObject": ("pysymex.core.memory.types", "HeapObject"),
    "SymbolicHeap": ("pysymex.core.memory.heap.store", "SymbolicHeap"),
    "FloatPrecision": ("pysymex.config.floats", "FloatPrecision"),
    "FloatConfig": ("pysymex.config.floats", "FloatConfig"),
    "SymbolicFloat": ("pysymex.core.types.numeric.float", "SymbolicFloat"),
    "AdvancedSymbolicFloat": ("pysymex.core.types.advanced_float", "AdvancedSymbolicFloat"),
    "FloatAnalyzer": ("pysymex.core.solver.floats.analysis", "FloatAnalyzer"),
    "AccuracyAnalyzer": ("pysymex.core.solver.floats.analysis", "AccuracyAnalyzer"),
    "ParallelSolver": ("pysymex.core.solver.partitioning", "ParallelSolver"),
    "ConstraintPartitioner": ("pysymex.core.solver.partitioning", "ConstraintPartitioner"),
    "simplify_constraints": (
        "pysymex.core.solver.constraints.simplification",
        "simplify_constraints",
    ),
    "quick_contradiction_check": (
        "pysymex.core.solver.constraints.contradictions",
        "quick_contradiction_check",
    ),
    "remove_subsumed": ("pysymex.core.solver.constraints.subsumption", "remove_subsumed"),
    "UnsatCoreResult": ("pysymex.core.solver.unsat", "UnsatCoreResult"),
    "extract_unsat_core": ("pysymex.core.solver.unsat", "extract_unsat_core"),
    "prune_with_core": ("pysymex.core.solver.unsat", "prune_with_core"),
    "SymbolicException": ("pysymex.core.exceptions.objects", "SymbolicException"),
    "ExceptionHandler": ("pysymex.core.exceptions.objects", "ExceptionHandler"),
    "ExceptionState": ("pysymex.core.exceptions.state", "ExceptionState"),
    "ExceptionAnalyzer": ("pysymex.core.exceptions.analyzer.core", "ExceptionAnalyzer"),
    "MemoryState": ("pysymex.core.memory.heap.state", "MemoryState"),
    "HavocValue": ("pysymex.core.types.havoc", "HavocValue"),
    "is_havoc": ("pysymex.core.types.havoc", "is_havoc"),
    "has_havoc": ("pysymex.core.types.havoc", "has_havoc"),
    "AnalysisTimeoutError": ("pysymex.resources", "AnalysisTimeoutError"),
    "GracefulDegradation": ("pysymex.resources", "GracefulDegradation"),
    "LimitExceeded": ("pysymex.resources", "LimitExceeded"),
    "PartialResult": ("pysymex.resources", "PartialResult"),
    "ResourceLimits": ("pysymex.resources", "ResourceLimits"),
    "ResourceSnapshot": ("pysymex.resources", "ResourceSnapshot"),
    "ResourceTracker": ("pysymex.resources", "ResourceTracker"),
    "ResourceType": ("pysymex.resources", "ResourceType"),
    "TimeoutError": ("pysymex.resources", "TimeoutError"),
    "create_partial_result": ("pysymex.resources", "create_partial_result"),
    "timeout_context": ("pysymex.resources", "timeout_context"),
}

NON_Z3_EXPORTS = {
    "AnalysisTimeoutError",
    "GracefulDegradation",
    "LimitExceeded",
    "PartialResult",
    "ResourceLimits",
    "ResourceSnapshot",
    "ResourceTracker",
    "ResourceType",
    "TimeoutError",
    "create_partial_result",
    "timeout_context",
}
