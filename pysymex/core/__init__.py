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

"""Core exports for pysymex (lazy-loaded)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from pysymex._deps import ensure_z3_ready
from pysymex._lazy import lazy_dir, lazy_getattr

if TYPE_CHECKING:
    from pysymex.core.types import (
        SymbolicType as SymbolicType,
        SymbolicValue as SymbolicValue,
        SymbolicString as SymbolicString,
        SymbolicList as SymbolicList,
        SymbolicDict as SymbolicDict,
        SymbolicNone as SymbolicNone,
        AnySymbolic as AnySymbolic,
    )
    from pysymex.core.state import VMState as VMState
    from pysymex.core.solver.engine import IncrementalSolver as IncrementalSolver
    from pysymex.core.optimization import (
        ConstraintCache as ConstraintCache,
        get_constraint_cache as get_constraint_cache,
        cached_is_satisfiable as cached_is_satisfiable,
    )
    from pysymex.core.memory import (
        HeapObject as HeapObject,
        SymbolicHeap as SymbolicHeap,
        SymbolicArray as SymbolicArray,
        SymbolicMap as SymbolicMap,
        MemoryState as MemoryState,
    )
    from pysymex.core.types.floats import (
        FloatPrecision as FloatPrecision,
        FloatConfig as FloatConfig,
        AdvancedSymbolicFloat as AdvancedSymbolicFloat,
        FloatAnalyzer as FloatAnalyzer,
        AccuracyAnalyzer as AccuracyAnalyzer,
    )
    from pysymex.core.types.numeric import SymbolicFloat as SymbolicFloat
    from pysymex.core.parallel import (
        ExplorationStrategy as ExplorationStrategy,
        ExplorationConfig as ExplorationConfig,
        ExplorationResult as ExplorationResult,
        PathResult as PathResult,
        StateSignature as StateSignature,
        WorkItem as WorkItem,
        WorkQueue as WorkQueue,
        ParallelExplorer as ParallelExplorer,
        ParallelSolver as ParallelSolver,
        ProcessParallelVerifier as ProcessParallelVerifier,
        ConstraintPartitioner as ConstraintPartitioner,
        StateMerger as ParallelStateMerger,
    )
    from pysymex.core.objects.oop import (
        MethodType as OOPMethodType,
        EnhancedMethod as EnhancedMethod,
        InitParameter as InitParameter,
        EnhancedClass as EnhancedClass,
        EnhancedObject as EnhancedObject,
        EnhancedClassRegistry as EnhancedClassRegistry,
        EnhancedSuper as EnhancedSuper,
        enhanced_class_registry as enhanced_class_registry,
        create_enhanced_instance as create_enhanced_instance,
        extract_init_params as extract_init_params,
        make_dataclass as make_dataclass,
        is_dataclass as is_dataclass,
        get_enhanced_class as get_enhanced_class,
        register_enhanced_class as register_enhanced_class,
    )
    from pysymex.core.solver.constraints import (
        simplify_constraints as simplify_constraints,
        quick_contradiction_check as quick_contradiction_check,
        remove_subsumed as remove_subsumed,
    )
    from pysymex.core.solver.unsat import (
        UnsatCoreResult as UnsatCoreResult,
        extract_unsat_core as extract_unsat_core,
        prune_with_core as prune_with_core,
    )
    from pysymex.core.memory.collections import (
        OpResult as OpResult,
        SymbolicListOps as SymbolicListOps,
        SymbolicDictOps as SymbolicDictOps,
        SymbolicSetOps as SymbolicSetOps,
        SymbolicTupleOps as SymbolicTupleOps,
        SymbolicStringOps as SymbolicStringOps,
    )
    from pysymex.core.exceptions import (
        SymbolicException as SymbolicException,
        ExceptionHandler as ExceptionHandler,
        ExceptionState as ExceptionState,
        ExceptionAnalyzer as ExceptionAnalyzer,
    )
    from pysymex.core.objects import (
        SymbolicClass as SymbolicClass_ObjModel,
        SymbolicObject as SymbolicObject_ObjModel,
    )
    from pysymex.core.types.havoc import (
        HavocValue as HavocValue,
        is_havoc as is_havoc,
        has_havoc as has_havoc,
    )
    from pysymex.resources import (
        AnalysisTimeoutError as AnalysisTimeoutError,
        GracefulDegradation as GracefulDegradation,
        LimitExceeded as LimitExceeded,
        PartialResult as PartialResult,
        ResourceLimits as ResourceLimits,
        ResourceSnapshot as ResourceSnapshot,
        ResourceTracker as ResourceTracker,
        ResourceType as ResourceType,
        TimeoutError as TimeoutError,
        create_partial_result as create_partial_result,
        timeout_context as timeout_context,
    )

try:
    ensure_z3_ready()
    _z3_import_error: RuntimeError | None = None
except RuntimeError as exc:
    _z3_import_error = exc

_EXPORTS: dict[str, tuple[str, str]] = {
    "SymbolicType": ("pysymex.core.types", "SymbolicType"),
    "SymbolicValue": ("pysymex.core.types", "SymbolicValue"),
    "SymbolicString": ("pysymex.core.types", "SymbolicString"),
    "SymbolicList": ("pysymex.core.types", "SymbolicList"),
    "SymbolicDict": ("pysymex.core.types", "SymbolicDict"),
    "SymbolicNone": ("pysymex.core.types", "SymbolicNone"),
    "AnySymbolic": ("pysymex.core.types", "AnySymbolic"),
    "VMState": ("pysymex.core.state", "VMState"),
    "IncrementalSolver": ("pysymex.core.solver.engine", "IncrementalSolver"),
    "ConstraintCache": ("pysymex.core.optimization", "ConstraintCache"),
    "get_constraint_cache": ("pysymex.core.optimization", "get_constraint_cache"),
    "cached_is_satisfiable": ("pysymex.core.optimization", "cached_is_satisfiable"),
    "HeapObject": ("pysymex.core.memory", "HeapObject"),
    "SymbolicHeap": ("pysymex.core.memory", "SymbolicHeap"),
    "FloatPrecision": ("pysymex.core.types.floats", "FloatPrecision"),
    "FloatConfig": ("pysymex.core.types.floats", "FloatConfig"),
    "SymbolicFloat": ("pysymex.core.types.numeric", "SymbolicFloat"),
    "AdvancedSymbolicFloat": ("pysymex.core.types.floats", "AdvancedSymbolicFloat"),
    "FloatAnalyzer": ("pysymex.core.types.floats", "FloatAnalyzer"),
    "AccuracyAnalyzer": ("pysymex.core.types.floats", "AccuracyAnalyzer"),
    "ExplorationStrategy": ("pysymex.core.parallel", "ExplorationStrategy"),
    "ExplorationConfig": ("pysymex.core.parallel", "ExplorationConfig"),
    "ExplorationResult": ("pysymex.core.parallel", "ExplorationResult"),
    "PathResult": ("pysymex.core.parallel", "PathResult"),
    "StateSignature": ("pysymex.core.parallel", "StateSignature"),
    "WorkItem": ("pysymex.core.parallel", "WorkItem"),
    "WorkQueue": ("pysymex.core.parallel", "WorkQueue"),
    "ParallelExplorer": ("pysymex.core.parallel", "ParallelExplorer"),
    "ParallelSolver": ("pysymex.core.parallel", "ParallelSolver"),
    "ProcessParallelVerifier": ("pysymex.core.parallel", "ProcessParallelVerifier"),
    "ConstraintPartitioner": ("pysymex.core.parallel", "ConstraintPartitioner"),
    "ParallelStateMerger": ("pysymex.core.parallel", "StateMerger"),
    "OOPMethodType": ("pysymex.core.objects.oop", "MethodType"),
    "EnhancedMethod": ("pysymex.core.objects.oop", "EnhancedMethod"),
    "InitParameter": ("pysymex.core.objects.oop", "InitParameter"),
    "EnhancedClass": ("pysymex.core.objects.oop", "EnhancedClass"),
    "EnhancedObject": ("pysymex.core.objects.oop", "EnhancedObject"),
    "EnhancedClassRegistry": ("pysymex.core.objects.oop", "EnhancedClassRegistry"),
    "EnhancedSuper": ("pysymex.core.objects.oop", "EnhancedSuper"),
    "enhanced_class_registry": (
        "pysymex.core.objects.oop",
        "enhanced_class_registry",
    ),
    "create_enhanced_instance": (
        "pysymex.core.objects.oop",
        "create_enhanced_instance",
    ),
    "extract_init_params": ("pysymex.core.objects.oop", "extract_init_params"),
    "make_dataclass": ("pysymex.core.objects.oop", "make_dataclass"),
    "is_dataclass": ("pysymex.core.objects.oop", "is_dataclass"),
    "get_enhanced_class": ("pysymex.core.objects.oop", "get_enhanced_class"),
    "register_enhanced_class": (
        "pysymex.core.objects.oop",
        "register_enhanced_class",
    ),
    "simplify_constraints": ("pysymex.core.solver.constraints", "simplify_constraints"),
    "quick_contradiction_check": (
        "pysymex.core.solver.constraints",
        "quick_contradiction_check",
    ),
    "remove_subsumed": ("pysymex.core.solver.constraints", "remove_subsumed"),
    "UnsatCoreResult": ("pysymex.core.solver.unsat", "UnsatCoreResult"),
    "extract_unsat_core": ("pysymex.core.solver.unsat", "extract_unsat_core"),
    "prune_with_core": ("pysymex.core.solver.unsat", "prune_with_core"),
    "OpResult": ("pysymex.core.memory.collections", "OpResult"),
    "SymbolicListOps": ("pysymex.core.memory.collections", "SymbolicListOps"),
    "SymbolicDictOps": ("pysymex.core.memory.collections", "SymbolicDictOps"),
    "SymbolicSetOps": ("pysymex.core.memory.collections", "SymbolicSetOps"),
    "SymbolicTupleOps": ("pysymex.core.memory.collections", "SymbolicTupleOps"),
    "SymbolicStringOps": ("pysymex.core.memory.collections", "SymbolicStringOps"),
    "SymbolicException": ("pysymex.core.exceptions", "SymbolicException"),
    "ExceptionHandler": ("pysymex.core.exceptions", "ExceptionHandler"),
    "ExceptionState": ("pysymex.core.exceptions", "ExceptionState"),
    "ExceptionAnalyzer": ("pysymex.core.exceptions", "ExceptionAnalyzer"),
    "SymbolicArray": ("pysymex.core.memory", "SymbolicArray"),
    "SymbolicMap": ("pysymex.core.memory", "SymbolicMap"),
    "MemoryState": ("pysymex.core.memory", "MemoryState"),
    "SymbolicClass_ObjModel": ("pysymex.core.objects", "SymbolicClass"),
    "SymbolicObject_ObjModel": ("pysymex.core.objects", "SymbolicObject"),
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

_NON_Z3_EXPORTS = {
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


def __getattr__(name: str) -> object:
    """Lazy-load core exports to prevent eager side-effect imports."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

    if _z3_import_error is not None and name not in _NON_Z3_EXPORTS:
        raise RuntimeError(str(_z3_import_error)) from _z3_import_error

    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Dir."""
    return lazy_dir(_EXPORTS, globals())


__all__ = [
    "AccuracyAnalyzer",
    "AdvancedSymbolicFloat",
    "AnalysisTimeoutError",
    "AnySymbolic",
    "ConstraintCache",
    "ConstraintPartitioner",
    "ExceptionHandler",
    "ExceptionAnalyzer",
    "ExceptionState",
    "EnhancedSuper",
    "ExplorationConfig",
    "ExplorationResult",
    "ExplorationStrategy",
    "FloatAnalyzer",
    "FloatConfig",
    "FloatPrecision",
    "GracefulDegradation",
    "HavocValue",
    "HeapObject",
    "IncrementalSolver",
    "LimitExceeded",
    "MemoryState",
    "OOPMethodType",
    "OpResult",
    "ParallelExplorer",
    "ParallelSolver",
    "ParallelStateMerger",
    "PartialResult",
    "PathResult",
    "ProcessParallelVerifier",
    "ResourceLimits",
    "ResourceSnapshot",
    "ResourceTracker",
    "ResourceType",
    "StateSignature",
    "SymbolicArray",
    "SymbolicClass_ObjModel",
    "SymbolicDict",
    "SymbolicDictOps",
    "SymbolicException",
    "SymbolicFloat",
    "SymbolicHeap",
    "SymbolicList",
    "SymbolicListOps",
    "SymbolicMap",
    "SymbolicNone",
    "SymbolicObject_ObjModel",
    "SymbolicSetOps",
    "SymbolicString",
    "SymbolicStringOps",
    "SymbolicTupleOps",
    "SymbolicType",
    "SymbolicValue",
    "TimeoutError",
    "UnsatCoreResult",
    "VMState",
    "WorkItem",
    "WorkQueue",
    "cached_is_satisfiable",
    "create_partial_result",
    "enhanced_class_registry",
    "extract_init_params",
    "extract_unsat_core",
    "get_constraint_cache",
    "get_enhanced_class",
    "has_havoc",
    "is_dataclass",
    "is_havoc",
    "make_dataclass",
    "prune_with_core",
    "quick_contradiction_check",
    "register_enhanced_class",
    "remove_subsumed",
    "simplify_constraints",
    "timeout_context",
]
