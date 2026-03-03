"""Core exports for PySyMex (lazy-loaded)."""

from __future__ import annotations


from importlib import import_module

from typing import Any


from pysymex._deps import ensure_z3_ready

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
    "ShadowSolver": ("pysymex.core.solver", "ShadowSolver"),
    "ConstraintCache": ("pysymex.core.optimization", "ConstraintCache"),
    "get_constraint_cache": ("pysymex.core.optimization", "get_constraint_cache"),
    "cached_is_satisfiable": ("pysymex.core.optimization", "cached_is_satisfiable"),
    "StateMerger": ("pysymex.core.optimization", "StateMerger"),
    "LazySymbolicValue": ("pysymex.core.optimization", "LazySymbolicValue"),
    "CompactState": ("pysymex.core.optimization", "CompactState"),
    "ExecutionProfiler": ("pysymex.core.optimization", "ExecutionProfiler"),
    "HeapObject": ("pysymex.core.memory_model", "HeapObject"),
    "SymbolicHeap": ("pysymex.core.memory_model", "SymbolicHeap"),
    "FloatPrecision": ("pysymex.core.floats", "FloatPrecision"),
    "FloatConfig": ("pysymex.core.floats", "FloatConfig"),
    "SymbolicFloat": ("pysymex.core.floats", "SymbolicFloat"),
    "FloatAnalyzer": ("pysymex.core.floats", "FloatAnalyzer"),
    "AccuracyAnalyzer": ("pysymex.core.floats", "AccuracyAnalyzer"),
    "FileEventType": ("pysymex.watch", "FileEventType"),
    "FileEvent": ("pysymex.watch", "FileEvent"),
    "FileState": ("pysymex.watch", "FileState"),
    "FileWatcher": ("pysymex.watch", "FileWatcher"),
    "AnalysisCache": ("pysymex.watch", "AnalysisCache"),
    "IncrementalAnalyzer": ("pysymex.watch", "IncrementalAnalyzer"),
    "WatchModeRunner": ("pysymex.watch", "WatchModeRunner"),
    "DependencyTracker": ("pysymex.watch", "DependencyTracker"),
    "ExplorationStrategy": ("pysymex.core.parallel", "ExplorationStrategy"),
    "ExplorationConfig": ("pysymex.core.parallel", "ExplorationConfig"),
    "WorkQueue": ("pysymex.core.parallel", "WorkQueue"),
    "ParallelExplorer": ("pysymex.core.parallel", "ParallelExplorer"),
    "ParallelSolver": ("pysymex.core.parallel", "ParallelSolver"),
    "ConstraintPartitioner": ("pysymex.core.parallel", "ConstraintPartitioner"),
    "ParallelStateMerger": ("pysymex.core.parallel", "StateMerger"),
    "OOPMethodType": ("pysymex.core.oop_support", "MethodType"),
    "EnhancedMethod": ("pysymex.core.oop_support", "EnhancedMethod"),
    "InitParameter": ("pysymex.core.oop_support", "InitParameter"),
    "EnhancedClass": ("pysymex.core.oop_support", "EnhancedClass"),
    "EnhancedObject": ("pysymex.core.oop_support", "EnhancedObject"),
    "EnhancedClassRegistry": ("pysymex.core.oop_support", "EnhancedClassRegistry"),
    "EnhancedSuper": ("pysymex.core.oop_support", "EnhancedSuper"),
    "enhanced_class_registry": (
        "pysymex.core.oop_support",
        "enhanced_class_registry",
    ),
    "create_enhanced_instance": (
        "pysymex.core.oop_support",
        "create_enhanced_instance",
    ),
    "extract_init_params": ("pysymex.core.oop_support", "extract_init_params"),
    "make_dataclass": ("pysymex.core.oop_support", "make_dataclass"),
    "get_enhanced_class": ("pysymex.core.oop_support", "get_enhanced_class"),
    "register_enhanced_class": (
        "pysymex.core.oop_support",
        "register_enhanced_class",
    ),
    "simplify_constraints": ("pysymex.core.constraint_simplifier", "simplify_constraints"),
    "quick_contradiction_check": (
        "pysymex.core.constraint_simplifier",
        "quick_contradiction_check",
    ),
    "remove_subsumed": ("pysymex.core.constraint_simplifier", "remove_subsumed"),
    "UnsatCoreResult": ("pysymex.core.unsat_core", "UnsatCoreResult"),
    "extract_unsat_core": ("pysymex.core.unsat_core", "extract_unsat_core"),
    "prune_with_core": ("pysymex.core.unsat_core", "prune_with_core"),
    "OpResult": ("pysymex.core.collections", "OpResult"),
    "SymbolicListOps": ("pysymex.core.collections", "SymbolicListOps"),
    "SymbolicDictOps": ("pysymex.core.collections", "SymbolicDictOps"),
    "SymbolicSetOps": ("pysymex.core.collections", "SymbolicSetOps"),
    "SymbolicTupleOps": ("pysymex.core.collections", "SymbolicTupleOps"),
    "SymbolicStringOps": ("pysymex.core.collections", "SymbolicStringOps"),
    "SymbolicException": ("pysymex.core.exceptions", "SymbolicException"),
    "ExceptionHandler": ("pysymex.core.exceptions", "ExceptionHandler"),
    "ExceptionState": ("pysymex.core.exceptions", "ExceptionState"),
    "ExceptionAnalyzer": ("pysymex.core.exceptions", "ExceptionAnalyzer"),
    "SymbolicArray": ("pysymex.core.memory_model", "SymbolicArray"),
    "SymbolicMap": ("pysymex.core.memory_model", "SymbolicMap"),
    "MemoryState": ("pysymex.core.memory_model", "MemoryState"),
    "SymbolicClass_ObjModel": ("pysymex.core.object_model", "SymbolicClass"),
    "SymbolicObject_ObjModel": ("pysymex.core.object_model", "SymbolicObject"),
}


_NON_Z3_EXPORTS = {
    "FileEventType",
    "FileEvent",
    "FileState",
    "FileWatcher",
    "AnalysisCache",
    "IncrementalAnalyzer",
    "WatchModeRunner",
    "DependencyTracker",
}


__all__ = [
    "SymbolicType",
    "SymbolicValue",
    "SymbolicString",
    "SymbolicList",
    "SymbolicDict",
    "SymbolicNone",
    "AnySymbolic",
    "VMState",
    "ShadowSolver",
    "ConstraintCache",
    "get_constraint_cache",
    "cached_is_satisfiable",
    "StateMerger",
    "LazySymbolicValue",
    "CompactState",
    "ExecutionProfiler",
    "HeapObject",
    "SymbolicHeap",
    "FloatPrecision",
    "FloatConfig",
    "SymbolicFloat",
    "FloatAnalyzer",
    "AccuracyAnalyzer",
    "FileEventType",
    "FileEvent",
    "FileState",
    "FileWatcher",
    "AnalysisCache",
    "IncrementalAnalyzer",
    "WatchModeRunner",
    "DependencyTracker",
    "ExplorationStrategy",
    "ExplorationConfig",
    "WorkQueue",
    "ParallelExplorer",
    "ParallelSolver",
    "ConstraintPartitioner",
    "ParallelStateMerger",
    "OOPMethodType",
    "EnhancedMethod",
    "InitParameter",
    "EnhancedClass",
    "EnhancedObject",
    "EnhancedClassRegistry",
    "EnhancedSuper",
    "enhanced_class_registry",
    "create_enhanced_instance",
    "extract_init_params",
    "make_dataclass",
    "get_enhanced_class",
    "register_enhanced_class",
    "simplify_constraints",
    "quick_contradiction_check",
    "remove_subsumed",
    "UnsatCoreResult",
    "extract_unsat_core",
    "prune_with_core",
    "OpResult",
    "SymbolicListOps",
    "SymbolicDictOps",
    "SymbolicSetOps",
    "SymbolicTupleOps",
    "SymbolicStringOps",
    "SymbolicException",
    "ExceptionHandler",
    "ExceptionState",
    "ExceptionAnalyzer",
    "SymbolicArray",
    "SymbolicMap",
    "MemoryState",
    "SymbolicClass_ObjModel",
    "SymbolicObject_ObjModel",
]


def __getattr__(name: str) -> Any:
    """Lazy-load core exports to prevent eager side-effect imports."""

    target = _EXPORTS.get(name)

    if target is None:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

    if _z3_import_error is not None and name not in _NON_Z3_EXPORTS:
        raise RuntimeError(str(_z3_import_error)) from _z3_import_error

    module_name, attr_name = target

    module = import_module(module_name)

    value = getattr(module, attr_name)

    globals()[name] = value

    return value


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(globals()))
