"""Core exports for PySyMex (lazy-loaded)."""

from __future__ import annotations

from importlib import import_module

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
    # StateMerger: path-deduplication / state-merging for single-threaded exploration
    # (pysymex.core.optimization.StateMerger).
    # Do NOT confuse with ParallelStateMerger below, which comes from parallel_core.
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
    # ParallelStateMerger: thread-safe state merger used by ParallelExplorer
    # (pysymex.core.parallel_core.StateMerger).
    # Distinct from the single-threaded StateMerger exported above.
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
    "HavocValue": ("pysymex.core.havoc", "HavocValue"),
    "is_havoc": ("pysymex.core.havoc", "is_havoc"),
    "has_havoc": ("pysymex.core.havoc", "has_havoc"),
    "union_taint": ("pysymex.core.havoc", "union_taint"),
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

__all__: list[str] = [
    "AccuracyAnalyzer",
    "AnalysisCache",
    "AnySymbolic",
    "CompactState",
    "ConstraintCache",
    "ConstraintPartitioner",
    "DependencyTracker",
    "EnhancedClass",
    "EnhancedClassRegistry",
    "EnhancedMethod",
    "EnhancedObject",
    "EnhancedSuper",
    "ExceptionAnalyzer",
    "ExceptionHandler",
    "ExceptionState",
    "ExecutionProfiler",
    "ExplorationConfig",
    "ExplorationStrategy",
    "FileEvent",
    "FileEventType",
    "FileState",
    "FileWatcher",
    "FloatAnalyzer",
    "FloatConfig",
    "FloatPrecision",
    "HavocValue",
    "HeapObject",
    "IncrementalAnalyzer",
    "InitParameter",
    "LazySymbolicValue",
    "MemoryState",
    "OOPMethodType",
    "OpResult",
    "ParallelExplorer",
    "ParallelSolver",
    "ParallelStateMerger",
    "ShadowSolver",
    "StateMerger",
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
    "UnsatCoreResult",
    "VMState",
    "WatchModeRunner",
    "WorkQueue",
    "cached_is_satisfiable",
    "create_enhanced_instance",
    "enhanced_class_registry",
    "extract_init_params",
    "extract_unsat_core",
    "get_constraint_cache",
    "get_enhanced_class",
    "has_havoc",
    "is_havoc",
    "make_dataclass",
    "prune_with_core",
    "quick_contradiction_check",
    "register_enhanced_class",
    "remove_subsumed",
    "simplify_constraints",
    "union_taint",
]


def __getattr__(name: str) -> object:
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
