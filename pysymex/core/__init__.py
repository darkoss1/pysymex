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

from importlib import import_module

from pysymex._deps import ensure_z3_ready

try:
    ensure_z3_ready()
    _z3_import_error: RuntimeError | None = None
except RuntimeError as exc:
    _z3_import_error = exc

_EXPORTS: dict[str, tuple[str, str]] = {
    "SymbolicType": ("pysymex.core.types.scalars", "SymbolicType"),
    "SymbolicValue": ("pysymex.core.types.scalars", "SymbolicValue"),
    "SymbolicString": ("pysymex.core.types.scalars", "SymbolicString"),
    "SymbolicList": ("pysymex.core.types.scalars", "SymbolicList"),
    "SymbolicDict": ("pysymex.core.types.scalars", "SymbolicDict"),
    "SymbolicNone": ("pysymex.core.types.scalars", "SymbolicNone"),
    "AnySymbolic": ("pysymex.core.types.scalars", "AnySymbolic"),
    "VMState": ("pysymex.core.state", "VMState"),
    "IncrementalSolver": ("pysymex.core.solver.engine", "IncrementalSolver"),
    "ConstraintCache": ("pysymex.core.optimization", "ConstraintCache"),
    "get_constraint_cache": ("pysymex.core.optimization", "get_constraint_cache"),
    "cached_is_satisfiable": ("pysymex.core.optimization", "cached_is_satisfiable"),
    "HeapObject": ("pysymex.core.memory", "HeapObject"),
    "SymbolicHeap": ("pysymex.core.memory", "SymbolicHeap"),
    "FloatPrecision": ("pysymex.core.types.floats", "FloatPrecision"),
    "FloatConfig": ("pysymex.core.types.floats", "FloatConfig"),
    "SymbolicFloat": ("pysymex.core.types.floats", "SymbolicFloat"),
    "FloatAnalyzer": ("pysymex.core.types.floats", "FloatAnalyzer"),
    "AccuracyAnalyzer": ("pysymex.core.types.floats", "AccuracyAnalyzer"),
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
    "get_enhanced_class": ("pysymex.core.objects.oop", "get_enhanced_class"),
    "register_enhanced_class": (
        "pysymex.core.objects.oop",
        "register_enhanced_class",
    ),
    "simplify_constraints": ("pysymex.core.constraint_simplifier", "simplify_constraints"),
    "quick_contradiction_check": (
        "pysymex.core.constraint_simplifier",
        "quick_contradiction_check",
    ),
    "remove_subsumed": ("pysymex.core.constraint_simplifier", "remove_subsumed"),
    "UnsatCoreResult": ("pysymex.core.solver.unsat", "UnsatCoreResult"),
    "extract_unsat_core": ("pysymex.core.solver.unsat", "extract_unsat_core"),
    "prune_with_core": ("pysymex.core.solver.unsat", "prune_with_core"),
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
    "SymbolicArray": ("pysymex.core.memory", "SymbolicArray"),
    "SymbolicMap": ("pysymex.core.memory", "SymbolicMap"),
    "MemoryState": ("pysymex.core.memory", "MemoryState"),
    "SymbolicClass_ObjModel": ("pysymex.core.objects", "SymbolicClass"),
    "SymbolicObject_ObjModel": ("pysymex.core.objects", "SymbolicObject"),
    "HavocValue": ("pysymex.core.types.havoc", "HavocValue"),
    "is_havoc": ("pysymex.core.types.havoc", "is_havoc"),
    "has_havoc": ("pysymex.core.types.havoc", "has_havoc"),
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
    """Dir."""
    return sorted(set(_EXPORTS.keys()) | set(globals()))
