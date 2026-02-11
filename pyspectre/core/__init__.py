"""Core module for PySpectre.
Provides:
- Symbolic types (SymbolicValue, SymbolicString, SymbolicList, etc.)
- VM state representation
- Z3 solver interface
- Performance optimization utilities
- Symbolic memory and heap modeling
- Floating-point symbolic analysis
- Watch mode and incremental analysis
"""

from pyspectre.core.floats import (
    AccuracyAnalyzer,
    FloatAnalyzer,
    FloatConfig,
    FloatPrecision,
    SymbolicFloat,
)
from pyspectre.core.memory import (
    AllocationSite,
    AllocationType,
    EscapeAnalysis,
    HeapObject,
    PointsToAnalysis,
    SymbolicHeap,
    SymbolicPointer,
)
from pyspectre.core.oop_support import (
    EnhancedClass,
    EnhancedClassRegistry,
    EnhancedMethod,
    EnhancedObject,
    EnhancedSuper,
    InitParameter,
    create_enhanced_instance,
    enhanced_class_registry,
    extract_init_params,
    get_enhanced_class,
    make_dataclass,
    register_enhanced_class,
)
from pyspectre.core.oop_support import (
    MethodType as OOPMethodType,
)
from pyspectre.core.optimization import (
    CompactState,
    ConstraintCache,
    ExecutionProfiler,
    LazySymbolicValue,
    StateMerger,
    cached_is_satisfiable,
    get_constraint_cache,
)
from pyspectre.core.parallel import (
    ConstraintPartitioner,
    ExplorationConfig,
    ExplorationStrategy,
    ParallelExplorer,
    ParallelSolver,
    WorkQueue,
)
from pyspectre.core.parallel import (
    StateMerger as ParallelStateMerger,
)
from pyspectre.core.solver import ShadowSolver
from pyspectre.core.state import VMState
from pyspectre.core.types import (
    AnySymbolic,
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicType,
    SymbolicValue,
)
from pyspectre.core.watch import (
    AnalysisCache,
    DependencyTracker,
    FileEvent,
    FileEventType,
    FileState,
    FileWatcher,
    IncrementalAnalyzer,
    WatchModeRunner,
)

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
    "AllocationType",
    "AllocationSite",
    "SymbolicPointer",
    "HeapObject",
    "SymbolicHeap",
    "PointsToAnalysis",
    "EscapeAnalysis",
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
]
