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

"""Analysis module for bug detection and path exploration (lazy-loaded).

All public symbols are loaded on first access via ``__getattr__``.

Subpackages
-----------
abstract/       Abstract interpretation (Interval, Sign, Parity, Null domains)
detectors/      Bug detectors: base (runtime), static (bytecode-based), specialized
exceptions/     Exception analysis and handler detection
resources/      Resource leak detection and lifecycle state-machines
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._lazy import lazy_dir, lazy_getattr

if TYPE_CHECKING:
    from pysymex.analysis.concolic import (
        BranchRecord as BranchRecord,
        ConcreteInput as ConcreteInput,
        ConcolicExecutor as ConcolicExecutor,
        ExecutionTrace as ExecutionTrace,
        GenerationalSearch as GenerationalSearch,
    )
    from pysymex.analysis.detectors.base import DetectorRegistry as DetectorRegistry
    from pysymex.analysis.detectors.specialized import (
        InfiniteLoopDetector as InfiniteLoopDetector,
        IntegerOverflowDetector as IntegerOverflowDetector,
        NullDereferenceDetector as NullDereferenceDetector,
        UnreachableCodeDetector as UnreachableCodeDetector,
    )
    from pysymex.analysis.interprocedural import (
        CallGraph as CallGraph,
        CallSite as CallSite,
        CallType as CallType,
        FunctionSummary as FunctionSummary,
        InterproceduralAnalyzer as InterproceduralAnalyzer,
    )
    from pysymex.analysis.complexity import (
        ComplexityMetrics as ComplexityMetrics,
        ComplexityAnalysis as ComplexityAnalysis,
        analyze_complexity as analyze_complexity,
        estimate_complexity as estimate_complexity,
        tune_execution_config as tune_execution_config,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "AbstractInterpreter": ("pysymex.analysis.abstract.domains", "AbstractInterpreter"),
    "AbstractState": ("pysymex.analysis.abstract.domains", "AbstractState"),
    "AbstractValue": ("pysymex.analysis.abstract.domains", "AbstractValue"),
    "Interval": ("pysymex.analysis.abstract.domains", "Interval"),
    "Null": ("pysymex.analysis.abstract.domains", "Null"),
    "Parity": ("pysymex.analysis.abstract.domains", "Parity"),
    "ProductDomain": ("pysymex.analysis.abstract.domains", "ProductDomain"),
    "Sign": ("pysymex.analysis.abstract.domains", "Sign"),
    "AbstractAnalyzer": ("pysymex.analysis.abstract.interpreter", "AbstractAnalyzer"),
    "ArithmeticIssue": ("pysymex.analysis.arithmetic_safety", "ArithmeticIssue"),
    "ArithmeticIssueKind": ("pysymex.analysis.arithmetic_safety", "ArithmeticIssueKind"),
    "ArithmeticMode": ("pysymex.analysis.arithmetic_safety", "ArithmeticMode"),
    "ArithmeticSafetyAnalyzer": ("pysymex.analysis.arithmetic_safety", "ArithmeticSafetyAnalyzer"),
    "IntegerBounds": ("pysymex.analysis.arithmetic_safety", "IntegerBounds"),
    "IntegerWidth": ("pysymex.analysis.arithmetic_safety", "IntegerWidth"),
    "SafeArithmetic": ("pysymex.analysis.arithmetic_safety", "SafeArithmetic"),
    "AssertionAnalysis": ("pysymex.analysis.assertion_context", "AssertionAnalysis"),
    "ContextType": ("pysymex.analysis.assertion_context", "ContextType"),
    "analyze_assertion": ("pysymex.analysis.assertion_context", "analyze_assertion"),
    "analyze_function_name": ("pysymex.analysis.assertion_context", "analyze_function_name"),
    "analyze_source_context": ("pysymex.analysis.assertion_context", "analyze_source_context"),
    "is_intentional_assertion": ("pysymex.analysis.assertion_context", "is_intentional_assertion"),
    "BoundsChecker": ("pysymex.analysis.bounds_checking", "BoundsChecker"),
    "BoundsIssue": ("pysymex.analysis.bounds_checking", "BoundsIssue"),
    "BoundsIssueKind": ("pysymex.analysis.bounds_checking", "BoundsIssueKind"),
    "ListBoundsChecker": ("pysymex.analysis.bounds_checking", "ListBoundsChecker"),
    "NumpyBoundsChecker": ("pysymex.analysis.bounds_checking", "NumpyBoundsChecker"),
    "SymbolicArray": ("pysymex.analysis.bounds_checking", "SymbolicArray"),
    "SymbolicBuffer": ("pysymex.analysis.bounds_checking", "SymbolicBuffer"),
    "AnalysisResult": ("pysymex.analysis.cache", "AnalysisResult"),
    "AnalysisTask": ("pysymex.analysis.cache", "AnalysisTask"),
    "CacheKey": ("pysymex.analysis.cache", "CacheKey"),
    "CacheKeyType": ("pysymex.analysis.cache", "CacheKeyType"),
    "SharedAnalysisCache": ("pysymex.analysis.cache", "SharedAnalysisCache"),
    "global_cache": ("pysymex.analysis.cache", "global_cache"),
    "ComplexityMetrics": ("pysymex.analysis.complexity", "ComplexityMetrics"),
    "ComplexityAnalysis": ("pysymex.analysis.complexity", "ComplexityAnalysis"),
    "analyze_complexity": ("pysymex.analysis.complexity", "analyze_complexity"),
    "estimate_complexity": ("pysymex.analysis.complexity", "estimate_complexity"),
    "tune_execution_config": ("pysymex.analysis.complexity", "tune_execution_config"),
    "BranchDecision": ("pysymex.analysis.control.cfg", "BranchDecision"),
    "CFG": ("pysymex.analysis.control.cfg", "CFG"),
    "CFGNode": ("pysymex.analysis.control.cfg", "CFGNode"),
    "CFGNodeKind": ("pysymex.analysis.control.cfg", "CFGNodeKind"),
    "ControlDependency": ("pysymex.analysis.control.dependencies", "ControlDependency"),
    "ControlFlowAnalyzer": ("pysymex.analysis.control.dependencies", "ControlFlowAnalyzer"),
    "DominanceTree": ("pysymex.analysis.control.dependencies", "DominanceTree"),
    "PostDominanceTree": ("pysymex.analysis.control.dependencies", "PostDominanceTree"),
    "DataFlowAnalyzer": ("pysymex.analysis.dataflow.core", "DataFlowAnalyzer"),
    "DataFlowGraph": ("pysymex.analysis.dataflow.core", "DataFlowGraph"),
    "Definition": ("pysymex.analysis.dataflow.core", "Definition"),
    "Use": ("pysymex.analysis.dataflow.core", "Use"),
    "reaching_definitions": ("pysymex.analysis.dataflow.core", "reaching_definitions"),
    "DeadCodeAnalyzer": ("pysymex.analysis.dead_code.core", "DeadCodeAnalyzer"),
    "DeadCodeIssue": ("pysymex.analysis.dead_code.core", "DeadCodeIssue"),
    "LivenessAnalysis": ("pysymex.analysis.dead_code.core", "LivenessAnalysis"),
    "ExceptionAnalyzer": ("pysymex.analysis.exceptions.analyzer", "ExceptionAnalyzer"),
    "ExceptionHandler": ("pysymex.analysis.exceptions.analyzer", "ExceptionHandler"),
    "ExceptionIssue": ("pysymex.analysis.exceptions.analyzer", "ExceptionIssue"),
    "ExceptionPath": ("pysymex.analysis.exceptions.analyzer", "ExceptionPath"),
    "ExceptionType": ("pysymex.analysis.exceptions.analyzer", "ExceptionType"),
    "PropagationGraph": ("pysymex.analysis.exceptions.analyzer", "PropagationGraph"),
    "infer_caught_at": ("pysymex.analysis.exceptions.analyzer", "infer_caught_at"),
    "AbstractDetector": ("pysymex.analysis.integration.detector", "AbstractDetector"),
    "DetectorBridge": ("pysymex.analysis.integration.detector", "DetectorBridge"),
    "HybridAnalysis": ("pysymex.analysis.integration.detector", "HybridAnalysis"),
    "IntegrationAnalyzer": ("pysymex.analysis.integration.detector", "IntegrationAnalyzer"),
    "SymbolicSummary": ("pysymex.analysis.integration.detector", "SymbolicSummary"),
    "LoopAnalysis": ("pysymex.analysis.loops.core", "LoopAnalysis"),
    "LoopDetector": ("pysymex.analysis.loops.core", "LoopDetector"),
    "LoopInfo": ("pysymex.analysis.loops.core", "LoopInfo"),
    "LoopIssue": ("pysymex.analysis.loops.core", "LoopIssue"),
    "LoopInvariant": ("pysymex.analysis.loops.invariants", "LoopInvariant"),
    "InvariantInferrer": ("pysymex.analysis.loops.invariants", "InvariantInferrer"),
    "LoopWidening": ("pysymex.analysis.loops.widening", "LoopWidening"),
    "WideningMode": ("pysymex.analysis.loops.widening", "WideningMode"),
    "PatternMatcher": ("pysymex.analysis.patterns.core", "PatternMatcher"),
    "SecurityPattern": ("pysymex.analysis.patterns.core", "SecurityPattern"),
    "TaintPattern": ("pysymex.analysis.patterns.core", "TaintPattern"),
    "PropertyChecker": ("pysymex.analysis.properties.core", "PropertyChecker"),
    "SafetyProperty": ("pysymex.analysis.properties.core", "SafetyProperty"),
    "LivenessProperty": ("pysymex.analysis.properties.core", "LivenessProperty"),
    "TemporalLogic": ("pysymex.analysis.properties.core", "TemporalLogic"),
    "ResourceAnalyzer": ("pysymex.analysis.resources.analysis", "ResourceAnalyzer"),
    "ResourceIssue": ("pysymex.analysis.resources.analysis", "ResourceIssue"),
    "ResourceKind": ("pysymex.analysis.resources.analysis", "ResourceKind"),
    "ResourceLeakDetector": ("pysymex.analysis.resources.analysis", "ResourceLeakDetector"),
    "LifecycleAnalyzer": ("pysymex.analysis.resources.lifecycle", "LifecycleAnalyzer"),
    "StateTransition": ("pysymex.analysis.resources.lifecycle", "StateTransition"),
    "SMTSlicer": ("pysymex.analysis.solver.slicing", "SMTSlicer"),
    "ConstraintSlicer": ("pysymex.analysis.solver.slicing", "ConstraintSlicer"),
    "SlicingMode": ("pysymex.analysis.solver.slicing", "SlicingMode"),
    "VariableImpact": ("pysymex.analysis.solver.slicing", "VariableImpact"),
    "FunctionSummary": ("pysymex.analysis.summaries.core", "FunctionSummary"),
    "SummaryDatabase": ("pysymex.analysis.summaries.core", "SummaryDatabase"),
    "SummaryInferrer": ("pysymex.analysis.summaries.core", "SummaryInferrer"),
    "TypeConstraintAnalyzer": (
        "pysymex.analysis.type_constraints.checker",
        "TypeConstraintAnalyzer",
    ),
    "TypeIssue": ("pysymex.analysis.type_constraints.checker", "TypeIssue"),
    "ConstraintCollector": ("pysymex.analysis.type_constraints.checker", "ConstraintCollector"),
    "TypeInferrer": ("pysymex.analysis.type_inference.core", "TypeInferrer"),
    "TypeVariable": ("pysymex.analysis.type_inference.core", "TypeVariable"),
    "UnificationError": ("pysymex.analysis.type_inference.core", "UnificationError"),
}


def __getattr__(name: str) -> object:
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    return lazy_dir(_EXPORTS, globals())
