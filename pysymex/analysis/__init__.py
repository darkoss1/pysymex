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

from importlib import import_module
from typing import TYPE_CHECKING

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
    "CachedAnalysis": ("pysymex.analysis.cache", "CachedAnalysis"),
    "FileCache": ("pysymex.analysis.cache", "FileCache"),
    "InvalidationRule": ("pysymex.analysis.cache", "InvalidationRule"),
    "InvalidationStrategy": ("pysymex.analysis.cache", "InvalidationStrategy"),
    "LRUCache": ("pysymex.analysis.cache", "LRUCache"),
    "ParallelAnalyzer": ("pysymex.analysis.cache", "ParallelAnalyzer"),
    "PersistentCache": ("pysymex.analysis.cache", "PersistentCache"),
    "ProgressReporter": ("pysymex.analysis.cache", "ProgressReporter"),
    "SmartInvalidator": ("pysymex.analysis.cache", "SmartInvalidator"),
    "TieredCache": ("pysymex.analysis.cache", "TieredCache"),
    "hash_bytecode": ("pysymex.analysis.cache", "hash_bytecode"),
    "hash_dict": ("pysymex.analysis.cache", "hash_dict"),
    "hash_file": ("pysymex.analysis.cache", "hash_file"),
    "hash_function": ("pysymex.analysis.cache", "hash_function"),
    "CG": ("pysymex.analysis.interprocedural.callgraph", "CallGraph"),
    "CallGraphBuilder": ("pysymex.analysis.interprocedural.callgraph", "CallGraphBuilder"),
    "CallGraphEdge": ("pysymex.analysis.interprocedural.callgraph", "CallGraphEdge"),
    "CallGraphNode": ("pysymex.analysis.interprocedural.callgraph", "CallGraphNode"),
    "BranchRecord": ("pysymex.analysis.concolic", "BranchRecord"),
    "ConcolicExecutor": ("pysymex.analysis.concolic", "ConcolicExecutor"),
    "ConcolicResult": ("pysymex.analysis.concolic", "ConcolicResult"),
    "ConcreteInput": ("pysymex.analysis.concolic", "ConcreteInput"),
    "ExecutionTrace": ("pysymex.analysis.concolic", "ExecutionTrace"),
    "GenerationalSearch": ("pysymex.analysis.concolic", "GenerationalSearch"),
    "ConcurrencyAnalyzer": ("pysymex.analysis.concurrency", "ConcurrencyAnalyzer"),
    "ConcurrencyIssue": ("pysymex.analysis.concurrency", "ConcurrencyIssue"),
    "ConcurrencyIssueKind": ("pysymex.analysis.concurrency", "ConcurrencyIssueKind"),
    "HappensBeforeGraph": ("pysymex.analysis.concurrency", "HappensBeforeGraph"),
    "LockOrderChecker": ("pysymex.analysis.concurrency", "LockOrderChecker"),
    "MemoryOperation": ("pysymex.analysis.concurrency", "MemoryOperation"),
    "MemoryOrder": ("pysymex.analysis.concurrency", "MemoryOrder"),
    "OperationKind": ("pysymex.analysis.concurrency", "OperationKind"),
    "Thread": ("pysymex.analysis.concurrency", "Thread"),
    "ThreadSafetyChecker": ("pysymex.analysis.concurrency", "ThreadSafetyChecker"),
    "ThreadState": ("pysymex.analysis.concurrency", "ThreadState"),
    "Contract": ("pysymex.analysis.contracts", "Contract"),
    "ContractCompiler": ("pysymex.analysis.contracts", "ContractCompiler"),
    "ContractKind": ("pysymex.analysis.contracts", "ContractKind"),
    "ContractVerifier": ("pysymex.analysis.contracts", "ContractVerifier"),
    "ContractViolation": ("pysymex.analysis.contracts", "ContractViolation"),
    "FunctionContract": ("pysymex.analysis.contracts", "FunctionContract"),
    "VerificationReport": ("pysymex.analysis.contracts", "VerificationReport"),
    "VerificationResult": ("pysymex.analysis.contracts", "VerificationResult"),
    "ensures": ("pysymex.analysis.contracts", "ensures"),
    "get_function_contract": ("pysymex.analysis.contracts", "get_function_contract"),
    "invariant": ("pysymex.analysis.contracts", "invariant"),
    "loop_invariant": ("pysymex.analysis.contracts", "loop_invariant"),
    "requires": ("pysymex.analysis.contracts", "requires"),
    "CrossFunctionAnalyzer": ("pysymex.analysis.cross_function", "CrossFunctionAnalyzer"),
    "DeadCodeAnalyzer": ("pysymex.analysis.dead_code", "DeadCodeAnalyzer"),
    "AssertionErrorDetector": ("pysymex.analysis.detectors.base", "AssertionErrorDetector"),
    "AttributeErrorDetector": ("pysymex.analysis.detectors.base", "AttributeErrorDetector"),
    "Detector": ("pysymex.analysis.detectors.base", "Detector"),
    "DetectorRegistry": ("pysymex.analysis.detectors.base", "DetectorRegistry"),
    "DivisionByZeroDetector": ("pysymex.analysis.detectors.base", "DivisionByZeroDetector"),
    "FormatStringDetector": ("pysymex.analysis.detectors.base", "FormatStringDetector"),
    "IndexErrorDetector": ("pysymex.analysis.detectors.base", "IndexErrorDetector"),
    "Issue": ("pysymex.analysis.detectors.base", "Issue"),
    "IssueKind": ("pysymex.analysis.detectors.base", "IssueKind"),
    "KeyErrorDetector": ("pysymex.analysis.detectors.base", "KeyErrorDetector"),
    "OverflowDetector": ("pysymex.analysis.detectors.base", "OverflowDetector"),
    "ResourceLeakDetector": ("pysymex.analysis.detectors.base", "ResourceLeakDetector"),
    "TypeErrorDetector": ("pysymex.analysis.detectors.base", "TypeErrorDetector"),
    "StaticAnalyzer": ("pysymex.analysis.detectors.static", "StaticAnalyzer"),
    "CommandInjectionDetector": (
        "pysymex.analysis.detectors.specialized",
        "CommandInjectionDetector",
    ),
    "InfiniteLoopDetector": ("pysymex.analysis.detectors.specialized", "InfiniteLoopDetector"),
    "IntegerOverflowDetector": (
        "pysymex.analysis.detectors.specialized",
        "IntegerOverflowDetector",
    ),
    "NullDereferenceDetector": (
        "pysymex.analysis.detectors.specialized",
        "NullDereferenceDetector",
    ),
    "PathTraversalDetector": ("pysymex.analysis.detectors.specialized", "PathTraversalDetector"),
    "SQLInjectionDetector": ("pysymex.analysis.detectors.specialized", "SQLInjectionDetector"),
    "UnreachableCodeDetector": (
        "pysymex.analysis.detectors.specialized",
        "UnreachableCodeDetector",
    ),
    "UseAfterFreeDetector": ("pysymex.analysis.detectors.specialized", "UseAfterFreeDetector"),
    "Scanner": ("pysymex.analysis.pipeline", "Scanner"),
    "ScannerConfig": ("pysymex.analysis.pipeline", "ScannerConfig"),
    "ExceptionAnalyzer": ("pysymex.analysis.exceptions.analyzer", "ExceptionAnalyzer"),
    "FlowSensitiveAnalyzer": ("pysymex.analysis.specialized.flow", "FlowSensitiveAnalyzer"),
    "AssertionContext": ("pysymex.analysis.detectors.filter", "AssertionContext"),
    "Confidence": ("pysymex.analysis.detectors.filter", "Confidence"),
    "FilterResult": ("pysymex.analysis.detectors.filter", "FilterResult"),
    "calculate_confidence": ("pysymex.analysis.detectors.filter", "calculate_confidence"),
    "deduplicate_issues": ("pysymex.analysis.detectors.filter", "deduplicate_issues"),
    "detect_assertion_context": ("pysymex.analysis.detectors.filter", "detect_assertion_context"),
    "filter_issue": ("pysymex.analysis.detectors.filter", "filter_issue"),
    "filter_issues": ("pysymex.analysis.detectors.filter", "filter_issues"),
    "is_type_checking_block_issue": (
        "pysymex.analysis.detectors.filter",
        "is_type_checking_block_issue",
    ),
    "is_typing_false_positive": ("pysymex.analysis.detectors.filter", "is_typing_false_positive"),
    "FunctionSummarizer": ("pysymex.models.builtins.functions", "FunctionSummarizer"),
    "CallContext": ("pysymex.analysis.interprocedural", "CallContext"),
    "CallGraph": ("pysymex.analysis.interprocedural", "CallGraph"),
    "CallSite": ("pysymex.analysis.interprocedural", "CallSite"),
    "CallType": ("pysymex.analysis.interprocedural", "CallType"),
    "ContextSensitiveAnalyzer": ("pysymex.analysis.interprocedural", "ContextSensitiveAnalyzer"),
    "FunctionSummary": ("pysymex.analysis.interprocedural", "FunctionSummary"),
    "InterproceduralAnalyzer": ("pysymex.analysis.interprocedural", "InterproceduralAnalyzer"),
    "InductionVariable": ("pysymex.analysis.loops", "InductionVariable"),
    "LoopBound": ("pysymex.analysis.loops", "LoopBound"),
    "LoopBoundInference": ("pysymex.analysis.loops", "LoopBoundInference"),
    "LoopDetector": ("pysymex.analysis.loops", "LoopDetector"),
    "LoopInfo": ("pysymex.analysis.loops", "LoopInfo"),
    "LoopInvariantGenerator": ("pysymex.analysis.loops", "LoopInvariantGenerator"),
    "LoopType": ("pysymex.analysis.loops", "LoopType"),
    "LoopWidening": ("pysymex.analysis.loops", "LoopWidening"),
    "PatternAnalyzer": ("pysymex.analysis.patterns", "PatternAnalyzer"),
    "ArithmeticVerifier": ("pysymex.analysis.properties", "ArithmeticVerifier"),
    "EquivalenceChecker": ("pysymex.analysis.properties", "EquivalenceChecker"),
    "ProofStatus": ("pysymex.analysis.properties", "ProofStatus"),
    "PropertyKind": ("pysymex.analysis.properties", "PropertyKind"),
    "PropertyProof": ("pysymex.analysis.properties", "PropertyProof"),
    "PropertyProver": ("pysymex.analysis.properties", "PropertyProver"),
    "PropertySpec": ("pysymex.analysis.properties", "PropertySpec"),
    "ValueRangeChecker": ("pysymex.analysis.specialized.ranges", "ValueRangeChecker"),
    "ResourceAnalyzer": ("pysymex.analysis.resources.analysis", "ResourceAnalyzer"),
    "FileResourceChecker": ("pysymex.analysis.resources.lifecycle", "FileResourceChecker"),
    "LockResourceChecker": ("pysymex.analysis.resources.lifecycle", "LockResourceChecker"),
    "ResourceIssue": ("pysymex.analysis.resources.lifecycle", "ResourceIssue"),
    "ResourceIssueKind": ("pysymex.analysis.resources.lifecycle", "ResourceIssueKind"),
    "ResourceKind": ("pysymex.analysis.resources.lifecycle", "ResourceKind"),
    "ResourceLifecycleChecker": (
        "pysymex.analysis.resources.lifecycle",
        "ResourceLifecycleChecker",
    ),
    "ResourceState": ("pysymex.analysis.resources.lifecycle", "ResourceState"),
    "ResourceStateMachine": ("pysymex.analysis.resources.lifecycle", "ResourceStateMachine"),
    "StateTransition": ("pysymex.analysis.resources.lifecycle", "StateTransition"),
    "TrackedResource": ("pysymex.analysis.resources.lifecycle", "TrackedResource"),
    "AnalysisPipeline": ("pysymex.analysis.integration", "AnalysisPipeline"),
    "StringAnalyzer": ("pysymex.analysis.specialized.strings", "StringAnalyzer"),
    "ExceptionInfo": ("pysymex.analysis.summaries", "ExceptionInfo"),
    "FuncSummary": ("pysymex.analysis.summaries", "FunctionSummary"),
    "ModifiedVariable": ("pysymex.analysis.summaries", "ModifiedVariable"),
    "ParameterInfo": ("pysymex.analysis.summaries", "ParameterInfo"),
    "ReadVariable": ("pysymex.analysis.summaries", "ReadVariable"),
    "SummaryAnalyzer": ("pysymex.analysis.summaries", "SummaryAnalyzer"),
    "SummaryBuilder": ("pysymex.analysis.summaries", "SummaryBuilder"),
    "SummaryCallSite": ("pysymex.analysis.summaries", "CallSite"),
    "SummaryRegistry": ("pysymex.analysis.summaries", "SummaryRegistry"),
    "Protocol": ("pysymex.analysis.type_constraints", "Protocol"),
    "ProtocolChecker": ("pysymex.analysis.type_constraints", "ProtocolChecker"),
    "SymbolicType": ("pysymex.analysis.type_constraints", "SymbolicType"),
    "TypeConstraintChecker": ("pysymex.analysis.type_constraints", "TypeConstraintChecker"),
    "TypeEncoder": ("pysymex.analysis.type_constraints", "TypeEncoder"),
    "TypeIssue": ("pysymex.analysis.type_constraints", "TypeIssue"),
    "TypeIssueKind": ("pysymex.analysis.type_constraints", "TypeIssueKind"),
    "TypeKind": ("pysymex.analysis.type_constraints", "TypeKind"),
    "Variance": ("pysymex.analysis.type_constraints", "Variance"),
    "TypeAnalyzer": ("pysymex.analysis.type_inference", "TypeAnalyzer"),
    "StubRepository": ("pysymex.analysis.type_stubs", "StubRepository"),
}


def __getattr__(name: str) -> object:
    """Lazy-load analysis exports to prevent eager side-effect imports."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
    module_name, attr_name = target
    module = import_module(module_name)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Dir."""
    return sorted(set(_EXPORTS.keys()) | set(globals()))
