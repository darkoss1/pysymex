"""Analysis module for bug detection and path exploration.
This module provides:
- Bug detectors (division by zero, assertions, index errors, etc.)
- Enhanced detectors (null dereference, overflow, type errors) [v1.1]
- Advanced detectors (command injection, SQL injection, etc.)
- Inter-procedural analysis (call graphs, function summaries)
- Taint analysis (track untrusted data flows)
- Concolic execution (concrete + symbolic hybrid)
- Loop analysis (detection, bounds, invariants)
- Path management and exploration strategies
- Abstract interpretation (interval, sign, parity domains)
- Caching and parallel analysis
NEW (v2.0):
- Type inference system with pattern recognition
- Flow-sensitive analysis with CFG building
- Pattern handlers for safe Python idioms
- Enhanced detectors with improved precision
- Function/method models for built-ins
- Security-focused taint analysis
- Abstract interpretation with multiple domains
- Scanner integration with unified pipeline
- Type stub support (.pyi files)
- Symbolic execution engine with Z3
- Cross-function analysis (call graphs, effects)
- Value range analysis
"""

from pyspectre.analysis.abstract_domains import (
    AbstractInterpreter,
    AbstractState,
    AbstractValue,
    Interval,
    Null,
    Parity,
    ProductDomain,
    Sign,
)
from pyspectre.analysis.abstract_interpreter import AbstractAnalyzer
from pyspectre.analysis.advanced_detectors import (
    CommandInjectionDetector,
    InfiniteLoopDetector,
    IntegerOverflowDetector,
    NullDereferenceDetector,
    PathTraversalDetector,
    SQLInjectionDetector,
    UnreachableCodeDetector,
    UseAfterFreeDetector,
    register_advanced_detectors,
)
from pyspectre.analysis.arithmetic_safety import (
    ArithmeticIssue,
    ArithmeticIssueKind,
    ArithmeticMode,
    ArithmeticSafetyAnalyzer,
    IntegerBounds,
    IntegerWidth,
    SafeArithmetic,
)
from pyspectre.analysis.bounds_checking import (
    BoundsChecker,
    BoundsIssue,
    BoundsIssueKind,
    ListBoundsChecker,
    NumpyBoundsChecker,
    SymbolicArray,
    SymbolicBuffer,
)
from pyspectre.analysis.cache import (
    AnalysisResult,
    AnalysisTask,
    CachedAnalysis,
    CacheKey,
    CacheKeyType,
    FileCache,
    InvalidationRule,
    InvalidationStrategy,
    LRUCache,
    ParallelAnalyzer,
    PersistentCache,
    ProgressReporter,
    SmartInvalidator,
    TieredCache,
    hash_bytecode,
    hash_dict,
    hash_file,
    hash_function,
)
from pyspectre.analysis.callgraph import (
    CallGraph as CG,
)
from pyspectre.analysis.callgraph import (
    CallGraphBuilder,
    CallGraphEdge,
    CallGraphNode,
)
from pyspectre.analysis.concolic import (
    BranchRecord,
    ConcolicExecutor,
    ConcolicResult,
    ConcreteInput,
    ExecutionTrace,
    GenerationalSearch,
)
from pyspectre.analysis.concurrency import (
    ConcurrencyAnalyzer,
    ConcurrencyIssue,
    ConcurrencyIssueKind,
    HappensBeforeGraph,
    LockOrderChecker,
    MemoryOperation,
    MemoryOrder,
    OperationKind,
    Thread,
    ThreadSafetyChecker,
    ThreadState,
)
from pyspectre.analysis.contracts import (
    Contract,
    ContractAnalyzer,
    ContractCompiler,
    ContractKind,
    ContractVerifier,
    ContractViolation,
    FunctionContract,
    VerificationReport,
    VerificationResult,
    ensures,
    get_function_contract,
    invariant,
    loop_invariant,
    requires,
)
from pyspectre.analysis.cross_function import CrossFunctionAnalyzer
from pyspectre.analysis.dead_code import DeadCodeAnalyzer
from pyspectre.analysis.detectors import (
    AssertionErrorDetector,
    AttributeErrorDetector,
    Detector,
    DetectorRegistry,
    DivisionByZeroDetector,
    FormatStringDetector,
    IndexErrorDetector,
    Issue,
    IssueKind,
    KeyErrorDetector,
    OverflowDetector,
    ResourceLeakDetector,
    TypeErrorDetector,
)
from pyspectre.analysis.enhanced_detectors import EnhancedAnalyzer
from pyspectre.analysis.enhanced_scanner import EnhancedScanner, ScannerConfig
from pyspectre.analysis.exception_analysis import ExceptionAnalyzer
from pyspectre.analysis.flow_sensitive import FlowSensitiveAnalyzer
from pyspectre.analysis.function_models import FunctionSummarizer
from pyspectre.analysis.interprocedural import (
    CallContext,
    CallGraph,
    CallSite,
    CallType,
    ContextSensitiveAnalyzer,
    FunctionSummary,
    InterproceduralAnalyzer,
)
from pyspectre.analysis.loops import (
    InductionVariable,
    LoopBound,
    LoopBoundInference,
    LoopDetector,
    LoopInfo,
    LoopInvariantGenerator,
    LoopType,
    LoopWidening,
)
from pyspectre.analysis.pattern_handlers import PatternAnalyzer
from pyspectre.analysis.properties import (
    ArithmeticVerifier,
    EquivalenceChecker,
    ProofStatus,
    PropertyKind,
    PropertyProof,
    PropertyProver,
    PropertySpec,
)
from pyspectre.analysis.range_analysis import ValueRangeChecker
from pyspectre.analysis.resource_analysis import ResourceAnalyzer
from pyspectre.analysis.resource_lifecycle import (
    FileResourceChecker,
    LockResourceChecker,
    ResourceIssue,
    ResourceIssueKind,
    ResourceKind,
    ResourceLifecycleChecker,
    ResourceState,
    ResourceStateMachine,
    StateTransition,
    TrackedResource,
)
from pyspectre.analysis.scanner_integration import AnalysisPipeline
from pyspectre.analysis.string_analysis import StringAnalyzer
from pyspectre.analysis.summaries import (
    CallSite as SummaryCallSite,
)
from pyspectre.analysis.summaries import (
    ExceptionInfo,
    ModifiedVariable,
    ParameterInfo,
    ReadVariable,
    SummaryAnalyzer,
    SummaryBuilder,
    SummaryRegistry,
)
from pyspectre.analysis.summaries import (
    FunctionSummary as FuncSummary,
)
from pyspectre.analysis.symbolic_engine import SymbolicExecutor
from pyspectre.analysis.taint import (
    TaintAnalyzer,
    TaintedValue,
    TaintFlow,
    TaintLabel,
    TaintPolicy,
    TaintSink,
    TaintSource,
    TaintTracker,
)
from pyspectre.analysis.taint_analysis import TaintChecker
from pyspectre.analysis.type_constraints import (
    Protocol,
    ProtocolChecker,
    SymbolicType,
    TypeConstraintChecker,
    TypeEncoder,
    TypeIssue,
    TypeIssueKind,
    TypeKind,
    Variance,
)
from pyspectre.analysis.type_inference import TypeAnalyzer
from pyspectre.analysis.type_stubs import StubRepository
from pyspectre.analysis.fp_filter import (
    AssertionContext,
    Confidence,
    FilterResult,
    calculate_confidence,
    deduplicate_issues,
    detect_assertion_context,
    filter_issue,
    filter_issues,
    is_type_checking_block_issue,
    is_typing_false_positive,
)
from pyspectre.analysis.assertion_context import (
    AssertionAnalysis,
    ContextType,
    analyze_assertion,
    analyze_function_name,
    analyze_source_context,
    is_intentional_assertion,
)

__all__ = [
    "Issue",
    "IssueKind",
    "Detector",
    "DivisionByZeroDetector",
    "AssertionErrorDetector",
    "IndexErrorDetector",
    "KeyErrorDetector",
    "TypeErrorDetector",
    "AttributeErrorDetector",
    "OverflowDetector",
    "DetectorRegistry",
    "NullDereferenceDetector",
    "InfiniteLoopDetector",
    "ResourceLeakDetector",
    "UseAfterFreeDetector",
    "IntegerOverflowDetector",
    "FormatStringDetector",
    "CommandInjectionDetector",
    "PathTraversalDetector",
    "SQLInjectionDetector",
    "UnreachableCodeDetector",
    "register_advanced_detectors",
    "CallType",
    "CallSite",
    "FunctionSummary",
    "CallGraph",
    "InterproceduralAnalyzer",
    "CallContext",
    "ContextSensitiveAnalyzer",
    "TaintSource",
    "TaintSink",
    "TaintLabel",
    "TaintedValue",
    "TaintFlow",
    "TaintPolicy",
    "TaintTracker",
    "TaintAnalyzer",
    "ConcreteInput",
    "BranchRecord",
    "ExecutionTrace",
    "ConcolicExecutor",
    "ConcolicResult",
    "GenerationalSearch",
    "LoopType",
    "LoopBound",
    "LoopInfo",
    "InductionVariable",
    "LoopDetector",
    "LoopBoundInference",
    "LoopInvariantGenerator",
    "LoopWidening",
    "ContractKind",
    "VerificationResult",
    "ContractViolation",
    "Contract",
    "FunctionContract",
    "ContractCompiler",
    "ContractVerifier",
    "requires",
    "ensures",
    "invariant",
    "loop_invariant",
    "get_function_contract",
    "VerificationReport",
    "ContractAnalyzer",
    "PropertyKind",
    "ProofStatus",
    "PropertySpec",
    "PropertyProof",
    "PropertyProver",
    "ArithmeticVerifier",
    "EquivalenceChecker",
    "AbstractValue",
    "Interval",
    "Sign",
    "Parity",
    "Null",
    "ProductDomain",
    "AbstractState",
    "AbstractInterpreter",
    "ParameterInfo",
    "ModifiedVariable",
    "ReadVariable",
    "SummaryCallSite",
    "ExceptionInfo",
    "FuncSummary",
    "SummaryBuilder",
    "SummaryRegistry",
    "SummaryAnalyzer",
    "CallGraphNode",
    "CallGraphEdge",
    "CG",
    "CallGraphBuilder",
    "CacheKeyType",
    "CacheKey",
    "hash_bytecode",
    "hash_function",
    "hash_file",
    "hash_dict",
    "LRUCache",
    "PersistentCache",
    "TieredCache",
    "AnalysisTask",
    "AnalysisResult",
    "ProgressReporter",
    "ParallelAnalyzer",
    "CachedAnalysis",
    "InvalidationStrategy",
    "InvalidationRule",
    "SmartInvalidator",
    "FileCache",
    "ArithmeticMode",
    "IntegerWidth",
    "ArithmeticIssueKind",
    "IntegerBounds",
    "ArithmeticIssue",
    "ArithmeticSafetyAnalyzer",
    "SafeArithmetic",
    "BoundsIssueKind",
    "BoundsIssue",
    "SymbolicArray",
    "SymbolicBuffer",
    "BoundsChecker",
    "ListBoundsChecker",
    "NumpyBoundsChecker",
    "TypeKind",
    "Variance",
    "TypeIssueKind",
    "SymbolicType",
    "TypeIssue",
    "Protocol",
    "TypeEncoder",
    "TypeConstraintChecker",
    "ProtocolChecker",
    "ResourceKind",
    "ResourceState",
    "ResourceIssueKind",
    "ResourceIssue",
    "StateTransition",
    "TrackedResource",
    "ResourceStateMachine",
    "ResourceLifecycleChecker",
    "FileResourceChecker",
    "LockResourceChecker",
    "MemoryOrder",
    "OperationKind",
    "ThreadState",
    "ConcurrencyIssueKind",
    "ConcurrencyIssue",
    "MemoryOperation",
    "Thread",
    "HappensBeforeGraph",
    "ConcurrencyAnalyzer",
    "ThreadSafetyChecker",
    "LockOrderChecker",
    "TypeAnalyzer",
    "FlowSensitiveAnalyzer",
    "PatternAnalyzer",
    "EnhancedAnalyzer",
    "FunctionSummarizer",
    "TaintChecker",
    "AbstractAnalyzer",
    "AnalysisPipeline",
    "StubRepository",
    "SymbolicExecutor",
    "CrossFunctionAnalyzer",
    "ValueRangeChecker",
    "DeadCodeAnalyzer",
    "ResourceAnalyzer",
    "ExceptionAnalyzer",
    "StringAnalyzer",
    "EnhancedScanner",
    "ScannerConfig",
    "Confidence",
    "AssertionContext",
    "FilterResult",
    "is_typing_false_positive",
    "is_type_checking_block_issue",
    "filter_issue",
    "filter_issues",
    "deduplicate_issues",
    "calculate_confidence",
    "detect_assertion_context",
    "ContextType",
    "AssertionAnalysis",
    "analyze_assertion",
    "analyze_function_name",
    "analyze_source_context",
    "is_intentional_assertion",
]
