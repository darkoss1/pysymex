"""Execution module for pysymex."""

from pysymex.execution.async_executor import (
    AsyncSymbolicExecutor,
    SymbolicEventLoop,
    analyze_async,
)

from pysymex.execution.concurrency_executor import (
    ConcurrentSymbolicExecutor,
    analyze_concurrent,
)

from pysymex.execution.dispatcher import (
    OpcodeDispatcher,
    OpcodeResult,
    opcode_handler,
)

from pysymex.execution.executor import (
    ExecutionConfig,
    ExecutionResult,
    SymbolicExecutor,
    analyze,
    analyze_code,
    quick_check,
)

from pysymex.execution.verified_executor import (
    ArithmeticIssue,
    ContractIssue,
    InferredProperty,
    RankingFunction,
    TerminationAnalyzer,
    TerminationProof,
    TerminationStatus,
    VerifiedExecutionConfig,
    VerifiedExecutionResult,
    VerifiedExecutor,
    check_arithmetic,
    check_contracts,
    prove_termination,
    verify,
)

__all__ = [
    "OpcodeDispatcher",
    "OpcodeResult",
    "opcode_handler",
    "SymbolicExecutor",
    "ExecutionConfig",
    "ExecutionResult",
    "analyze",
    "analyze_code",
    "quick_check",
    "VerifiedExecutor",
    "VerifiedExecutionConfig",
    "VerifiedExecutionResult",
    "TerminationStatus",
    "TerminationProof",
    "RankingFunction",
    "TerminationAnalyzer",
    "ContractIssue",
    "ArithmeticIssue",
    "InferredProperty",
    "verify",
    "check_contracts",
    "check_arithmetic",
    "prove_termination",
    "AsyncSymbolicExecutor",
    "SymbolicEventLoop",
    "analyze_async",
    "ConcurrentSymbolicExecutor",
    "analyze_concurrent",
]
