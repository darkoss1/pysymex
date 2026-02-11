"""Execution module for PySpectre."""

from pyspectre.execution.dispatcher import (
    OpcodeDispatcher,
    OpcodeResult,
    opcode_handler,
)
from pyspectre.execution.executor import (
    ExecutionConfig,
    ExecutionResult,
    SymbolicExecutor,
    analyze,
    analyze_code,
    quick_check,
)
from pyspectre.execution.verified_executor import (
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
]
