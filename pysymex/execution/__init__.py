"""Execution module for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.
"""

from __future__ import annotations

from importlib import import_module

_EXPORTS: dict[str, tuple[str, str]] = {
    "ExecutionContext": ("pysymex.execution.protocols", "ExecutionContext"),
    "OpcodeDispatcher": ("pysymex.execution.dispatcher", "OpcodeDispatcher"),
    "OpcodeResult": ("pysymex.execution.dispatcher", "OpcodeResult"),
    "opcode_handler": ("pysymex.execution.dispatcher", "opcode_handler"),
    "SymbolicExecutor": ("pysymex.execution.executor", "SymbolicExecutor"),
    "ExecutionConfig": ("pysymex.execution.executor", "ExecutionConfig"),
    "ExecutionResult": ("pysymex.execution.executor", "ExecutionResult"),
    "analyze": ("pysymex.execution.executor", "analyze"),
    "analyze_code": ("pysymex.execution.executor", "analyze_code"),
    "quick_check": ("pysymex.execution.executor", "quick_check"),
    "VerifiedExecutor": ("pysymex.execution.verified_executor", "VerifiedExecutor"),
    "VerifiedExecutionConfig": ("pysymex.execution.verified_executor", "VerifiedExecutionConfig"),
    "VerifiedExecutionResult": ("pysymex.execution.verified_executor", "VerifiedExecutionResult"),
    "TerminationStatus": ("pysymex.execution.verified_executor", "TerminationStatus"),
    "TerminationProof": ("pysymex.execution.verified_executor", "TerminationProof"),
    "RankingFunction": ("pysymex.execution.verified_executor", "RankingFunction"),
    "TerminationAnalyzer": ("pysymex.execution.verified_executor", "TerminationAnalyzer"),
    "ContractIssue": ("pysymex.execution.verified_executor", "ContractIssue"),
    "ArithmeticIssue": ("pysymex.execution.verified_executor", "ArithmeticIssue"),
    "InferredProperty": ("pysymex.execution.verified_executor", "InferredProperty"),
    "verify": ("pysymex.execution.verified_executor", "verify"),
    "check_contracts": ("pysymex.execution.verified_executor", "check_contracts"),
    "check_arithmetic": ("pysymex.execution.verified_executor", "check_arithmetic"),
    "prove_termination": ("pysymex.execution.verified_executor", "prove_termination"),
    "AsyncSymbolicExecutor": ("pysymex.execution.async_executor", "AsyncSymbolicExecutor"),
    "SymbolicEventLoop": ("pysymex.execution.async_executor", "SymbolicEventLoop"),
    "analyze_async": ("pysymex.execution.async_executor", "analyze_async"),
    "ConcurrentSymbolicExecutor": (
        "pysymex.execution.concurrency_executor",
        "ConcurrentSymbolicExecutor",
    ),
    "analyze_concurrent": ("pysymex.execution.concurrency_executor", "analyze_concurrent"),
}


def __getattr__(name: str) -> object:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.execution' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return list(_EXPORTS.keys())


__all__: list[str] = [
    "ArithmeticIssue",
    "AsyncSymbolicExecutor",
    "ConcurrentSymbolicExecutor",
    "ContractIssue",
    "ExecutionConfig",
    "ExecutionResult",
    "InferredProperty",
    "OpcodeDispatcher",
    "OpcodeResult",
    "RankingFunction",
    "SymbolicEventLoop",
    "SymbolicExecutor",
    "TerminationAnalyzer",
    "TerminationProof",
    "TerminationStatus",
    "VerifiedExecutionConfig",
    "VerifiedExecutionResult",
    "VerifiedExecutor",
    "analyze",
    "analyze_async",
    "analyze_code",
    "analyze_concurrent",
    "check_arithmetic",
    "check_contracts",
    "opcode_handler",
    "prove_termination",
    "quick_check",
    "verify",
]
