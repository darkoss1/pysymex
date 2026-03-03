"""pysymex package exports (lazy-loaded)."""

from __future__ import annotations


from importlib import import_module

from importlib.metadata import PackageNotFoundError, version

from typing import Any


from pysymex._deps import ensure_z3_ready

try:
    __version__ = version("pysymex")

except PackageNotFoundError:
    __version__ = "0.1.0a0"

try:
    ensure_z3_ready()

    avail = True

    err = None

except RuntimeError as exc:
    avail = False

    err = exc

Z3_AVAILABLE: bool = avail

_Z3_IMPORT_ERROR: RuntimeError | None = err


_EXPORTS: dict[str, tuple[str, str]] = {
    "analyze": ("pysymex.api", "analyze"),
    "analyze_file": ("pysymex.api", "analyze_file"),
    "analyze_code": ("pysymex.api", "analyze_code"),
    "quick_check": ("pysymex.api", "quick_check"),
    "check_division_by_zero": ("pysymex.api", "check_division_by_zero"),
    "check_assertions": ("pysymex.api", "check_assertions"),
    "check_index_errors": ("pysymex.api", "check_index_errors"),
    "format_issues": ("pysymex.api", "format_issues"),
    "SymbolicExecutor": ("pysymex.execution.executor", "SymbolicExecutor"),
    "ExecutionConfig": ("pysymex.execution.executor", "ExecutionConfig"),
    "ExecutionResult": ("pysymex.execution.executor", "ExecutionResult"),
    "SymbolicValue": ("pysymex.core.types", "SymbolicValue"),
    "SymbolicString": ("pysymex.core.types", "SymbolicString"),
    "SymbolicList": ("pysymex.core.types", "SymbolicList"),
    "SymbolicDict": ("pysymex.core.types", "SymbolicDict"),
    "SymbolicNone": ("pysymex.core.types", "SymbolicNone"),
    "VMState": ("pysymex.core.state", "VMState"),
    "ShadowSolver": ("pysymex.core.solver", "ShadowSolver"),
    "Issue": ("pysymex.analysis.detectors", "Issue"),
    "IssueKind": ("pysymex.analysis.detectors", "IssueKind"),
    "PysymexConfig": ("pysymex.config", "PysymexConfig"),
    "load_config": ("pysymex.config", "load_config"),
    "configure_logging": ("pysymex.logging", "configure_logging"),
    "get_logger": ("pysymex.logging", "get_logger"),
    "LogLevel": ("pysymex.logging", "LogLevel"),
    "format_result": ("pysymex.reporting.formatters", "format_result"),
    "VerifiedExecutor": ("pysymex.execution.verified_executor", "VerifiedExecutor"),
    "VerifiedExecutionConfig": (
        "pysymex.execution.verified_executor",
        "VerifiedExecutionConfig",
    ),
    "VerifiedExecutionResult": (
        "pysymex.execution.verified_executor",
        "VerifiedExecutionResult",
    ),
    "verify": ("pysymex.execution.verified_executor", "verify"),
    "check_contracts": ("pysymex.execution.verified_executor", "check_contracts"),
    "check_arithmetic": ("pysymex.execution.verified_executor", "check_arithmetic"),
    "prove_termination": ("pysymex.execution.verified_executor", "prove_termination"),
    "scan_file": ("pysymex.scanner", "scan_file"),
    "scan_directory": ("pysymex.scanner", "scan_directory"),
    "Z3Engine": ("pysymex.analysis.solver", "Z3Engine"),
    "Z3Prover": ("pysymex.analysis.solver", "Z3Engine"),
    "CallGraph": ("pysymex.analysis.solver", "CallGraph"),
    "FunctionSummary": ("pysymex.analysis.solver", "FunctionSummary"),
    "BugType": ("pysymex.analysis.solver", "BugType"),
    "Severity": ("pysymex.analysis.solver", "Severity"),
    "TaintSource": ("pysymex.analysis.solver", "TaintSource"),
    "VerificationResult": ("pysymex.analysis.solver", "VerificationResult"),
    "CrashCondition": ("pysymex.analysis.solver", "CrashCondition"),
    "verify_function": ("pysymex.analysis.solver", "verify_function"),
    "verify_code": ("pysymex.analysis.solver", "verify_code"),
    "z3_verify_file": ("pysymex.analysis.solver", "verify_file"),
    "z3_verify_directory": ("pysymex.analysis.solver", "verify_directory"),
    "is_z3_available": ("pysymex.analysis.solver", "is_z3_available"),
}


_NON_Z3_EXPORTS = {
    "PysymexConfig",
    "load_config",
    "configure_logging",
    "get_logger",
    "LogLevel",
    "Z3_AVAILABLE",
}


__all__ = [
    "analyze",
    "analyze_file",
    "analyze_code",
    "quick_check",
    "check_division_by_zero",
    "check_assertions",
    "check_index_errors",
    "SymbolicExecutor",
    "ExecutionConfig",
    "ExecutionResult",
    "SymbolicValue",
    "SymbolicString",
    "SymbolicList",
    "SymbolicDict",
    "SymbolicNone",
    "VMState",
    "ShadowSolver",
    "Issue",
    "IssueKind",
    "PysymexConfig",
    "load_config",
    "configure_logging",
    "get_logger",
    "LogLevel",
    "format_issues",
    "format_result",
    "VerifiedExecutor",
    "VerifiedExecutionConfig",
    "VerifiedExecutionResult",
    "verify",
    "check_contracts",
    "check_arithmetic",
    "prove_termination",
    "scan_file",
    "scan_directory",
    "Z3Engine",
    "Z3Prover",
    "CallGraph",
    "FunctionSummary",
    "BugType",
    "Severity",
    "TaintSource",
    "VerificationResult",
    "CrashCondition",
    "verify_function",
    "verify_code",
    "z3_verify_file",
    "z3_verify_directory",
    "is_z3_available",
    "Z3_AVAILABLE",
]


def __getattr__(name: str) -> Any:
    """Lazy-load package exports to avoid startup side effects."""

    if name == "Z3_AVAILABLE":
        return Z3_AVAILABLE

    target = _EXPORTS.get(name)

    if target is None:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

    if _Z3_IMPORT_ERROR is not None and name not in _NON_Z3_EXPORTS:
        raise RuntimeError(str(_Z3_IMPORT_ERROR)) from _Z3_IMPORT_ERROR

    module_name, attr_name = target

    module = import_module(module_name)

    value = getattr(module, attr_name)

    globals()[name] = value

    return value


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(globals()))
