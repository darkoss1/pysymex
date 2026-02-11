"""PySpectre: A symbolic execution engine for Python bytecode.
PySpectre analyzes Python functions by executing them symbolically using
the Z3 theorem prover, detecting potential runtime errors like:
- Division by zero
- Assertion failures
- Index out of bounds
- Key errors
- Type errors
Example:
    >>> from pyspectre import analyze
    >>> def risky(x, y):
    ...     return x // y
    >>> result = analyze(risky)
    >>> for issue in result.issues:
    ...     print(issue.format())
"""

from importlib.metadata import version, PackageNotFoundError

from pyspectre.analysis.detectors import Issue, IssueKind
from pyspectre.analysis.z3_prover import (
    Z3_AVAILABLE,
    BugType,
    CallGraph,
    CrashCondition,
    FunctionSummary,
    Severity,
    TaintSource,
    VerificationResult,
    Z3Engine,
    Z3Prover,
    is_z3_available,
    verify_code,
    verify_function,
)
from pyspectre.analysis.z3_prover import (
    verify_directory as z3_verify_directory,
)
from pyspectre.analysis.z3_prover import (
    verify_file as z3_verify_file,
)
from pyspectre.api import (
    analyze,
    analyze_code,
    analyze_file,
    check_assertions,
    check_division_by_zero,
    check_index_errors,
    format_issues,
    quick_check,
)
from pyspectre.core.solver import ShadowSolver
from pyspectre.core.state import VMState
from pyspectre.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pyspectre.execution.executor import (
    ExecutionConfig,
    ExecutionResult,
    SymbolicExecutor,
)
from pyspectre.execution.verified_executor import (
    VerifiedExecutionConfig,
    VerifiedExecutionResult,
    VerifiedExecutor,
    check_arithmetic,
    check_contracts,
    prove_termination,
    verify,
)
from pyspectre.reporting.formatters import format_result

from pyspectre.config import PySpectreConfig, load_config
from pyspectre.logging import LogLevel, configure_logging, get_logger
from pyspectre.scanner import scan_directory, scan_file

try:
    __version__ = version("pyspectre")
except PackageNotFoundError:
    __version__ = "0.3.0a0"

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
    "PySpectreConfig",
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
