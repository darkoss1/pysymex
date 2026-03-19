"""Main symbolic executor for PySyMex — slim hub with re-exports.

Extraction modules:
  - executor_types: ExecutionConfig, ExecutionResult, BRANCH_OPCODES
  - executor_core: SymbolicExecutor class
"""

from __future__ import annotations

import types
from collections.abc import Callable

from pysymex.analysis.detectors import Issue
from pysymex.execution.executor_core import SymbolicExecutor as SymbolicExecutor
from pysymex.execution.executor_types import BRANCH_OPCODES as BRANCH_OPCODES
from pysymex.execution.executor_types import ExecutionConfig as ExecutionConfig
from pysymex.execution.executor_types import ExecutionResult as ExecutionResult

import pysymex.execution.opcodes as _opcodes  # noqa: F401  # pyright: ignore[reportUnusedImport]

__all__ = [
    "ExecutionConfig",
    "ExecutionResult",
    "SymbolicExecutor",
    "analyze",
    "analyze_code",
    "quick_check",
]


def analyze(
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
    **config_kwargs: object,
) -> ExecutionResult:
    """
    Analyze a function for potential issues.
    Args:
        func: Function to analyze
        symbolic_args: Mapping of parameter names to types
        **config_kwargs: Additional configuration options
    Returns:
        ExecutionResult with issues and statistics
    Example:
        >>> def divide(x, y):
        ...     return x / y
        >>> result = analyze(divide, {"x": "int", "y": "int"})
        >>> print(result.issues)  # Division by zero issue
    """
    config = ExecutionConfig(**config_kwargs)
    executor = SymbolicExecutor(config)
    return executor.execute_function(func, symbolic_args)


def analyze_code(
    code: str | types.CodeType,
    symbolic_vars: dict[str, str] | None = None,
    **config_kwargs: object,
) -> ExecutionResult:
    """
    Analyze code for potential issues.
    Args:
        code: Source code string or code object
        symbolic_vars: Mapping of variable names to types
        **config_kwargs: Additional configuration options
    Returns:
        ExecutionResult with issues and statistics
    """
    if isinstance(code, str):
        compiled = compile(code, "<string>", "exec")
        code = compiled
    config = ExecutionConfig(**config_kwargs)
    executor = SymbolicExecutor(config)
    return executor.execute_code(code, symbolic_vars)


def quick_check(func: Callable[..., object]) -> list[Issue]:
    """
    Quick check a function for common issues.
    Args:
        func: Function to check
    Returns:
        List of issues found
    Example:
        >>> issues = quick_check(lambda x: 1/x)
        >>> print(issues[0].kind)  # IssueKind.DIVISION_BY_ZERO
    """
    result = analyze(func, max_paths=100, max_iterations=1000)
    return result.issues
