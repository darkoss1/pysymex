"""Public API for PySpectre."""

from __future__ import annotations
from collections.abc import Callable
from pathlib import Path
from typing import Any
from pyspectre.analysis.detectors import Issue, IssueKind
from pyspectre.execution.executor import (
    ExecutionConfig,
    ExecutionResult,
    SymbolicExecutor,
)
from pyspectre.reporting.formatters import format_result
from pyspectre.analysis.enhanced_scanner import (
    EnhancedScanner,
    ScannerConfig,
    EnhancedIssue,
)


def analyze(
    func: Callable,
    symbolic_args: dict[str, str] | None = None,
    *,
    max_paths: int = 1000,
    max_depth: int = 100,
    max_iterations: int = 10000,
    timeout: float = 60.0,
    verbose: bool = False,
    detect_division_by_zero: bool = True,
    detect_assertion_errors: bool = True,
    detect_index_errors: bool = True,
    detect_type_errors: bool = True,
    detect_overflow: bool = False,
) -> ExecutionResult:
    """
    Analyze a Python function for potential runtime errors.
    This is the main entry point for PySpectre. It performs symbolic execution
    on the given function and returns any issues found.
    Args:
        func: The function to analyze
        symbolic_args: Mapping of parameter names to their types.
                      Supported types: "int", "str", "list", "bool"
                      If not provided, all parameters default to "int"
        max_paths: Maximum number of paths to explore
        max_depth: Maximum recursion/call depth
        max_iterations: Maximum total iterations
        timeout: Timeout in seconds
        verbose: Print verbose output during analysis
        detect_division_by_zero: Check for division by zero
        detect_assertion_errors: Check for assertion failures
        detect_index_errors: Check for index out of bounds
        detect_type_errors: Check for type mismatches
        detect_overflow: Check for integer overflow (Python ints don't overflow,
                        but useful for bounded analysis)
    Returns:
        ExecutionResult containing issues, statistics, and coverage info
    Example:
        >>> def divide(x, y):
        ...     return x / y
        ...
        >>> result = analyze(divide, {"x": "int", "y": "int"})
        >>> if result.has_issues():
        ...     for issue in result.issues:
        ...         print(issue.format())
        >>> # Quick check with defaults
        >>> result = analyze(lambda x: 1/x)
        >>> print(len(result.issues))  # 1 - division by zero
    """
    config = ExecutionConfig(
        max_paths=max_paths,
        max_depth=max_depth,
        max_iterations=max_iterations,
        timeout_seconds=timeout,
        verbose=verbose,
        detect_division_by_zero=detect_division_by_zero,
        detect_assertion_errors=detect_assertion_errors,
        detect_index_errors=detect_index_errors,
        detect_type_errors=detect_type_errors,
        detect_overflow=detect_overflow,
    )
    executor = SymbolicExecutor(config)
    return executor.execute_function(func, symbolic_args or {})


def analyze_code(
    code: str,
    symbolic_vars: dict[str, str] | None = None,
    **kwargs,
) -> ExecutionResult:
    """
    Analyze a code snippet for potential runtime errors.
    Args:
        code: Python source code to analyze
        symbolic_vars: Mapping of variable names to types
        **kwargs: Additional configuration options (see analyze())
    Returns:
        ExecutionResult with issues found
    Example:
        >>> code = '''
        ... def foo(x, y):
        ...     return x / y
        ... '''
        >>> result = analyze_code(code, {"x": "int", "y": "int"})
    """
    compiled = compile(code, "<string>", "exec")
    config = ExecutionConfig(**kwargs)
    executor = SymbolicExecutor(config)
    return executor.execute_code(compiled, symbolic_vars or {})


def analyze_file(
    filepath: str | Path,
    function_name: str,
    symbolic_args: dict[str, str] | None = None,
    **kwargs,
) -> ExecutionResult:
    """
    Analyze a function from a Python file.
    Args:
        filepath: Path to the Python file
        function_name: Name of the function to analyze
        symbolic_args: Mapping of parameter names to types
        **kwargs: Additional configuration options
    Returns:
        ExecutionResult with issues found
    Example:
        >>> result = analyze_file("mymodule.py", "process_data", {"data": "list"})

    Security:
        - Path is validated against traversal attacks
        - Function name is sanitized
        - Configuration parameters are bounds-checked
        - Code is executed in a sandboxed namespace
    """
    from pyspectre.security import (
        validate_path,
        validate_config,
        sanitize_function_name,
        create_sandbox_namespace,
        PathTraversalError,
        SecurityError,
    )

    try:
        validated_path = validate_path(
            filepath,
            must_exist=True,
            must_be_file=True,
            allowed_extensions=[".py", ".pyw"],
        )
    except PathTraversalError as e:
        raise ValueError(f"Security error: {e}") from e

    try:
        safe_name = sanitize_function_name(function_name)
    except ValueError as e:
        raise ValueError(f"Invalid function name: {e}") from e

    config_params = validate_config(
        max_paths=kwargs.get("max_paths", 1000),
        max_depth=kwargs.get("max_depth", 100),
        max_iterations=kwargs.get("max_iterations", 10000),
        timeout=kwargs.get("timeout", 60.0),
    )

    source = validated_path.read_text(encoding="utf-8")
    compiled = compile(source, str(validated_path), "exec")

    namespace = create_sandbox_namespace(allow_builtins=True)
    exec(compiled, namespace)  # nosec B102 - sandboxed namespace

    if safe_name not in namespace:
        raise ValueError(f"Function '{safe_name}' not found in {validated_path}")
    func = namespace[safe_name]
    if not callable(func):
        raise ValueError(f"'{safe_name}' is not a callable")

    analyze_kwargs = {
        "max_paths": config_params["max_paths"],
        "max_depth": config_params["max_depth"],
        "max_iterations": config_params["max_iterations"],
        "timeout": config_params["timeout"],
    }
    for key in [
        "verbose",
        "detect_division_by_zero",
        "detect_assertion_errors",
        "detect_index_errors",
        "detect_type_errors",
        "detect_overflow",
    ]:
        if key in kwargs:
            analyze_kwargs[key] = kwargs[key]

    return analyze(func, symbolic_args, **analyze_kwargs)


def quick_check(func: Callable) -> list[Issue]:
    """
    Quick check a function for common issues.
    This is a convenience function for simple cases where you just want
    to know if there are any potential issues.
    Args:
        func: Function to check
    Returns:
        List of issues found (empty if none)
    Example:
        >>> issues = quick_check(lambda x: 1/x)
        >>> if issues:
        ...     print(f"Found {len(issues)} issues")
    """
    result = analyze(func, max_paths=100, max_iterations=500)
    return result.issues


def check_division_by_zero(func: Callable) -> list[Issue]:
    """
    Check specifically for division by zero issues.
    Args:
        func: Function to check
    Returns:
        List of division by zero issues
    """
    result = analyze(
        func,
        detect_division_by_zero=True,
        detect_assertion_errors=False,
        detect_index_errors=False,
        detect_type_errors=False,
    )
    return result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)


def check_assertions(func: Callable) -> list[Issue]:
    """
    Check specifically for assertion errors.
    Args:
        func: Function to check
    Returns:
        List of assertion error issues
    """
    result = analyze(
        func,
        detect_division_by_zero=False,
        detect_assertion_errors=True,
        detect_index_errors=False,
        detect_type_errors=False,
    )
    return result.get_issues_by_kind(IssueKind.ASSERTION_ERROR)


def check_index_errors(func: Callable) -> list[Issue]:
    """
    Check specifically for index out of bounds errors.
    Args:
        func: Function to check
    Returns:
        List of index error issues
    """
    result = analyze(
        func,
        detect_division_by_zero=False,
        detect_assertion_errors=False,
        detect_index_errors=True,
        detect_type_errors=False,
    )
    return result.get_issues_by_kind(IssueKind.INDEX_ERROR)


def format_issues(
    issues: list[Issue],
    format_type: str = "text",
) -> str:
    """
    Format a list of issues for display.
    Args:
        issues: List of issues to format
        format_type: Output format ("text", "json", "markdown")
    Returns:
        Formatted string
    """
    lines = []
    for i, issue in enumerate(issues, 1):
        if format_type == "json":
            import json

            lines.append(json.dumps(issue.to_dict(), indent=2))
        else:
            lines.append(f"[{i}] {issue.format()}")
    return "\n\n".join(lines)


check = analyze
scan = analyze_file
__all__ = [
    "analyze",
    "analyze_code",
    "analyze_file",
    "quick_check",
    "check_division_by_zero",
    "check_assertions",
    "check_index_errors",
    "format_issues",
    "format_result",
    "ExecutionResult",
    "ExecutionConfig",
    "Issue",
    "IssueKind",
    "check",
    "scan",
    "scan_static",
]


def scan_static(
    path: str | Path,
    recursive: bool = False,
    verbose: bool = False,
    min_confidence: float = 0.7,
    show_suppressed: bool = False,
) -> list[EnhancedIssue]:
    """
    Perform static analysis scanning using the Enhanced Scanner.

    Args:
        path: File or directory path to scan
        recursive: Whether to scan directories recursively
        verbose: Print verbose output
        min_confidence: Minimum confidence threshold (0.0-1.0)
        show_suppressed: Whether to include suppressed issues in the result

    Returns:
        List of EnhancedIssue objects found
    """
    config = ScannerConfig(
        verbose=verbose,
        min_confidence=min_confidence,
        show_suppressed=show_suppressed,
    )
    scanner = EnhancedScanner(config)

    path_obj = Path(path)
    if path_obj.is_file():
        return scanner.scan_file(str(path_obj))
    elif path_obj.is_dir():
        pattern = "**/*.py" if recursive else "*.py"
        return scanner.scan_directory(str(path_obj), pattern)
    else:
        raise ValueError(f"Path not found: {path}")
