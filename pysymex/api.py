"""Public API for pysymex.

This module exposes the user-facing functions for symbolic execution,
static scanning, and pipeline analysis.  Most users should start with
:func:`analyze` (single function) or :func:`scan_static` (whole file/dir).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.integration import (
    AnalysisConfig,
    AnalysisPipeline,
    AnalysisResult,
)
from pysymex.analysis.pipeline import (
    ScanIssue,
    Scanner,
    ScannerConfig,
)
from pysymex.execution.concurrency_executor import analyze_concurrent
from pysymex.execution.executor import (
    ExecutionConfig,
    ExecutionResult,
    SymbolicExecutor,
)
from pysymex.execution.verified_executor import verify
from pysymex.reporting.formatters import format_result


def analyze(
    func: Callable[..., object],
    symbolic_args: Mapping[str, str] | None = None,
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
    """Analyse a Python function for potential runtime errors.

    This is the main entry point for pysymex.  It performs symbolic
    execution on *func* and returns any issues found.

    Args:
        func: The function to analyse.
        symbolic_args: Mapping of parameter names to their types.
            Supported types: ``"int"``, ``"str"``, ``"list"``, ``"bool"``.
            Parameters not listed default to ``"int"``.
        max_paths: Maximum number of paths to explore.
        max_depth: Maximum recursion/call depth.
        max_iterations: Maximum total iterations.
        timeout: Timeout in seconds.
        verbose: Print verbose output during analysis.
        detect_division_by_zero: Check for division by zero.
        detect_assertion_errors: Check for assertion failures.
        detect_index_errors: Check for index out of bounds.
        detect_type_errors: Check for type mismatches.
        detect_overflow: Check for integer overflow.

    Returns:
        :class:`ExecutionResult` containing issues, statistics, and
        coverage info.

    Example::

        result = analyze(lambda x, y: x / y, {"x": "int", "y": "int"})
        for issue in result.issues:
            print(issue.format())
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
    return executor.execute_function(func, dict(symbolic_args) if symbolic_args else {})


def analyze_code(
    code: str,
    symbolic_vars: Mapping[str, str] | None = None,
    **kwargs: object,
) -> ExecutionResult:
    """Analyse a code snippet for potential runtime errors.

    Compiles *code* to a code object and runs symbolic execution on it.

    Args:
        code: Python source code to analyse.
        symbolic_vars: Mapping of variable names to types.
        **kwargs: Additional :class:`ExecutionConfig` options.

    Returns:
        :class:`ExecutionResult` with issues found.
    """
    compiled = compile(code, "<string>", "exec")
    config = ExecutionConfig(**kwargs)
    executor = SymbolicExecutor(config)
    return executor.execute_code(compiled, dict(symbolic_vars) if symbolic_vars else {})


def analyze_file(
    filepath: str | Path,
    function_name: str,
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: object,
) -> ExecutionResult:
    """Analyse a function from a Python file.

    Loads the file, executes it in a sandboxed namespace, and runs
    symbolic execution on the named function.

    Args:
        filepath: Path to the Python file.
        function_name: Name of the function to analyse.
        symbolic_args: Mapping of parameter names to types.
        **kwargs: Additional configuration options.

    Returns:
        :class:`ExecutionResult` with issues found.

    Raises:
        ValueError: If path validation fails or function is not found.
        FileNotFoundError: If *filepath* does not exist.
    """
    from pysymex.security import (
        PathTraversalError,
        create_sandbox_namespace,
        sanitize_function_name,
        validate_config,
        validate_path,
    )

    try:
        validated_path = validate_path(
            filepath,
            must_exist=True,
            must_be_file=True,
            allowed_extensions=[".py", ".pyw"],
        )
    except PathTraversalError as e:
        raise ValueError(f"Security error: {e }") from e

    try:
        safe_name = sanitize_function_name(function_name)
    except ValueError as e:
        raise ValueError(f"Invalid function name: {e }") from e

    config_params = validate_config(
        max_paths=int(kwargs.get("max_paths", 1000)),
        max_depth=int(kwargs.get("max_depth", 100)),
        max_iterations=int(kwargs.get("max_iterations", 10000)),
        timeout=float(kwargs.get("timeout", 60.0)),
    )

    source = validated_path.read_text(encoding="utf-8")
    compiled = compile(source, str(validated_path), "exec")

    namespace = create_sandbox_namespace(allow_builtins=True)
    from pysymex.security import make_restricted_import

    builtins_dict = namespace.get("__builtins__", {})
    if isinstance(builtins_dict, dict):
        builtins_dict["__import__"] = make_restricted_import()
    exec(compiled, namespace)

    if safe_name not in namespace:
        raise ValueError(f"Function '{safe_name }' not found in {validated_path }")
    func = namespace[safe_name]
    if not callable(func):
        raise ValueError(f"'{safe_name }' is not a callable")

    analyze_kwargs: dict[str, object] = {
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


def quick_check(func: Callable[..., object]) -> list[Issue]:
    """Quick-check a function for common issues.

    Convenience wrapper with low resource limits for fast feedback.

    Args:
        func: Function to check.

    Returns:
        List of issues found (empty if none).
    """
    result = analyze(func, max_paths=100, max_iterations=500)
    return result.issues


def check_division_by_zero(func: Callable[..., object]) -> list[Issue]:
    """Check specifically for division-by-zero issues.

    Args:
        func: Function to check.

    Returns:
        List of division-by-zero issues.
    """
    result = analyze(
        func,
        detect_division_by_zero=True,
        detect_assertion_errors=False,
        detect_index_errors=False,
        detect_type_errors=False,
    )
    return result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)


def check_assertions(func: Callable[..., object]) -> list[Issue]:
    """Check specifically for assertion errors.

    Args:
        func: Function to check.

    Returns:
        List of assertion-error issues.
    """
    result = analyze(
        func,
        detect_division_by_zero=False,
        detect_assertion_errors=True,
        detect_index_errors=False,
        detect_type_errors=False,
    )
    return result.get_issues_by_kind(IssueKind.ASSERTION_ERROR)


def check_index_errors(func: Callable[..., object]) -> list[Issue]:
    """Check specifically for index-out-of-bounds errors.

    Args:
        func: Function to check.

    Returns:
        List of index-error issues.
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
    issues: Sequence[Issue],
    format_type: str = "text",
) -> str:
    """Format a list of issues for display.

    Args:
        issues: List of issues to format.
        format_type: Output format (``"text"``, ``"json"``, ``"markdown"``).

    Returns:
        Formatted string.
    """
    lines: list[str] = []
    for i, issue in enumerate(issues, 1):
        if format_type == "json":
            import json

            lines.append(json.dumps(issue.to_dict(), indent=2))
        else:
            lines.append(f"[{i }] {issue .format ()}")
    return "\n\n".join(lines)


check: Callable[..., object] = analyze
scan: Callable[..., object] = analyze_file
__all__ = [
    "AnalysisConfig",
    "AnalysisPipeline",
    "AnalysisResult",
    "ExecutionConfig",
    "ExecutionResult",
    "Issue",
    "IssueKind",
    "analyze",
    "analyze_async",
    "analyze_code",
    "analyze_code_async",
    "analyze_concurrent",
    "analyze_file",
    "analyze_file_async",
    "check",
    "check_assertions",
    "check_division_by_zero",
    "check_index_errors",
    "format_issues",
    "format_result",
    "quick_check",
    "scan",
    "scan_directory_async",
    "scan_pipeline",
    "scan_static",
    "verify",
]


def analyze_async(*args: object, **kwargs: object) -> object:
    """Async version of analyze(). See :func:`pysymex.async_api.analyze_async`."""
    from pysymex.async_api import analyze_async as _impl

    return _impl(*args, **kwargs)


def analyze_code_async(*args: object, **kwargs: object) -> object:
    """Async version of analyze_code(). See :func:`pysymex.async_api.analyze_code_async`."""
    from pysymex.async_api import analyze_code_async as _impl

    return _impl(*args, **kwargs)


def analyze_file_async(*args: object, **kwargs: object) -> object:
    """Async version of analyze_file(). See :func:`pysymex.async_api.analyze_file_async`."""
    from pysymex.async_api import analyze_file_async as _impl

    return _impl(*args, **kwargs)


def scan_directory_async(*args: object, **kwargs: object) -> object:
    """Async directory scan. See :func:`pysymex.async_api.scan_directory_async`."""
    from pysymex.async_api import scan_directory_async as _impl

    return _impl(*args, **kwargs)


def scan_static(
    path: str | Path,
    recursive: bool = True,
    verbose: bool = False,
    min_confidence: float = 0.7,
    show_suppressed: bool = False,
) -> list[ScanIssue]:
    """Perform static vulnerability scanning on a specified file or directory path.

    Utilizes the Enhanced Static Analysis Scanner to identify common bug patterns
    (e.g., division by zero, null dereference) through fast pattern matching 
    instead of full symbolic execution.

    Args:
        path: File or directory path to scan.
        recursive: Whether to scan directories recursively.
        verbose: Enable detailed logging during the scan.
        min_confidence: Minimum confidence score to report an issue (0.0 to 1.0).
        show_suppressed: If True, include issues marked as suppressed.

    Returns:
        A list of ScanIssue objects representing detected vulnerabilities.
    """
    config = ScannerConfig(
        verbose=verbose,
        min_confidence=min_confidence,
        show_suppressed=show_suppressed,
    )
    scanner = Scanner(config)

    path_obj = Path(path)
    if path_obj.is_file():
        return scanner.scan_file(str(path_obj))
    elif path_obj.is_dir():
        pattern = "**/*.py" if recursive else "*.py"
        return scanner.scan_directory(str(path_obj), pattern)
    else:
        raise ValueError(f"Path not found: {path }")


def scan_pipeline(
    path: str | Path,
    recursive: bool = True,
    min_confidence: float = 0.5,
    type_inference: bool = True,
    flow_analysis: bool = True,
    taint_analysis: bool = True,
) -> dict[str, AnalysisResult]:
    """Run the full analysis pipeline on a file or directory.

    Integrates type inference, flow-sensitive analysis, pattern
    recognition, taint analysis, and abstract interpretation.

    Args:
        path: File or directory path to analyse.
        recursive: Scan directories recursively.
        min_confidence: Minimum confidence threshold.
        type_inference: Enable type-inference pass.
        flow_analysis: Enable flow-sensitive analysis.
        taint_analysis: Enable taint-flow analysis.

    Returns:
        Mapping of file paths to :class:`AnalysisResult` objects.

    Raises:
        ValueError: If *path* does not exist.
    """
    config = AnalysisConfig(
        type_inference=type_inference,
        flow_analysis=flow_analysis,
        taint_analysis=taint_analysis,
        min_confidence=min_confidence,
    )
    pipeline = AnalysisPipeline(config)

    path_obj = Path(path)
    if path_obj.is_file():
        result = pipeline.analyze_file(str(path_obj))
        return {str(path_obj): result}
    elif path_obj.is_dir():
        return pipeline.analyze_directory(str(path_obj), recursive=recursive)
    else:
        raise ValueError(f"Path not found: {path }")
