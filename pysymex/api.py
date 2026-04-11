# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Public API for pysymex.

This module exposes the user-facing functions for symbolic execution,
static scanning, and pipeline analysis.  Most users should start with
:func:`analyze` (single function) or :func:`scan_static` (whole file/dir).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Unpack, cast

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
from pysymex.async_api import AnalyzeConfigKwargs
from pysymex.execution.executors.concurrent import analyze_concurrent
from pysymex.execution.executors import (
    ExecutionConfig,
    ExecutionResult,
    SymbolicExecutor,
)
from pysymex.execution.executors.verified import verify
from pysymex.reporting.formatters import format_result


def _to_int(value: object, default: int) -> int:
    """Convert a generic config value to int with fallback."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _to_float(value: object, default: float) -> float:
    """Convert a generic config value to float with fallback."""
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _to_bool(value: object, default: bool) -> bool:
    """Convert a generic config value to bool with fallback."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def analyze(
    func: Callable[..., object],
    symbolic_args: Mapping[str, str] | None = None,
    *,
    config: ExecutionConfig | None = None,
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
    if config is None:
        resolved_config = ExecutionConfig(
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
    else:
        resolved_config = config
    executor = SymbolicExecutor(resolved_config)
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
    config_ctor = cast("Callable[..., ExecutionConfig]", ExecutionConfig)
    config = config_ctor(**kwargs)
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
    from pysymex.sandbox import (
        PathTraversalError,
        sanitize_function_name,
        validate_config,
        validate_path,
    )

    kwargs_mut = dict(kwargs)
    sandbox_mode = _to_bool(kwargs_mut.pop("sandbox", False), False)
    sandbox_config = kwargs_mut.pop("sandbox_config", None)

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
        max_paths=_to_int(kwargs_mut.get("max_paths", 1000), 1000),
        max_depth=_to_int(kwargs_mut.get("max_depth", 100), 100),
        max_iterations=_to_int(kwargs_mut.get("max_iterations", 10000), 10000),
        timeout=_to_float(kwargs_mut.get("timeout", 60.0), 60.0),
    )

    if sandbox_mode:
        from pysymex.sandbox.bridge import extract_bytecode

        bytecode_blob = extract_bytecode(
            validated_path.read_bytes(),
            str(validated_path),
            sandbox_config=(sandbox_config if isinstance(sandbox_config, Mapping) else None),
        )
        compiled = bytecode_blob.reconstruct()

        from pysymex.sandbox.execution import get_hardened_builtins

        namespace: dict[str, object] = {
            "__builtins__": get_hardened_builtins(),
            "__name__": "__main__",
            "__file__": str(validated_path),
        }
        exec(compiled, namespace)
    else:
        from pysymex.sandbox.execution import hardened_exec

        source = validated_path.read_text(encoding="utf-8")
        namespace = hardened_exec(source, str(validated_path))

    if safe_name not in namespace:
        raise ValueError(f"Function '{safe_name}' not found in {validated_path}")
    func_obj = namespace[safe_name]
    if not callable(func_obj):
        raise ValueError(f"'{safe_name}' is not a callable")
    max_paths_cfg = cast("int", config_params["max_paths"])
    max_depth_cfg = cast("int", config_params["max_depth"])
    max_iterations_cfg = cast("int", config_params["max_iterations"])
    timeout_cfg = cast("float", config_params["timeout"])

    return analyze(
        func_obj,
        symbolic_args,
        max_paths=max_paths_cfg,
        max_depth=max_depth_cfg,
        max_iterations=max_iterations_cfg,
        timeout=timeout_cfg,
        verbose=_to_bool(kwargs_mut.get("verbose", False), False),
        detect_division_by_zero=_to_bool(kwargs_mut.get("detect_division_by_zero", True), True),
        detect_assertion_errors=_to_bool(kwargs_mut.get("detect_assertion_errors", True), True),
        detect_index_errors=_to_bool(kwargs_mut.get("detect_index_errors", True), True),
        detect_type_errors=_to_bool(kwargs_mut.get("detect_type_errors", True), True),
        detect_overflow=_to_bool(kwargs_mut.get("detect_overflow", False), False),
    )


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
    deduped: dict[tuple[int | None, int | None, tuple[tuple[str, object], ...]], Issue] = {}
    for issue in result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO):
        counterexample = issue.get_counterexample() or {}
        key = (
            issue.pc,
            issue.line_number,
            tuple(sorted(counterexample.items())),
        )
        deduped.setdefault(key, issue)
    return list(deduped.values())


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
    if format_type == "json":
        import json

        return json.dumps([issue.to_dict() for issue in issues], indent=2)

    lines: list[str] = []
    for i, issue in enumerate(issues, 1):
        lines.append(f"[{i}] {issue.format()}")
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


async def analyze_async(
    func: Callable[..., object],
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: Unpack[AnalyzeConfigKwargs],
) -> ExecutionResult:
    """Async version of analyze(). See :func:`pysymex.async_api.analyze_async`."""
    from pysymex.async_api import analyze_async as _impl

    return await _impl(func, symbolic_args, **kwargs)


async def analyze_code_async(
    code: str,
    symbolic_vars: Mapping[str, str] | None = None,
    **kwargs: Unpack[AnalyzeConfigKwargs],
) -> ExecutionResult:
    """Async version of analyze_code(). See :func:`pysymex.async_api.analyze_code_async`."""
    from pysymex.async_api import analyze_code_async as _impl

    return await _impl(code, symbolic_vars, **kwargs)


async def analyze_file_async(
    filepath: str | Path,
    function_name: str,
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: Unpack[AnalyzeConfigKwargs],
) -> ExecutionResult:
    """Async version of analyze_file(). See :func:`pysymex.async_api.analyze_file_async`."""
    from pysymex.async_api import analyze_file_async as _impl

    return await _impl(filepath, function_name, symbolic_args, **kwargs)


async def scan_directory_async(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = 100,
    timeout: float = 30.0,
    max_concurrency: int | None = None,
    auto_tune: bool = False,
) -> list[object]:
    """Async directory scan. See :func:`pysymex.async_api.scan_directory_async`."""
    from pysymex.async_api import scan_directory_async as _impl

    return await _impl(
        dir_path,
        pattern=pattern,
        verbose=verbose,
        max_paths=max_paths,
        timeout=timeout,
        max_concurrency=max_concurrency,
        auto_tune=auto_tune,
    )


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
        raise ValueError(f"Path not found: {path}")


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
        raise ValueError(f"Path not found: {path}")


