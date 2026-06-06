# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""Public symbolic execution entry points."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TypedDict, Unpack

from pysymex.analysis.detectors import Issue
from pysymex.api.conversions import to_bool, to_float, to_int
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.executors import SymbolicExecutor
from pysymex.execution.results.result import ExecutionResult
from pysymex.execution.strategies.manager.types import ExplorationStrategy
from pysymex.logger import get_logger
from pysymex.scanner.types import ScanResult

logger = get_logger(__name__)


class AnalyzeConfigKwargs(TypedDict, total=False):
    """TypedDict defining configuration options for symbolic function analysis.

    Attributes:
        config (ExecutionConfig | None): Pre-configured ExecutionConfig instance.
        max_paths (int): Maximum number of execution paths to explore.
        max_depth (int): Maximum call stack/execution depth limit.
        max_iterations (int): Maximum number of VM instructions/iterations to execute.
        timeout (float): Execution timeout in seconds.
        verbose (bool): Whether to enable verbose execution log output.
        detect_division_by_zero (bool): Enable detection of division-by-zero errors.
        detect_assertion_errors (bool): Enable detection of failed assertions.
        detect_index_errors (bool): Enable detection of index-out-of-bounds errors.
        detect_type_errors (bool): Enable detection of runtime TypeError occurrences.
        detect_overflow (bool): Enable detection of arithmetic overflows.
    """

    config: ExecutionConfig | None
    max_paths: int
    max_depth: int
    max_iterations: int
    timeout: float
    verbose: bool
    detect_division_by_zero: bool
    detect_assertion_errors: bool
    detect_index_errors: bool
    detect_type_errors: bool
    detect_overflow: bool


class AnalyzeFileConfigKwargs(AnalyzeConfigKwargs, total=False):
    """TypedDict defining configuration options for file-level analysis, extending AnalyzeConfigKwargs.

    Attributes:
        reporter (object): A reporter object to handle issues discovered during analysis.
        sandbox (bool): Whether to run the analysis in a sandbox environment.
        sandbox_config (object): Sandbox isolation and access control configurations.
    """

    reporter: object
    sandbox: bool
    sandbox_config: object


def timeout_from_kwargs(kwargs: AnalyzeConfigKwargs) -> float:
    """Return the analysis timeout from typed API keyword arguments."""
    timeout_val = kwargs.get("timeout", 60.0)
    return float(timeout_val)


def _analyze_sync(
    func: Callable[..., object],
    symbolic_args: Mapping[str, str] | None = None,
    *,
    config: ExecutionConfig | None = None,
    max_paths: int = 1000,
    max_depth: int = 100,
    max_iterations: int = 10000,
    timeout: float = 60.0,
    verbose: bool = False,
    strategy: str | ExplorationStrategy = ExplorationStrategy.ADAPTIVE,
    detect_division_by_zero: bool = True,
    detect_assertion_errors: bool = True,
    detect_index_errors: bool = True,
    detect_type_errors: bool = True,
    detect_overflow: bool = False,
) -> ExecutionResult:
    """Analyse a Python function for potential runtime errors."""
    if isinstance(strategy, str):
        try:
            from pysymex.execution.strategies.manager.types import ExplorationStrategy as ES

            strategy = ES(strategy.lower())
        except (ValueError, KeyError):
            logger.warning("Unknown exploration strategy %r; using adaptive", strategy)
            strategy = ExplorationStrategy.ADAPTIVE

    if config is None:
        resolved_config = ExecutionConfig(
            max_paths=max_paths,
            max_depth=max_depth,
            max_iterations=max_iterations,
            timeout_seconds=timeout,
            verbose=verbose,
            strategy=strategy,
            detect_division_by_zero=detect_division_by_zero,
            detect_assertion_errors=detect_assertion_errors,
            detect_index_errors=detect_index_errors,
            detect_type_errors=detect_type_errors,
            detect_overflow=detect_overflow,
        )
    else:
        resolved_config = config
    logger.verbose(
        "Analyzing function %s with strategy=%s max_paths=%d timeout=%.3fs",
        getattr(func, "__qualname__", getattr(func, "__name__", "<unknown>")),
        resolved_config.strategy.value,
        resolved_config.max_paths,
        resolved_config.timeout_seconds,
    )
    executor = SymbolicExecutor(resolved_config)
    result = executor.execute_function(func, dict(symbolic_args) if symbolic_args else {})
    logger.verbose(
        "Analysis finished for %s: issues=%d paths=%d completed=%d",
        result.function_name,
        len(result.issues),
        result.paths_explored,
        result.paths_completed,
    )
    return result


def _analyze_code_sync(
    code: str,
    symbolic_vars: Mapping[str, str] | None = None,
    **kwargs: object,
) -> ExecutionResult:
    """Analyse a code snippet for potential runtime errors."""
    logger.verbose("Analyzing code snippet length=%d", len(code))
    compiled = compile(code, "<string>", "exec")
    config = ExecutionConfig(
        max_paths=to_int(kwargs.get("max_paths", 10000), 10000),
        max_depth=to_int(kwargs.get("max_depth", 1000), 1000),
        max_iterations=to_int(kwargs.get("max_iterations", 100000), 100000),
        timeout_seconds=to_float(kwargs.get("timeout_seconds", 300.0), 300.0),
        verbose=to_bool(kwargs.get("verbose", False), False),
        detect_division_by_zero=to_bool(kwargs.get("detect_division_by_zero", True), True),
        detect_assertion_errors=to_bool(kwargs.get("detect_assertion_errors", True), True),
        detect_index_errors=to_bool(kwargs.get("detect_index_errors", True), True),
        detect_type_errors=to_bool(kwargs.get("detect_type_errors", True), True),
        detect_overflow=to_bool(kwargs.get("detect_overflow", False), False),
    )
    executor = SymbolicExecutor(config)
    return executor.execute_code(compiled, dict(symbolic_vars) if symbolic_vars else {})


def _analyze_file_sync(
    filepath: str | Path,
    function_name: str,
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: object,
) -> ExecutionResult:
    """Analyse a function from a Python file."""
    from pysymex.api.file import analyze_file_from_path

    logger.verbose("Analyzing file %s function=%s", filepath, function_name)
    return analyze_file_from_path(_analyze_sync, filepath, function_name, symbolic_args, **kwargs)


async def analyze(
    func: Callable[..., object],
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: Unpack[AnalyzeConfigKwargs],
) -> ExecutionResult:
    """Analyse a Python function asynchronously."""
    timeout_secs = timeout_from_kwargs(kwargs)
    async with asyncio.timeout(timeout_secs + 5.0):
        return await asyncio.to_thread(_analyze_sync, func, symbolic_args, **kwargs)


async def analyze_code(
    code: str,
    symbolic_vars: Mapping[str, str] | None = None,
    **kwargs: Unpack[AnalyzeConfigKwargs],
) -> ExecutionResult:
    """Analyse a code snippet asynchronously."""
    timeout_secs = timeout_from_kwargs(kwargs)
    analyze_kwargs: dict[str, object] = dict(kwargs)
    analyze_kwargs.setdefault("timeout_seconds", timeout_secs)
    analyze_kwargs.pop("timeout", None)
    async with asyncio.timeout(timeout_secs + 5.0):
        return await asyncio.to_thread(_analyze_code_sync, code, symbolic_vars, **analyze_kwargs)


async def analyze_file(
    filepath: str | Path,
    function_name: str,
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: Unpack[AnalyzeFileConfigKwargs],
) -> ExecutionResult:
    """Analyse a function from a Python file asynchronously."""
    timeout_secs = timeout_from_kwargs(kwargs)
    async with asyncio.timeout(timeout_secs + 30.0):
        return await asyncio.to_thread(
            _analyze_file_sync, filepath, function_name, symbolic_args, **kwargs
        )


async def scan_directory(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = 100,
    timeout: float = 30.0,
    max_concurrency: int | None = None,
    auto_tune: bool = False,
) -> list[ScanResult]:
    """Scan a directory asynchronously."""
    from pysymex.scanner.async_scanner import scan_directory as _scan_directory

    return await _scan_directory(
        dir_path,
        pattern=pattern,
        verbose=verbose,
        max_paths=max_paths,
        timeout=timeout,
        max_concurrency=max_concurrency,
        auto_tune=auto_tune,
    )


def quick_check(func: Callable[..., object]) -> list[Issue]:
    """Quick-check a function for common issues."""
    from pysymex.api.checks import quick_check as _quick_check

    return _quick_check(_analyze_sync, func)


def check_division_by_zero(func: Callable[..., object]) -> list[Issue]:
    """Check specifically for division-by-zero issues."""
    from pysymex.api.checks import check_division_by_zero as _check_division_by_zero

    return _check_division_by_zero(_analyze_sync, func)


def check_assertions(func: Callable[..., object]) -> list[Issue]:
    """Check specifically for assertion errors."""
    from pysymex.api.checks import check_assertions as _check_assertions

    return _check_assertions(_analyze_sync, func)


def check_index_errors(func: Callable[..., object]) -> list[Issue]:
    """Check specifically for index-out-of-bounds errors."""
    from pysymex.api.checks import check_index_errors as _check_index_errors

    return _check_index_errors(_analyze_sync, func)


def format_issues(issues: Sequence[Issue], format_type: str = "text") -> str:
    """Format a list of issues for display."""
    from pysymex.api.checks import format_issues as _format_issues

    return _format_issues(issues, format_type)


check: Callable[..., object] = analyze
scan: Callable[..., object] = analyze_file

__all__ = [
    "AnalyzeConfigKwargs",
    "AnalyzeFileConfigKwargs",
    "analyze",
    "analyze_code",
    "analyze_file",
    "check",
    "check_assertions",
    "check_division_by_zero",
    "check_index_errors",
    "format_issues",
    "quick_check",
    "scan",
    "scan_directory",
    "timeout_from_kwargs",
]
