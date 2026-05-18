# pysymex: Python Symbolic Execution & Formal Verification
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

"""Async versions of the public pysymex API.

Provides non-blocking wrappers around the synchronous analysis functions
using :mod:`asyncio`.  CPU-bound Z3 work is dispatched via
``asyncio.to_thread()``; parallel file scanning uses
``asyncio.TaskGroup`` with a concurrency-limiting ``asyncio.Semaphore``.

These are intended for embedding pysymex in async applications such as
LSP servers, web frameworks (FastAPI, Starlette), or Jupyter notebooks.

Requires Python 3.11+ for native ``TaskGroup`` support.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict, Unpack

from pysymex.execution.executors import ExecutionResult
from pysymex.scanner.types import ScanResult

if TYPE_CHECKING:
    from pysymex.execution.types import ExecutionConfig


class AnalyzeConfigKwargs(TypedDict, total=False):
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


def _timeout_from_kwargs(kwargs: AnalyzeConfigKwargs) -> float:
    """Return the analysis timeout from typed async API keyword arguments."""
    timeout_val = kwargs.get("timeout", 60.0)
    return float(timeout_val)


async def analyze_async(
    func: Callable[..., object],
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: Unpack[AnalyzeConfigKwargs],
) -> ExecutionResult:
    """Async version of :func:`pysymex.api.analyze`.

    Offloads CPU-bound symbolic execution to a thread so the event loop
    remains responsive.

    Args:
        func: The function to analyze.
        symbolic_args: Mapping of parameter names to their types.
        **kwargs: Additional configuration options (see ``analyze()``).

    Returns:
        ExecutionResult containing issues, statistics, and coverage info.
    """
    from pysymex.api import analyze

    timeout_secs = _timeout_from_kwargs(kwargs)
    async with asyncio.timeout(timeout_secs + 5.0):
        return await asyncio.to_thread(analyze, func, symbolic_args, **kwargs)


async def analyze_code_async(
    code: str,
    symbolic_vars: Mapping[str, str] | None = None,
    **kwargs: Unpack[AnalyzeConfigKwargs],
) -> ExecutionResult:
    """Async version of :func:`pysymex.api.analyze_code`.

    Offloads CPU-bound symbolic execution to a thread so the event loop
    remains responsive.

    Args:
        code: Python source code to analyze.
        symbolic_vars: Mapping of variable names to types.
        **kwargs: Additional configuration options.

    Returns:
        ExecutionResult with issues found.
    """
    from pysymex.api import analyze_code

    timeout_secs = _timeout_from_kwargs(kwargs)
    # Remove timeout from kwargs to avoid ExecutionConfig error
    kwargs.pop("timeout", None)
    async with asyncio.timeout(timeout_secs + 5.0):
        return await asyncio.to_thread(analyze_code, code, symbolic_vars, **kwargs)


async def analyze_file_async(
    filepath: str | Path,
    function_name: str,
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: Unpack[AnalyzeConfigKwargs],
) -> ExecutionResult:
    """Async version of :func:`pysymex.api.analyze_file`.

    File I/O and Z3 solving are both offloaded to a thread.

    Args:
        filepath: Path to the Python file.
        function_name: Name of the function to analyze.
        symbolic_args: Mapping of parameter names to types.
        **kwargs: Additional configuration options.

    Returns:
        ExecutionResult with issues found.
    """
    from pysymex.api import analyze_file

    timeout_secs = _timeout_from_kwargs(kwargs)
    # Remove timeout from kwargs to avoid ExecutionConfig error
    kwargs.pop("timeout", None)
    async with asyncio.timeout(timeout_secs + 5.0):
        return await asyncio.to_thread(
            analyze_file, filepath, function_name, symbolic_args, **kwargs
        )


async def scan_directory_async(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = 100,
    timeout: float = 30.0,
    max_concurrency: int | None = None,
    auto_tune: bool = False,
) -> list[object]:
    """Async directory scanner delegated to the scanner async SSoT.

    Args:
        dir_path: Path to directory.
        pattern: Glob pattern for files.
        verbose: Print progress.
        max_paths: Maximum paths per function.
        timeout: Timeout per file in seconds.
        max_concurrency: Max simultaneous file scans.
            Defaults to ``os.cpu_count()``.
        auto_tune: Automatically adjust config per function.

    Returns:
        List of :class:`ScanResult`, one per file.
    """
    from pysymex.scanner.async_scanner import scan_directory_async as _scan_directory_async

    results: list[ScanResult] = await _scan_directory_async(
        dir_path,
        pattern=pattern,
        verbose=verbose,
        max_paths=max_paths,
        timeout=timeout,
        max_concurrency=max_concurrency,
        auto_tune=auto_tune,
    )
    return list(results)
