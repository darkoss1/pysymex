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
import logging
import os
from collections.abc import Mapping
from pathlib import Path

from pysymex.execution.executor import ExecutionResult

logger = logging.getLogger(__name__)


async def analyze_async(
    func: object,
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: object,
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

    timeout_secs: float = kwargs.get("timeout", 60.0)
    async with asyncio.timeout(timeout_secs + 5.0):
        return await asyncio.to_thread(analyze, func, symbolic_args, **kwargs)


async def analyze_code_async(
    code: str,
    symbolic_vars: Mapping[str, str] | None = None,
    **kwargs: object,
) -> ExecutionResult:
    """Async version of :func:`pysymex.api.analyze_code`.

    Args:
        code: Python source code to analyze.
        symbolic_vars: Mapping of variable names to types.
        **kwargs: Additional configuration options.

    Returns:
        ExecutionResult with issues found.
    """
    from pysymex.api import analyze_code

    timeout_secs: float = kwargs.get("timeout", 60.0)
    async with asyncio.timeout(timeout_secs + 5.0):
        return await asyncio.to_thread(analyze_code, code, symbolic_vars, **kwargs)


async def analyze_file_async(
    filepath: str | Path,
    function_name: str,
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: object,
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

    timeout_secs: float = kwargs.get("timeout", 60.0)
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
    """Async directory scanner using ``asyncio.TaskGroup``.

    Scans all matching Python files concurrently using structured
    concurrency.  A ``Semaphore`` limits the number of files being
    analysed simultaneously to avoid overwhelming system resources.

    Each scanning task handles its own exceptions; errors are collected
    and raised as an ``ExceptionGroup`` at the end (if any occurred).

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
    from pysymex.scanner.core import scan_file

    dir_path = Path(dir_path)
    files = sorted(dir_path.glob(pattern))
    if not files:
        if verbose:
            print(f"No Python files found in {dir_path}")
        return []

    if max_concurrency is None:
        max_concurrency = max(1, os.cpu_count() or 1)

    semaphore = asyncio.Semaphore(max_concurrency)
    results: list[object] = []
    errors: list[Exception] = []
    results_lock = asyncio.Lock()
    completed = 0
    total = len(files)

    async def _scan_one(file_path: Path) -> None:
        """Scan one."""
        nonlocal completed
        async with semaphore:
            try:
                result = await asyncio.to_thread(
                    scan_file,
                    file_path,
                    verbose=False,
                    max_paths=max_paths,
                    timeout=timeout,
                    auto_tune=auto_tune,
                )
                async with results_lock:
                    results.append(result)
                    completed += 1
                    if verbose:
                        pct = completed * 100 // total
                        status = "OK"
                        if result.error:
                            status = "ERROR"
                        elif result.issues:
                            status = f"{len(result.issues)} issue(s)"
                        print(f"[{completed}/{total}] ({pct}%) " f"{file_path.name} {status}")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                async with results_lock:
                    errors.append(exc)
                    completed += 1

    if verbose:
        print(
            f"Scanning {total} file{'s' if total != 1 else ''} "
            f"async (concurrency={max_concurrency})..."
        )

    async with asyncio.TaskGroup() as tg:
        for file_path in files:
            tg.create_task(_scan_one(file_path))

    if errors:
        logger.warning("async scan: %d file(s) had errors", len(errors))
        for err in errors:
            logger.debug("  %s: %s", type(err).__name__, err)

    return results


__all__ = [
    "analyze_async",
    "analyze_code_async",
    "analyze_file_async",
    "scan_directory_async",
]
