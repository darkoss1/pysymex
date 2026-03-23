"""Async scanner using ``asyncio.TaskGroup`` for structured concurrency.

This module provides :func:`scan_directory_async`, a drop-in async
replacement for :func:`pysymex.scanner.core.scan_directory` that uses
Python 3.11+ :class:`asyncio.TaskGroup` for concurrent file scanning.

Key design decisions:

* **No new dependencies** - file I/O uses subprocesses or threads.
* **Semaphore-bounded concurrency** - prevents resource exhaustion.
* **Per-task error handling** - individual file errors are captured.
* **Cancellation-safe** - ``asyncio.CancelledError`` propagates.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
from functools import partial
from pathlib import Path

from pysymex.scanner.types import ScanResult

logger = logging.getLogger(__name__)


_pool: concurrent.futures.ProcessPoolExecutor | None = None


def _get_pool() -> concurrent.futures.ProcessPoolExecutor:
    """Get or create a shared ProcessPoolExecutor."""
    global _pool
    if _pool is None:
        _pool = concurrent.futures.ProcessPoolExecutor(max_workers=max(1, os.cpu_count() or 1))
    return _pool


async def _scan_file_async(
    file_path: Path,
    max_paths: int,
    timeout: float,
    auto_tune: bool,
    trace_enabled: bool | None,
    trace_output_dir: str | None,
    trace_verbosity: str,
) -> ScanResult:
    """Scan a single file in a subprocess, returning its :class:`ScanResult`.

    Uses a ProcessPoolExecutor to ensure Z3 context isolation and bypass the GIL.
    """
    from pysymex.scanner.core import scan_file

    task = partial(
        scan_file,
        file_path,
        verbose=False,
        max_paths=max_paths,
        timeout=timeout,
        auto_tune=auto_tune,
        trace_enabled=trace_enabled,
        trace_output_dir=trace_output_dir,
        trace_verbosity=trace_verbosity,
    )

    async with asyncio.timeout(timeout + 10.0):
        use_process_pool = os.getenv("PYSYMEX_ASYNC_USE_PROCESS_POOL", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if not use_process_pool:
            return await asyncio.to_thread(task)

        loop = asyncio.get_running_loop()
        pool = _get_pool()
        try:
            return await loop.run_in_executor(pool, task)
        except Exception as exc:
            if isinstance(exc, (PermissionError, OSError)) or "Access is denied" in str(exc):
                logger.warning(
                    "ProcessPool scan failed for %s, retrying in-thread: %s", file_path, exc
                )
                return await asyncio.to_thread(task)
            raise


async def scan_directory_async(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = 100,
    timeout: float = 30.0,
    max_concurrency: int | None = None,
    auto_tune: bool = False,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
) -> list[ScanResult]:
    """Scan all Python files in a directory using ``asyncio.TaskGroup``.

    This is the structured-concurrency counterpart of
    :func:`pysymex.scanner.core.scan_directory`.  It creates one async
    task per file inside a ``TaskGroup`` and uses a ``Semaphore`` to cap
    concurrency.

    **Cancellation behaviour**: if any task raises
    ``asyncio.CancelledError`` (e.g. from a signal handler calling
    ``task.cancel()``), the TaskGroup cancels all remaining sibling
    tasks and re-raises the error.

    **Error handling**: file-level errors are caught per task and
    collected.  After the TaskGroup exits, they are raised as an
    ``ExceptionGroup`` (which callers can handle with ``except*``).

    Args:
        dir_path: Root directory to scan.
        pattern: Glob pattern (default ``**/*.py``).
        verbose: Print progress lines.
        max_paths: Maximum execution paths per function.
        timeout: Per-file timeout in seconds.
        max_concurrency: Maximum parallel scans.  Defaults to
            ``os.cpu_count()``.
        auto_tune: Auto-tune analysis config per function.

    Returns:
        List of :class:`ScanResult` objects, one per file.

    Raises:
        ExceptionGroup: If one or more files failed to scan.
    """
    dir_path = Path(dir_path)
    files = sorted(dir_path.glob(pattern))
    if not files:
        if verbose:
            print(f"No Python files found in {dir_path}")
        return []

    if max_concurrency is None or max_concurrency <= 0:
        max_concurrency = max(1, os.cpu_count() or 1)

    semaphore = asyncio.Semaphore(max_concurrency)

    results: list[ScanResult] = []
    errors: list[Exception] = []
    completed = 0
    total = len(files)

    async def _bounded_scan(file_path: Path) -> None:
        """Acquire semaphore, scan file, record result."""
        nonlocal completed
        async with semaphore:
            try:
                result = await _scan_file_async(
                    file_path,
                    max_paths,
                    timeout,
                    auto_tune,
                    trace_enabled,
                    trace_output_dir,
                    trace_verbosity,
                )
                results.append(result)
                completed += 1
                if verbose:
                    pct = completed * 100 // total
                    status = (
                        "ERROR"
                        if result.error
                        else (f"{len(result.issues)} issue(s)" if result.issues else "OK")
                    )
                    print(f"[{completed}/{total}] ({pct}%) {file_path.name} {status}")
            except asyncio.CancelledError:
                raise
            except (TimeoutError, Exception) as exc:

                errors.append(exc)
                completed += 1
                logger.error("Async scan failed for %s: %s", file_path, exc)

    if verbose:
        print(
            f"Scanning {total} file{'s' if total != 1 else ''} "
            f"async (concurrency={max_concurrency})..."
        )

    async with asyncio.TaskGroup() as tg:
        for file_path in files:
            tg.create_task(_bounded_scan(file_path))

    if errors:
        try:
            raise ExceptionGroup(
                f"async scan: {len(errors)} file(s) had errors",
                errors,
            )
        except* OSError as eg:
            logger.warning(
                "%d OS error(s) during async scan",
                len(eg.exceptions),
            )
        except* Exception as eg:
            logger.warning(
                "%d error(s) during async scan",
                len(eg.exceptions),
            )

    if verbose:
        total_issues = sum(len(r.issues) for r in results)
        files_with_issues = sum(1 for r in results if r.issues)
        err_count = sum(1 for r in results if r.error)
        print(
            f"\nSummary: {total_issues} issues in {files_with_issues}/{len(results)} files",
            end="",
        )
        if err_count:
            print(f" ({err_count} errors)")
        else:
            print()

    return results


__all__ = ["scan_directory_async"]
