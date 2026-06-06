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

"""Async scanner using ``asyncio.TaskGroup`` for structured concurrency.

This module provides :func:`scan_directory`, a drop-in async
counterpart to :func:`pysymex.scanner.directory.scan_directory` that uses
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
from pysymex.logger import get_logger
import os
from functools import partial
from pathlib import Path

from pysymex.config.defaults import (
    DEFAULT_SCAN_RANDOM_SEED,
    DEFAULT_SCANNER_FILE_MAX_PATHS,
    DEFAULT_SCANNER_TIMEOUT_SECONDS,
    DEFAULT_TRACE_VERBOSITY,
)
from pysymex.config.environment import async_scanner_process_pool_enabled
from pysymex.pathing import normalize_input_path
from pysymex.scanner.types import ScanResult

logger = get_logger(__name__)

_pool: concurrent.futures.ProcessPoolExecutor | None = None


def _get_pool() -> concurrent.futures.ProcessPoolExecutor:
    """Return the lazy process-global :class:`ProcessPoolExecutor` used for file scans.

    Returns:
        Shared executor that runs :func:`~pysymex.scanner.file.scan_file` in worker processes.
    """
    global _pool
    if _pool is None:
        _pool = concurrent.futures.ProcessPoolExecutor(max_workers=max(1, os.cpu_count() or 1))
    return _pool


async def _scan_file_async(
    file_path: Path,
    max_paths: int,
    timeout: float,
    auto_tune: bool,
    use_sandbox: bool,
    deterministic_mode: bool,
    random_seed: int,
    no_cache: bool,
    max_iterations: int,
    trace_enabled: bool | None,
    trace_output_dir: str | None,
    trace_verbosity: str,
    enable_fp_filtering: bool,
) -> ScanResult:
    """Scan a single Python file asynchronously in a subprocess.

    Uses a ProcessPoolExecutor to run :func:`~pysymex.scanner.file.scan_file`
    to isolate Z3 solver environments and avoid blocking the event loop with the GIL.
    Falls back to running in-thread if subprocess allocation fails.

    Returns:
        The finished scan result payload.
    """
    from pysymex.scanner.file import scan_file

    task = partial(
        scan_file,
        file_path,
        verbose=False,
        max_paths=max_paths,
        timeout=timeout,
        auto_tune=auto_tune,
        use_sandbox=use_sandbox,
        deterministic_mode=deterministic_mode,
        random_seed=random_seed,
        no_cache=no_cache,
        max_iterations=max_iterations,
        trace_enabled=trace_enabled,
        trace_output_dir=trace_output_dir,
        trace_verbosity=trace_verbosity,
        enable_fp_filtering=enable_fp_filtering,
    )

    async with asyncio.timeout(timeout + 10.0):
        if not async_scanner_process_pool_enabled():
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


async def scan_directory(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = DEFAULT_SCANNER_FILE_MAX_PATHS,
    timeout: float = DEFAULT_SCANNER_TIMEOUT_SECONDS,
    max_concurrency: int | None = None,
    auto_tune: bool = False,
    use_sandbox: bool = True,
    deterministic_mode: bool = False,
    random_seed: int = DEFAULT_SCAN_RANDOM_SEED,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = DEFAULT_TRACE_VERBOSITY,
    enable_fp_filtering: bool = True,
) -> list[ScanResult]:
    """Scan all Python files in a directory using ``asyncio.TaskGroup``.

    Structured-concurrency counterpart of
    :func:`pysymex.scanner.directory.scan_directory`. Worker tasks pull paths from a
    bounded queue so at most ``max_concurrency`` file scans run at once.

    Cancellation: if any task raises :class:`asyncio.CancelledError`, the
    :class:`asyncio.TaskGroup` cancels remaining sibling tasks and re-raises.

    Args:
        dir_path: Root directory to scan.
        pattern: Glob pattern for source files (default ``**/*.py``).
        verbose: Print per-file progress and summary lines to stdout.
        max_paths: Maximum symbolic paths explored per code object.
        timeout: Per-file scan timeout in seconds.
        max_concurrency: Concurrent worker tasks; defaults to CPU count when unset.
        auto_tune: Auto-tune execution config per function.
        use_sandbox: Run each file scan with sandboxed extraction when enabled.
        deterministic_mode: Use deterministic execution settings for each file.
        random_seed: Seed for deterministic mode.
        no_cache: Disable process-local, executor-result, and solver caches
            for each file scan.
        max_iterations: Cap VM iterations per path (``0`` means no extra cap).
        trace_enabled: Override trace collection; ``None`` uses environment defaults.
        trace_output_dir: Directory for trace artifacts when tracing is enabled.
        trace_verbosity: Trace detail level string.
        enable_fp_filtering: Apply false-positive filtering to emitted issues.

    Returns:
        :class:`~pysymex.scanner.types.ScanResult` list sorted by ``file_path``.

    Raises:
        ExceptionGroup: When one or more file tasks fail with unexpected exceptions.
    """
    dir_path = normalize_input_path(dir_path)
    files = sorted(dir_path.glob(pattern))
    if not files:
        if verbose:
            print(f"No Python files found in {dir_path}")
        return []

    if max_concurrency is None or max_concurrency <= 0:
        max_concurrency = max(1, os.cpu_count() or 1)
    max_concurrency = max(1, min(max_concurrency, len(files)))

    results: list[ScanResult] = []
    errors: list[Exception] = []
    completed = 0
    total = len(files)
    progress_lock = asyncio.Lock()
    queue: asyncio.Queue[Path | None] = asyncio.Queue(maxsize=max_concurrency * 2)

    async def _consume_files() -> None:
        """Consume queued files and scan them concurrently."""
        nonlocal completed
        while True:
            file_path = await queue.get()
            if file_path is None:
                queue.task_done()
                return
            try:
                result = await _scan_file_async(
                    file_path=file_path,
                    max_paths=max_paths,
                    timeout=timeout,
                    auto_tune=auto_tune,
                    use_sandbox=use_sandbox,
                    deterministic_mode=deterministic_mode,
                    random_seed=random_seed,
                    no_cache=no_cache,
                    max_iterations=max_iterations,
                    trace_enabled=trace_enabled,
                    trace_output_dir=trace_output_dir,
                    trace_verbosity=trace_verbosity,
                    enable_fp_filtering=enable_fp_filtering,
                )
                async with progress_lock:
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
            except Exception as exc:
                async with progress_lock:
                    errors.append(exc)
                    completed += 1
                logger.error("Async scan failed for %s: %s", file_path, exc)
            finally:
                queue.task_done()

    if verbose:
        print(
            f"Scanning {total} file{'s' if total != 1 else ''} "
            f"async (concurrency={max_concurrency})..."
        )

    async with asyncio.TaskGroup() as tg:
        for _ in range(max_concurrency):
            tg.create_task(_consume_files())

        for file_path in files:
            await queue.put(file_path)

        for _ in range(max_concurrency):
            await queue.put(None)

        await queue.join()

    if errors:
        raise ExceptionGroup(
            f"async scan: {len(errors)} file(s) had errors",
            errors,
        )

    if verbose:
        total_issues = sum(len(r.issues) for r in results)
        files_with_issues = sum(1 for r in results if r.issues)
        err_count = sum(1 for r in results if r.error)
        degraded_count = sum(1 for r in results if r.degraded_passes)
        print(
            f"\nSummary: {total_issues} issues in {files_with_issues}/{len(results)} files",
            end="",
        )
        if err_count:
            print(f" ({err_count} errors, {degraded_count} degraded)")
        elif degraded_count:
            print(f" ({degraded_count} degraded)")
        else:
            print()

    return sorted(results, key=lambda result: result.file_path)
