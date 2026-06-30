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

"""Parallel directory scanner execution."""

from __future__ import annotations

import atexit
import concurrent.futures
from contextlib import ExitStack
from typing import TYPE_CHECKING, TypedDict

from pysymex._internal.logging.root import get_logger
from pysymex._internal.scanner.directory.failures import build_failed_scan_result

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.scanner.protocols import ScanReporter
    from pysymex._internal.scanner.types import ScanResult

logger = get_logger(__name__)
_worker_bytecode_session_stack: ExitStack | None = None
_worker_context_cleanup_registered = False


class _ScanFileSubmitKwargs(TypedDict):
    """Keyword bundle forwarded from parallel directory scans to file scans."""

    verbose: bool
    max_paths: int | None
    max_depth: int | None
    timeout: float | None
    auto_tune: bool
    use_sandbox: bool
    no_cache: bool
    max_iterations: int | None
    trace_enabled: bool | None
    trace_output_dir: str | None
    trace_verbosity: str
    enable_fp_filtering: bool
    detect_overflow: bool
    function_filter: str | None


def _close_scan_worker_context() -> None:
    """Close process-local scanner worker resources."""
    global _worker_bytecode_session_stack

    stack = _worker_bytecode_session_stack
    _worker_bytecode_session_stack = None
    if stack is not None:
        stack.close()


def _initialize_scan_worker(use_sandbox: bool) -> None:
    """Initialize reusable process-local resources for directory scan workers."""
    global _worker_bytecode_session_stack
    global _worker_context_cleanup_registered

    if not _worker_context_cleanup_registered:
        atexit.register(_close_scan_worker_context)
        _worker_context_cleanup_registered = True

    if not use_sandbox or _worker_bytecode_session_stack is not None:
        return

    from pysymex._internal.sandbox.bridge.bytecode import bytecode_extraction_session
    from pysymex._internal.sandbox.errors import SandboxSetupError

    stack = ExitStack()
    try:
        stack.enter_context(bytecode_extraction_session())
    except SandboxSetupError:
        stack.close()
        logger.warning(
            "Sandbox bytecode session unavailable in scan worker; using per-file extraction",
            exc_info=True,
        )
        return
    _worker_bytecode_session_stack = stack


def scan_parallel_strategy(
    files: list[Path],
    workers_count: int,
    verbose: bool,
    max_paths: int | None,
    timeout: float | None,
    auto_tune: bool,
    max_depth: int | None = None,
    reporter: ScanReporter | None = None,
    use_sandbox: bool = True,
    no_cache: bool = False,
    max_iterations: int | None = None,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
    enable_fp_filtering: bool = True,
    detect_overflow: bool = False,
    function_filter: str | None = None,
) -> list[ScanResult]:
    """Scan a list of files concurrently across multiple worker processes.

    Submits each file path to a :class:`concurrent.futures.ProcessPoolExecutor` to isolate
    the Z3 solver context states, avoiding GIL contention and memory leaks.

    Args:
        files: A list of source file paths to analyze.
        workers_count: Number of concurrent process workers to initialize.
        verbose: Enable verbose reporter callbacks when ``reporter`` is provided.
        max_paths: Max paths to explore per code object.
        max_depth: Max symbolic step depth to explore per path.
        timeout: Individual file analysis timeout in seconds.
        reporter: Callback listener hook notifying on scan status updates and issues.

    Returns:
        A sorted list of :class:`~pysymex._internal.scanner.types.ScanResult` elements.

    Side Effects:
        - Spawns multiple worker processes.
        - Catches KeyboardInterrupt, cancels pending tasks, and returns already completed results.
        - Falls back to sequential execution if ProcessPoolExecutor initialization fails.

    """
    from pysymex._internal.scanner.file import scan_file
    from pysymex._internal.scanner.directory.sequential import scan_sequential_strategy

    total = len(files)

    results: list[ScanResult] = []
    completed = 0
    cancelled = False
    logger.verbose(
        "Starting parallel directory scan for %d file(s) workers=%d",
        total,
        workers_count,
    )
    scan_kwargs = _ScanFileSubmitKwargs(
        verbose=False,
        max_paths=max_paths,
        max_depth=max_depth,
        timeout=timeout,
        auto_tune=auto_tune,
        use_sandbox=use_sandbox,
        no_cache=no_cache,
        max_iterations=max_iterations,
        trace_enabled=trace_enabled,
        trace_output_dir=trace_output_dir,
        trace_verbosity=trace_verbosity,
        enable_fp_filtering=enable_fp_filtering,
        detect_overflow=detect_overflow,
        function_filter=function_filter,
    )

    try:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=workers_count,
            initializer=_initialize_scan_worker,
            initargs=(use_sandbox,),
        ) as executor:
            future_to_file: dict[concurrent.futures.Future[ScanResult], Path] = {}
            file_iter = iter(files)

            for _ in range(workers_count):
                try:
                    f = next(file_iter)
                    fut = executor.submit(
                        scan_file,
                        file_path=f,
                        **scan_kwargs,
                    )
                    future_to_file[fut] = f
                except StopIteration:
                    break

            while future_to_file:
                if cancelled:
                    break

                done, _ = concurrent.futures.wait(
                    future_to_file.keys(),
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )

                for future in done:
                    file_path = future_to_file.pop(future)
                    result = None
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as exc:
                        logger.warning("Parallel scan failed for %s", file_path, exc_info=True)
                        result = build_failed_scan_result(file_path, exc)
                        results.append(result)
                        if verbose and reporter:
                            reporter.on_error(file_path, str(exc))

                    completed += 1
                    if verbose and reporter:
                        reporter.on_progress(completed, total, file_path, result)

                    try:
                        f = next(file_iter)
                        fut = executor.submit(
                            scan_file,
                            file_path=f,
                            **scan_kwargs,
                        )
                        future_to_file[fut] = f
                    except StopIteration:
                        continue
    except KeyboardInterrupt:
        cancelled = True
        logger.warning("Parallel scan interrupted; returning %d collected result(s)", len(results))
        if verbose and reporter:
            reporter.on_status(f"Interrupted; returning {len(results)} result(s) collected so far.")
    except (RuntimeError, concurrent.futures.process.BrokenProcessPool) as exc:
        logger.warning("Parallel scanning failed (%s), falling back to sequential", exc)
        if verbose and reporter:
            reporter.on_status(
                "[!] Parallel scanning unavailable, falling back to sequential mode (workers=1).",
            )
        return scan_sequential_strategy(
            files=files,
            verbose=verbose,
            max_paths=max_paths,
            timeout=timeout,
            max_depth=max_depth,
            auto_tune=auto_tune,
            reporter=reporter,
            use_sandbox=use_sandbox,
            no_cache=no_cache,
            max_iterations=max_iterations,
            trace_enabled=trace_enabled,
            trace_output_dir=trace_output_dir,
            trace_verbosity=trace_verbosity,
            enable_fp_filtering=enable_fp_filtering,
            detect_overflow=detect_overflow,
            function_filter=function_filter,
        )

    if verbose and reporter:
        reporter.on_summary(results, total)
    logger.verbose(
        "Parallel directory scan finished results=%d total=%d cancelled=%s",
        len(results),
        total,
        cancelled,
    )
    return sorted(results, key=lambda result: result.file_path)
