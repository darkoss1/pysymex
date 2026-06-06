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

import concurrent.futures
from pathlib import Path

from pysymex.analysis.detectors.protocols import ScanReporter
from pysymex.logger import get_logger
from pysymex.scanner.directory.failures import build_failed_scan_result
from pysymex.scanner.directory.sequential import scan_sequential
from pysymex.scanner.file import scan_file
from pysymex.scanner.summary import print_parallel_progress, print_scan_summary
from pysymex.scanner.types import ScanResult

logger = get_logger(__name__)


def scan_parallel(
    files: list[Path],
    workers_count: int,
    verbose: bool,
    max_paths: int,
    timeout: float,
    auto_tune: bool,
    reporter: ScanReporter | None = None,
    use_sandbox: bool = True,
    deterministic_mode: bool = False,
    random_seed: int = 42,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
    enable_fp_filtering: bool = True,
) -> list[ScanResult]:
    """Scan a list of files concurrently across multiple worker processes.

    Submits each file path to a :class:`concurrent.futures.ProcessPoolExecutor` to isolate
    the Z3 solver context states, avoiding GIL contention and memory leaks.

    Args:
        files: A list of source file paths to analyze.
        workers_count: Number of concurrent process workers to initialize.
        verbose: Write execution progress to stdout.
        max_paths: Max paths to explore per code object.
        timeout: Individual file analysis timeout in seconds.
        reporter: Callback listener hook notifying on scan status updates and issues.

    Returns:
        A sorted list of :class:`~pysymex.scanner.types.ScanResult` elements.

    Side Effects:
        - Spawns multiple worker processes.
        - Catches KeyboardInterrupt, cancels pending tasks, and returns already completed results.
        - Falls back to sequential execution if ProcessPoolExecutor initialization fails.
    """
    total = len(files)
    if verbose and not reporter:
        print(f"Scanning {total} file{'s' if total != 1 else ''} using {workers_count} workers...")

    results: list[ScanResult] = []
    completed = 0
    cancelled = False
    logger.verbose(
        "Starting parallel directory scan for %d file(s) workers=%d", total, workers_count
    )

    try:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=workers_count,
        ) as executor:
            future_to_file: dict[concurrent.futures.Future[ScanResult], Path] = {}
            file_iter = iter(files)

            for _ in range(workers_count):
                try:
                    f = next(file_iter)
                    fut = executor.submit(
                        scan_file,
                        file_path=f,
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
                    future_to_file[fut] = f
                except StopIteration:
                    break

            while future_to_file:
                if cancelled:
                    break

                done, _ = concurrent.futures.wait(
                    future_to_file.keys(), return_when=concurrent.futures.FIRST_COMPLETED
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
                        if verbose:
                            if reporter:
                                reporter.on_error(file_path, str(exc))
                            else:
                                print(f"[X] Error scanning {file_path.name}: {exc}")

                    completed += 1
                    if verbose:
                        if reporter:
                            reporter.on_progress(completed, total, file_path, result)
                        else:
                            print_parallel_progress(completed, total, file_path, result)

                    try:
                        f = next(file_iter)
                        fut = executor.submit(
                            scan_file,
                            file_path=f,
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
                        future_to_file[fut] = f
                    except StopIteration:
                        continue
    except KeyboardInterrupt:
        cancelled = True
        logger.warning("Parallel scan interrupted; returning %d collected result(s)", len(results))
        if verbose and not reporter:
            print(f"\n\u26a1 Interrupted \u2013 returning {len(results)} results collected so far.")
    except (RuntimeError, concurrent.futures.process.BrokenProcessPool) as exc:
        logger.warning("Parallel scanning failed (%s), falling back to sequential", exc)
        if reporter:
            reporter.on_status(
                "[!] Parallel scanning unavailable, falling back to sequential mode (workers=1)."
            )
        elif verbose:
            print("[!] Parallel scanning unavailable, falling back to sequential mode (workers=1).")
        return scan_sequential(
            files=files,
            verbose=verbose,
            max_paths=max_paths,
            timeout=timeout,
            auto_tune=auto_tune,
            reporter=reporter,
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

    if verbose and not cancelled:
        if reporter:
            reporter.on_summary(results, total)
        else:
            print_scan_summary(results, total)
    logger.verbose(
        "Parallel directory scan finished results=%d total=%d cancelled=%s",
        len(results),
        total,
        cancelled,
    )
    return sorted(results, key=lambda result: result.file_path)
