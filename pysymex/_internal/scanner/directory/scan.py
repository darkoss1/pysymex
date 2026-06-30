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

"""Directory scanner entry point."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.config.defaults import DEFAULT_TRACE_VERBOSITY
from pysymex._internal.logging.root import get_logger
from pysymex._internal.pathing import normalize_input_path
from pysymex._internal.scanner.directory.parallel import scan_parallel_strategy
from pysymex._internal.scanner.directory.planning import (
    estimate_total_source_bytes,
    plan_directory_execution,
    select_directory_files,
)
from pysymex._internal.scanner.directory.sequential import scan_sequential_strategy

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.scanner.protocols import ScanReporter
    from pysymex._internal.scanner.types import ScanResult

_scan_parallel = scan_parallel_strategy
_scan_sequential = scan_sequential_strategy

logger = get_logger(__name__)


def scan_directory(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int | None = None,
    timeout: float | None = None,
    max_depth: int | None = None,
    workers: int | None = None,
    auto_tune: bool = True,
    reporter: ScanReporter | None = None,
    use_sandbox: bool = True,
    no_cache: bool = False,
    max_iterations: int | None = None,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = DEFAULT_TRACE_VERBOSITY,
    enable_fp_filtering: bool = True,
    detect_overflow: bool = False,
    function_filter: str | None = None,
) -> list[ScanResult]:
    """Scan all Python files matching a pattern in a directory.

    Locates files matching the glob search pattern, calculates the appropriate number of
    parallel worker subprocesses based on system CPU cores and sandbox settings, and coordinates
    sequential or parallel analysis runs.

    Args:
        dir_path: The target root directory path to scan.
        pattern: The glob search pattern filtering target files.
        verbose: Enable verbose reporter callbacks when ``reporter`` is provided.
        max_paths: Maximum number of symbolic execution paths to explore per function.
        max_depth: Maximum symbolic step depth to explore per path.
        timeout: Individual file analysis execution timeout in seconds.
        workers: Desired number of parallel worker processes. Clamped dynamically if 0 or None.
        recursive: Scan subdirectories recursively.
        detect_overflow: Enable explicit bounded-integer overflow checks for every file scan.
        function_filter: Optional exact function/class-method path to scan in each file.

    Returns:
        A sorted list of :class:`~pysymex._internal.scanner.types.ScanResult` instances, one per scanned file.

    Side Effects:
        - Spawns worker processes using :class:`concurrent.futures.ProcessPoolExecutor` when parallel execution is enabled.
        - Flushes local solver cache mappings between sequential runs.

    """
    dir_path = normalize_input_path(dir_path)
    selection = select_directory_files(dir_path, pattern)
    files = list(selection.files)

    if files:
        logger.verbose(
            "Directory scan discovered %d file(s) in %s pattern=%s",
            len(files),
            dir_path,
            selection.effective_pattern,
        )
        if verbose and reporter:
            reporter.on_status(f"Scanning {len(files)} Python files in {dir_path}...\n")
    else:
        logger.warning(
            "Directory scan found no Python files in %s pattern=%s",
            dir_path,
            selection.effective_pattern,
        )
        if verbose and reporter:
            reporter.on_summary([], 0)
        return []

    execution_plan = plan_directory_execution(
        len(files),
        workers,
        use_sandbox=use_sandbox,
        trace_enabled=trace_enabled,
        total_source_bytes=estimate_total_source_bytes(selection.files),
    )
    logger.verbose(
        "Directory scan runtime mode=%s workers=%d logical_cores=%d",
        execution_plan.mode,
        execution_plan.workers_count,
        execution_plan.logical_cores,
    )
    if verbose and reporter:
        reporter.on_status(
            "Runtime: "
            f"mode={execution_plan.mode}; "
            f"workers={execution_plan.workers_count}; "
            f"logical_cores={execution_plan.logical_cores}",
        )

    if execution_plan.workers_count <= 1:
        if use_sandbox:
            from pysymex._internal.sandbox.bridge.bytecode import (
                bytecode_extraction_session,
            )
            from pysymex._internal.sandbox.errors import SandboxSetupError

            try:
                with bytecode_extraction_session():
                    logger.verbose(
                        "Using scoped sandbox bytecode extraction session for %d file(s)",
                        len(files),
                    )
                    return _scan_sequential(
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
            except SandboxSetupError:
                logger.warning(
                    "Scoped sandbox bytecode session unavailable; using per-file sandbox",
                    exc_info=True,
                )
        return _scan_sequential(
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

    return _scan_parallel(
        files=files,
        workers_count=execution_plan.workers_count,
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
