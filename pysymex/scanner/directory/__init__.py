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

import os
import sys
from pathlib import Path

from pysymex.analysis.detectors.protocols import ScanReporter
from pysymex.config.defaults import (
    DEFAULT_SCAN_RANDOM_SEED,
    DEFAULT_SCANNER_DIRECTORY_MAX_PATHS,
    DEFAULT_SCANNER_DIRECTORY_TIMEOUT_SECONDS,
    DEFAULT_TRACE_VERBOSITY,
)
from pysymex.logger import get_logger
from pysymex.pathing import normalize_input_path
from pysymex.scanner.directory.parallel import scan_parallel
from pysymex.scanner.directory.sequential import scan_sequential
from pysymex.scanner.types import ScanResult
from pysymex.scanner.workers import (
    auto_worker_count,
    effective_worker_count,
)

logger = get_logger(__name__)


def scan_directory(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = DEFAULT_SCANNER_DIRECTORY_MAX_PATHS,
    timeout: int = DEFAULT_SCANNER_DIRECTORY_TIMEOUT_SECONDS,
    workers: int | None = None,
    recursive: bool = False,
    auto_tune: bool = False,
    reporter: ScanReporter | None = None,
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
    """Scan all Python files matching a pattern in a directory.

    Locates files matching the glob search pattern, calculates the appropriate number of
    parallel worker subprocesses based on system CPU cores and sandbox settings, and coordinates
    sequential or parallel analysis runs.

    Args:
        dir_path: The target root directory path to scan.
        pattern: The glob search pattern filtering target files.
        verbose: Write logs and output status notifications to stdout.
        max_paths: Maximum number of symbolic execution paths to explore per function.
        timeout: Individual file analysis execution timeout in seconds.
        workers: Desired number of parallel worker processes. Clamped dynamically if 0 or None.
        recursive: Scan subdirectories recursively.

    Returns:
        A sorted list of :class:`~pysymex.scanner.types.ScanResult` instances, one per scanned file.

    Side Effects:
        - Spawns worker processes using :class:`concurrent.futures.ProcessPoolExecutor` when parallel execution is enabled.
        - Flushes local solver cache mappings between sequential runs.
    """
    dir_path = normalize_input_path(dir_path)
    effective_pattern = pattern
    if pattern == "**/*.py":
        effective_pattern = "**/*.py" if recursive else "*.py"
    files = sorted(dir_path.glob(effective_pattern))

    if files:
        logger.verbose(
            "Directory scan discovered %d file(s) in %s pattern=%s",
            len(files),
            dir_path,
            effective_pattern,
        )
        if reporter:
            reporter.on_status(f"Scanning {len(files)} Python files in {dir_path}...\n")
        elif verbose:
            print(f"Scanning {len(files)} Python files in {dir_path}...\n")
    else:
        logger.warning(
            "Directory scan found no Python files in %s pattern=%s",
            dir_path,
            effective_pattern,
        )
        if verbose and reporter:
            reporter.on_summary([], 0)
        elif verbose:
            print(f"No Python files found in {dir_path}")
        return []

    if workers is None or workers <= 0:
        workers_count = auto_worker_count(
            use_sandbox=use_sandbox,
            file_count=len(files),
            trace_enabled=trace_enabled,
        )
    else:
        workers_count = effective_worker_count(len(files), workers)

    logical_cores = max(1, os.cpu_count() or 1)
    execution_mode = "parallel" if workers_count > 1 else "sequential"
    logger.verbose(
        "Directory scan runtime mode=%s workers=%d logical_cores=%d",
        execution_mode,
        workers_count,
        logical_cores,
    )
    if reporter:
        reporter.on_status(
            f"Runtime: mode={execution_mode}; workers={workers_count}; logical_cores={logical_cores}"
        )
    elif verbose:
        print(
            f"Runtime: mode={execution_mode}; workers={workers_count}; logical_cores={logical_cores}"
        )

    if workers_count <= 1:
        if use_sandbox and sys.platform == "win32":
            from pysymex.sandbox.bridge.bytecode import sandbox_bytecode_extraction_session
            from pysymex.sandbox.errors import SandboxSetupError

            try:
                with sandbox_bytecode_extraction_session():
                    logger.verbose(
                        "Using scoped Windows sandbox bytecode extraction session for %d file(s)",
                        len(files),
                    )
                    return scan_sequential(
                        files,
                        verbose,
                        max_paths,
                        timeout,
                        auto_tune,
                        reporter,
                        use_sandbox,
                        deterministic_mode,
                        random_seed,
                        no_cache,
                        max_iterations,
                        trace_enabled,
                        trace_output_dir,
                        trace_verbosity,
                        enable_fp_filtering,
                    )
            except SandboxSetupError:
                logger.warning(
                    "Scoped Windows sandbox bytecode session unavailable; using per-file sandbox",
                    exc_info=True,
                )
        return scan_sequential(
            files,
            verbose,
            max_paths,
            timeout,
            auto_tune,
            reporter,
            use_sandbox,
            deterministic_mode,
            random_seed,
            no_cache,
            max_iterations,
            trace_enabled,
            trace_output_dir,
            trace_verbosity,
            enable_fp_filtering,
        )

    return scan_parallel(
        files,
        workers_count,
        verbose,
        max_paths,
        timeout,
        auto_tune,
        reporter,
        use_sandbox,
        deterministic_mode,
        random_seed,
        no_cache,
        max_iterations,
        trace_enabled,
        trace_output_dir,
        trace_verbosity,
        enable_fp_filtering,
    )


__all__ = ["scan_parallel", "scan_sequential", "scan_directory"]
