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

"""Sequential directory scanner execution."""

from __future__ import annotations

from pathlib import Path

from pysymex.analysis.detectors.protocols import ScanReporter
from pysymex.core.solver.engine.queries import clear_solver_caches
from pysymex.logger import get_logger
from pysymex.scanner.directory.failures import build_failed_scan_result
from pysymex.scanner.file import scan_file
from pysymex.scanner.summary import print_scan_summary
from pysymex.scanner.types import ScanResult

logger = get_logger(__name__)


def scan_sequential(
    files: list[Path],
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
    """Scan a list of files sequentially one-by-one in the host process.

    Args:
        files: A list of source file paths to analyze.
        verbose: Write execution progress to stdout.
        max_paths: Max paths to explore per code object.
        timeout: Individual file analysis timeout in seconds.
        reporter: Callback listener hook notifying on scan status updates and issues.

    Returns:
        A list of :class:`~pysymex.scanner.types.ScanResult` elements.

    Side Effects:
        - Flushes internal solver caches after each file analysis via :func:`~pysymex.core.solver.engine.clear_solver_caches`.
        - Emits progress and errors to console or the reporter.
    """
    results: list[ScanResult] = []
    total = len(files)
    logger.verbose("Starting sequential directory scan for %d file(s)", total)
    if verbose and not reporter:
        print(f"Scanning {total} file{'s' if total != 1 else ''} sequentially...")
    for i, file_path in enumerate(files, 1):
        if logger.state.trace_enabled:
            logger.trace("Sequential scan started for %s index=%d/%d", file_path, i, total)
        if verbose and not reporter:
            print(f"[{i}/{total}] {file_path.name}...", end=" ", flush=True)
        try:
            result = scan_file(
                file_path,
                verbose=False,
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
            results.append(result)
            clear_solver_caches()
            if verbose:
                if reporter:
                    reporter.on_progress(i, total, file_path, result)
                else:
                    if result.error:
                        print("\u274c Error")
                    elif result.issues:
                        print(f"\u26a0\ufe0f  {len(result.issues)} issues")
                    else:
                        print("\u2705")
        except Exception as exc:
            logger.warning("Sequential scan failed for %s", file_path, exc_info=True)
            results.append(build_failed_scan_result(file_path, exc))
            if verbose:
                if reporter:
                    reporter.on_error(file_path, str(exc))
                else:
                    print(f"\u274c Error: {exc}")
    if verbose:
        if reporter:
            reporter.on_summary(results, total)
        else:
            print_scan_summary(results, total)
    logger.verbose("Sequential directory scan finished results=%d total=%d", len(results), total)
    return results
