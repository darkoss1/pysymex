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

import types
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.core.cache.control import clear_process_caches
from pysymex._internal.logging.root import get_logger
from pysymex._internal.scanner.directory.failures import build_failed_scan_result
from pysymex._internal.scanner.file import scan_file

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.execution.scan.types import ScanExecutionSetup
    from pysymex._internal.scanner.protocols import ScanReporter
    from pysymex._internal.scanner.types import ScanResult

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class _PreloadedScanCode:
    """Source and sandbox-extracted code object for one directory scan file."""

    content: str
    code_obj: types.CodeType


def _preload_sandbox_code_objects(files: list[Path]) -> dict[Path, _PreloadedScanCode]:
    """Batch-extract sandbox bytecode for files that can be read up front."""
    sources: dict[str, bytes] = {}
    content_by_path: dict[Path, str] = {}
    path_by_filename: dict[str, Path] = {}
    for file_path in files:
        try:
            source = file_path.read_bytes()
            content = source.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        filename = str(file_path)
        sources[filename] = source
        content_by_path[file_path] = content
        path_by_filename[filename] = file_path

    if not sources:
        return {}

    from pysymex._internal.sandbox.bridge.bytecode import extract_bytecode_batch

    try:
        blobs = extract_bytecode_batch(sources)
    except Exception:
        logger.warning(
            "Sandbox batch bytecode extraction unavailable; using per-file extraction",
            exc_info=True,
        )
        return {}

    preloaded: dict[Path, _PreloadedScanCode] = {}
    for filename, blob in blobs.items():
        file_path = path_by_filename.get(filename)
        if file_path is None:
            continue
        try:
            code_obj = blob.reconstruct()
        except Exception:
            logger.warning(
                "Sandbox batch bytecode payload failed validation for %s",
                file_path,
                exc_info=True,
            )
            continue
        preloaded[file_path] = _PreloadedScanCode(
            content=content_by_path[file_path],
            code_obj=code_obj,
        )
    return preloaded


def _build_shared_execution_setup(
    *,
    max_paths: int | None,
    max_depth: int | None,
    timeout: float | None,
    no_cache: bool,
    max_iterations: int | None,
    enable_fp_filtering: bool,
    detect_overflow: bool,
    trace_enabled: bool | None,
) -> ScanExecutionSetup | None:
    """Build one reusable execution setup for non-traced directory scans."""
    if trace_enabled is not False:
        return None

    from pysymex._internal.execution.scan.setup import build_scan_execution_setup

    return build_scan_execution_setup(
        max_paths=max_paths,
        max_depth=max_depth,
        timeout=timeout,
        no_cache=no_cache,
        max_iterations=max_iterations,
        enable_fp_filtering=enable_fp_filtering,
        detect_overflow=detect_overflow,
    )


def scan_sequential_strategy(
    files: list[Path],
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
    """Scan a list of files sequentially one-by-one in the host process.

    Args:
        files: A list of source file paths to analyze.
        verbose: Enable verbose reporter callbacks when ``reporter`` is provided.
        max_paths: Max paths to explore per code object.
        max_depth: Max symbolic step depth to explore per path.
        timeout: Individual file analysis timeout in seconds.
        reporter: Callback listener hook notifying on scan status updates and issues.

    Returns:
        A list of :class:`~pysymex._internal.scanner.types.ScanResult` elements.

    Side Effects:
        - Flushes registered process-local caches after each file analysis.
        - Emits progress and errors through the reporter when provided.

    """
    results: list[ScanResult] = []
    total = len(files)
    preloaded_code = _preload_sandbox_code_objects(files) if use_sandbox else {}
    shared_execution_setup = _build_shared_execution_setup(
        max_paths=max_paths,
        max_depth=max_depth,
        timeout=timeout,
        no_cache=no_cache,
        max_iterations=max_iterations,
        enable_fp_filtering=enable_fp_filtering,
        detect_overflow=detect_overflow,
        trace_enabled=trace_enabled,
    )
    logger.verbose("Starting sequential directory scan for %d file(s)", total)
    try:
        for i, file_path in enumerate(files, 1):
            if logger.state.trace_enabled:
                logger.trace("Sequential scan started for %s index=%d/%d", file_path, i, total)
            try:
                preloaded = preloaded_code.get(file_path)
                result = scan_file(
                    file_path,
                    verbose=False,
                    max_paths=max_paths,
                    max_depth=max_depth,
                    timeout=timeout,
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
                    preloaded_content=preloaded.content if preloaded is not None else None,
                    preloaded_code_obj=preloaded.code_obj if preloaded is not None else None,
                    execution_setup=shared_execution_setup,
                )
                results.append(result)
                clear_process_caches()
                if verbose and reporter:
                    reporter.on_progress(i, total, file_path, result)
                if result.error and "KeyboardInterrupt" in result.error:
                    break
            except Exception as exc:
                logger.warning("Sequential scan failed for %s", file_path, exc_info=True)
                results.append(build_failed_scan_result(file_path, exc))
                if verbose and reporter:
                    reporter.on_error(file_path, str(exc))
    except KeyboardInterrupt:
        logger.warning("Sequential scan interrupted by user; returning collected results")
    if verbose and reporter:
        reporter.on_summary(results, total)
    logger.verbose("Sequential directory scan finished results=%d total=%d", len(results), total)
    return results
