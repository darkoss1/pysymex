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

"""Async single-file scan execution for directory scans."""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
from contextlib import nullcontext
from functools import partial
from typing import TYPE_CHECKING

from pysymex._internal.config.environment import async_scanner_process_pool_enabled
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.scanner.types import ScanResult

logger = get_logger(__name__)

_pool: concurrent.futures.ProcessPoolExecutor | None = None


def _get_pool() -> concurrent.futures.ProcessPoolExecutor:
    """Return the lazy process-global :class:`ProcessPoolExecutor` used for file scans."""
    global _pool
    if _pool is None:
        _pool = concurrent.futures.ProcessPoolExecutor(max_workers=max(1, os.cpu_count() or 1))
    return _pool


async def scan_file_async(
    file_path: Path,
    max_paths: int | None,
    timeout: float | None,
    max_depth: int | None,
    auto_tune: bool,
    use_sandbox: bool,
    no_cache: bool,
    max_iterations: int | None,
    trace_enabled: bool | None,
    trace_output_dir: str | None,
    trace_verbosity: str,
    enable_fp_filtering: bool,
    detect_overflow: bool = False,
    function_filter: str | None = None,
) -> ScanResult:
    """Scan one Python file without blocking the async directory scanner."""
    from pysymex._internal.scanner.file import scan_file

    task = partial(
        scan_file,
        file_path,
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

    timeout_context = asyncio.timeout(timeout + 10.0) if timeout is not None else nullcontext()
    async with timeout_context:
        if not async_scanner_process_pool_enabled():
            return await asyncio.to_thread(task)

        loop = asyncio.get_running_loop()
        pool = _get_pool()
        try:
            return await loop.run_in_executor(pool, task)
        except Exception as exc:
            if isinstance(exc, (PermissionError, OSError)) or "Access is denied" in str(exc):
                logger.warning(
                    "ProcessPool scan failed for %s, retrying in-thread: %s",
                    file_path,
                    exc,
                )
                return await asyncio.to_thread(task)
            raise
