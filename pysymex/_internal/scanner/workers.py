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

"""Scanner worker-count helpers.

Part of the scan orchestration planning. Determines optimal worker processes
counts based on system resources and trace/sandbox settings.
"""

from __future__ import annotations

import os

_TINY_NOSANDBOX_FILE_LIMIT = 100
_TINY_NOSANDBOX_TOTAL_BYTES_LIMIT = 512 * 1024
_BATCHABLE_SANDBOX_FILE_LIMIT = 100
_BATCHABLE_SANDBOX_TOTAL_BYTES_LIMIT = 512 * 1024


def effective_worker_count(file_count: int, desired_workers: int) -> int:
    """Clamp worker count to a useful range for the current file set size.

    Prevents over-parallelization overhead when the number of target files is small.

    Args:
        file_count: Number of files to be scanned.
        desired_workers: Configured target worker count.

    Returns:
        The clamped, optimal integer worker count.

    """
    if file_count <= 1:
        return 1
    if desired_workers <= 1:
        return 1

    # Avoid over-parallelizing tiny directories where process overhead dominates.
    max_useful_for_files = max(1, file_count // 2)
    return max(1, min(desired_workers, max_useful_for_files))


def _tiny_no_sandbox_workload(
    *,
    file_count: int | None,
    total_source_bytes: int | None,
) -> bool:
    """Return whether trusted directory scanning should avoid process startup."""
    if file_count is None or file_count <= 1:
        return False
    if file_count >= _TINY_NOSANDBOX_FILE_LIMIT:
        return False
    if total_source_bytes is None:
        return True
    return total_source_bytes <= _TINY_NOSANDBOX_TOTAL_BYTES_LIMIT


def _batchable_sandbox_workload(
    *,
    file_count: int | None,
    total_source_bytes: int | None,
) -> bool:
    """Return whether sandbox scans should prefer one batched sequential extraction."""
    if file_count is None or file_count <= 1:
        return False
    if file_count >= _BATCHABLE_SANDBOX_FILE_LIMIT:
        return False
    if total_source_bytes is None:
        return False
    return total_source_bytes <= _BATCHABLE_SANDBOX_TOTAL_BYTES_LIMIT


def auto_worker_count(
    *,
    use_sandbox: bool,
    file_count: int | None = None,
    total_source_bytes: int | None = None,
    trace_enabled: bool | None = None,
) -> int:
    """Return a conservative default worker count for symbolic scans.

    Calculates optimal process count based on CPU availability, sandbox activation, and
    tracing settings to avoid over-subscribing the host.

    Args:
        use_sandbox: If ``True``, reduces concurrency to account for sandbox compilation overhead.
        file_count: Optional count of files to scan to allow target-aware clamping.
        total_source_bytes: Optional total source bytes for workload-aware no-sandbox planning.
        trace_enabled: Optional tracing flag. If active, reduces worker count to reduce IO thrash.

    Returns:
        A conservative, safe worker process count.

    """
    cpu_count = max(1, os.cpu_count() or 1)
    half_cpu = max(1, cpu_count // 2)
    cap = 4 if use_sandbox else 8
    desired_workers = min(cap, half_cpu)

    # Trace-heavy runs generate more I/O and metadata; keep concurrency slightly lower.
    if trace_enabled:
        desired_workers = max(1, desired_workers - 1)

    if use_sandbox and _batchable_sandbox_workload(
        file_count=file_count,
        total_source_bytes=total_source_bytes,
    ):
        return 1

    if not use_sandbox and _tiny_no_sandbox_workload(
        file_count=file_count,
        total_source_bytes=total_source_bytes,
    ):
        return 1

    if file_count is None:
        return desired_workers
    return effective_worker_count(file_count, desired_workers)
