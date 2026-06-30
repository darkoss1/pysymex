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

"""Directory scan file selection and worker planning."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from pysymex._internal.scanner.workers import auto_worker_count, effective_worker_count

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class DirectoryFileSelection:
    """Resolved target files and effective glob pattern for a directory scan."""

    files: tuple[Path, ...]
    effective_pattern: str


@dataclass(frozen=True, slots=True)
class DirectoryExecutionPlan:
    """Worker-count decision for a directory scan."""

    workers_count: int
    logical_cores: int
    mode: Literal["parallel", "sequential"]


def estimate_total_source_bytes(files: tuple[Path, ...]) -> int | None:
    """Return a best-effort total source size for directory scan planning."""
    total = 0
    for file_path in files:
        try:
            total += file_path.stat().st_size
        except OSError:
            return None
    return total


def select_directory_files(
    dir_path: Path,
    pattern: str,
) -> DirectoryFileSelection:
    """Resolve directory scan targets in deterministic path order."""
    return DirectoryFileSelection(
        files=tuple(sorted(dir_path.glob(pattern))),
        effective_pattern=pattern,
    )


def plan_directory_execution(
    file_count: int,
    workers: int | None,
    *,
    use_sandbox: bool,
    trace_enabled: bool | None,
    total_source_bytes: int | None = None,
) -> DirectoryExecutionPlan:
    """Select worker count and execution mode for a directory scan."""
    if workers is None or workers <= 0:
        workers_count = auto_worker_count(
            use_sandbox=use_sandbox,
            file_count=file_count,
            total_source_bytes=total_source_bytes,
            trace_enabled=trace_enabled,
        )
    else:
        workers_count = effective_worker_count(file_count, workers)

    logical_cores = max(1, os.cpu_count() or 1)
    mode: Literal["parallel", "sequential"] = "parallel" if workers_count > 1 else "sequential"
    return DirectoryExecutionPlan(
        workers_count=workers_count,
        logical_cores=logical_cores,
        mode=mode,
    )
