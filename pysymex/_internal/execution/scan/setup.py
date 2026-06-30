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

"""Executor setup for source-file scan execution passes."""

from __future__ import annotations

from pysymex._internal.analysis.scan.symbolic_inputs import scanner_solver_timeout_ms
from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.execution.executors.core import SymbolicExecutor
from pysymex._internal.execution.scan.types import ScanExecutionObserver, ScanExecutionSetup


def build_scan_execution_setup(
    *,
    max_paths: int | None,
    max_depth: int | None,
    timeout: float | None,
    no_cache: bool,
    max_iterations: int | None,
    enable_fp_filtering: bool,
    detect_overflow: bool = False,
    execution_observer: ScanExecutionObserver | None = None,
) -> ScanExecutionSetup:
    """Build the execution configuration and executor used by a file scan."""
    config = ExecutionConfig(
        max_paths=max_paths,
        max_depth=max_depth,
        max_iterations=max_iterations,
        timeout_seconds=timeout,
        solver_timeout_ms=scanner_solver_timeout_ms(timeout),
        enable_caching=not no_cache,
        enable_solver_cache=not no_cache,
        enable_cross_function=False,
        enable_fp_filtering=enable_fp_filtering,
        detect_overflow=detect_overflow,
    )
    executor = SymbolicExecutor(config=config)
    if execution_observer is not None:
        execution_observer.activate(executor)
    return ScanExecutionSetup(config=config, executor=executor)
