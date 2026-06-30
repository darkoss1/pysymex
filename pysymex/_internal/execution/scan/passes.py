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

"""Symbolic execution pass orchestration for source-file scans."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.scan.budget import ScanTimeBudget
from pysymex._internal.execution.scan.metrics import ExecutionMetrics
from pysymex._internal.execution.scan.module import run_module_item
from pysymex._internal.execution.scan.partition import split_module_item
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.execution.executors.core import SymbolicExecutor
    from pysymex._internal.execution.scan.types import (
        CodeContext,
        ExecutorTracer,
        ScanExecutionObserver,
        ScanIssueSink,
    )

logger = get_logger(__name__)


def run_symbolic_execution_passes(
    *,
    scan_code_with_context: list[CodeContext],
    source_type_hints: dict[tuple[str, str | None], dict[str, str]],
    module_globals: dict[str, object],
    file_path: Path,
    base_config: ExecutionConfig,
    executor: SymbolicExecutor,
    auto_tune: bool,
    tracer: ExecutorTracer | None,
    issue_sink: ScanIssueSink,
    execution_observer: ScanExecutionObserver | None = None,
) -> ExecutionMetrics:
    """Execute module and source-level callable scan passes."""
    from pysymex._internal.execution.scan.callables import run_callable_items

    metrics = ExecutionMetrics()
    time_budget = ScanTimeBudget.start(base_config.timeout_seconds)
    module_item, other_items = split_module_item(scan_code_with_context)

    seen_codes: set[int] = set()
    try:
        if module_item is not None:
            run_module_item(
                module_item=module_item,
                seen_codes=seen_codes,
                module_globals=module_globals,
                file_path=file_path,
                executor=executor,
                issue_sink=issue_sink,
                metrics=metrics,
                time_budget=time_budget,
                execution_observer=execution_observer,
            )

        run_callable_items(
            items=other_items,
            seen_codes=seen_codes,
            source_type_hints=source_type_hints,
            module_globals=module_globals,
            base_config=base_config,
            executor=executor,
            auto_tune=auto_tune,
            tracer=tracer,
            issue_sink=issue_sink,
            metrics=metrics,
            time_budget=time_budget,
            execution_observer=execution_observer,
        )
    except KeyboardInterrupt:
        logger.warning("Symbolic execution scan interrupted by user.")
        metrics.execution_errors.append("KeyboardInterrupt: Scan interrupted by user")
    return metrics
