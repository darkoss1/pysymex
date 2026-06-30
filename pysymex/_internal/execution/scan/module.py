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

"""Module-code execution pass owner for source-file scans."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.symbolic_inputs import build_symbolic_vars
from pysymex._internal.execution.scan.budget import SCAN_TIME_LIMIT_DEGRADED_PASS, ScanTimeBudget
from pysymex._internal.execution.scan.globals import merge_module_execution_globals
from pysymex._internal.execution.scan.issues import emit_execution_issues
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.execution.executors.core import SymbolicExecutor
    from pysymex._internal.execution.scan.metrics import ExecutionMetrics
    from pysymex._internal.execution.scan.types import (
        CodeContext,
        ScanExecutionObserver,
        ScanIssueSink,
    )

logger = get_logger(__name__)


def run_module_item(
    *,
    module_item: CodeContext,
    seen_codes: set[int],
    module_globals: dict[str, object],
    file_path: Path,
    executor: SymbolicExecutor,
    issue_sink: ScanIssueSink,
    metrics: ExecutionMetrics,
    time_budget: ScanTimeBudget,
    execution_observer: ScanExecutionObserver | None,
) -> None:
    """Execute the module code object and merge its resulting globals."""
    code, class_name, full_path = module_item
    seen_codes.add(id(code))
    if time_budget.expired():
        metrics.record_degraded_pass(SCAN_TIME_LIMIT_DEGRADED_PASS)
        return
    if execution_observer is not None:
        execution_observer.begin_code(code)
    symbolic_vars = build_symbolic_vars(
        code,
        class_name=class_name,
        include_collection_heuristics=True,
    )
    try:
        execution = executor.execute_code(
            code,
            symbolic_vars=symbolic_vars,
            initial_globals=module_globals,
            symbolic_vars_are_inferred=True,
        )
        merge_module_execution_globals(module_globals, execution.final_locals)
        emit_execution_issues(execution, code, class_name, full_path, issue_sink)
        metrics.record(code, execution)
    except Exception as exc:
        logger.debug("Module execution failed for %s: %s", str(file_path), exc, exc_info=True)
        metrics.record_error(code, exc)
