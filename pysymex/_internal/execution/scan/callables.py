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

"""Callable-code execution pass owner for source-file scans."""

from __future__ import annotations

import dataclasses
import inspect
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.complexity import tune_execution_config
from pysymex._internal.analysis.scan.symbolic_inputs import (
    build_symbolic_vars,
    merge_runtime_annotations,
)
from pysymex._internal.execution.executors.core import SymbolicExecutor
from pysymex._internal.execution.scan.budget import SCAN_TIME_LIMIT_DEGRADED_PASS, ScanTimeBudget
from pysymex._internal.execution.scan.hints import callable_type_hints
from pysymex._internal.execution.scan.issues import emit_execution_issues
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import types

    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.execution.scan.metrics import ExecutionMetrics
    from pysymex._internal.execution.scan.types import (
        CodeContext,
        ExecutorTracer,
        ScanExecutionObserver,
        ScanIssueSink,
    )

logger = get_logger(__name__)


def run_callable_items(
    *,
    items: list[CodeContext],
    seen_codes: set[int],
    source_type_hints: dict[tuple[str, str | None], dict[str, str]],
    module_globals: dict[str, object],
    base_config: ExecutionConfig,
    executor: SymbolicExecutor,
    auto_tune: bool,
    tracer: ExecutorTracer | None,
    issue_sink: ScanIssueSink,
    metrics: ExecutionMetrics,
    time_budget: ScanTimeBudget,
    execution_observer: ScanExecutionObserver | None,
) -> None:
    """Execute non-module code objects discovered during a source scan."""
    for code, class_name, full_path in prioritize_scan_items(items):
        if id(code) in seen_codes:
            continue
        if _is_generator_code(code):
            seen_codes.add(id(code))
            continue
        if time_budget.expired():
            metrics.record_degraded_pass(SCAN_TIME_LIMIT_DEGRADED_PASS)
            break
        seen_codes.add(id(code))
        active_executor = _executor_for_remaining_budget(
            executor=executor,
            base_config=base_config,
            time_budget=time_budget,
            tracer=tracer,
            execution_observer=execution_observer,
        )
        if auto_tune:
            tune_config = tune_execution_config(code, active_executor.config)
            tune_config = dataclasses.replace(
                tune_config,
                enable_state_merging=base_config.enable_state_merging,
                enable_caching=base_config.enable_caching,
                enable_solver_cache=base_config.enable_solver_cache,
            )
            active_executor = SymbolicExecutor(
                config=tune_config,
                detector_registry=executor.detector_registry,
            )
            if tracer:
                tracer.install(active_executor)
            if execution_observer is not None:
                execution_observer.activate(active_executor)

        hints = callable_type_hints(
            source_type_hints=source_type_hints,
            code_name=code.co_name,
            class_name=class_name,
        )
        merge_runtime_annotations(hints, module_globals.get(code.co_name))

        if execution_observer is not None:
            execution_observer.begin_code(code)
        symbolic_vars = build_symbolic_vars(
            code,
            class_name=class_name,
            type_hints=hints,
            include_collection_heuristics=True,
        )
        try:
            execution = active_executor.execute_code(
                code,
                symbolic_vars=symbolic_vars,
                initial_globals=module_globals,
                symbolic_vars_are_inferred=True,
            )
            emit_execution_issues(execution, code, class_name, full_path, issue_sink)
            metrics.record(code, execution)
        except Exception as exc:
            logger.debug("Symbolic execution failed for %s", code.co_name, exc_info=True)
            metrics.record_error(code, exc)


def _executor_for_remaining_budget(
    *,
    executor: SymbolicExecutor,
    base_config: ExecutionConfig,
    time_budget: ScanTimeBudget,
    tracer: ExecutorTracer | None,
    execution_observer: ScanExecutionObserver | None,
) -> SymbolicExecutor:
    """Return a callable-pass executor whose timeout is clipped to file budget."""
    remaining_config = time_budget.config_with_remaining_timeout(base_config)
    active_executor = SymbolicExecutor(
        config=remaining_config,
        detector_registry=executor.detector_registry,
    )
    if tracer:
        tracer.install(active_executor)
    if execution_observer is not None:
        execution_observer.activate(active_executor)
    return active_executor


def prioritize_scan_items(items: list[CodeContext]) -> list[CodeContext]:
    """Return callables in deterministic cheap-first scan order."""
    return [
        item
        for _priority, _index, item in sorted(
            (_scan_priority(item), index, item) for index, item in enumerate(items)
        )
    ]


def _scan_priority(item: CodeContext) -> int:
    """Prioritize no-argument wrappers before symbolic-argument entrypoints."""
    code, _class_name, _full_path = item
    return 0 if code.co_argcount == 0 and not code.co_kwonlyargcount else 1


def _is_generator_code(code: types.CodeType) -> bool:
    """Return whether *code* must be entered through generator resumption."""
    flags = getattr(code, "co_flags", 0)
    return bool(flags & inspect.CO_GENERATOR)
