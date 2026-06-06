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

"""Symbolic execution and range-analysis passes for single-file scanning.

Part of the single-file scanner pipeline. Orchestrates symbolic execution passes
and scanner value-range checks on targets, collecting metrics and
managing type annotations and VM execution limits.
"""

from __future__ import annotations

import dataclasses
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, TypeAlias

from pysymex.core.cache import get_instructions as cached_get_instructions
from pysymex.analysis.scan.complexity import tune_execution_config
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.executors import SymbolicExecutor
from pysymex.execution.results.result import ExecutionResult
from pysymex.logger import get_logger
from pysymex.scanner.annotation_hints import merge_runtime_annotations
from pysymex.scanner.execution.issues import emit_execution_issues
from pysymex.scanner.issue_sink import ScannerIssueSink
from pysymex.scanner.symbolic_vars import build_symbolic_vars
from pysymex.scanner.trace_runtime import ScannerTracer

logger = get_logger(__name__)

CodeContext: TypeAlias = tuple[types.CodeType, str | None, str | None]
_AGGREGATE_SOLVER_INT_STATS = ("queries", "sat_results", "unsat_results", "unknown_results")
_AGGREGATE_SOLVER_FLOAT_STATS = ("solver_time_ms",)


class ScanExecutionObserver(Protocol):
    """Observer for optional scanner execution progress reporting.

    Defines hooks triggered before execution begins for individual code objects
    or when registering with symbolic executors.
    """

    def activate(self, engine: SymbolicExecutor) -> None:
        """Activate the execution observer on the specified symbolic executor.

        Args:
            engine: Symbolic executor to register observer hooks on.
        """
        ...

    def begin_code(self, code: types.CodeType) -> None:
        """Notify the observer that execution has begun for a specific code object.

        Args:
            code: Compiled bytecode object whose execution is starting.
        """
        ...


@dataclass
class ExecutionMetrics:
    """Aggregate execution measurements reported by a file scan.

    Accumulates execution metrics, coverage records, and error traces
    collected across all execution passes within a single file scan session.
    """

    paths_explored: int = 0
    memory_samples: list[float] = field(default_factory=list[float])
    execution_errors: list[str] = field(default_factory=list[str])
    degraded_passes: list[str] = field(default_factory=list[str])
    degraded_by_code: dict[int, frozenset[str]] = field(default_factory=dict[int, frozenset[str]])
    complete_coverage: dict[int, frozenset[int]] = field(default_factory=dict[int, frozenset[int]])
    suppressed_issue_offsets_by_code: dict[int, frozenset[int]] = field(
        default_factory=dict[int, frozenset[int]]
    )
    solver_stats: dict[str, object] = field(default_factory=dict[str, object])

    def record(self, code: types.CodeType, execution: ExecutionResult) -> None:
        """Record metrics from an individual execution result.

        Args:
            code: The compiled code object under execution.
            execution: The symbolic execution result to record metrics from.

        Side Effects:
            Appends coverage, degraded passes, memory, and path details to
            the instance's metrics tracking collections.
        """
        self.paths_explored += execution.paths_explored
        self._record_solver_stats(execution.solver_stats)
        if execution.avg_memory_mb > 0:
            self.memory_samples.append(execution.avg_memory_mb)
        for degraded_pass in execution.degraded_passes:
            if degraded_pass not in self.degraded_passes:
                self.degraded_passes.append(degraded_pass)
        if execution.degraded_passes:
            existing = self.degraded_by_code.get(id(code), frozenset())
            self.degraded_by_code[id(code)] = existing | frozenset(execution.degraded_passes)
        if execution.paths_completed == 0 or execution.paths_pruned or execution.degraded_passes:
            return
        instructions = list(cached_get_instructions(code))
        self.complete_coverage[id(code)] = frozenset(
            instructions[index].offset
            for index in execution.coverage
            if 0 <= index < len(instructions)
        )
        self.suppressed_issue_offsets_by_code[id(code)] = execution.suppressed_issue_offsets

    @property
    def avg_memory_mb(self) -> float:
        """Calculate the average memory usage across all recorded execution samples.

        Returns:
            The average memory usage in MB, or ``0.0`` if no samples are recorded.
        """
        if not self.memory_samples:
            return 0.0
        return sum(self.memory_samples) / len(self.memory_samples)

    def record_error(self, code: types.CodeType, exc: Exception) -> None:
        """Preserve an internal pass failure as scan-status evidence.

        Args:
            code: The compiled code object where the error occurred.
            exc: The exception raised during execution.

        Side Effects:
            Appends a formatted error string to ``execution_errors``.
        """
        self.execution_errors.append(f"{code.co_name}: {type(exc).__name__}({exc})")

    @property
    def error(self) -> str | None:
        """Return a consolidated error message string if any execution errors were recorded.

        Returns:
            A string detailing all recorded errors, or ``None`` if no errors occurred.
        """
        if not self.execution_errors:
            return None
        return f"Execution Error: {'; '.join(self.execution_errors)}"

    def _record_solver_stats(self, stats: dict[str, object]) -> None:
        """Accumulate stable scalar solver counters from an execution result."""
        for key in _AGGREGATE_SOLVER_INT_STATS:
            value = stats.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, int):
                continue
            current = self.solver_stats.get(key, 0)
            if isinstance(current, bool) or not isinstance(current, int):
                current = 0
            self.solver_stats[key] = current + value

        for key in _AGGREGATE_SOLVER_FLOAT_STATS:
            value = stats.get(key, 0.0)
            if isinstance(value, bool) or not isinstance(value, int | float):
                continue
            current = self.solver_stats.get(key, 0.0)
            if isinstance(current, bool) or not isinstance(current, int | float):
                current = 0.0
            self.solver_stats[key] = float(current) + float(value)


def _merge_module_execution_globals(
    module_globals: dict[str, object],
    final_locals: dict[str, object],
) -> None:
    """Merge module execution locals without losing concrete top-level functions.

    Side Effects:
        Mutates ``module_globals`` in-place.
    """
    for name, value in final_locals.items():
        existing = module_globals.get(name)
        if isinstance(existing, types.FunctionType):
            modeled_object = getattr(value, "_modeled_object", None)
            if isinstance(modeled_object, types.CodeType):
                continue
        init_hints = getattr(existing, "_pysymex_init_type_hints", None)
        if init_hints is not None:
            setattr(value, "_pysymex_init_type_hints", init_hints)
        if getattr(existing, "_pysymex_plain_class_definition", False) is True:
            setattr(value, "_pysymex_plain_class_definition", True)
        module_globals[name] = value


def run_symbolic_execution_passes(
    *,
    scan_code_with_context: list[CodeContext],
    source_type_hints: dict[tuple[str, str | None], dict[str, str]],
    module_globals: dict[str, object],
    file_path: Path,
    base_config: ExecutionConfig,
    executor: SymbolicExecutor,
    auto_tune: bool,
    tracer: ScannerTracer | None,
    issue_sink: ScannerIssueSink,
    execution_observer: ScanExecutionObserver | None = None,
) -> ExecutionMetrics:
    """Execute the module and source-level callable scanner passes.

    Coordinates execution of module-level statements and individual callable objects
    using symbolic execution. Auto-tunes execution configurations per function to
    prevent path explosion while maintaining target coverage.

    Args:
        scan_code_with_context: List of code objects with enclosing class and path.
        source_type_hints: Static type hints extracted from source definitions.
        module_globals: Global namespace dictionary to populate during scan.
        file_path: Path of the source file.
        base_config: The baseline configuration for symbolic execution.
        executor: The symbolic executor instance.
        auto_tune: If True, tunes solver/VM limits dynamically based on bytecode complexity.
        tracer: An optional tracer to register on the executor.
        issue_sink: Destination for processed scanner issues.
        execution_observer: Optional observer for tracking progress.

    Returns:
        An ``ExecutionMetrics`` object summarizing paths, memory, and coverages.

    Side Effects:
        Mutates ``module_globals`` in-place. Emits issues to ``issue_sink``.
    """
    metrics = ExecutionMetrics()
    module_item: CodeContext | None = None
    other_items: list[CodeContext] = []
    for item in scan_code_with_context:
        if item[0].co_name == "<module>":
            module_item = item
        else:
            other_items.append(item)

    seen_codes: set[int] = set()
    if module_item is not None:
        code, class_name, full_path = module_item
        seen_codes.add(id(code))
        if execution_observer is not None:
            execution_observer.begin_code(code)
        symbolic_vars = build_symbolic_vars(
            code, class_name=class_name, include_collection_heuristics=True
        )
        try:
            execution = executor.execute_code(
                code, symbolic_vars=symbolic_vars, initial_globals=module_globals
            )
            _merge_module_execution_globals(module_globals, execution.final_locals)
            emit_execution_issues(execution, code, class_name, full_path, issue_sink)
            metrics.record(code, execution)
        except Exception as exc:
            logger.debug("Module execution failed for %s: %s", str(file_path), exc, exc_info=True)
            metrics.record_error(code, exc)

    for code, class_name, full_path in other_items:
        if id(code) in seen_codes:
            continue
        seen_codes.add(id(code))
        if auto_tune:
            tune_config = tune_execution_config(code, base_config)
            tune_config = dataclasses.replace(
                tune_config,
                enable_state_merging=base_config.enable_state_merging,
                enable_caching=base_config.enable_caching,
                enable_solver_cache=base_config.enable_solver_cache,
            )
            executor = SymbolicExecutor(config=tune_config)
            if tracer:
                tracer.install(executor)
            if execution_observer is not None:
                execution_observer.activate(executor)

        hints: dict[str, str] = dict(source_type_hints.get((code.co_name, class_name), {}))
        if class_name:
            for param, hint in source_type_hints.get(("__init__", class_name), {}).items():
                if param not in {"self", "cls"}:
                    hints[f"__init__.{param}"] = hint
        merge_runtime_annotations(hints, module_globals.get(code.co_name))

        if execution_observer is not None:
            execution_observer.begin_code(code)
        symbolic_vars = build_symbolic_vars(
            code, class_name=class_name, type_hints=hints, include_collection_heuristics=True
        )
        try:
            execution = executor.execute_code(
                code, symbolic_vars=symbolic_vars, initial_globals=module_globals
            )
            emit_execution_issues(execution, code, class_name, full_path, issue_sink)
            metrics.record(code, execution)
        except Exception as exc:
            logger.debug("Symbolic execution failed for %s", code.co_name, exc_info=True)
            metrics.record_error(code, exc)
    return metrics
