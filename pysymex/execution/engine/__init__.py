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

"""Execution lifecycle helpers shared by public executor entrypoints.

This package owns run-preparation steps that coordinate session bytecode
metadata, dispatcher streams, and per-code line mappings before exploration.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import dis
from types import CodeType
from typing import TYPE_CHECKING, cast

from pysymex.core.bytecode import instruction_stream_key
from pysymex.analysis.static.types import TypeAnalyzer
from pysymex.analysis.static.loops import LoopDetector, LoopWidening
from pysymex.execution.engine.bytecode_metadata import (
    build_line_mapping,
    clear_line_mapping_cache,
    line_mapping_cache_stats,
    prepare_bytecode_execution,
)
from pysymex.execution.detectors import filter_final_issues
from pysymex.execution.entrypoint_globals import (
    referenced_same_module_instance_globals,
    same_module_function_or_class_globals,
)
from pysymex.execution.fallback.infrastructure import (
    cross_function_prepass_event,
    state_merger_prepass_event,
    type_inference_prepass_event,
)
from pysymex.execution.results.result import ExecutionResult
from pysymex.execution.results.builder import build_execution_result
from pysymex.execution.scheduling import (
    collect_state_merger_stats,
    collect_worklist_stats,
    create_path_manager,
)
from pysymex.execution.scheduling.telemetry import SchedulerEventSource
from pysymex.execution.session.state import ExecutionSession
from pysymex.execution.engine.lifecycle import reset_execution_run
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.analysis.static.cross_function import CrossFunctionAnalyzer
    from pysymex.core.graph.cig import ConstraintInteractionGraph
    from pysymex.core.state.record import VMState
    from pysymex.execution.config.settings import ExecutionConfig
    from pysymex.execution.strategies.merger.state import StateMerger
    from pysymex.resources.tracker import ResourceTracker
    from pysymex.typing import SolverProtocol, StackValue

__all__ = [
    "build_line_mapping",
    "clear_line_mapping_cache",
    "finalize_execution_result",
    "line_mapping_cache_stats",
    "OptionalFunctionPrepassResult",
    "prepare_bytecode_execution",
    "resolve_line_number",
    "reset_execution_run",
    "run_optional_function_prepasses",
    "seed_function_execution_context",
    "start_path_exploration",
]

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class OptionalFunctionPrepassResult:
    """Updated optional pre-pass state after function execution preparation."""

    cross_function: CrossFunctionAnalyzer | None
    effect_summaries: dict[str, object] | None
    type_analyzer: TypeAnalyzer | None
    type_inference_ran: bool


def resolve_line_number(
    *,
    session: ExecutionSession,
    pc: int,
    active_instructions: list[dis.Instruction],
) -> int | None:
    """Resolve a source line for a program counter in the active instruction stream."""
    if active_instructions is session.instructions:
        return session.pc_to_line.get(pc)
    for index in range(min(pc, len(active_instructions) - 1), -1, -1):
        instr = active_instructions[index]
        if (position := getattr(instr, "positions", None)) is not None and position.lineno:
            return position.lineno
        if getattr(instr, "starts_line", None) is not None:
            return instr.starts_line
    return None


def start_path_exploration(
    *,
    session: ExecutionSession,
    config: ExecutionConfig,
    interaction_graph: ConstraintInteractionGraph,
    state_merger: StateMerger | None,
    initial_state: VMState,
    code: CodeType,
) -> None:
    """Seed the run worklist and configure optional path pre-analysis."""
    session.worklist = create_path_manager(
        config.strategy,
        deterministic=config.deterministic_mode,
        random_seed=config.random_seed,
        cig=interaction_graph,
        frontier_runtime_mode=config.frontier_runtime_mode,
    )
    if session.scheduler_event_observers and isinstance(session.worklist, SchedulerEventSource):
        session.worklist.add_scheduler_event_observer(session.record_scheduler_event)
    session.worklist.add_state(initial_state)
    if config.use_loop_analysis:
        session.loop_detector = LoopDetector()
        session.loop_detector.analyze_cfg(session.instructions)
        session.loop_detectors[instruction_stream_key(session.instructions)] = session.loop_detector
        session.loop_widening = LoopWidening(widening_threshold=config.max_loop_iterations)
    if state_merger is not None:
        try:
            state_merger.detect_join_points(session.instructions, code=code)
        except (AttributeError, TypeError, IndexError, ValueError):
            logger.warning("State merger join-point detection failed", exc_info=True)
            session.record_fallback_event(state_merger_prepass_event())


def seed_function_execution_context(
    *,
    initial_state: VMState,
    func: Callable[..., object],
    code: CodeType,
) -> VMState:
    """Bind closure cells and same-module globals before function exploration."""
    try:
        closure = getattr(func, "__closure__", None)
        freevars = list(getattr(code, "co_freevars", ()))
        if closure and freevars:
            for fv_name, cell in zip(freevars, closure, strict=False):
                try:
                    initial_state = initial_state.set_local(fv_name, cell.cell_contents)
                except ValueError:
                    continue
    except (AttributeError, TypeError):
        logger.debug("Closure cell binding skipped", exc_info=True)

    try:
        module_vars: dict[str, StackValue] = {}
        for g_name, g_val in same_module_function_or_class_globals(func).items():
            module_vars[g_name] = cast("StackValue", g_val)
        for g_name, g_val in referenced_same_module_instance_globals(func, code).items():
            module_vars[g_name] = cast("StackValue", g_val)
        if module_vars:
            for g_name, g_val in module_vars.items():
                initial_state.global_vars[g_name] = g_val
    except (AttributeError, TypeError):
        logger.debug("Module global seeding skipped", exc_info=True)
    return initial_state


def run_optional_function_prepasses(
    *,
    session: ExecutionSession,
    code: CodeType,
    cross_function: CrossFunctionAnalyzer | None,
    enable_type_inference: bool,
) -> OptionalFunctionPrepassResult:
    """Run optional function-level pre-passes while preserving degraded metadata."""
    effect_summaries: dict[str, object] | None = None
    if cross_function is not None:
        try:
            cross_function.analyze_module(code)
            effect_summaries = cast(
                "dict[str, object]",
                getattr(cross_function, "effect_summaries", {}),
            )
        except (AttributeError, TypeError, RuntimeError, RecursionError):
            logger.warning("Cross-function analysis failed", exc_info=True)
            session.record_fallback_event(cross_function_prepass_event())
            cross_function = None

    type_analyzer: TypeAnalyzer | None = None
    if enable_type_inference:
        try:
            type_analyzer = TypeAnalyzer()
            type_analyzer.analyze_function(code)
        except (ImportError, AttributeError, TypeError, RuntimeError):
            logger.warning("Type analyzer initialization failed", exc_info=True)
            session.record_fallback_event(type_inference_prepass_event())
            type_analyzer = None

    return OptionalFunctionPrepassResult(
        cross_function=cross_function,
        effect_summaries=effect_summaries,
        type_analyzer=type_analyzer,
        type_inference_ran=enable_type_inference,
    )


def finalize_execution_result(
    *,
    session: ExecutionSession,
    enable_fp_filtering: bool,
    resource_tracker: ResourceTracker | None,
    solver: SolverProtocol,
    detector_query_stats: dict[str, object],
    state_merger: StateMerger | None,
    function_name: str,
    source_file: str,
    include_final_stack: bool,
    include_final_exception: bool,
) -> ExecutionResult:
    """Coordinate final result construction after a completed execution run."""
    if resource_tracker is None:
        raise RuntimeError("Resource tracker is unavailable")
    return build_execution_result(
        session=session,
        final_issues=filter_final_issues(
            session=session,
            enable_fp_filtering=enable_fp_filtering,
        ),
        resource_snapshot=resource_tracker.snapshot(),
        solver_stats=solver.get_stats(),
        detector_query_stats=detector_query_stats,
        state_merger_stats=collect_state_merger_stats(state_merger),
        worklist_stats=collect_worklist_stats(session.worklist),
        function_name=function_name,
        source_file=source_file,
        include_final_stack=include_final_stack,
        include_final_exception=include_final_exception,
    )
