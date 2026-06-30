"""Tests for engine-owned worklist draining."""

from __future__ import annotations

import dis
from collections.abc import Callable
from typing import cast

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.graph.cig import ConstraintInteractionGraph
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.engine.exploration import start_path_exploration
from pysymex._internal.execution.engine.exploration import (
    start_path_exploration as direct_start_path_exploration,
)
from pysymex._internal.execution.engine.finalization import finalize_execution_result
from pysymex._internal.execution.engine.finalization import (
    finalize_execution_result as direct_finalize_execution_result,
)
from pysymex._internal.execution.engine.line.resolution import resolve_line_number
from pysymex._internal.execution.engine.line.resolution import (
    resolve_line_number as direct_resolve_line_number,
)
from pysymex._internal.execution.engine.seeding import seed_function_execution_context
from pysymex._internal.execution.engine.seeding import (
    seed_function_execution_context as direct_seed_function_execution_context,
)
from pysymex._internal.execution.engine.worklist import WorklistLoopContext, drain_worklist
from pysymex._internal.execution.scheduling.factory import create_path_manager
from pysymex._internal.execution.scheduling.telemetry import SchedulerEvent
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.execution.strategies.manager.path import AdaptivePathManager
from tests.unit.execution.executors.core_executor_helpers import IncrementalSensitiveSolver


def _loop_context(
    *,
    session: ExecutionSession,
    config: ExecutionConfig,
    solver: IncrementalSensitiveSolver,
    execute_step: Callable[[VMState], None],
) -> WorklistLoopContext:
    return WorklistLoopContext(
        session=session,
        config=config,
        solver=solver,
        resource_tracker=None,
        execute_step=execute_step,
    )


def _scheduler_observer_count(worklist: object) -> int:
    observers = getattr(worklist, "_scheduler_event_observers", ())
    if not isinstance(observers, list):
        return 0
    return len(cast("list[object]", observers))


def test_engine_public_exports_use_direct_owners() -> None:
    assert resolve_line_number is direct_resolve_line_number
    assert start_path_exploration is direct_start_path_exploration
    assert seed_function_execution_context is direct_seed_function_execution_context
    assert finalize_execution_result is direct_finalize_execution_result


def test_drain_worklist_restores_outer_active_solver_context() -> None:
    """Nested worklist loops must not erase an existing active solver context."""
    config = ExecutionConfig(max_paths=2, max_iterations=20)
    session = ExecutionSession()
    session.worklist = create_path_manager(config.strategy)
    outer_solver = IncrementalSensitiveSolver()
    inner_solver = IncrementalSensitiveSolver()

    def execute_step(_state: VMState) -> None:
        raise AssertionError("empty worklist should not execute a step")

    token = SolverContext.active.set(outer_solver)
    try:
        drain_worklist(
            _loop_context(
                session=session,
                config=config,
                solver=inner_solver,
                execute_step=execute_step,
            )
        )
        active_solver = SolverContext.active.get()
    finally:
        SolverContext.active.reset(token)

    assert active_solver is outer_solver


def test_drain_worklist_automatic_mode_sets_no_total_deadline() -> None:
    """Automatic host exploration must not synthesize a wall-clock stop."""

    class RecordingSolver(IncrementalSensitiveSolver):
        def __init__(self) -> None:
            super().__init__()
            self.deadlines: list[float | None] = []

        def set_deadline(self, deadline_time: float | None) -> None:
            self.deadlines.append(deadline_time)

    config = ExecutionConfig()
    session = ExecutionSession()
    session.worklist = create_path_manager(config.strategy)
    solver = RecordingSolver()

    drain_worklist(
        _loop_context(
            session=session,
            config=config,
            solver=solver,
            execute_step=lambda _state: None,
        )
    )

    assert solver.deadlines == [None, None]


def test_resolve_line_number_uses_root_session_mapping() -> None:
    """Root bytecode line resolution should use the prepared session PC map."""
    session = ExecutionSession()
    session.instructions = list(
        dis.get_instructions(test_resolve_line_number_uses_root_session_mapping)
    )
    session.pc_to_line[0] = 123

    line_no = resolve_line_number(
        session=session,
        pc=0,
        active_instructions=session.instructions,
    )

    assert line_no == 123


def test_drain_worklist_records_step_timing_count_and_scheduler_reward() -> None:
    config = ExecutionConfig(max_paths=2, max_iterations=20)
    session = ExecutionSession()
    worklist = create_path_manager(config.strategy)
    assert isinstance(worklist, AdaptivePathManager)
    session.worklist = worklist
    state = VMState(pc=0)
    worklist.add_state(state)
    executed_pcs: list[int] = []

    def execute_step(next_state: VMState) -> None:
        executed_pcs.append(next_state.pc)

    drain_worklist(
        _loop_context(
            session=session,
            config=config,
            solver=IncrementalSensitiveSolver(),
            execute_step=execute_step,
        )
    )

    assert executed_pcs == [0]
    assert session.iterations == 1
    assert session.phase_counts["execute_step"] == 1
    assert session.phase_timers_seconds["execute_step"] >= 0.0
    assert worklist.get_stats()["total_rewards"] == -0.5


def test_start_path_exploration_skips_scheduler_observer_without_trace() -> None:
    """Default execution should not allocate scheduler events when tracing is absent."""
    session = ExecutionSession()

    start_path_exploration(
        session=session,
        config=ExecutionConfig(use_loop_analysis=False),
        interaction_graph=ConstraintInteractionGraph(),
        state_merger=None,
        initial_state=VMState(pc=0),
        code=test_start_path_exploration_skips_scheduler_observer_without_trace.__code__,
    )

    assert isinstance(session.worklist, AdaptivePathManager)
    assert _scheduler_observer_count(session.worklist) == 0


def test_start_path_exploration_connects_scheduler_observer_when_trace_installed() -> None:
    """Scheduler telemetry is connected only when a session observer exists."""
    session = ExecutionSession()
    events: list[SchedulerEvent] = []
    session.add_scheduler_event_observer(events.append)

    start_path_exploration(
        session=session,
        config=ExecutionConfig(use_loop_analysis=False),
        interaction_graph=ConstraintInteractionGraph(),
        state_merger=None,
        initial_state=VMState(pc=0, path_id=3),
        code=test_start_path_exploration_connects_scheduler_observer_when_trace_installed.__code__,
    )

    assert isinstance(session.worklist, AdaptivePathManager)
    assert _scheduler_observer_count(session.worklist) == 1
    assert len(events) == 1
    assert events[0].action == "enqueue"
    assert events[0].path_id == 3
