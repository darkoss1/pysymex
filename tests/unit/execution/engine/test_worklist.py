"""Tests for engine-owned worklist draining."""

from __future__ import annotations

from collections.abc import Callable
import dis
from typing import cast

from pysymex.core.graph.cig import ConstraintInteractionGraph
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.state.record import VMState
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.engine import resolve_line_number, start_path_exploration
from pysymex.execution.engine.worklist import WorklistLoopContext, drain_worklist
from pysymex.execution.scheduling.telemetry import SchedulerEvent
from pysymex.execution.scheduling import create_path_manager
from pysymex.execution.session.state import ExecutionSession
from pysymex.execution.strategies.manager.path import AdaptivePathManager
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
        record_degraded_passes=session.record_degraded_passes,
    )


def _scheduler_observer_count(worklist: object) -> int:
    observers = getattr(worklist, "_scheduler_event_observers", ())
    if not isinstance(observers, list):
        return 0
    return len(cast("list[object]", observers))


def test_drain_worklist_restores_outer_active_solver_context() -> None:
    """Nested worklist loops must not erase an existing active solver context."""
    config = ExecutionConfig(max_paths=2, max_iterations=20)
    session = ExecutionSession()
    session.worklist = create_path_manager(config.strategy)
    outer_solver = IncrementalSensitiveSolver()
    inner_solver = IncrementalSensitiveSolver()

    def execute_step(_state: VMState) -> None:
        raise AssertionError("empty worklist should not execute a step")

    token = active_incremental_solver.set(outer_solver)
    try:
        drain_worklist(
            _loop_context(
                session=session,
                config=config,
                solver=inner_solver,
                execute_step=execute_step,
            )
        )
        active_solver = active_incremental_solver.get()
    finally:
        active_incremental_solver.reset(token)

    assert active_solver is outer_solver


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
    config = ExecutionConfig(max_paths=2, max_iterations=20, deterministic_mode=True)
    session = ExecutionSession()
    worklist = create_path_manager(
        config.strategy,
        deterministic=config.deterministic_mode,
        random_seed=config.random_seed,
    )
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
