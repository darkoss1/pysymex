from __future__ import annotations

from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    append_fallback_events,
    degraded_passes_from_events,
    may_be_feasible,
    terminal_result_with_events,
    unknown_branch_names,
    unknown_feasibility_events,
)


def test_unknown_feasibility_event_is_single_deduplicated_diagnostic() -> None:
    spec = UnknownFeasibilitySpec(
        label="demo_unknown",
        owner="tests",
        subject="demo branch",
    )
    events = unknown_feasibility_events(
        state=VMState(pc=11),
        spec=spec,
        branches=[
            FeasibilityBranch("then", SolverResult.unknown()),
            FeasibilityBranch("else", SolverResult.sat(None)),
            FeasibilityBranch("then", SolverResult.unknown()),
        ],
    )

    assert unknown_branch_names(
        [
            FeasibilityBranch("then", SolverResult.unknown()),
            FeasibilityBranch("then", SolverResult.unknown()),
        ]
    ) == ["then"]
    assert len(events) == 1
    assert degraded_passes_from_events(events) == ["demo_unknown"]
    assert events[0].reason == "solver could not establish then demo branch feasibility"
    assert events[0].pc == 11


def test_unknown_helper_preserves_terminal_and_result_diagnostics() -> None:
    spec = UnknownFeasibilitySpec(
        label="terminal_unknown",
        owner="tests",
        subject="terminal branch",
    )
    events = unknown_feasibility_events(
        state=VMState(pc=7),
        spec=spec,
        branches=[FeasibilityBranch("path", SolverResult.unknown())],
    )

    terminal = terminal_result_with_events(events)
    assert terminal.terminal is True
    assert terminal.new_states == []
    assert terminal.degraded_passes == ["terminal_unknown"]
    assert terminal.fallback_events == events

    result = append_fallback_events(OpcodeResult.continue_with(VMState(pc=8)), events)
    assert result.terminal is False
    assert result.new_states[0].pc == 8
    assert result.degraded_passes == ["terminal_unknown"]
    assert result.fallback_events == events


def test_solver_result_may_be_feasible_policy() -> None:
    assert may_be_feasible(SolverResult.sat(None)) is True
    assert may_be_feasible(SolverResult.unknown()) is True
    assert may_be_feasible(SolverResult.unsat()) is False
