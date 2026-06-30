"""Tests that path-feasibility observers do not change pruning behavior."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.feasibility.policy import check_path_feasibility
from pysymex._internal.execution.feasibility.telemetry import PathFeasibilityEvent
from pysymex._internal.execution.session.state.core import ExecutionSession


class UnknownSolver:
    """Solver double that forces path-feasibility checks to stay inconclusive."""

    def __init__(self) -> None:
        self.checked_constraints: list[list[z3.BoolRef]] = []
        self.prefix_args: list[int | None] = []
        self.added_constraints: list[z3.BoolRef] = []

    def check(
        self,
        *assumptions: z3.BoolRef,
        need_model: bool = True,
    ) -> SolverResult | z3.CheckSatResult:
        _ = assumptions
        _ = need_model
        return SolverResult.unknown()

    def push(self) -> None:
        return None

    def pop(self) -> None:
        return None

    def reset(self) -> None:
        self.checked_constraints = []
        self.prefix_args = []
        self.added_constraints = []

    def path_may_be_feasible(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        self.checked_constraints.append(list(constraints))
        self.prefix_args.append(known_sat_prefix_len)
        return True

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        self.checked_constraints.append(list(constraints))
        self.prefix_args.append(known_sat_prefix_len)
        return SolverResult.unknown()

    def add(self, *constraints: z3.BoolRef) -> None:
        self.added_constraints.extend(constraints)

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        _ = constraints
        return None

    def check_sat_cached(
        self,
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = constraints
        self.prefix_args.append(known_sat_prefix_len)
        return SolverResult.unknown()

    def get_stats(self) -> dict[str, object]:
        return {}

    def constraint_optimizer(self) -> object:
        return self

    def set_deadline(self, deadline_time: float | None) -> None:
        _ = deadline_time


def test_path_feasibility_observer_does_not_bypass_solver_unknown() -> None:
    session = ExecutionSession()
    observed: list[PathFeasibilityEvent] = []
    session.add_path_feasibility_event_observer(observed.append)
    solver = UnknownSolver()
    x = z3.Int("observer_transparency_x")
    state = VMState(path_constraints=[x >= 0, x < 0], pending_constraint_count=2)

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    assert result is True
    assert len(solver.checked_constraints) == 1
    assert solver.prefix_args == [0]
    assert solver.added_constraints == []
    assert session.paths_pruned == 0
    assert state.pending_constraint_count == 2
    assert len(observed) == 1
    assert observed[0].result == "inconclusive"
    assert observed[0].result_source == "solver_unknown"
    assert observed[0].solver_called is True
