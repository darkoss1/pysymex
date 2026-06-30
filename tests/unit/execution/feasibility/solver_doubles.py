"""Solver doubles shared by execution feasibility tests."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex._internal.core.solver.engine.results import SolverResult


class RecordingSolver:
    """Solver double for execution-facing path feasibility tests."""

    def __init__(self, *, feasible: bool, result: SolverResult | None = None) -> None:
        self.result = result or (SolverResult.sat(None) if feasible else SolverResult.unsat())
        self.prefix_args: list[int | None] = []
        self.checked_constraints: list[list[z3.BoolRef]] = []
        self.added_constraints: list[z3.BoolRef] = []

    def check(
        self,
        *assumptions: z3.BoolRef,
        need_model: bool = True,
    ) -> SolverResult | z3.CheckSatResult:
        _ = assumptions
        _ = need_model
        return self.result

    def push(self) -> None:
        return None

    def pop(self) -> None:
        return None

    def add(self, *constraints: z3.BoolRef) -> None:
        self.added_constraints.extend(constraints)

    def reset(self) -> None:
        self.prefix_args = []
        self.checked_constraints = []
        self.added_constraints = []

    def path_may_be_feasible(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        _ = list(constraints)
        self.prefix_args.append(known_sat_prefix_len)
        return not self.result.is_unsat

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        self.checked_constraints.append(list(constraints))
        self.prefix_args.append(known_sat_prefix_len)
        return self.result

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
        return self.result

    def get_stats(self) -> dict[str, object]:
        return {}

    def constraint_optimizer(self) -> object:
        return self

    def set_deadline(self, deadline_time: float | None) -> None:
        _ = deadline_time


class ExtendingSolver(RecordingSolver):
    """Solver double that exposes the incremental path-extension capability."""

    def __init__(self) -> None:
        super().__init__(feasible=True)
        self.extended_constraints: list[z3.BoolRef] = []

    def extend_path(self, constraints: Iterable[z3.BoolRef]) -> None:
        self.extended_constraints.extend(constraints)
