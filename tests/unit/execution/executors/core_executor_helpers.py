"""Shared helpers for core symbolic executor tests."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex._internal.core.solver.engine.results import SolverResult


class IncrementalSensitiveSolver:
    """A fake solver that would misclassify UNSAT if prefix mode were used."""

    def __init__(self) -> None:
        self.prefix_args: list[int | None] = []

    def check(
        self,
        *assumptions: z3.BoolRef,
        need_model: bool = True,
    ) -> SolverResult | z3.CheckSatResult:
        _ = need_model
        solver = z3.Solver()
        solver.add(*assumptions)
        if solver.check() == z3.sat:
            return SolverResult.sat(solver.model())
        return SolverResult.unsat()

    def push(self) -> None:
        return None

    def pop(self) -> None:
        return None

    def add(self, *constraints: z3.BoolRef) -> None:
        _ = constraints

    def reset(self) -> None:
        self.prefix_args = []

    def path_may_be_feasible(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        self.prefix_args.append(known_sat_prefix_len)
        if known_sat_prefix_len is not None:
            return True
        exprs = list(constraints)
        solver = z3.Solver()
        solver.add(*exprs)
        return solver.check() == z3.sat

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        return (
            SolverResult.sat(None)
            if self.path_may_be_feasible(constraints, known_sat_prefix_len)
            else SolverResult.unsat()
        )

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        solver = z3.Solver()
        solver.add(*constraints)
        if solver.check() != z3.sat:
            return None
        return solver.model()

    def check_sat_cached(
        self,
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = known_sat_prefix_len
        solver = z3.Solver()
        solver.add(*constraints)
        if solver.check() == z3.sat:
            return SolverResult.sat(solver.model())
        return SolverResult.unsat()

    def get_stats(self) -> dict[str, object]:
        return {}

    def constraint_optimizer(self) -> object:
        return self

    def set_deadline(self, deadline_time: float | None) -> None:
        _ = deadline_time


class UnknownSolver(IncrementalSensitiveSolver):
    """A solver double that models Z3 timeout/unknown for detector feasibility."""

    def path_may_be_feasible(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        _ = constraints
        self.prefix_args.append(known_sat_prefix_len)
        return True

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = list(constraints)
        self.prefix_args.append(known_sat_prefix_len)
        return SolverResult.unknown()

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        _ = constraints
        return None

    def check_sat_cached(
        self,
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = constraints
        _ = known_sat_prefix_len
        return SolverResult.unknown()


def simple(x: int) -> int:
    if x > 0:
        return x + 1
    return x - 1
