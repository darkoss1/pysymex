from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol, cast

import z3

from pysymex.core.state import VMState
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig


class IncrementalSensitiveSolver:
    """Simulates an unsafe incremental mode that can hide UNSAT suffixes."""

    def __init__(self) -> None:
        self.prefix_lengths: list[int | None] = []

    def is_sat(self, constraints: object, known_sat_prefix_len: int | None = None) -> bool:
        self.prefix_lengths.append(known_sat_prefix_len)
        if hasattr(constraints, "to_list"):
            chain = cast("_ConstraintLike", constraints)
            exprs = chain.to_list()
        else:
            exprs = list(cast(Iterable[z3.BoolRef], constraints))

        # Deliberately emulate buggy behavior when prefix hints are used.
        if known_sat_prefix_len is not None:
            return True

        solver = z3.Solver()
        solver.add(*exprs)
        return solver.check() == z3.sat


@dataclass(frozen=True)
class BenchmarkOutcome:
    total_candidates: int
    expected_unsat: int
    expected_sat: int
    predicted_unsat: int
    predicted_sat: int
    correctly_classified: int
    accuracy: float


class _ConstraintLike(Protocol):
    def to_list(self) -> list[z3.BoolRef]:
        ...


def _build_candidates() -> tuple[VMState, list[VMState], int, int]:
    x = z3.Int("x")
    y = z3.Int("y")
    z = z3.Int("z")

    parent = VMState(path_constraints=[x >= 0], pc=10)

    candidates = [
        VMState(path_constraints=[x >= 0, x < 0], pc=11),
        VMState(path_constraints=[y == 3, y != 3], pc=12),
        VMState(path_constraints=[z > 5, z < 2], pc=13),
        VMState(path_constraints=[x >= 0, x <= 3], pc=14),
        VMState(path_constraints=[y > 1, y < 8], pc=15),
    ]

    expected_unsat = 3
    expected_sat = 2
    return parent, candidates, expected_unsat, expected_sat


def run_benchmark() -> BenchmarkOutcome:
    executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40, enable_chtd=True))
    fake_solver = IncrementalSensitiveSolver()
    executor.solver = fake_solver  # type: ignore[assignment]

    parent, candidates, expected_unsat, expected_sat = _build_candidates()

    partition = getattr(executor, "_partition_chtd_unsat")
    unsat_states, sat_states = partition(
        parent_state=parent,
        forked_states=candidates,
    )

    correctly_classified = 0
    for state in unsat_states:
        solver = z3.Solver()
        solver.add(*state.path_constraints.to_list())
        if solver.check() == z3.unsat:
            correctly_classified += 1

    for state in sat_states:
        solver = z3.Solver()
        solver.add(*state.path_constraints.to_list())
        if solver.check() == z3.sat:
            correctly_classified += 1

    total = len(candidates)
    accuracy = correctly_classified / total if total else 0.0

    print("=== CHTD Lossless Validation Benchmark ===")
    print(f"Total candidates: {total}")
    print(f"Expected UNSAT: {expected_unsat}, Predicted UNSAT: {len(unsat_states)}")
    print(f"Expected SAT:   {expected_sat}, Predicted SAT:   {len(sat_states)}")
    print(f"Classification accuracy: {accuracy * 100.0:.1f}%")
    print(f"Prefix lengths observed in solver calls: {fake_solver.prefix_lengths}")

    return BenchmarkOutcome(
        total_candidates=total,
        expected_unsat=expected_unsat,
        expected_sat=expected_sat,
        predicted_unsat=len(unsat_states),
        predicted_sat=len(sat_states),
        correctly_classified=correctly_classified,
        accuracy=accuracy,
    )


def main() -> int:
    outcome = run_benchmark()
    if outcome.accuracy < 1.0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
