from __future__ import annotations

from collections.abc import Iterable

import pytest
import z3

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability


def test_path_is_sat_uses_solver_for_long_nontrivial_contradictions() -> None:
    x = z3.Int("x")
    padding = [z3.Int(f"p{i}") == i for i in range(12)]

    assert PathSatisfiability.is_sat([*padding, x > 0, x < 0]) is False


def test_path_is_sat_keeps_satisfiable_long_paths_feasible() -> None:
    x = z3.Int("x")
    padding = [z3.Int(f"q{i}") == i for i in range(12)]

    assert PathSatisfiability.is_sat([*padding, x > 0, x < 5]) is True


def test_path_is_sat_preserves_known_prefix_after_literal_filtering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    x = z3.Int("prefix_filter_x")
    y = z3.Int("prefix_filter_y")
    seen_prefixes: list[int | None] = []
    seen_constraint_counts: list[int] = []

    def feasible(
        constraints: Iterable[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        materialized = list(constraints)
        seen_prefixes.append(known_sat_prefix_len)
        seen_constraint_counts.append(len(materialized))
        return True

    monkeypatch.setattr(
        "pysymex._internal.execution.opcodes.common.satisfiability.path_may_be_feasible",
        feasible,
    )

    assert (
        PathSatisfiability.is_sat(
            [Z3_TRUE, x > 0, Z3_TRUE, y > 0, x < 5],
            known_sat_prefix_len=4,
        )
        is True
    )
    assert seen_prefixes == [2]
    assert seen_constraint_counts == [3]
