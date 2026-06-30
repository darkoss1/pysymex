"""Tests for exact state coverage shared by merging and loop convergence."""

from __future__ import annotations

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.strategies.merger.equality.coverage import (
    constraints_exactly_subsume,
    state_exactly_covers,
    state_payload_equal_except_locals,
)


def test_state_exactly_covers_stronger_recurrent_constraints() -> None:
    x = z3.Int("x")
    prior = VMState(local_vars={"value": 1}, path_constraints=[x > 0], pc=4)
    recurrent = VMState(
        local_vars={"value": 1},
        path_constraints=[x > 0, x < 10],
        visited_pcs={4, 5, 6},
        pc=4,
    )

    assert constraints_exactly_subsume(prior, recurrent) is True
    assert state_exactly_covers(prior, recurrent) is True


def test_state_exactly_covers_rejects_changed_payload() -> None:
    prior = VMState(local_vars={"value": 1}, pc=4)
    recurrent = VMState(local_vars={"value": 2}, pc=4)

    assert state_exactly_covers(prior, recurrent) is False
    assert state_payload_equal_except_locals(prior, recurrent) is True


def test_constraint_coverage_rejects_nonprefix_constraints() -> None:
    x = z3.Int("x")
    prior = VMState(path_constraints=[x > 0], pc=4)
    recurrent = VMState(path_constraints=[x >= 1], pc=4)

    assert constraints_exactly_subsume(prior, recurrent) is False
    assert state_exactly_covers(prior, recurrent) is False
