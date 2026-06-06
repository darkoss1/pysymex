"""Tests for modeled ``__len__`` return normalization."""

from __future__ import annotations

from typing import cast
from unittest.mock import patch

import z3

from pysymex.core.state.record import VMState
from pysymex.core.state.types import CallFrame, wrap_cow_dict
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.opcodes.common.control.length_returns import (
    fork_feasible_negative_symbolic_length,
    normalize_length_protocol_return,
)
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def _length_frame(protocol_method: str = "__len__") -> CallFrame:
    return CallFrame(
        "modeled_len",
        0,
        wrap_cow_dict({}),
        0,
        protocol_method=protocol_method,
    )


def test_normalize_length_protocol_return_proves_positive_mod_sum_without_solver() -> None:
    """Positive-divisor modulo sums cannot produce negative ``__len__`` results."""
    x = z3.Int("len_mod_x")
    y = z3.Int("len_mod_y")
    return_value = SymbolicValue(
        _name="len_mod_sum",
        z3_int=(x % 4) + (y % 2),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        affinity_type="int",
    )

    with patch(
        "pysymex.core.solver.engine.queries.check_sat_result",
        side_effect=AssertionError("syntactic nonnegative length should not query solver"),
    ):
        result = normalize_length_protocol_return(
            _length_frame(),
            return_value,
            VMState(),
        )

    assert result is not None
    normalized, issue, degraded = result
    assert isinstance(normalized, SymbolicValue)
    solver = z3.Solver()
    solver.add(z3.Xor(normalized.z3_bool, return_value.z3_int != 0))
    assert solver.check() == z3.unsat
    assert issue is None
    assert degraded is None


def test_negative_length_fork_skips_positive_mod_sum_without_solver() -> None:
    """The negative-length branch is impossible for positive modulo sums."""
    x = z3.Int("fork_len_mod_x")
    return_value = SymbolicValue(
        _name="fork_len_mod_sum",
        z3_int=x % 3,
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        affinity_type="int",
    )

    with patch(
        "pysymex.core.solver.engine.queries.check_sat_result",
        side_effect=AssertionError("syntactic nonnegative length should not query solver"),
    ):
        result = fork_feasible_negative_symbolic_length(
            _length_frame(),
            return_value,
            VMState(),
            ctx=cast("OpcodeDispatcher", object()),
        )

    assert result is None


def test_negative_length_fork_reports_concrete_negative_len_return() -> None:
    """A concrete negative ``__len__`` result is a ``ValueError`` path."""
    result = fork_feasible_negative_symbolic_length(
        _length_frame(),
        SymbolicValue.from_const(-1),
        VMState(),
        ctx=cast("OpcodeDispatcher", object()),
    )

    assert result is not None
    resumed_state, error_result = result
    assert resumed_state is None
    assert len(error_result.issues) == 1
    assert error_result.issues[0].kind.name == "VALUE_ERROR"
    assert "__len__() should return >= 0" in error_result.issues[0].message
