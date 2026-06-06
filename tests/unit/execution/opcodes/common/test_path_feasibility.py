from __future__ import annotations

from unittest.mock import patch

import z3

from pysymex.execution.opcodes.common.path_feasibility import path_is_sat


def test_path_is_sat_short_circuits_literal_false_without_solver() -> None:
    x = z3.Int("x")

    with patch(
        "pysymex.execution.opcodes.common.path_feasibility.path_may_be_feasible",
        side_effect=AssertionError("literal false should not query the solver"),
    ):
        assert path_is_sat([x > 0, z3.BoolVal(False)]) is False


def test_path_is_sat_strips_literal_true_before_solver() -> None:
    x = z3.Int("x")

    with patch(
        "pysymex.execution.opcodes.common.path_feasibility.path_may_be_feasible",
        return_value=True,
    ) as may_be_feasible:
        assert path_is_sat([z3.BoolVal(True), x > 0]) is True

    may_be_feasible.assert_called_once_with([x > 0])


def test_path_is_sat_short_circuits_negated_true_without_solver() -> None:
    x = z3.Int("x_path_not_true")

    with patch(
        "pysymex.execution.opcodes.common.path_feasibility.path_may_be_feasible",
        side_effect=AssertionError("Not(True) should not query the solver"),
    ):
        assert path_is_sat([x > 0, z3.Not(z3.BoolVal(True))]) is False


def test_path_is_sat_strips_negated_false_before_solver() -> None:
    x = z3.Int("x_path_not_false")

    with patch(
        "pysymex.execution.opcodes.common.path_feasibility.path_may_be_feasible",
        return_value=True,
    ) as may_be_feasible:
        assert path_is_sat([z3.Not(z3.BoolVal(False)), x > 0]) is True

    may_be_feasible.assert_called_once_with([x > 0])


def test_path_is_sat_short_circuits_constant_false_comparison_without_solver() -> None:
    x = z3.Int("x_path_constant_false")

    with patch(
        "pysymex.execution.opcodes.common.path_feasibility.path_may_be_feasible",
        side_effect=AssertionError("constant false comparison should not query the solver"),
    ):
        assert path_is_sat([x > 0, z3.IntVal(3) < z3.IntVal(3)]) is False
