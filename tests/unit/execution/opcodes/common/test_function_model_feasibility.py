from __future__ import annotations

import z3
import pytest

from pysymex.core.solver.engine.results import SolverResult
from pysymex.execution.calls import model_dispatch as models
from pysymex.execution.calls.model_dispatch import path_is_sat


def test_function_model_path_is_sat_uses_solver_for_long_nontrivial_contradictions() -> None:
    x = z3.Int("x")
    padding = [z3.Int(f"p{i}") == i for i in range(12)]

    assert path_is_sat([*padding, x > 0, x < 0]) is False


def test_function_model_path_is_sat_keeps_satisfiable_long_paths_feasible() -> None:
    x = z3.Int("x")
    padding = [z3.Int(f"q{i}") == i for i in range(12)]

    assert path_is_sat([*padding, x > 0, x < 5]) is True


def test_model_side_effect_issue_feasibility_rejects_solver_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unknown_result(constraints: list[z3.BoolRef]) -> SolverResult:
        assert constraints
        return SolverResult.unknown()

    monkeypatch.setattr(models, "check_sat_result", unknown_result)

    assert models.reportable_issue_path_is_sat([z3.BoolVal(True)]) is False


def test_model_side_effect_issue_feasibility_accepts_verified_witness_before_solver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = z3.String("model_side_effect_witness_text_str")
    parsed = z3.Int("int_model_side_effect_witness_text_int")

    def fail_solver(_constraints: list[z3.BoolRef]) -> SolverResult:
        raise AssertionError("verified concrete witness should avoid the solver")

    monkeypatch.setattr(models, "check_sat_result", fail_solver)

    assert (
        models.reportable_issue_path_is_sat(
            [
                z3.InRe(text, z3.Plus(z3.Re("0"))),
                parsed == z3.StrToInt(text),
                parsed == 0,
            ]
        )
        is True
    )
