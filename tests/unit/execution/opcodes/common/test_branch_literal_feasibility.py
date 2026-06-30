from __future__ import annotations

from unittest.mock import patch

import z3

from pysymex._internal.execution.opcodes.common.control.feasibility.branching import branch_feasible


def test_branch_feasible_rejects_exact_false_literal_without_solver() -> None:
    with patch(
        "pysymex._internal.core.solver.engine.policies.path_may_be_feasible"
    ) as solver_query:
        assert branch_feasible([], z3.Not(z3.BoolVal(True))) is False

    solver_query.assert_not_called()


def test_branch_feasible_checks_existing_path_for_exact_true_literal() -> None:
    x = z3.Int("branch_exact_true_x")

    with patch(
        "pysymex._internal.core.solver.engine.policies.path_may_be_feasible",
        return_value=False,
    ) as solver_query:
        assert branch_feasible([x > 0, x < 0], z3.Not(z3.BoolVal(False))) is False

    solver_query.assert_called_once()
    constraints = solver_query.call_args.args[0]
    assert constraints == [x > 0, x < 0]
