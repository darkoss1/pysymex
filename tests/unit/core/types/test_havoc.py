import z3

import pysymex._internal.core.types.havoc


class TestHavocValue:
    """Test suite for pysymex._internal.core.types.havoc.HavocValue."""

    def test_havoc(self) -> None:
        """Scenario: havoc factory call; expected HavocValue instance result."""
        value, _constraint = pysymex._internal.core.types.havoc.HavocValue.havoc("h0")
        assert isinstance(value, pysymex._internal.core.types.havoc.HavocValue)

    def test_havoc_type_constraint_requires_exactly_one_type(self) -> None:
        """Scenario: havoc type discriminator; expected exactly one active type."""
        value, constraint = pysymex._internal.core.types.havoc.HavocValue.havoc("h_exactly_one")
        type_vars = [
            value.is_int,
            value.is_bool,
            value.is_str,
            value.is_path,
            value.is_obj,
            value.is_none,
            value.is_float,
            value.is_list,
            value.is_dict,
        ]

        all_false_solver = z3.Solver()
        all_false_solver.add(constraint, *[z3.Not(type_var) for type_var in type_vars])
        assert all_false_solver.check() == z3.unsat

        two_true_solver = z3.Solver()
        two_true_solver.add(constraint, value.is_int, value.is_bool)
        assert two_true_solver.check() == z3.unsat

        one_true_solver = z3.Solver()
        one_true_solver.add(
            constraint,
            value.is_int,
            *[z3.Not(type_var) for type_var in type_vars[1:]],
        )
        assert one_true_solver.check() == z3.sat


def test_is_havoc() -> None:
    """Scenario: check helper on havoc value; expected true."""
    value, _constraint = pysymex._internal.core.types.havoc.HavocValue.havoc("h1")
    assert pysymex._internal.core.types.havoc.is_havoc(value) is True
