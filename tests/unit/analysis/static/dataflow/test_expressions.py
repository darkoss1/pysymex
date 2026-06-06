"""Tests for available-expression analysis."""

from __future__ import annotations

from pysymex.analysis.static.dataflow.expressions import AvailableExpressions
from pysymex.analysis.static.dataflow.types import Expression
from tests.unit.analysis.static.dataflow.helpers import MockCFG, MockInstr, make_block


class TestAvailableExpressions:
    """Test suite for pysymex.analysis.static.dataflow.expressions.AvailableExpressions."""

    def test_initial_value(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {
            0: make_block(
                0,
                [
                    MockInstr("LOAD_FAST", 10, "x"),
                    MockInstr("LOAD_FAST", 12, "y"),
                    MockInstr("BINARY_OP", 14, "+", "+"),
                ],
            )
        }
        ae = AvailableExpressions(cfg)
        assert len(ae.initial_value()) == 1

    def test_boundary_value(self) -> None:
        ae = AvailableExpressions(MockCFG())
        assert ae.boundary_value() == frozenset()

    def test_transfer(self) -> None:
        cfg = MockCFG()
        bb = make_block(
            0,
            [
                MockInstr("LOAD_FAST", 10, "x"),
                MockInstr("LOAD_FAST", 12, "y"),
                MockInstr("BINARY_OP", 14, "+", "+"),
            ],
        )
        cfg.blocks = {0: bb}
        ae = AvailableExpressions(cfg)
        out = ae.transfer(bb, frozenset())
        assert len(out) == 1

    def test_collects_cpython_unary_expression(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {
            0: make_block(
                0,
                [
                    MockInstr("LOAD_FAST", 10, "x"),
                    MockInstr("UNARY_NEGATIVE", 12, argrepr="-"),
                ],
            )
        }

        ae = AvailableExpressions(cfg)

        assert Expression("-", ("x",)) in ae.all_expressions

    def test_transfer_delete_kills_expressions_using_deleted_variable(self) -> None:
        ae = AvailableExpressions(MockCFG())
        killed = Expression("+", ("x", "y"))
        retained = Expression("*", ("a", "b"))
        bb = make_block(0, [MockInstr("DELETE_NAME", 10, "x")])

        out = ae.transfer(bb, frozenset([killed, retained]))

        assert killed not in out
        assert retained in out

    def test_meet(self) -> None:
        ae = AvailableExpressions(MockCFG())
        e1 = Expression("+", ("a", "b"))
        e2 = Expression("-", ("a", "c"))
        assert ae.meet([frozenset([e1, e2]), frozenset([e1])]) == frozenset([e1])
