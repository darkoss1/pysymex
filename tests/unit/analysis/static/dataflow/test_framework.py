"""Tests for the data-flow fixed-point framework."""

from __future__ import annotations

from tests.unit.analysis.static.dataflow.helpers import ConcreteDataFlow, MockCFG, make_block


class TestDataFlowAnalysis:
    """Test suite for pysymex.analysis.static.dataflow.framework.DataFlowAnalysis."""

    def test_initial_value(self) -> None:
        df = ConcreteDataFlow(MockCFG())
        assert df.initial_value() == "init"

    def test_boundary_value(self) -> None:
        df = ConcreteDataFlow(MockCFG())
        assert df.boundary_value() == "bound"

    def test_transfer(self) -> None:
        df = ConcreteDataFlow(MockCFG())
        bb = make_block(1)
        assert df.transfer(bb, "x") == "x_1"

    def test_meet(self) -> None:
        df = ConcreteDataFlow(MockCFG())
        assert df.meet(["b", "a"]) == "a+b"

    def test_is_forward(self) -> None:
        df = ConcreteDataFlow(MockCFG())
        assert df.is_forward() is True

    def test_analyze(self) -> None:
        cfg = MockCFG()
        b0 = make_block(0, successors={1})
        b1 = make_block(1, predecessors={0})
        cfg.blocks = {0: b0, 1: b1}
        df = ConcreteDataFlow(cfg)
        df.analyze()
        assert df.in_facts[0] == "bound"
        assert df.out_facts[0] == "bound_0"
        assert df.in_facts[1] == "bound_0"
        assert df.out_facts[1] == "bound_0_1"

    def test_get_in(self) -> None:
        df = ConcreteDataFlow(MockCFG())
        assert df.get_in(99) == "init"

    def test_get_out(self) -> None:
        df = ConcreteDataFlow(MockCFG())
        assert df.get_out(99) == "init"
