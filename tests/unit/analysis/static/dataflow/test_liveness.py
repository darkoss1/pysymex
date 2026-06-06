"""Tests for live-variable analysis."""

from __future__ import annotations

from pysymex.analysis.static.dataflow.liveness import LiveVariables
from tests.unit.analysis.static.dataflow.helpers import MockCFG, MockInstr, make_block


class TestLiveVariables:
    """Test suite for pysymex.analysis.static.dataflow.liveness.LiveVariables."""

    def test_is_forward(self) -> None:
        lv = LiveVariables(MockCFG())
        assert lv.is_forward() is False

    def test_initial_value(self) -> None:
        lv = LiveVariables(MockCFG())
        assert lv.initial_value() == frozenset()

    def test_boundary_value(self) -> None:
        lv = LiveVariables(MockCFG())
        assert lv.boundary_value() == frozenset()

    def test_transfer(self) -> None:
        lv = LiveVariables(MockCFG())
        bb = make_block(1, [MockInstr("LOAD_NAME", 20, "y")])
        out = lv.transfer(bb, frozenset(["x"]))
        assert "x" in out and "y" in out

    def test_meet(self) -> None:
        lv = LiveVariables(MockCFG())
        assert lv.meet([frozenset(["a"]), frozenset(["b"])]) == frozenset(["a", "b"])

    def test_is_live_at(self) -> None:
        cfg = MockCFG()
        instr1 = MockInstr("STORE_NAME", 10, "x")
        instr2 = MockInstr("LOAD_NAME", 20, "y")
        cfg.blocks = {1: make_block(1, [instr1, instr2])}
        lv = LiveVariables(cfg)
        lv.out_facts[1] = frozenset(["z"])
        assert lv.is_live_at("y", 10) is True
        assert lv.is_live_at("z", 10) is True
