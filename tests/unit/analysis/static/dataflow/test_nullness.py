"""Tests for nullness analysis."""

from __future__ import annotations

from pysymex.analysis.static.dataflow.nullness import NullAnalysis
from pysymex.analysis.static.dataflow.types import NullInfo, NullState
from tests.unit.analysis.static.dataflow.helpers import MockCFG, MockInstr, make_block


class TestNullAnalysis:
    """Test suite for pysymex.analysis.static.dataflow.nullness.NullAnalysis."""

    def test_initial_value(self) -> None:
        na = NullAnalysis(MockCFG())
        assert isinstance(na.initial_value(), NullInfo)

    def test_boundary_value(self) -> None:
        na = NullAnalysis(MockCFG())
        assert isinstance(na.boundary_value(), NullInfo)

    def test_transfer(self) -> None:
        na = NullAnalysis(MockCFG())
        bb = make_block(0, [MockInstr("LOAD_CONST", 10, None), MockInstr("STORE_NAME", 12, "x")])
        out = na.transfer(bb, NullInfo())
        assert out.get_state("x") == NullState.DEFINITELY_NULL

    def test_transfer_delete_clears_nullness_fact(self) -> None:
        na = NullAnalysis(MockCFG())
        bb = make_block(
            0,
            [
                MockInstr("LOAD_CONST", 10, None),
                MockInstr("STORE_NAME", 12, "x"),
                MockInstr("DELETE_NAME", 14, "x"),
            ],
        )
        out = na.transfer(bb, NullInfo())

        assert out.get_state("x") == NullState.UNKNOWN

    def test_meet(self) -> None:
        na = NullAnalysis(MockCFG())
        i1 = NullInfo({"x": NullState.DEFINITELY_NULL})
        i2 = NullInfo({"x": NullState.DEFINITELY_NOT_NULL})
        met = na.meet([i1, i2])
        assert met.get_state("x") == NullState.MAYBE_NULL

    def test_is_definitely_null(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {
            0: make_block(0, [MockInstr("LOAD_CONST", 10, None), MockInstr("STORE_NAME", 12, "x")])
        }
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo({"x": NullState.DEFINITELY_NULL})
        assert na.is_definitely_null("x", 10) is True

    def test_is_definitely_null_replays_block_instructions_to_pc(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {
            0: make_block(0, [MockInstr("LOAD_CONST", 10, None), MockInstr("STORE_NAME", 12, "x")])
        }
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo()

        assert na.is_definitely_null("x", 14) is True

    def test_is_definitely_not_null(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {
            0: make_block(0, [MockInstr("LOAD_CONST", 10, 42), MockInstr("STORE_NAME", 12, "x")])
        }
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo({"x": NullState.DEFINITELY_NOT_NULL})
        assert na.is_definitely_not_null("x", 10) is True

    def test_is_definitely_not_null_replays_block_instructions_to_pc(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {
            0: make_block(0, [MockInstr("LOAD_CONST", 10, 42), MockInstr("STORE_NAME", 12, "x")])
        }
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo()

        assert na.is_definitely_not_null("x", 14) is True
        assert na.may_be_null("x", 14) is False

    def test_may_be_null(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {
            0: make_block(0, [MockInstr("LOAD_CONST", 10, None), MockInstr("STORE_NAME", 12, "x")])
        }
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo({"x": NullState.MAYBE_NULL})
        assert na.may_be_null("x", 10) is True
