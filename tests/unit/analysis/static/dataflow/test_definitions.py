"""Tests for reaching definitions and def-use chains."""

from __future__ import annotations

from pysymex.analysis.static.dataflow.definitions import DefUseAnalysis, ReachingDefinitions
from pysymex.analysis.static.dataflow.types import Definition, Use
from tests.unit.analysis.static.dataflow.helpers import MockCFG, MockInstr, make_block


class TestReachingDefinitions:
    """Test suite for pysymex.analysis.static.dataflow.definitions.ReachingDefinitions."""

    def test_initial_value(self) -> None:
        rd = ReachingDefinitions(MockCFG())
        assert rd.initial_value() == frozenset()

    def test_boundary_value(self) -> None:
        rd = ReachingDefinitions(MockCFG())
        assert rd.boundary_value() == frozenset()

    def test_transfer(self) -> None:
        rd = ReachingDefinitions(MockCFG())
        instr = MockInstr("STORE_NAME", 10, "x")
        bb = make_block(1, [instr])
        out = rd.transfer(bb, frozenset([Definition("x", 0, 5)]))
        assert len(out) == 1
        d = next(iter(out))
        assert d.var_name == "x" and d.pc == 10

    def test_meet(self) -> None:
        rd = ReachingDefinitions(MockCFG())
        d1 = Definition("x", 1, 10)
        d2 = Definition("y", 2, 20)
        met = rd.meet([frozenset([d1]), frozenset([d2])])
        assert d1 in met and d2 in met

    def test_get_reaching_defs_at(self) -> None:
        cfg = MockCFG()
        instr1 = MockInstr("STORE_NAME", 10, "x")
        instr2 = MockInstr("LOAD_NAME", 20, "x")
        bb = make_block(1, [instr1, instr2])
        cfg.blocks = {1: bb}
        rd = ReachingDefinitions(cfg)
        rd.in_facts[1] = frozenset()
        defs = rd.get_reaching_defs_at(20)
        assert len(defs) == 1
        d = next(iter(defs))
        assert d.var_name == "x" and d.pc == 10


class TestDefUseAnalysis:
    """Test suite for pysymex.analysis.static.dataflow.definitions.DefUseAnalysis."""

    def test_get_chain(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {0: make_block(0)}
        dua = DefUseAnalysis(cfg)
        assert dua.get_chain(Definition("x", 1, 10)) is None

    def test_get_definitions_for_use(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {0: make_block(0)}
        dua = DefUseAnalysis(cfg)
        assert len(dua.get_definitions_for_use(Use("x", 0, 20))) == 0

    def test_find_dead_stores(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {0: make_block(0, [MockInstr("STORE_NAME", 10, "x")])}
        dua = DefUseAnalysis(cfg)
        dead = dua.find_dead_stores()
        assert len(dead) == 1
        assert dead[0].var_name == "x"
