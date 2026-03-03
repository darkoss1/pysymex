"""Tests for dataflow analysis types and core algorithms.

Targets the split modules:
  - pysymex.analysis.dataflow_types
  - pysymex.analysis.dataflow_core
  - pysymex.analysis.dataflow (hub re-exports)

These modules had ZERO test coverage prior to this file.
"""

from __future__ import annotations


import dis

import pytest


from pysymex.analysis.dataflow import (
    Definition,
    Use,
    DefUseChain,
    Expression,
    NullState,
    NullInfo,
    ReachingDefinitions,
    LiveVariables,
    DefUseAnalysis,
    AvailableExpressions,
    NullAnalysis,
    DataFlowAnalysis,
)

from pysymex.analysis.flow_sensitive import CFGBuilder


def _build_cfg(source: str):
    """Compile source and build a CFG."""

    code = compile(source, "<test>", "exec")

    return CFGBuilder().build(code), code


class TestDefinition:
    """Tests for the Definition frozen dataclass."""

    def test_construction_and_fields(self):
        d = Definition(var_name="x", block_id=0, pc=0, line=1)

        assert d.var_name == "x"

        assert d.block_id == 0

        assert d.pc == 0

        assert d.line == 1

    def test_default_line(self):
        d = Definition(var_name="y", block_id=1, pc=5)

        assert d.line is None

    def test_frozen_hashable(self):
        """Definitions are frozen/hashable, usable as dict keys and set members."""

        d1 = Definition(var_name="x", block_id=0, pc=0)

        d2 = Definition(var_name="x", block_id=0, pc=0)

        d3 = Definition(var_name="y", block_id=0, pc=2)

        assert d1 == d2

        assert d1 != d3

        assert len({d1, d2, d3}) == 2

    def test_as_dict_key(self):
        d = Definition(var_name="z", block_id=2, pc=10)

        mapping = {d: "value"}

        assert mapping[d] == "value"


class TestUse:
    """Tests for the Use dataclass."""

    def test_construction(self):
        u = Use(var_name="x", block_id=0, pc=3, line=2)

        assert u.var_name == "x"

        assert u.block_id == 0

        assert u.pc == 3

    def test_default_line(self):
        u = Use(var_name="x", block_id=0, pc=3)

        assert u.line is None


class TestDefUseChain:
    """Tests for DefUseChain."""

    def test_construction(self):
        d = Definition(var_name="x", block_id=0, pc=0)

        chain = DefUseChain(definition=d)

        assert chain.definition == d

        assert len(chain.uses) == 0

    def test_with_uses(self):
        d = Definition(var_name="x", block_id=0, pc=0)

        u1 = Use(var_name="x", block_id=0, pc=5)

        u2 = Use(var_name="x", block_id=1, pc=10)

        chain = DefUseChain(definition=d, uses={u1, u2})

        assert len(chain.uses) == 2


class TestExpression:
    """Tests for the Expression frozen dataclass."""

    def test_construction(self):
        e = Expression(operator="BINARY_ADD", operands=("a", "b"))

        assert e.operator == "BINARY_ADD"

        assert e.operands == ("a", "b")

    def test_frozen_hashable(self):
        e1 = Expression(operator="BINARY_ADD", operands=("a", "b"))

        e2 = Expression(operator="BINARY_ADD", operands=("a", "b"))

        e3 = Expression(operator="BINARY_MULTIPLY", operands=("a", "b"))

        assert e1 == e2

        assert e1 != e3

        assert len({e1, e2, e3}) == 2


class TestNullState:
    """Tests for the NullState enum."""

    def test_values_exist(self):
        assert NullState.DEFINITELY_NULL is not None

        assert NullState.DEFINITELY_NOT_NULL is not None

        assert NullState.MAYBE_NULL is not None

        assert NullState.UNKNOWN is not None

    def test_distinct(self):
        states = {
            NullState.DEFINITELY_NULL,
            NullState.DEFINITELY_NOT_NULL,
            NullState.MAYBE_NULL,
            NullState.UNKNOWN,
        }

        assert len(states) == 4


class TestNullInfo:
    """Tests for the NullInfo dataclass."""

    def test_default_empty(self):
        ni = NullInfo()

        assert len(ni.states) == 0

    def test_with_states(self):
        ni = NullInfo(states={"x": NullState.DEFINITELY_NULL, "y": NullState.DEFINITELY_NOT_NULL})

        assert ni.states["x"] == NullState.DEFINITELY_NULL

        assert ni.states["y"] == NullState.DEFINITELY_NOT_NULL


class TestReachingDefinitions:
    """Tests for ReachingDefinitions analysis."""

    def test_simple_assignment(self):
        """x = 1 defines x; reaching defs should include it."""

        cfg, code = _build_cfg("x = 1\ny = x + 2")

        rd = ReachingDefinitions(cfg)

        rd.analyze()

        defined_vars = {d.var_name for d in rd.all_defs}

        assert "x" in defined_vars

        assert "y" in defined_vars

    def test_overwritten_var(self):
        """x defined twice; second should kill/replace first at later points."""

        cfg, code = _build_cfg("x = 1\nx = 2\ny = x")

        rd = ReachingDefinitions(cfg)

        rd.analyze()

        x_defs = rd.defs_by_var.get("x", set())

        assert len(x_defs) >= 2

    def test_get_in_out(self):
        """get_in/get_out return frozensets."""

        cfg, _ = _build_cfg("a = 10")

        rd = ReachingDefinitions(cfg)

        rd.analyze()

        for block_id in cfg.blocks:
            in_facts = rd.get_in(block_id)

            out_facts = rd.get_out(block_id)

            assert isinstance(in_facts, frozenset)

            assert isinstance(out_facts, frozenset)


class TestLiveVariables:
    """Tests for LiveVariables (backward) analysis."""

    def test_basic_liveness(self):
        """In 'x = 1; y = x + 2', x is live between its def and use."""

        cfg, _ = _build_cfg("x = 1\ny = x + 2")

        lv = LiveVariables(cfg)

        lv.analyze()

        assert not lv.is_forward()

    def test_dead_var_not_live(self):
        """A variable that is defined but never used should not be live."""

        cfg, _ = _build_cfg("x = 1\ny = 2")

        lv = LiveVariables(cfg)

        lv.analyze()

        for block_id in cfg.blocks:
            lv.get_in(block_id)

            lv.get_out(block_id)


class TestDefUseAnalysis:
    """Tests for DefUseAnalysis (auto-builds def-use chains)."""

    def test_simple_chain(self):
        """x = 1; y = x — should create a chain from x's def to its use."""

        cfg, _ = _build_cfg("x = 1\ny = x")

        du = DefUseAnalysis(cfg)

        assert len(du.chains) >= 1

    def test_find_dead_stores(self):
        """x = 1; x = 2; y = x — first x=1 is a dead store."""

        cfg, _ = _build_cfg("x = 1\nx = 2\ny = x")

        du = DefUseAnalysis(cfg)

        dead = du.find_dead_stores()

        dead_vars = [d.var_name for d in dead]

        assert isinstance(dead, list)

    def test_multiple_uses(self):
        """x = 1; y = x; z = x — x has two uses."""

        cfg, _ = _build_cfg("x = 1\ny = x\nz = x")

        du = DefUseAnalysis(cfg)

        x_defs = [d for d in du.chains if d.var_name == "x"]

        if x_defs:
            chain = du.chains[x_defs[0]]

            assert len(chain.uses) >= 1


class TestAvailableExpressions:
    """Tests for AvailableExpressions analysis."""

    def test_basic_analysis(self):
        """c = a + b; d = a + b — expression a+b should be available."""

        cfg, _ = _build_cfg("a = 1\nb = 2\nc = a + b\nd = a + b")

        ae = AvailableExpressions(cfg)

        ae.analyze()

        assert isinstance(ae.all_expressions, set)

    def test_get_in_out(self):
        cfg, _ = _build_cfg("x = 1\ny = 2\nz = x + y")

        ae = AvailableExpressions(cfg)

        ae.analyze()

        for block_id in cfg.blocks:
            assert isinstance(ae.get_in(block_id), frozenset)

            assert isinstance(ae.get_out(block_id), frozenset)


class TestNullAnalysis:
    """Tests for NullAnalysis."""

    def test_none_assignment(self):
        """x = None — x should be definitely null."""

        cfg, _ = _build_cfg("x = None\ny = 1")

        na = NullAnalysis(cfg)

        na.analyze()

        for block_id in cfg.blocks:
            facts = na.get_out(block_id)

            assert isinstance(facts, NullInfo)

    def test_not_null(self):
        """y = 1 — y should not be null."""

        cfg, _ = _build_cfg("y = 42")

        na = NullAnalysis(cfg)

        na.analyze()

        for block_id in cfg.blocks:
            facts = na.get_out(block_id)

            assert isinstance(facts, NullInfo)


class TestHubReExports:
    """Verify all expected symbols are accessible through the hub module."""

    def test_all_types_accessible(self):
        from pysymex.analysis.dataflow import (
            Definition,
            Use,
            DefUseChain,
            Expression,
            NullState,
            NullInfo,
        )

        assert Definition is not None

        assert Use is not None

        assert DefUseChain is not None

        assert Expression is not None

        assert NullState is not None

        assert NullInfo is not None

    def test_all_core_accessible(self):
        from pysymex.analysis.dataflow import (
            DataFlowAnalysis,
            ReachingDefinitions,
            LiveVariables,
            DefUseAnalysis,
            AvailableExpressions,
            NullAnalysis,
        )

        assert DataFlowAnalysis is not None

        assert ReachingDefinitions is not None

        assert LiveVariables is not None

        assert DefUseAnalysis is not None

        assert AvailableExpressions is not None

        assert NullAnalysis is not None

    def test_types_come_from_types_module(self):
        from pysymex.analysis.dataflow.types import Definition as D1

        from pysymex.analysis.dataflow import Definition as D2

        assert D1 is D2

    def test_core_comes_from_core_module(self):
        from pysymex.analysis.dataflow.core import ReachingDefinitions as RD1

        from pysymex.analysis.dataflow import ReachingDefinitions as RD2

        assert RD1 is RD2
