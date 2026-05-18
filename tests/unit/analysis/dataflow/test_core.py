"""Test suite for pysymex.analysis.dataflow.core — data-flow analysis passes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.analysis.control.cfg import ControlFlowGraph, BasicBlock
from pysymex.analysis.dataflow.core import (
    DataFlowAnalysis,
    ReachingDefinitions,
    LiveVariables,
    DefUseAnalysis,
    AvailableExpressions,
    TypeFlowAnalysis,
    NullAnalysis,
)
from pysymex.analysis.dataflow.types import Definition, Use, Expression, NullState, NullInfo
from pysymex.analysis.type_inference import PyType, TypeAnalyzer, TypeEnvironment

if TYPE_CHECKING:
    from collections.abc import Iterable


class MockInstr:
    """Minimal instruction stub satisfying the attrs BasicBlock expects."""

    def __init__(self, opname: str, offset: int, argval: object = None, argrepr: str = "") -> None:
        self.opname = opname
        self.offset = offset
        self.argval = argval
        self.argrepr = argrepr
        self.starts_line: int | None = 10
        self.positions: object = None


def _make_block(
    block_id: int,
    instrs: list[MockInstr] | None = None,
    *,
    successors: set[int] | None = None,
    predecessors: set[int] | None = None,
) -> BasicBlock:
    """Create a BasicBlock with the correct constructor and assign mock instructions.

    Because BasicBlock.instructions is typed as ``list[dis.Instruction]`` and
    MockInstr is *not* a real ``dis.Instruction``, we assign through
    ``object.__setattr__`` to bypass pyright's attribute-assignability check.
    This mirrors what production code does when populating blocks from external
    bytecode parsers.
    """
    bb = BasicBlock(id=block_id, start_pc=0, end_pc=0)
    if instrs is not None:
        object.__setattr__(bb, "instructions", instrs)  # type: ignore[assignment]  # MockInstr duck-types dis.Instruction
    if successors is not None:
        bb.successors = successors
    if predecessors is not None:
        bb.predecessors = predecessors
    return bb


class MockCFG(ControlFlowGraph):
    """Minimal CFG stub for unit tests."""

    def __init__(self) -> None:
        super().__init__()
        self.entry_block_id = 0
        self.exit_block_ids = {1}

    def iter_blocks_forward(self) -> Iterable[BasicBlock]:
        """Iterate blocks in insertion order."""
        return [self.blocks[k] for k in sorted(self.blocks.keys())]

    def iter_blocks_reverse(self) -> Iterable[BasicBlock]:
        """Iterate blocks in reverse insertion order."""
        return [self.blocks[k] for k in sorted(self.blocks.keys(), reverse=True)]

    def get_block_at_pc(self, pc: int) -> BasicBlock | None:
        """Return the first block, if any."""
        if self.blocks:
            return next(iter(self.blocks.values()))
        return None


class ConcreteDataFlow(DataFlowAnalysis[str]):
    """Concrete data-flow analysis for testing the abstract base class."""

    def initial_value(self) -> str:
        """Return the initial data-flow value."""
        return "init"

    def boundary_value(self) -> str:
        """Return the boundary data-flow value."""
        return "bound"

    def transfer(self, block: BasicBlock, in_fact: str) -> str:
        """Apply the transfer function."""
        return in_fact + "_" + str(block.id)

    def meet(self, facts: list[str]) -> str:
        """Compute the meet of data-flow facts."""
        return "+".join(sorted(facts)) if facts else "init"


class TestDataFlowAnalysis:
    """Test suite for pysymex.analysis.dataflow.core.DataFlowAnalysis."""

    def test_initial_value(self) -> None:
        """Test initial_value returns the configured string."""
        df = ConcreteDataFlow(MockCFG())
        assert df.initial_value() == "init"

    def test_boundary_value(self) -> None:
        """Test boundary_value returns the configured string."""
        df = ConcreteDataFlow(MockCFG())
        assert df.boundary_value() == "bound"

    def test_transfer(self) -> None:
        """Test transfer appends block id to the fact."""
        df = ConcreteDataFlow(MockCFG())
        bb = _make_block(1)
        assert df.transfer(bb, "x") == "x_1"

    def test_meet(self) -> None:
        """Test meet joins facts in sorted order."""
        df = ConcreteDataFlow(MockCFG())
        assert df.meet(["b", "a"]) == "a+b"

    def test_is_forward(self) -> None:
        """Test is_forward returns True for forward analysis."""
        df = ConcreteDataFlow(MockCFG())
        assert df.is_forward() is True

    def test_analyze(self) -> None:
        """Test analyze propagates data-flow facts through the CFG."""
        cfg = MockCFG()
        b0 = _make_block(0, successors={1})
        b1 = _make_block(1, predecessors={0})
        cfg.blocks = {0: b0, 1: b1}
        df = ConcreteDataFlow(cfg)
        df.analyze()
        assert df.in_facts[0] == "bound"
        assert df.out_facts[0] == "bound_0"
        assert df.in_facts[1] == "bound_0"
        assert df.out_facts[1] == "bound_0_1"

    def test_get_in(self) -> None:
        """Test get_in returns initial value for unknown blocks."""
        df = ConcreteDataFlow(MockCFG())
        assert df.get_in(99) == "init"

    def test_get_out(self) -> None:
        """Test get_out returns initial value for unknown blocks."""
        df = ConcreteDataFlow(MockCFG())
        assert df.get_out(99) == "init"


class TestReachingDefinitions:
    """Test suite for pysymex.analysis.dataflow.core.ReachingDefinitions."""

    def test_initial_value(self) -> None:
        """Test initial_value returns empty frozenset."""
        rd = ReachingDefinitions(MockCFG())
        assert rd.initial_value() == frozenset()

    def test_boundary_value(self) -> None:
        """Test boundary_value returns empty frozenset."""
        rd = ReachingDefinitions(MockCFG())
        assert rd.boundary_value() == frozenset()

    def test_transfer(self) -> None:
        """Test transfer generates a new definition for STORE_NAME."""
        rd = ReachingDefinitions(MockCFG())
        instr = MockInstr("STORE_NAME", 10, "x")
        bb = _make_block(1, [instr])
        out = rd.transfer(bb, frozenset([Definition("x", 0, 5)]))
        assert len(out) == 1
        d = next(iter(out))
        assert d.var_name == "x" and d.pc == 10

    def test_meet(self) -> None:
        """Test meet unions reaching definitions."""
        rd = ReachingDefinitions(MockCFG())
        d1 = Definition("x", 1, 10)
        d2 = Definition("y", 2, 20)
        met = rd.meet([frozenset([d1]), frozenset([d2])])
        assert d1 in met and d2 in met

    def test_get_reaching_defs_at(self) -> None:
        """Test get_reaching_defs_at finds definitions reaching a given PC."""
        cfg = MockCFG()
        instr1 = MockInstr("STORE_NAME", 10, "x")
        instr2 = MockInstr("LOAD_NAME", 20, "x")
        bb = _make_block(1, [instr1, instr2])
        cfg.blocks = {1: bb}
        rd = ReachingDefinitions(cfg)
        rd.in_facts[1] = frozenset()
        defs = rd.get_reaching_defs_at(20)
        assert len(defs) == 1
        d = next(iter(defs))
        assert d.var_name == "x" and d.pc == 10


class TestLiveVariables:
    """Test suite for pysymex.analysis.dataflow.core.LiveVariables."""

    def test_is_forward(self) -> None:
        """Test is_forward returns False for backward analysis."""
        lv = LiveVariables(MockCFG())
        assert lv.is_forward() is False

    def test_initial_value(self) -> None:
        """Test initial_value returns empty frozenset."""
        lv = LiveVariables(MockCFG())
        assert lv.initial_value() == frozenset()

    def test_boundary_value(self) -> None:
        """Test boundary_value returns empty frozenset."""
        lv = LiveVariables(MockCFG())
        assert lv.boundary_value() == frozenset()

    def test_transfer(self) -> None:
        """Test transfer adds used variables to the live set."""
        lv = LiveVariables(MockCFG())
        instr = MockInstr("LOAD_NAME", 20, "y")
        bb = _make_block(1, [instr])
        out = lv.transfer(bb, frozenset(["x"]))
        assert "x" in out and "y" in out

    def test_meet(self) -> None:
        """Test meet unions live variable sets."""
        lv = LiveVariables(MockCFG())
        assert lv.meet([frozenset(["a"]), frozenset(["b"])]) == frozenset(["a", "b"])

    def test_is_live_at(self) -> None:
        """Test is_live_at correctly identifies live variables."""
        cfg = MockCFG()
        instr1 = MockInstr("STORE_NAME", 10, "x")
        instr2 = MockInstr("LOAD_NAME", 20, "y")
        bb = _make_block(1, [instr1, instr2])
        cfg.blocks = {1: bb}
        lv = LiveVariables(cfg)
        lv.out_facts[1] = frozenset(["z"])
        assert lv.is_live_at("y", 10) is True
        assert lv.is_live_at("z", 10) is True


class TestDefUseAnalysis:
    """Test suite for pysymex.analysis.dataflow.core.DefUseAnalysis."""

    def test_get_chain(self) -> None:
        """Test get_chain returns None for an unknown definition."""
        cfg = MockCFG()
        bb = _make_block(0)
        cfg.blocks = {0: bb}
        dua = DefUseAnalysis(cfg)
        d = Definition("x", 1, 10)
        assert dua.get_chain(d) is None

    def test_get_definitions_for_use(self) -> None:
        """Test get_definitions_for_use returns empty for unknown use."""
        cfg = MockCFG()
        bb = _make_block(0)
        cfg.blocks = {0: bb}
        dua = DefUseAnalysis(cfg)
        u = Use("x", 0, 20)
        assert len(dua.get_definitions_for_use(u)) == 0

    def test_find_dead_stores(self) -> None:
        """Test find_dead_stores detects a store with no subsequent use."""
        cfg = MockCFG()
        instr1 = MockInstr("STORE_NAME", 10, "x")
        bb = _make_block(0, [instr1])
        cfg.blocks = {0: bb}
        dua = DefUseAnalysis(cfg)
        dead = dua.find_dead_stores()
        assert len(dead) == 1
        assert dead[0].var_name == "x"


class TestAvailableExpressions:
    """Test suite for pysymex.analysis.dataflow.core.AvailableExpressions."""

    def test_initial_value(self) -> None:
        """Test initial_value returns the universe of expressions in the CFG."""
        cfg = MockCFG()
        bb = _make_block(
            0,
            [
                MockInstr("LOAD_FAST", 10, "x"),
                MockInstr("LOAD_FAST", 12, "y"),
                MockInstr("BINARY_OP", 14, "+", "+"),
            ],
        )
        cfg.blocks = {0: bb}
        ae = AvailableExpressions(cfg)
        assert len(ae.initial_value()) == 1

    def test_boundary_value(self) -> None:
        """Test boundary_value returns empty frozenset."""
        ae = AvailableExpressions(MockCFG())
        assert ae.boundary_value() == frozenset()

    def test_transfer(self) -> None:
        """Test transfer generates available expressions."""
        cfg = MockCFG()
        bb = _make_block(
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

    def test_meet(self) -> None:
        """Test meet intersects expression sets."""
        ae = AvailableExpressions(MockCFG())
        e1 = Expression("+", ("a", "b"))
        e2 = Expression("-", ("a", "c"))
        assert ae.meet([frozenset([e1, e2]), frozenset([e1])]) == frozenset([e1])


class TestTypeFlowAnalysis:
    """Test suite for pysymex.analysis.dataflow.core.TypeFlowAnalysis."""

    def test_initial_value(self) -> None:
        """Test initial_value returns a TypeEnvironment."""
        cfg = MockCFG()
        analyzer = TypeAnalyzer()
        tfa = TypeFlowAnalysis(cfg, analyzer)
        assert isinstance(tfa.initial_value(), TypeEnvironment)

    def test_boundary_value(self) -> None:
        """Test boundary_value returns a TypeEnvironment."""
        cfg = MockCFG()
        analyzer = TypeAnalyzer()
        tfa = TypeFlowAnalysis(cfg, analyzer)
        assert isinstance(tfa.boundary_value(), TypeEnvironment)

    def test_transfer(self) -> None:
        """Test transfer infers types from instructions."""
        cfg = MockCFG()
        analyzer = TypeAnalyzer()
        tfa = TypeFlowAnalysis(cfg, analyzer)
        bb = _make_block(0, [MockInstr("LOAD_CONST", 10, 42), MockInstr("STORE_NAME", 12, "x")])
        out_env = tfa.transfer(bb, TypeEnvironment())
        assert out_env.get_type("x").is_numeric()

    def test_meet(self) -> None:
        """Test meet produces union types."""
        cfg = MockCFG()
        analyzer = TypeAnalyzer()
        tfa = TypeFlowAnalysis(cfg, analyzer)
        e1 = TypeEnvironment()
        e1.set_type("x", PyType.int_type())
        e2 = TypeEnvironment()
        e2.set_type("x", PyType.str_type())
        met = tfa.meet([e1, e2])
        assert met.get_type("x").name == "Union"

    def test_get_type_at(self) -> None:
        """Test get_type_at looks up the type at a given PC."""
        cfg = MockCFG()
        bb = _make_block(0, [MockInstr("LOAD_CONST", 10, 42), MockInstr("STORE_NAME", 12, "x")])
        cfg.blocks = {0: bb}
        analyzer = TypeAnalyzer()
        tfa = TypeFlowAnalysis(cfg, analyzer)
        tfa.in_facts[0] = TypeEnvironment()
        t = tfa.get_type_at(14, "x")
        assert t.is_numeric()


class TestNullAnalysis:
    """Test suite for pysymex.analysis.dataflow.core.NullAnalysis."""

    def test_initial_value(self) -> None:
        """Test initial_value returns a NullInfo."""
        na = NullAnalysis(MockCFG())
        assert isinstance(na.initial_value(), NullInfo)

    def test_boundary_value(self) -> None:
        """Test boundary_value returns a NullInfo."""
        na = NullAnalysis(MockCFG())
        assert isinstance(na.boundary_value(), NullInfo)

    def test_transfer(self) -> None:
        """Test transfer tracks null state through instructions."""
        na = NullAnalysis(MockCFG())
        bb = _make_block(0, [MockInstr("LOAD_CONST", 10, None), MockInstr("STORE_NAME", 12, "x")])
        out = na.transfer(bb, NullInfo())
        assert out.get_state("x") == NullState.DEFINITELY_NULL

    def test_meet(self) -> None:
        """Test meet produces MAYBE_NULL from conflicting states."""
        na = NullAnalysis(MockCFG())
        i1 = NullInfo({"x": NullState.DEFINITELY_NULL})
        i2 = NullInfo({"x": NullState.DEFINITELY_NOT_NULL})
        met = na.meet([i1, i2])
        assert met.get_state("x") == NullState.MAYBE_NULL

    def test_is_definitely_null(self) -> None:
        """Test is_definitely_null returns True when state is DEFINITELY_NULL."""
        cfg = MockCFG()
        bb = _make_block(0, [MockInstr("LOAD_CONST", 10, None), MockInstr("STORE_NAME", 12, "x")])
        cfg.blocks = {0: bb}
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo({"x": NullState.DEFINITELY_NULL})
        assert na.is_definitely_null("x", 10) is True

    def test_is_definitely_not_null(self) -> None:
        """Test is_definitely_not_null returns True when state is DEFINITELY_NOT_NULL."""
        cfg = MockCFG()
        bb = _make_block(0, [MockInstr("LOAD_CONST", 10, 42), MockInstr("STORE_NAME", 12, "x")])
        cfg.blocks = {0: bb}
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo({"x": NullState.DEFINITELY_NOT_NULL})
        assert na.is_definitely_not_null("x", 10) is True

    def test_may_be_null(self) -> None:
        """Test may_be_null returns True when state is MAYBE_NULL."""
        cfg = MockCFG()
        bb = _make_block(0, [MockInstr("LOAD_CONST", 10, None), MockInstr("STORE_NAME", 12, "x")])
        cfg.blocks = {0: bb}
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo({"x": NullState.MAYBE_NULL})
        assert na.may_be_null("x", 10) is True
