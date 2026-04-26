import pytest
import dis
from unittest.mock import Mock
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


class MockInstr:
    def __init__(self, opname: str, offset: int, argval: object = None, argrepr: str = "") -> None:
        self.opname = opname
        self.offset = offset
        self.argval = argval
        self.argrepr = argrepr
        self.starts_line = 10
        self.positions = None


class MockCFG(ControlFlowGraph):
    def __init__(self) -> None:
        self.blocks = {}
        self.entry_block_id = 0
        self.exit_block_ids = {1}
        self.reverse_postorder = [0, 1]

    def iter_blocks_forward(self) -> list[BasicBlock]:
        return [self.blocks[k] for k in sorted(self.blocks.keys())]

    def iter_blocks_reverse(self) -> list[BasicBlock]:
        return [self.blocks[k] for k in sorted(self.blocks.keys(), reverse=True)]

    def get_block_at_pc(self, pc: int) -> BasicBlock | None:
        if self.blocks:
            return next(iter(self.blocks.values()))
        return None


class ConcreteDataFlow(DataFlowAnalysis[str]):
    def initial_value(self) -> str:
        return "init"

    def boundary_value(self) -> str:
        return "bound"

    def transfer(self, block: BasicBlock, in_fact: str) -> str:
        return in_fact + "_" + str(block.id)

    def meet(self, facts: list[str]) -> str:
        return "+".join(sorted(facts)) if facts else "init"


class TestDataFlowAnalysis:
    """Test suite for pysymex.analysis.dataflow.core.DataFlowAnalysis."""

    def test_initial_value(self) -> None:
        """Test initial_value behavior."""
        df = ConcreteDataFlow(MockCFG())
        assert df.initial_value() == "init"

    def test_boundary_value(self) -> None:
        """Test boundary_value behavior."""
        df = ConcreteDataFlow(MockCFG())
        assert df.boundary_value() == "bound"

    def test_transfer(self) -> None:
        """Test transfer behavior."""
        df = ConcreteDataFlow(MockCFG())
        b = BasicBlock(1, [], [])
        assert df.transfer(b, "x") == "x_1"

    def test_meet(self) -> None:
        """Test meet behavior."""
        df = ConcreteDataFlow(MockCFG())
        assert df.meet(["b", "a"]) == "a+b"

    def test_is_forward(self) -> None:
        """Test is_forward behavior."""
        df = ConcreteDataFlow(MockCFG())
        assert df.is_forward() is True

    def test_analyze(self) -> None:
        """Test analyze behavior."""
        cfg = MockCFG()
        b0 = BasicBlock(0, [], [])
        b0.successors = [1]
        b1 = BasicBlock(1, [], [])
        b1.predecessors = [0]
        cfg.blocks = {0: b0, 1: b1}
        df = ConcreteDataFlow(cfg)
        df.analyze()
        assert df.in_facts[0] == "bound"
        assert df.out_facts[0] == "bound_0"
        assert df.in_facts[1] == "bound_0"
        assert df.out_facts[1] == "bound_0_1"

    def test_get_in(self) -> None:
        """Test get_in behavior."""
        df = ConcreteDataFlow(MockCFG())
        assert df.get_in(99) == "init"

    def test_get_out(self) -> None:
        """Test get_out behavior."""
        df = ConcreteDataFlow(MockCFG())
        assert df.get_out(99) == "init"


class TestReachingDefinitions:
    """Test suite for pysymex.analysis.dataflow.core.ReachingDefinitions."""

    def test_initial_value(self) -> None:
        """Test initial_value behavior."""
        rd = ReachingDefinitions(MockCFG())
        assert rd.initial_value() == frozenset()

    def test_boundary_value(self) -> None:
        """Test boundary_value behavior."""
        rd = ReachingDefinitions(MockCFG())
        assert rd.boundary_value() == frozenset()

    def test_transfer(self) -> None:
        """Test transfer behavior."""
        rd = ReachingDefinitions(MockCFG())
        instr = MockInstr("STORE_NAME", 10, "x")
        b = BasicBlock(1, [], [])
        b.instructions = [instr]
        out = rd.transfer(b, frozenset([Definition("x", 0, 5)]))
        assert len(out) == 1
        d = next(iter(out))
        assert d.var_name == "x" and d.pc == 10

    def test_meet(self) -> None:
        """Test meet behavior."""
        rd = ReachingDefinitions(MockCFG())
        d1 = Definition("x", 1, 10)
        d2 = Definition("y", 2, 20)
        met = rd.meet([frozenset([d1]), frozenset([d2])])
        assert d1 in met and d2 in met

    def test_get_reaching_defs_at(self) -> None:
        """Test get_reaching_defs_at behavior."""
        cfg = MockCFG()
        instr1 = MockInstr("STORE_NAME", 10, "x")
        instr2 = MockInstr("LOAD_NAME", 20, "x")
        b = BasicBlock(1, [], [])
        b.instructions = [instr1, instr2]
        cfg.blocks = {1: b}
        rd = ReachingDefinitions(cfg)
        rd.in_facts[1] = frozenset()
        defs = rd.get_reaching_defs_at(20)
        assert len(defs) == 1
        d = next(iter(defs))
        assert d.var_name == "x" and d.pc == 10


class TestLiveVariables:
    """Test suite for pysymex.analysis.dataflow.core.LiveVariables."""

    def test_is_forward(self) -> None:
        """Test is_forward behavior."""
        lv = LiveVariables(MockCFG())
        assert lv.is_forward() is False

    def test_initial_value(self) -> None:
        """Test initial_value behavior."""
        lv = LiveVariables(MockCFG())
        assert lv.initial_value() == frozenset()

    def test_boundary_value(self) -> None:
        """Test boundary_value behavior."""
        lv = LiveVariables(MockCFG())
        assert lv.boundary_value() == frozenset()

    def test_transfer(self) -> None:
        """Test transfer behavior."""
        lv = LiveVariables(MockCFG())
        instr = MockInstr("LOAD_NAME", 20, "y")
        b = BasicBlock(1, [], [])
        b.instructions = [instr]
        out = lv.transfer(b, frozenset(["x"]))
        assert "x" in out and "y" in out

    def test_meet(self) -> None:
        """Test meet behavior."""
        lv = LiveVariables(MockCFG())
        assert lv.meet([frozenset(["a"]), frozenset(["b"])]) == frozenset(["a", "b"])

    def test_is_live_at(self) -> None:
        """Test is_live_at behavior."""
        cfg = MockCFG()
        instr1 = MockInstr("STORE_NAME", 10, "x")
        instr2 = MockInstr("LOAD_NAME", 20, "y")
        b = BasicBlock(1, [], [])
        b.instructions = [instr1, instr2]
        cfg.blocks = {1: b}
        lv = LiveVariables(cfg)
        lv.out_facts[1] = frozenset(["z"])
        assert lv.is_live_at("y", 10) is True
        assert lv.is_live_at("z", 10) is True


class TestDefUseAnalysis:
    """Test suite for pysymex.analysis.dataflow.core.DefUseAnalysis."""

    def test_get_chain(self) -> None:
        """Test get_chain behavior."""
        cfg = MockCFG()
        b = BasicBlock(0, [], [])
        cfg.blocks = {0: b}
        dua = DefUseAnalysis(cfg)
        d = Definition("x", 1, 10)
        assert dua.get_chain(d) is None

    def test_get_definitions_for_use(self) -> None:
        """Test get_definitions_for_use behavior."""
        cfg = MockCFG()
        b = BasicBlock(0, [], [])
        cfg.blocks = {0: b}
        dua = DefUseAnalysis(cfg)
        u = Use("x", 0, 20)
        assert len(dua.get_definitions_for_use(u)) == 0

    def test_find_dead_stores(self) -> None:
        """Test find_dead_stores behavior."""
        cfg = MockCFG()
        instr1 = MockInstr("STORE_NAME", 10, "x")
        b = BasicBlock(0, [], [])
        b.instructions = [instr1]
        cfg.blocks = {0: b}
        dua = DefUseAnalysis(cfg)
        dead = dua.find_dead_stores()
        assert len(dead) == 1
        assert dead[0].var_name == "x"


class TestAvailableExpressions:
    """Test suite for pysymex.analysis.dataflow.core.AvailableExpressions."""

    def test_initial_value(self) -> None:
        """Test initial_value behavior."""
        cfg = MockCFG()
        b = BasicBlock(0, [], [])
        b.instructions = [
            MockInstr("LOAD_FAST", 10, "x"),
            MockInstr("LOAD_FAST", 12, "y"),
            MockInstr("BINARY_OP", 14, "+", "+"),
        ]
        cfg.blocks = {0: b}
        ae = AvailableExpressions(cfg)
        assert len(ae.initial_value()) == 1

    def test_boundary_value(self) -> None:
        """Test boundary_value behavior."""
        ae = AvailableExpressions(MockCFG())
        assert ae.boundary_value() == frozenset()

    def test_transfer(self) -> None:
        """Test transfer behavior."""
        cfg = MockCFG()
        b = BasicBlock(0, [], [])
        b.instructions = [
            MockInstr("LOAD_FAST", 10, "x"),
            MockInstr("LOAD_FAST", 12, "y"),
            MockInstr("BINARY_OP", 14, "+", "+"),
        ]
        cfg.blocks = {0: b}
        ae = AvailableExpressions(cfg)
        out = ae.transfer(b, frozenset())
        assert len(out) == 1

    def test_meet(self) -> None:
        """Test meet behavior."""
        ae = AvailableExpressions(MockCFG())
        e1 = Expression("+", ("a", "b"))
        e2 = Expression("-", ("a", "c"))
        assert ae.meet([frozenset([e1, e2]), frozenset([e1])]) == frozenset([e1])


class TestTypeFlowAnalysis:
    """Test suite for pysymex.analysis.dataflow.core.TypeFlowAnalysis."""

    def test_initial_value(self) -> None:
        """Test initial_value behavior."""
        cfg = MockCFG()
        analyzer = TypeAnalyzer()
        tfa = TypeFlowAnalysis(cfg, analyzer)
        assert isinstance(tfa.initial_value(), TypeEnvironment)

    def test_boundary_value(self) -> None:
        """Test boundary_value behavior."""
        cfg = MockCFG()
        analyzer = TypeAnalyzer()
        tfa = TypeFlowAnalysis(cfg, analyzer)
        assert isinstance(tfa.boundary_value(), TypeEnvironment)

    def test_transfer(self) -> None:
        """Test transfer behavior."""
        cfg = MockCFG()
        analyzer = TypeAnalyzer()
        tfa = TypeFlowAnalysis(cfg, analyzer)
        b = BasicBlock(0, [], [])
        b.instructions = [MockInstr("LOAD_CONST", 10, 42), MockInstr("STORE_NAME", 12, "x")]
        out_env = tfa.transfer(b, TypeEnvironment())
        assert out_env.get_type("x").is_numeric()

    def test_meet(self) -> None:
        """Test meet behavior."""
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
        """Test get_type_at behavior."""
        cfg = MockCFG()
        b = BasicBlock(0, [], [])
        b.instructions = [MockInstr("LOAD_CONST", 10, 42), MockInstr("STORE_NAME", 12, "x")]
        cfg.blocks = {0: b}
        analyzer = TypeAnalyzer()
        tfa = TypeFlowAnalysis(cfg, analyzer)
        tfa.in_facts[0] = TypeEnvironment()
        t = tfa.get_type_at(14, "x")
        assert t.is_numeric()


class TestNullAnalysis:
    """Test suite for pysymex.analysis.dataflow.core.NullAnalysis."""

    def test_initial_value(self) -> None:
        """Test initial_value behavior."""
        na = NullAnalysis(MockCFG())
        assert isinstance(na.initial_value(), NullInfo)

    def test_boundary_value(self) -> None:
        """Test boundary_value behavior."""
        na = NullAnalysis(MockCFG())
        assert isinstance(na.boundary_value(), NullInfo)

    def test_transfer(self) -> None:
        """Test transfer behavior."""
        na = NullAnalysis(MockCFG())
        b = BasicBlock(0, [], [])
        b.instructions = [MockInstr("LOAD_CONST", 10, None), MockInstr("STORE_NAME", 12, "x")]
        out = na.transfer(b, NullInfo())
        assert out.get_state("x") == NullState.DEFINITELY_NULL

    def test_meet(self) -> None:
        """Test meet behavior."""
        na = NullAnalysis(MockCFG())
        i1 = NullInfo({"x": NullState.DEFINITELY_NULL})
        i2 = NullInfo({"x": NullState.DEFINITELY_NOT_NULL})
        met = na.meet([i1, i2])
        assert met.get_state("x") == NullState.MAYBE_NULL

    def test_is_definitely_null(self) -> None:
        """Test is_definitely_null behavior."""
        cfg = MockCFG()
        b = BasicBlock(0, [], [])
        b.instructions = [MockInstr("LOAD_CONST", 10, None), MockInstr("STORE_NAME", 12, "x")]
        cfg.blocks = {0: b}
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo({"x": NullState.DEFINITELY_NULL})
        assert na.is_definitely_null("x", 10) is True

    def test_is_definitely_not_null(self) -> None:
        """Test is_definitely_not_null behavior."""
        cfg = MockCFG()
        b = BasicBlock(0, [], [])
        b.instructions = [MockInstr("LOAD_CONST", 10, 42), MockInstr("STORE_NAME", 12, "x")]
        cfg.blocks = {0: b}
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo({"x": NullState.DEFINITELY_NOT_NULL})
        assert na.is_definitely_not_null("x", 10) is True

    def test_may_be_null(self) -> None:
        """Test may_be_null behavior."""
        cfg = MockCFG()
        b = BasicBlock(0, [], [])
        b.instructions = [MockInstr("LOAD_CONST", 10, None), MockInstr("STORE_NAME", 12, "x")]
        cfg.blocks = {0: b}
        na = NullAnalysis(cfg)
        na.in_facts[0] = NullInfo({"x": NullState.MAYBE_NULL})
        assert na.may_be_null("x", 10) is True
