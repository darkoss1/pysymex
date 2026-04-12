import pytest
from unittest.mock import Mock, patch
from pysymex.analysis.specialized.flow import FlowSensitiveAnalyzer, FlowContext
from pysymex.analysis.control.cfg import BasicBlock, ControlFlowGraph
from pysymex.analysis.dataflow.types import Definition

class MockCFG(ControlFlowGraph):
    def __init__(self) -> None:
        self.blocks = {}
        self.entry_block_id = 0
        self.exit_block_ids = {1}
        self.reverse_postorder = [0, 1]
        self.natural_loops = {}
    
    def iter_blocks_forward(self) -> list[BasicBlock]:
        return [self.blocks[k] for k in sorted(self.blocks.keys())]
        
    def iter_blocks_reverse(self) -> list[BasicBlock]:
        return [self.blocks[k] for k in sorted(self.blocks.keys(), reverse=True)]
        
    def get_block_at_pc(self, pc: int) -> BasicBlock | None:
        for b in self.blocks.values():
            if any(getattr(i, 'offset', -1) == pc for i in b.instructions):
                return b
        if self.blocks:
            return next(iter(self.blocks.values()))
        return None

class TestFlowSensitiveAnalyzer:
    """Test suite for pysymex.analysis.specialized.flow.FlowSensitiveAnalyzer."""
    @patch("pysymex.analysis.specialized.flow.CFGBuilder")
    def test_get_definitions_reaching(self, mock_cfg_builder) -> None:
        """Test get_definitions_reaching behavior."""
        cfg_mock = MockCFG()
        cfg_mock.blocks = {1: BasicBlock(1, 0, 10)}
        mock_cfg_builder.return_value.build.return_value = cfg_mock
        
        analyzer = FlowSensitiveAnalyzer(Mock()) # type: ignore[arg-type]
        analyzer.reaching_defs = Mock()
        analyzer.reaching_defs.get_reaching_defs_at.return_value = [Definition("x", 1, 10)]
        defs = analyzer.get_definitions_reaching(10, "x")
        assert isinstance(defs, set)
        assert len(defs) == 1

    @patch("pysymex.analysis.specialized.flow.CFGBuilder")
    def test_is_variable_live(self, mock_cfg_builder) -> None:
        """Test is_variable_live behavior."""
        cfg_mock = MockCFG()
        cfg_mock.blocks = {1: BasicBlock(1, 0, 10)}
        mock_cfg_builder.return_value.build.return_value = cfg_mock
        
        analyzer = FlowSensitiveAnalyzer(Mock()) # type: ignore[arg-type]
        analyzer.live_vars = Mock()
        analyzer.live_vars.is_live_at.return_value = True
        assert analyzer.is_variable_live(10, "x") is True

    @patch("pysymex.analysis.specialized.flow.CFGBuilder")
    def test_is_dead_store(self, mock_cfg_builder) -> None:
        """Test is_dead_store behavior."""
        cfg_mock = MockCFG()
        cfg_mock.blocks = {1: BasicBlock(1, 0, 10)}
        mock_cfg_builder.return_value.build.return_value = cfg_mock
        
        analyzer = FlowSensitiveAnalyzer(Mock()) # type: ignore[arg-type]
        analyzer.def_use = Mock()
        mock_chain = Mock()
        mock_chain.is_dead.return_value = True
        analyzer.def_use.get_chain.return_value = mock_chain
        
        assert analyzer.is_dead_store(Definition("x", 1, 10)) is True

    @patch("pysymex.analysis.specialized.flow.CFGBuilder")
    def test_may_be_null(self, mock_cfg_builder) -> None:
        """Test may_be_null behavior."""
        cfg_mock = MockCFG()
        cfg_mock.blocks = {1: BasicBlock(1, 0, 10)}
        mock_cfg_builder.return_value.build.return_value = cfg_mock
        
        analyzer = FlowSensitiveAnalyzer(Mock()) # type: ignore[arg-type]
        analyzer.null_analysis = Mock()
        analyzer.null_analysis.may_be_null.return_value = True
        assert analyzer.may_be_null(10, "x") is True

    @patch("pysymex.analysis.specialized.flow.CFGBuilder")
    def test_is_in_loop(self, mock_cfg_builder) -> None:
        """Test is_in_loop behavior."""
        cfg_mock = MockCFG()
        cfg_mock.blocks = {1: BasicBlock(1, 0, 10)}
        cfg_mock.natural_loops = {1: {1}}
        cfg_mock.get_block_at_pc = Mock(return_value=BasicBlock(1, 0, 10))
        mock_cfg_builder.return_value.build.return_value = cfg_mock
        
        analyzer = FlowSensitiveAnalyzer(Mock()) # type: ignore[arg-type]
        assert analyzer.is_in_loop(10) is True

    @patch("pysymex.analysis.specialized.flow.CFGBuilder")
    def test_get_loop_header(self, mock_cfg_builder) -> None:
        """Test get_loop_header behavior."""
        cfg_mock = MockCFG()
        cfg_mock.blocks = {1: BasicBlock(1, 0, 10)}
        cfg_mock.natural_loops = {2: {1, 2}}
        cfg_mock.get_block_at_pc = Mock(return_value=BasicBlock(1, 0, 10))
        mock_cfg_builder.return_value.build.return_value = cfg_mock
        
        analyzer = FlowSensitiveAnalyzer(Mock()) # type: ignore[arg-type]
        assert analyzer.get_loop_header(10) == 2

    @patch("pysymex.analysis.specialized.flow.CFGBuilder")
    def test_get_dominator(self, mock_cfg_builder) -> None:
        """Test get_dominator behavior."""
        cfg_mock = MockCFG()
        b = BasicBlock(1, 0, 10)
        b.immediate_dominator = 0
        cfg_mock.blocks = {1: b}
        cfg_mock.get_block_at_pc = Mock(return_value=b)
        mock_cfg_builder.return_value.build.return_value = cfg_mock
        
        analyzer = FlowSensitiveAnalyzer(Mock()) # type: ignore[arg-type]
        assert analyzer.get_dominator(10) == 0

    @patch("pysymex.analysis.specialized.flow.CFGBuilder")
    def test_is_reachable(self, mock_cfg_builder) -> None:
        """Test is_reachable behavior."""
        cfg_mock = MockCFG()
        b = BasicBlock(1, 0, 10)
        cfg_mock.blocks = {1: b}
        cfg_mock.get_block_at_pc = Mock(return_value=b)
        cfg_mock.is_reachable = Mock(return_value=True)
        mock_cfg_builder.return_value.build.return_value = cfg_mock
        
        analyzer = FlowSensitiveAnalyzer(Mock()) # type: ignore[arg-type]
        assert analyzer.is_reachable(10) is True

class TestFlowContext:
    """Test suite for pysymex.analysis.specialized.flow.FlowContext."""
    def setup_analyzer(self) -> FlowSensitiveAnalyzer:
        analyzer = Mock()
        analyzer.cfg = MockCFG()
        analyzer.cfg.get_block_at_pc = Mock(return_value=BasicBlock(1, 0, 10))
        analyzer.reaching_defs = Mock()
        analyzer.reaching_defs.get_reaching_defs_at.return_value = [Definition("x", 1, 10)]
        analyzer.live_vars = Mock()
        analyzer.live_vars.get_out.return_value = {"x"}
        analyzer.null_analysis = Mock()
        
        from pysymex.analysis.dataflow.types import NullInfo, NullState
        analyzer.null_analysis.get_in.return_value = NullInfo({"x": NullState.DEFINITELY_NULL})
        return analyzer

    def test_create(self) -> None:
        """Test create behavior."""
        analyzer = self.setup_analyzer()
        ctx = FlowContext.create(analyzer, 10)
        assert ctx.pc == 10
        assert ctx.block is not None
        assert ctx.block.id == 1

    def test_is_variable_defined(self) -> None:
        """Test is_variable_defined behavior."""
        analyzer = self.setup_analyzer()
        ctx = FlowContext.create(analyzer, 10)
        assert ctx.is_variable_defined("x") is True

    def test_is_variable_live(self) -> None:
        """Test is_variable_live behavior."""
        analyzer = self.setup_analyzer()
        ctx = FlowContext.create(analyzer, 10)
        assert ctx.is_variable_live("x") is True

    def test_may_be_null(self) -> None:
        """Test may_be_null behavior."""
        analyzer = self.setup_analyzer()
        ctx = FlowContext.create(analyzer, 10)
        assert ctx.may_be_null("x") is True

    def test_is_definitely_null(self) -> None:
        """Test is_definitely_null behavior."""
        analyzer = self.setup_analyzer()
        ctx = FlowContext.create(analyzer, 10)
        assert ctx.is_definitely_null("x") is True

    def test_is_in_loop(self) -> None:
        """Test is_in_loop behavior."""
        analyzer = self.setup_analyzer()
        analyzer.is_in_loop.return_value = True
        ctx = FlowContext.create(analyzer, 10)
        assert ctx.is_in_loop() is True
