import pytest
import dis
from pysymex.analysis.control.cfg import (
    ExceptionEntryProtocol, EdgeKind, BasicBlock, ControlFlowGraph, CFGBuilder
)

class MockExceptionEntry(ExceptionEntryProtocol):
    def __init__(self, target: int, start: int, end: int) -> None:
        self._target = target
        self._start = start
        self._end = end
    @property
    def target(self) -> int: return self._target
    @property
    def start(self) -> int: return self._start
    @property
    def end(self) -> int: return self._end

class MockInstr:
    def __init__(self, opname: str, offset: int, argval: object = None) -> None:
        self.opname = opname
        self.offset = offset
        self.argval = argval
        self.starts_line = 10

class TestExceptionEntryProtocol:
    """Test suite for pysymex.analysis.control.cfg.ExceptionEntryProtocol."""
    def test_target(self) -> None:
        """Test target behavior."""
        entry = MockExceptionEntry(target=1, start=2, end=3)
        assert entry.target == 1

    def test_start(self) -> None:
        """Test start behavior."""
        entry = MockExceptionEntry(target=1, start=2, end=3)
        assert entry.start == 2

    def test_end(self) -> None:
        """Test end behavior."""
        entry = MockExceptionEntry(target=1, start=2, end=3)
        assert entry.end == 3

class TestEdgeKind:
    """Test suite for pysymex.analysis.control.cfg.EdgeKind."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert EdgeKind.SEQUENTIAL.name == "SEQUENTIAL"
        assert EdgeKind.BRANCH_TRUE.name == "BRANCH_TRUE"

class TestBasicBlock:
    """Test suite for pysymex.analysis.control.cfg.BasicBlock."""
    def test_block_id(self) -> None:
        """Test block_id behavior."""
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        assert b.block_id == 1

    def test_add_instruction(self) -> None:
        """Test add_instruction behavior."""
        b = BasicBlock(id=1, start_pc=0, end_pc=0)
        instr = MockInstr("LOAD_CONST", 2)
        b.add_instruction(instr) # type: ignore[arg-type]
        assert len(b.instructions) == 1
        assert b.end_pc == 2

    def test_add_successor(self) -> None:
        """Test add_successor behavior."""
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        b.add_successor(2, EdgeKind.BRANCH_TRUE)
        assert 2 in b.successors
        assert b.successor_edges[2] == EdgeKind.BRANCH_TRUE

    def test_get_terminator(self) -> None:
        """Test get_terminator behavior."""
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        assert b.get_terminator() is None
        instr = MockInstr("RETURN_VALUE", 10)
        b.add_instruction(instr) # type: ignore[arg-type]
        assert b.get_terminator() is instr

    def test_is_conditional(self) -> None:
        """Test is_conditional behavior."""
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        assert b.is_conditional() is False
        instr = MockInstr("POP_JUMP_IF_TRUE", 10)
        b.add_instruction(instr) # type: ignore[arg-type]
        assert b.is_conditional() is True

class TestControlFlowGraph:
    """Test suite for pysymex.analysis.control.cfg.ControlFlowGraph."""
    def test_entry(self) -> None:
        """Test entry behavior."""
        cfg = ControlFlowGraph()
        b = BasicBlock(id=0, start_pc=0, end_pc=10)
        cfg.add_block(b)
        assert cfg.entry is b

    def test_add_block(self) -> None:
        """Test add_block behavior."""
        cfg = ControlFlowGraph()
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        cfg.add_block(b)
        assert 1 in cfg.blocks
        assert cfg.pc_to_block[5] == 1

    def test_get_block(self) -> None:
        """Test get_block behavior."""
        cfg = ControlFlowGraph()
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        cfg.add_block(b)
        assert cfg.get_block(1) is b
        assert cfg.get_block(99) is None

    def test_get_block_at_pc(self) -> None:
        """Test get_block_at_pc behavior."""
        cfg = ControlFlowGraph()
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        cfg.add_block(b)
        assert cfg.get_block_at_pc(5) is b
        assert cfg.get_block_at_pc(99) is None

    def test_get_predecessors(self) -> None:
        """Test get_predecessors behavior."""
        cfg = ControlFlowGraph()
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        b.predecessors.add(2)
        cfg.add_block(b)
        assert 2 in cfg.get_predecessors(1)
        assert len(cfg.get_predecessors(99)) == 0

    def test_get_successors(self) -> None:
        """Test get_successors behavior."""
        cfg = ControlFlowGraph()
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        b.successors.add(2)
        cfg.add_block(b)
        assert 2 in cfg.get_successors(1)
        assert len(cfg.get_successors(99)) == 0

    def test_is_reachable(self) -> None:
        """Test is_reachable behavior."""
        cfg = ControlFlowGraph()
        cfg.dominators[1] = {1}
        assert cfg.is_reachable(1) is True
        assert cfg.is_reachable(2) is False

    def test_dominates(self) -> None:
        """Test dominates behavior."""
        cfg = ControlFlowGraph()
        cfg.blocks[1] = BasicBlock(id=1, start_pc=0, end_pc=10)
        cfg.blocks[2] = BasicBlock(id=2, start_pc=0, end_pc=10)
        cfg.dominators[2] = {1, 2}
        assert cfg.dominates(1, 2) is True
        assert cfg.dominates(3, 2) is False

    def test_get_immediate_dominator(self) -> None:
        """Test get_immediate_dominator behavior."""
        cfg = ControlFlowGraph()
        b = BasicBlock(id=2, start_pc=0, end_pc=10)
        b.immediate_dominator = 1
        cfg.add_block(b)
        assert cfg.get_immediate_dominator(2) == 1
        assert cfg.get_immediate_dominator(99) is None

    def test_is_loop_header(self) -> None:
        """Test is_loop_header behavior."""
        cfg = ControlFlowGraph()
        cfg.loop_headers.add(1)
        assert cfg.is_loop_header(1) is True
        assert cfg.is_loop_header(2) is False

    def test_get_loop_body(self) -> None:
        """Test get_loop_body behavior."""
        cfg = ControlFlowGraph()
        cfg.natural_loops[1] = {1, 2, 3}
        assert 2 in cfg.get_loop_body(1)
        assert len(cfg.get_loop_body(99)) == 0

    def test_iter_blocks_forward(self) -> None:
        """Test iter_blocks_forward behavior."""
        cfg = ControlFlowGraph()
        b0 = BasicBlock(id=0, start_pc=0, end_pc=2)
        b1 = BasicBlock(id=1, start_pc=4, end_pc=6)
        b0.successors.add(1)
        b1.predecessors.add(0)
        cfg.add_block(b0)
        cfg.add_block(b1)
        blocks = list(cfg.iter_blocks_forward())
        assert blocks[0].id == 0
        assert blocks[1].id == 1

    def test_iter_blocks_reverse(self) -> None:
        """Test iter_blocks_reverse behavior."""
        cfg = ControlFlowGraph()
        b0 = BasicBlock(id=0, start_pc=0, end_pc=2)
        b1 = BasicBlock(id=1, start_pc=4, end_pc=6)
        b0.successors.add(1)
        b1.predecessors.add(0)
        cfg.add_block(b0)
        cfg.add_block(b1)
        blocks = list(cfg.iter_blocks_reverse())
        assert blocks[0].id == 1
        assert blocks[1].id == 0

class TestCFGBuilder:
    """Test suite for pysymex.analysis.control.cfg.CFGBuilder."""
    def test_build(self) -> None:
        """Test build behavior."""
        def my_func() -> int:
            return 42
        builder = CFGBuilder()
        cfg = builder.build(my_func.__code__)
        assert isinstance(cfg, ControlFlowGraph)
        assert len(cfg.blocks) > 0
        assert cfg.entry is not None

    def test_build_from_instructions(self) -> None:
        """Test build_from_instructions behavior."""
        def my_func() -> int: return 42
        builder = CFGBuilder()
        # Fallback to fetching instructions to pass to build_from_instructions
        instructions = list(dis.get_instructions(my_func.__code__))
        cfg = builder.build_from_instructions(instructions)
        assert isinstance(cfg, ControlFlowGraph)
        assert len(cfg.blocks) > 0
