import dis
from pathlib import Path
from typing import cast

import pysymex.analysis.static.control.cfg as cfg_module
from pysymex.analysis.static.control.models import (
    BasicBlock,
    ControlFlowGraph,
    EdgeKind,
)
from pysymex.analysis.static.control.protocols import ExceptionEntryProtocol
from pysymex.analysis.static.control.cfg import CFGBuilder
from pytest import MonkeyPatch


class MockExceptionEntry(ExceptionEntryProtocol):
    def __init__(self, target: int, start: int, end: int) -> None:
        self._target = target
        self._start = start
        self._end = end

    @property
    def target(self) -> int:
        return self._target

    @property
    def start(self) -> int:
        return self._start

    @property
    def end(self) -> int:
        return self._end


class MockInstr:
    def __init__(self, opname: str, offset: int, argval: object = None) -> None:
        self.opname = opname
        self.offset = offset
        self.argval = argval
        self.starts_line = 10


def _instruction(opname: str, offset: int, argval: object = None) -> dis.Instruction:
    return cast(dis.Instruction, MockInstr(opname, offset, argval))


class TestExceptionEntryProtocol:
    """Test suite for pysymex.analysis.static.control.cfg.ExceptionEntryProtocol."""

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
    """Test suite for pysymex.analysis.static.control.cfg.EdgeKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert EdgeKind.SEQUENTIAL.name == "SEQUENTIAL"
        assert EdgeKind.BRANCH_TRUE.name == "BRANCH_TRUE"


class TestBasicBlock:
    """Test suite for pysymex.analysis.static.control.cfg.BasicBlock."""

    def test_block_id(self) -> None:
        """Test block_id behavior."""
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        assert b.block_id == 1

    def test_add_instruction(self) -> None:
        """Test add_instruction behavior."""
        b = BasicBlock(id=1, start_pc=0, end_pc=0)
        instr = _instruction("LOAD_CONST", 2)
        b.add_instruction(instr)
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
        instr = _instruction("RETURN_VALUE", 10)
        b.add_instruction(instr)
        assert b.get_terminator() is instr

    def test_is_conditional(self) -> None:
        """Test is_conditional behavior."""
        b = BasicBlock(id=1, start_pc=0, end_pc=10)
        assert b.is_conditional() is False
        instr = _instruction("POP_JUMP_IF_TRUE", 10)
        b.add_instruction(instr)
        assert b.is_conditional() is True


class TestControlFlowGraph:
    """Test suite for pysymex.analysis.static.control.cfg.ControlFlowGraph."""

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

    def test_iter_blocks_forward_uses_deterministic_successor_order(self) -> None:
        """Traversal order is stable for analysis diagnostics and dataflow worklists."""
        cfg = ControlFlowGraph()
        b0 = BasicBlock(id=0, start_pc=0, end_pc=2)
        b1 = BasicBlock(id=1, start_pc=4, end_pc=6)
        b2 = BasicBlock(id=2, start_pc=8, end_pc=10)
        b0.successors.update({2, 1})
        b1.predecessors.add(0)
        b2.predecessors.add(0)
        cfg.add_block(b0)
        cfg.add_block(b1)
        cfg.add_block(b2)

        blocks = list(cfg.iter_blocks_forward())

        assert [block.id for block in blocks] == [0, 1, 2]

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
    """Test suite for pysymex.analysis.static.control.cfg.CFGBuilder."""

    def test_loop_detection_imports_canonical_detector(self) -> None:
        assert cfg_module.__file__ is not None
        source = Path(cfg_module.__file__).resolve()
        text = source.read_text(encoding="utf-8")

        assert "pysymex.analysis.static.loops.detector import LoopDetector" in text
        assert "pysymex.analysis.static.loops.core import LoopDetector" not in text

    def test_build(self) -> None:
        """Test build behavior."""

        def my_func() -> int:
            return 42

        builder = CFGBuilder()
        cfg = builder.build(my_func.__code__)
        assert isinstance(cfg, ControlFlowGraph)
        assert len(cfg.blocks) > 0
        assert cfg.entry is not None

    def test_build_reports_exception_table_extraction_failure(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Exception-table extraction failure should be visible on the returned CFG."""

        def my_func() -> int:
            try:
                return 42
            except ValueError:
                return 0

        def fail_bytecode(code: object) -> object:
            raise RuntimeError("bytecode unavailable")

        monkeypatch.setattr(cfg_module.dis, "Bytecode", fail_bytecode)

        cfg = CFGBuilder().build(my_func.__code__)

        assert len(cfg.blocks) > 0
        assert cfg.construction_warnings == [
            "Failed to extract bytecode exception table for CFG: RuntimeError: bytecode unavailable"
        ]

    def test_build_from_instructions(self) -> None:
        """Test build_from_instructions behavior."""

        def my_func() -> int:
            return 42

        builder = CFGBuilder()
        instructions = list(dis.get_instructions(my_func.__code__))
        cfg = builder.build_from_instructions(instructions)
        assert isinstance(cfg, ControlFlowGraph)
        assert len(cfg.blocks) > 0

    def test_for_loop_cfg_has_one_loop_header_and_no_exit_self_loop(self) -> None:
        def loop(xs: list[int]) -> int:
            total = 0
            for x in xs:
                total += x
            return total

        instructions = list(dis.get_instructions(loop.__code__))
        for_iter = next(instr for instr in instructions if instr.opname == "FOR_ITER")
        assert isinstance(for_iter.argval, int)

        cfg = CFGBuilder().build(loop.__code__)
        header_block = cfg.get_block_at_pc(for_iter.offset)
        exit_block = cfg.get_block_at_pc(for_iter.argval)

        assert header_block is not None
        assert exit_block is not None
        assert cfg.loop_headers == {header_block.id}
        assert exit_block.id not in cfg.loop_headers
        assert (exit_block.id, exit_block.id) not in cfg.loop_back_edges

    def test_build_from_nonzero_offset_instructions_detects_loop_header(self) -> None:
        instructions = [
            _instruction("LOAD_CONST", 10),
            _instruction("POP_JUMP_IF_FALSE", 12, 20),
            _instruction("JUMP_BACKWARD", 14, 12),
            _instruction("RETURN_VALUE", 20),
        ]

        cfg = CFGBuilder().build_from_instructions(instructions)
        header_block = cfg.get_block_at_pc(12)
        back_block = cfg.get_block_at_pc(14)

        assert header_block is not None
        assert back_block is not None
        assert header_block.id in cfg.loop_headers
        assert (back_block.id, header_block.id) in cfg.loop_back_edges
