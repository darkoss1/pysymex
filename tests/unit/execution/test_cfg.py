from __future__ import annotations

import dis

from pysymex.execution.cfg import BasicBlock, ControlFlowGraph, build_cfg


class TestBasicBlock:
    """Test suite for pysymex.execution.cfg.BasicBlock."""

    def test_init(self) -> None:
        """Test basic block initialization."""
        instr = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
        block = BasicBlock(
            start_pc=0,
            end_pc=2,
            instructions=[instr],
            successors=[4],
            is_branch=True,
            is_return=False,
        )
        assert block.start_pc == 0
        assert block.end_pc == 2
        assert block.instructions == [instr]
        assert block.successors == [4]
        assert block.is_branch is True
        assert block.is_return is False


class TestControlFlowGraph:
    """Test suite for pysymex.execution.cfg.ControlFlowGraph."""

    def test_get_block_for_pc_found(self) -> None:
        """Test getting block by PC when found."""
        instr1 = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
        block1 = BasicBlock(0, 2, [instr1], [4])
        cfg = ControlFlowGraph(blocks={0: block1}, entry_pc=0, exit_pcs=set())
        assert cfg.get_block_for_pc(0) is block1
        assert cfg.get_block_for_pc(2) is block1

    def test_get_block_for_pc_not_found(self) -> None:
        """Test getting block by PC when not found."""
        cfg = ControlFlowGraph(blocks={}, entry_pc=0, exit_pcs=set())
        assert cfg.get_block_for_pc(8) is None

    def test_get_successors_found(self) -> None:
        """Test getting successors when block found."""
        instr1 = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
        block1 = BasicBlock(0, 2, [instr1], [4, 6])
        cfg = ControlFlowGraph(blocks={0: block1}, entry_pc=0, exit_pcs=set())
        assert cfg.get_successors(0) == [4, 6]

    def test_get_successors_not_found(self) -> None:
        """Test getting successors when block not found."""
        cfg = ControlFlowGraph(blocks={}, entry_pc=0, exit_pcs=set())
        assert cfg.get_successors(10) == []


class TestBuildCfg:
    """Test suite for build_cfg."""

    def test_sequential(self) -> None:
        """Test build_cfg with sequential code."""
        code = compile("x = 1\ny = 2", "<test>", "exec")
        instrs = list(dis.get_instructions(code))
        cfg = build_cfg(instrs)
        assert cfg.entry_pc == 0
        assert len(cfg.blocks) >= 1
        assert len(cfg.exit_pcs) >= 1

    def test_empty(self) -> None:
        """Test build_cfg with empty instruction list."""
        empty_cfg = build_cfg([])
        assert len(empty_cfg.blocks) == 0

    def test_branching(self) -> None:
        """Test build_cfg with branching code."""
        branch_code = compile("if x:\n  y = 1\nelse:\n  y = 2", "<test>", "exec")
        branch_instrs = list(dis.get_instructions(branch_code))
        branch_cfg = build_cfg(branch_instrs)
        assert len(branch_cfg.blocks) > 1
        branch_blocks = [b for b in branch_cfg.blocks.values() if b.is_branch]
        assert len(branch_blocks) >= 1

    def test_jumping(self) -> None:
        """Test build_cfg with jumping code."""
        jump_code = compile("while True:\n  pass", "<test>", "exec")
        jump_instrs = list(dis.get_instructions(jump_code))
        jump_cfg = build_cfg(jump_instrs)
        assert len(jump_cfg.blocks) > 0
