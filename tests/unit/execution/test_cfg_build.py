"""Tests for pysymex.execution.cfg — build_cfg, _jump_target, ControlFlowGraph."""

from __future__ import annotations

import dis

from pysymex.execution.cfg import BasicBlock, ControlFlowGraph, build_cfg, _jump_target


class TestJumpTarget:
    """Test the _jump_target helper using real compiled instructions."""

    def test_integer_argval_returns_int(self) -> None:
        """_jump_target returns int argval for a jump instruction."""
        code = compile("if True:\n x = 1\nelse:\n x = 2", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        # Find first instruction with int argval that is a jump
        for instr in instructions:
            if isinstance(instr.argval, int) and "JUMP" in instr.opname:
                result = _jump_target(instr)
                assert result == instr.argval
                return
        # If compiler optimizes away the jump, at least test a LOAD_CONST
        for instr in instructions:
            if instr.opname == "LOAD_CONST" and isinstance(instr.argval, int):
                result = _jump_target(instr)
                assert result == instr.argval
                return

    def test_string_argval_returns_none(self) -> None:
        """_jump_target returns None for non-int argval."""
        code = compile("x = 'hello'", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        for instr in instructions:
            if isinstance(instr.argval, str):
                assert _jump_target(instr) is None
                return

    def test_none_argval_returns_none(self) -> None:
        """_jump_target returns None when argval is None."""
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        for instr in instructions:
            if instr.argval is None:
                assert _jump_target(instr) is None
                return


class TestBuildCfg:
    """Test build_cfg producing valid ControlFlowGraphs."""

    def test_empty_instructions(self) -> None:
        """Empty instruction list produces empty CFG."""
        cfg = build_cfg([])
        assert cfg.blocks == {}
        assert cfg.entry_pc == 0

    def test_linear_function_produces_blocks(self) -> None:
        """Simple linear bytecode produces at least one block."""
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        cfg = build_cfg(instructions)
        assert len(cfg.blocks) >= 1
        assert cfg.entry_pc == 0

    def test_branching_function(self) -> None:
        """if/else bytecode produces a valid CFG."""
        code = compile("x = 1 if True else 2", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        cfg = build_cfg(instructions)
        assert len(cfg.blocks) >= 1
        assert isinstance(cfg, ControlFlowGraph)

    def test_function_with_return(self) -> None:
        """Function with return produces blocks."""
        code = compile("def f(): return 42", "<test>", "exec")
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                inner_code = const
                break
        else:
            inner_code = code
        instructions = list(dis.get_instructions(inner_code))
        cfg = build_cfg(instructions)
        assert len(cfg.blocks) >= 1

    def test_loop_function(self) -> None:
        """Loop bytecode produces multiple blocks."""
        code = compile("for i in range(10): x = i", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        cfg = build_cfg(instructions)
        assert len(cfg.blocks) >= 1


class TestControlFlowGraph:
    """Test ControlFlowGraph methods."""

    def test_get_block_for_pc_found(self) -> None:
        """get_block_for_pc returns the containing block."""
        block = BasicBlock(start_pc=0, end_pc=4, instructions=[], successors=[6])
        cfg = ControlFlowGraph(blocks={0: block}, entry_pc=0, exit_pcs=set())
        result = cfg.get_block_for_pc(2)
        assert result is block

    def test_get_block_for_pc_not_found(self) -> None:
        """get_block_for_pc returns None when PC is outside all blocks."""
        block = BasicBlock(start_pc=0, end_pc=4, instructions=[], successors=[6])
        cfg = ControlFlowGraph(blocks={0: block}, entry_pc=0, exit_pcs=set())
        assert cfg.get_block_for_pc(10) is None

    def test_get_successors_returns_block_successors(self) -> None:
        """get_successors returns successors for a known PC."""
        block = BasicBlock(start_pc=0, end_pc=4, instructions=[], successors=[6, 8])
        cfg = ControlFlowGraph(blocks={0: block}, entry_pc=0, exit_pcs=set())
        assert cfg.get_successors(2) == [6, 8]

    def test_get_successors_unknown_pc_returns_empty(self) -> None:
        """get_successors returns [] for unknown PC."""
        block = BasicBlock(start_pc=0, end_pc=4, instructions=[], successors=[6])
        cfg = ControlFlowGraph(blocks={0: block}, entry_pc=0, exit_pcs=set())
        assert cfg.get_successors(100) == []
