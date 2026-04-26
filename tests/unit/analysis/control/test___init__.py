"""Tests for pysymex.analysis.control — CFG construction and dominator analysis."""

from __future__ import annotations

import dis

from pysymex.analysis.control import (
    BasicBlock,
    CFGBuilder,
    ControlFlowGraph,
    EdgeKind,
)


class TestEdgeKind:
    """Tests for EdgeKind enum members."""

    def test_sequential_exists(self) -> None:
        """SEQUENTIAL edge kind exists."""
        assert EdgeKind.SEQUENTIAL.name == "SEQUENTIAL"

    def test_branch_true_exists(self) -> None:
        """BRANCH_TRUE edge kind exists."""
        assert EdgeKind.BRANCH_TRUE.name == "BRANCH_TRUE"

    def test_branch_false_exists(self) -> None:
        """BRANCH_FALSE edge kind exists."""
        assert EdgeKind.BRANCH_FALSE.name == "BRANCH_FALSE"

    def test_jump_exists(self) -> None:
        """JUMP edge kind exists."""
        assert EdgeKind.JUMP.name == "JUMP"

    def test_exception_exists(self) -> None:
        """EXCEPTION edge kind exists."""
        assert EdgeKind.EXCEPTION.name == "EXCEPTION"

    def test_return_exists(self) -> None:
        """RETURN edge kind exists."""
        assert EdgeKind.RETURN.name == "RETURN"

    def test_loop_back_exists(self) -> None:
        """LOOP_BACK edge kind exists."""
        assert EdgeKind.LOOP_BACK.name == "LOOP_BACK"

    def test_loop_exit_exists(self) -> None:
        """LOOP_EXIT edge kind exists."""
        assert EdgeKind.LOOP_EXIT.name == "LOOP_EXIT"


class TestBasicBlock:
    """Tests for BasicBlock dataclass."""

    def test_init(self) -> None:
        """BasicBlock initializes with id and pc range."""
        bb = BasicBlock(id=0, start_pc=0, end_pc=4)
        assert bb.id == 0
        assert bb.start_pc == 0
        assert bb.end_pc == 4

    def test_block_id_alias(self) -> None:
        """block_id is an alias for id."""
        bb = BasicBlock(id=5, start_pc=0, end_pc=0)
        assert bb.block_id == 5

    def test_hash(self) -> None:
        """BasicBlock is hashable based on id."""
        bb = BasicBlock(id=7, start_pc=0, end_pc=0)
        assert hash(bb) == hash(7)

    def test_add_instruction(self) -> None:
        """add_instruction appends to instructions and updates end_pc."""
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        bb = BasicBlock(id=0, start_pc=0, end_pc=0)
        for instr in instructions:
            bb.add_instruction(instr)
        assert len(bb.instructions) == len(instructions)
        assert bb.end_pc == instructions[-1].offset

    def test_add_successor(self) -> None:
        """add_successor adds to successors and successor_edges."""
        bb = BasicBlock(id=0, start_pc=0, end_pc=0)
        bb.add_successor(1, EdgeKind.SEQUENTIAL)
        assert 1 in bb.successors
        assert bb.successor_edges[1] == EdgeKind.SEQUENTIAL

    def test_get_terminator_empty(self) -> None:
        """get_terminator returns None for empty block."""
        bb = BasicBlock(id=0, start_pc=0, end_pc=0)
        assert bb.get_terminator() is None

    def test_get_terminator_nonempty(self) -> None:
        """get_terminator returns last instruction."""
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        bb = BasicBlock(id=0, start_pc=0, end_pc=0)
        for instr in instructions:
            bb.add_instruction(instr)
        term = bb.get_terminator()
        assert term is not None
        assert term is instructions[-1]

    def test_is_conditional_false_for_simple(self) -> None:
        """is_conditional returns False for a simple assignment block."""
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        bb = BasicBlock(id=0, start_pc=0, end_pc=0)
        for instr in instructions:
            bb.add_instruction(instr)
        assert bb.is_conditional() is False

    def test_repr(self) -> None:
        """repr shows id and pc range."""
        bb = BasicBlock(id=2, start_pc=0, end_pc=10)
        assert "BasicBlock(2" in repr(bb)

    def test_default_flags(self) -> None:
        """Default flags are False."""
        bb = BasicBlock(id=0, start_pc=0, end_pc=0)
        assert bb.is_entry is False
        assert bb.is_exit is False
        assert bb.is_loop_header is False
        assert bb.is_exception_handler is False


class TestControlFlowGraph:
    """Tests for ControlFlowGraph structure."""

    def test_empty_cfg(self) -> None:
        """Empty CFG has no blocks."""
        cfg = ControlFlowGraph()
        assert cfg.blocks == {}
        assert cfg.entry is None

    def test_add_block(self) -> None:
        """add_block registers block and pc mapping."""
        cfg = ControlFlowGraph()
        bb = BasicBlock(id=0, start_pc=0, end_pc=4)
        cfg.add_block(bb)
        assert cfg.get_block(0) is bb
        assert cfg.get_block_at_pc(0) is bb

    def test_get_block_missing(self) -> None:
        """get_block returns None for missing id."""
        cfg = ControlFlowGraph()
        assert cfg.get_block(99) is None

    def test_get_block_at_pc_missing(self) -> None:
        """get_block_at_pc returns None for unmapped pc."""
        cfg = ControlFlowGraph()
        assert cfg.get_block_at_pc(99) is None

    def test_get_predecessors_empty(self) -> None:
        """get_predecessors returns empty set for no predecessors."""
        cfg = ControlFlowGraph()
        assert cfg.get_predecessors(0) == set()

    def test_get_successors_empty(self) -> None:
        """get_successors returns empty set for no successors."""
        cfg = ControlFlowGraph()
        assert cfg.get_successors(0) == set()

    def test_is_reachable(self) -> None:
        """is_reachable checks dominator set membership."""
        cfg = ControlFlowGraph()
        cfg.dominators[0] = {0}
        assert cfg.is_reachable(0) is True
        assert cfg.is_reachable(1) is False

    def test_dominates(self) -> None:
        """dominates checks if A is in B's dominator set."""
        cfg = ControlFlowGraph()
        cfg.dominators[1] = {0, 1}
        assert cfg.dominates(0, 1) is True
        assert cfg.dominates(1, 0) is False

    def test_is_loop_header(self) -> None:
        """is_loop_header checks loop_headers set."""
        cfg = ControlFlowGraph()
        cfg.loop_headers.add(3)
        assert cfg.is_loop_header(3) is True
        assert cfg.is_loop_header(0) is False

    def test_get_loop_body_empty(self) -> None:
        """get_loop_body returns empty set for non-loop header."""
        cfg = ControlFlowGraph()
        assert cfg.get_loop_body(0) == set()


class TestCFGBuilder:
    """Tests for CFGBuilder from bytecode."""

    def test_build_simple_assignment(self) -> None:
        """Build CFG from simple assignment code."""
        code = compile("x = 1", "<test>", "exec")
        builder = CFGBuilder()
        cfg = builder.build(code)
        assert len(cfg.blocks) >= 1
        assert cfg.entry is not None
        assert cfg.entry.is_entry is True

    def test_build_conditional(self) -> None:
        """Build CFG from if/else code produces branches."""
        code = compile("x = 1\nif x > 0:\n    y = 2\nelse:\n    y = 3\n", "<test>", "exec")
        builder = CFGBuilder()
        cfg = builder.build(code)
        assert len(cfg.blocks) >= 2

    def test_build_loop(self) -> None:
        """Build CFG from for loop detects loop structure."""
        code = compile("s = 0\nfor i in range(10):\n    s += i\n", "<test>", "exec")
        builder = CFGBuilder()
        cfg = builder.build(code)
        assert len(cfg.blocks) >= 2

    def test_build_from_instructions(self) -> None:
        """build_from_instructions works with instruction list."""
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        builder = CFGBuilder()
        cfg = builder.build_from_instructions(instructions)
        assert len(cfg.blocks) >= 1

    def test_build_empty_code(self) -> None:
        """Building from empty instruction list returns empty CFG."""
        builder = CFGBuilder()
        cfg = builder.build_from_instructions([])
        assert len(cfg.blocks) == 0

    def test_exit_blocks_identified(self) -> None:
        """Blocks ending with RETURN are marked as exit."""
        code = compile("def f():\n    return 1\n", "<test>", "exec")
        # Get the inner function code
        inner_code = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        builder = CFGBuilder()
        cfg = builder.build(inner_code)
        assert len(cfg.exit_block_ids) >= 1

    def test_dominators_computed(self) -> None:
        """Dominators are computed after build."""
        code = compile("x = 1\nif x:\n    y = 2\n", "<test>", "exec")
        builder = CFGBuilder()
        cfg = builder.build(code)
        assert len(cfg.dominators) >= 1
        # Entry block dominates itself
        assert cfg.entry_block_id in cfg.dominators.get(cfg.entry_block_id, set())

    def test_iter_blocks_forward(self) -> None:
        """iter_blocks_forward visits all blocks."""
        code = compile("x = 1\nif x:\n    y = 2\n", "<test>", "exec")
        builder = CFGBuilder()
        cfg = builder.build(code)
        forward = list(cfg.iter_blocks_forward())
        assert len(forward) >= 1

    def test_iter_blocks_reverse(self) -> None:
        """iter_blocks_reverse visits all blocks in reverse."""
        code = compile("x = 1\nif x:\n    y = 2\n", "<test>", "exec")
        builder = CFGBuilder()
        cfg = builder.build(code)
        reverse_list = list(cfg.iter_blocks_reverse())
        forward = list(cfg.iter_blocks_forward())
        assert len(reverse_list) == len(forward)
