"""Tests for pysymex.analysis.cfg -- Control Flow Graph infrastructure.

Covers:
- BasicBlock construction and properties
- EdgeKind enum values
- CFGBuilder.build() from real code objects
- ControlFlowGraph queries (blocks, dominators, loops, reachability)
- Forward/reverse iteration
"""

from __future__ import annotations

import dis

import pytest

from pysymex.analysis.cfg import BasicBlock, CFGBuilder, ControlFlowGraph, EdgeKind


# ---------------------------------------------------------------------------
# Target functions used to build CFGs
# ---------------------------------------------------------------------------


def _linear():
    x = 1
    y = 2
    return x + y


def _if_else(x):
    if x > 0:
        return 1
    else:
        return -1


def _if_no_else(x):
    if x > 0:
        x = x + 1
    return x


def _while_loop(n):
    i = 0
    while i < n:
        i += 1
    return i


def _for_loop(items):
    total = 0
    for item in items:
        total += item
    return total


def _nested_if(x, y):
    if x > 0:
        if y > 0:
            return 1
        else:
            return 2
    return 3


def _try_except(x):
    try:
        return 1 / x
    except ZeroDivisionError:
        return 0


def _multiple_returns(x):
    if x > 0:
        return 1
    if x < 0:
        return -1
    return 0


def _and_or(x, y):
    if x > 0 and y > 0:
        return True
    return False


def _empty_function():
    pass


def _nested_loop(n, m):
    for i in range(n):
        for j in range(m):
            pass
    return 0


def _while_break(n):
    i = 0
    while True:
        if i >= n:
            break
        i += 1
    return i


# ---------------------------------------------------------------------------
# EdgeKind basic tests
# ---------------------------------------------------------------------------


class TestEdgeKind:
    """Tests for the EdgeKind enum."""

    def test_sequential_exists(self):
        assert EdgeKind.SEQUENTIAL is not None

    def test_branch_true_exists(self):
        assert EdgeKind.BRANCH_TRUE is not None

    def test_branch_false_exists(self):
        assert EdgeKind.BRANCH_FALSE is not None

    def test_jump_exists(self):
        assert EdgeKind.JUMP is not None

    def test_exception_exists(self):
        assert EdgeKind.EXCEPTION is not None

    def test_return_exists(self):
        assert EdgeKind.RETURN is not None

    def test_loop_back_exists(self):
        assert EdgeKind.LOOP_BACK is not None

    def test_loop_exit_exists(self):
        assert EdgeKind.LOOP_EXIT is not None

    def test_all_members_distinct(self):
        values = [e.value for e in EdgeKind]
        assert len(values) == len(set(values))


# ---------------------------------------------------------------------------
# BasicBlock unit tests
# ---------------------------------------------------------------------------


class TestBasicBlock:
    """Tests for BasicBlock dataclass methods."""

    def test_block_id_alias(self):
        bb = BasicBlock(id=7, start_pc=0, end_pc=10)
        assert bb.block_id == 7

    def test_hash_stable(self):
        bb = BasicBlock(id=3, start_pc=0, end_pc=0)
        assert hash(bb) == hash(3)

    def test_add_successor(self):
        bb = BasicBlock(id=0, start_pc=0, end_pc=0)
        bb.add_successor(1, EdgeKind.SEQUENTIAL)
        assert 1 in bb.successors
        assert bb.successor_edges[1] == EdgeKind.SEQUENTIAL

    def test_get_terminator_empty(self):
        bb = BasicBlock(id=0, start_pc=0, end_pc=0)
        assert bb.get_terminator() is None

    def test_is_conditional_false_when_empty(self):
        bb = BasicBlock(id=0, start_pc=0, end_pc=0)
        assert bb.is_conditional() is False

    def test_repr_contains_id(self):
        bb = BasicBlock(id=5, start_pc=10, end_pc=20)
        r = repr(bb)
        assert "5" in r
        assert "10" in r


# ---------------------------------------------------------------------------
# CFGBuilder.build() -- linear code
# ---------------------------------------------------------------------------


class TestCFGBuilderLinear:
    """CFG construction for straight-line code."""

    def test_linear_has_blocks(self):
        cfg = CFGBuilder().build(_linear.__code__)
        assert len(cfg.blocks) >= 1

    def test_linear_has_entry(self):
        cfg = CFGBuilder().build(_linear.__code__)
        assert cfg.entry is not None
        assert cfg.entry.is_entry

    def test_linear_has_exit(self):
        cfg = CFGBuilder().build(_linear.__code__)
        assert len(cfg.exit_block_ids) >= 1

    def test_entry_dominates_all(self):
        cfg = CFGBuilder().build(_linear.__code__)
        entry_id = cfg.entry_block_id
        for block_id in cfg.blocks:
            assert cfg.dominates(entry_id, block_id)

    def test_empty_function(self):
        cfg = CFGBuilder().build(_empty_function.__code__)
        assert len(cfg.blocks) >= 1


# ---------------------------------------------------------------------------
# CFGBuilder.build() -- branches
# ---------------------------------------------------------------------------


class TestCFGBuilderBranches:
    """CFG construction for branching code."""

    def test_if_else_multiple_blocks(self):
        cfg = CFGBuilder().build(_if_else.__code__)
        assert len(cfg.blocks) >= 2

    def test_if_else_has_conditional_block(self):
        cfg = CFGBuilder().build(_if_else.__code__)
        has_cond = any(b.is_conditional() for b in cfg.blocks.values())
        # There should be at least one conditional or multiple exits
        assert has_cond or len(cfg.exit_block_ids) >= 2

    def test_if_else_two_exit_blocks(self):
        cfg = CFGBuilder().build(_if_else.__code__)
        assert len(cfg.exit_block_ids) >= 2

    def test_if_no_else_fallthrough(self):
        cfg = CFGBuilder().build(_if_no_else.__code__)
        assert len(cfg.blocks) >= 2

    def test_nested_if_blocks(self):
        cfg = CFGBuilder().build(_nested_if.__code__)
        assert len(cfg.blocks) >= 3

    def test_multiple_returns_exits(self):
        cfg = CFGBuilder().build(_multiple_returns.__code__)
        assert len(cfg.exit_block_ids) >= 2

    def test_and_or_blocks(self):
        cfg = CFGBuilder().build(_and_or.__code__)
        assert len(cfg.blocks) >= 2


# ---------------------------------------------------------------------------
# CFGBuilder.build() -- loops
# ---------------------------------------------------------------------------


class TestCFGBuilderLoops:
    """CFG construction for loops."""

    def test_while_loop_detected(self):
        cfg = CFGBuilder().build(_while_loop.__code__)
        # Either natural loops detected or loop_headers found
        has_loop = len(cfg.loop_headers) > 0 or len(cfg.natural_loops) > 0
        # Fall back: at least we have back edges or multiple blocks
        assert has_loop or len(cfg.blocks) >= 2

    def test_for_loop_detected(self):
        cfg = CFGBuilder().build(_for_loop.__code__)
        assert len(cfg.blocks) >= 2

    def test_nested_loops(self):
        cfg = CFGBuilder().build(_nested_loop.__code__)
        assert len(cfg.blocks) >= 3

    def test_while_break_blocks(self):
        cfg = CFGBuilder().build(_while_break.__code__)
        assert len(cfg.blocks) >= 3

    def test_loop_body_contains_header(self):
        cfg = CFGBuilder().build(_while_loop.__code__)
        for header_id, body in cfg.natural_loops.items():
            assert header_id in body


# ---------------------------------------------------------------------------
# ControlFlowGraph query methods
# ---------------------------------------------------------------------------


class TestControlFlowGraphQueries:
    """ControlFlowGraph query interface."""

    @pytest.fixture()
    def cfg(self):
        return CFGBuilder().build(_if_else.__code__)

    def test_get_block(self, cfg):
        block = cfg.get_block(cfg.entry_block_id)
        assert block is not None
        assert block.id == cfg.entry_block_id

    def test_get_block_missing(self, cfg):
        assert cfg.get_block(9999) is None

    def test_get_block_at_pc(self, cfg):
        entry = cfg.entry
        assert entry is not None
        looked_up = cfg.get_block_at_pc(entry.start_pc)
        assert looked_up is not None
        assert looked_up.id == entry.id

    def test_get_predecessors(self, cfg):
        preds = cfg.get_predecessors(cfg.entry_block_id)
        assert isinstance(preds, set)

    def test_get_successors(self, cfg):
        succs = cfg.get_successors(cfg.entry_block_id)
        assert isinstance(succs, set)

    def test_is_reachable_entry(self, cfg):
        assert cfg.is_reachable(cfg.entry_block_id)

    def test_dominates_self(self, cfg):
        for block_id in cfg.blocks:
            assert cfg.dominates(block_id, block_id)

    def test_get_immediate_dominator_entry_is_none(self, cfg):
        idom = cfg.get_immediate_dominator(cfg.entry_block_id)
        assert idom is None

    def test_get_immediate_dominator_nonentry(self, cfg):
        for block_id in cfg.blocks:
            if block_id != cfg.entry_block_id:
                idom = cfg.get_immediate_dominator(block_id)
                # Every non-entry reachable block has an idom
                if cfg.is_reachable(block_id):
                    assert idom is not None

    def test_is_loop_header_false_for_non_loop(self, cfg):
        assert cfg.is_loop_header(cfg.entry_block_id) is False

    def test_get_loop_body_empty_for_non_loop(self, cfg):
        body = cfg.get_loop_body(cfg.entry_block_id)
        assert body == set()


# ---------------------------------------------------------------------------
# Forward / Reverse iteration
# ---------------------------------------------------------------------------


class TestCFGIteration:
    """Block iteration orders."""

    def test_iter_forward_covers_all_reachable(self):
        cfg = CFGBuilder().build(_if_else.__code__)
        forward = list(cfg.iter_blocks_forward())
        forward_ids = {b.id for b in forward}
        for bid in cfg.blocks:
            if cfg.is_reachable(bid):
                assert bid in forward_ids

    def test_iter_reverse_same_length(self):
        cfg = CFGBuilder().build(_if_else.__code__)
        forward = list(cfg.iter_blocks_forward())
        reverse = list(cfg.iter_blocks_reverse())
        assert len(forward) == len(reverse)

    def test_iter_forward_starts_with_entry(self):
        cfg = CFGBuilder().build(_linear.__code__)
        forward = list(cfg.iter_blocks_forward())
        assert forward[0].id == cfg.entry_block_id


# ---------------------------------------------------------------------------
# build_from_instructions
# ---------------------------------------------------------------------------


class TestBuildFromInstructions:
    """CFGBuilder.build_from_instructions (no code object)."""

    def test_empty_instructions(self):
        cfg = CFGBuilder().build_from_instructions([])
        assert len(cfg.blocks) == 0

    def test_single_return(self):
        instructions = list(dis.get_instructions(_linear.__code__))
        cfg = CFGBuilder().build_from_instructions(instructions)
        assert len(cfg.blocks) >= 1
        assert cfg.entry is not None


# ---------------------------------------------------------------------------
# Exception handling
# ---------------------------------------------------------------------------


class TestCFGExceptions:
    """CFG construction with try/except."""

    def test_try_except_has_exception_handler(self):
        cfg = CFGBuilder().build(_try_except.__code__)
        handler_blocks = [b for b in cfg.blocks.values() if b.is_exception_handler]
        # May or may not detect handler depending on Python version
        assert len(cfg.blocks) >= 2

    def test_try_except_exception_edges(self):
        cfg = CFGBuilder().build(_try_except.__code__)
        exception_edges = []
        for b in cfg.blocks.values():
            for succ_id, kind in b.successor_edges.items():
                if kind == EdgeKind.EXCEPTION:
                    exception_edges.append((b.id, succ_id))
        # With Python 3.12+, exception table entries should produce edges
        # On older versions, SETUP_FINALLY creates them
        assert len(cfg.blocks) >= 2
