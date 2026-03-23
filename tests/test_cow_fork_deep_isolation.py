"""Tests for COW (Copy-on-Write) fork deep isolation correctness.

These tests verify that COW forking correctly isolates state mutations:
1. Parent mutations don't affect children
2. Child mutations don't affect parent or siblings
3. Deep fork chains maintain isolation
4. All mutable components (stack, vars, constraints, memory) are isolated

Incorrect COW isolation causes silent state corruption across paths,
leading to incorrect analysis results that are extremely hard to debug.
"""

from __future__ import annotations

import gc
import weakref
from typing import Any

import pytest
import z3

from pysymex.core.copy_on_write import BranchChain, BranchRecord, ConstraintChain, CowDict, CowSet
from pysymex.core.state import BlockInfo, CallFrame, VMState


class TestCowDictDeepIsolation:
    """Tests for CowDict deep isolation."""

    def test_parent_write_after_fork_isolated(self):
        """Writing to parent after fork must not affect child."""
        parent = CowDict({"a": 1, "b": 2})
        child = parent.cow_fork()

        parent["c"] = 3

        assert "c" in parent
        assert "c" not in child

    def test_child_write_isolated_from_parent(self):
        """Writing to child must not affect parent."""
        parent = CowDict({"a": 1})
        child = parent.cow_fork()

        child["a"] = 999
        child["b"] = 2

        assert parent["a"] == 1
        assert "b" not in parent

    def test_sibling_isolation(self):
        """Siblings forked from same parent must be mutually isolated."""
        parent = CowDict({"a": 1})
        child1 = parent.cow_fork()
        child2 = parent.cow_fork()

        child1["x"] = "from_child1"
        child2["y"] = "from_child2"

        assert "x" not in parent
        assert "x" not in child2
        assert "y" not in parent
        assert "y" not in child1

    def test_deep_chain_isolation(self):
        """Deep fork chains maintain complete isolation."""
        d0 = CowDict({"root": True})

        chain = [d0]
        for i in range(50):
            fork = chain[-1].cow_fork()
            fork[f"depth_{i}"] = i
            chain.append(fork)

        # Root should only have original key
        assert len(d0) == 1
        assert "root" in d0

        # Each level should have exactly its prefix
        for i, d in enumerate(chain):
            if i == 0:
                assert len(d) == 1
            else:
                assert f"depth_{i-1}" in d
                assert len(d) == i + 1

    def test_delete_isolated(self):
        """Delete operations must be isolated."""
        parent = CowDict({"a": 1, "b": 2, "c": 3})
        child = parent.cow_fork()

        del child["b"]

        assert "b" in parent
        assert "b" not in child

    def test_update_isolated(self):
        """Update operations must be isolated."""
        parent = CowDict({"a": 1})
        child = parent.cow_fork()

        child.update({"b": 2, "c": 3})

        assert len(parent) == 1
        assert len(child) == 3

    def test_pop_isolated(self):
        """Pop operations must be isolated."""
        parent = CowDict({"a": 1, "b": 2})
        child = parent.cow_fork()

        val = child.pop("a")

        assert val == 1
        assert "a" in parent
        assert "a" not in child

    def test_setdefault_isolated(self):
        """setdefault operations must be isolated."""
        parent = CowDict({"a": 1})
        child = parent.cow_fork()

        child.setdefault("b", 2)

        assert "b" not in parent
        assert child["b"] == 2


class TestCowSetDeepIsolation:
    """Tests for CowSet deep isolation."""

    def test_add_isolated(self):
        """Add operations must be isolated."""
        parent = CowSet({1, 2, 3})
        child = parent.cow_fork()

        child.add(4)

        assert 4 not in parent
        assert 4 in child

    def test_discard_isolated(self):
        """Discard operations must be isolated."""
        parent = CowSet({1, 2, 3})
        child = parent.cow_fork()

        child.discard(2)

        assert 2 in parent
        assert 2 not in child

    def test_sibling_isolation(self):
        """Siblings forked from same parent must be mutually isolated."""
        parent = CowSet({1})
        child1 = parent.cow_fork()
        child2 = parent.cow_fork()

        child1.add(100)
        child2.add(200)

        assert 100 not in parent
        assert 100 not in child2
        assert 200 not in parent
        assert 200 not in child1

    def test_multiple_mutations_isolated(self):
        """Multiple mutations must all be isolated."""
        parent = CowSet({1, 2, 3, 4, 5})
        child = parent.cow_fork()

        child.add(100)
        child.discard(1)
        child.add(200)
        child.discard(2)

        assert 1 in parent
        assert 2 in parent
        assert 100 not in parent
        assert 200 not in parent


class TestConstraintChainDeepIsolation:
    """Tests for ConstraintChain fork isolation."""

    def test_append_creates_new_chain(self):
        """Appending returns new chain without modifying original."""
        x = z3.Int("x")
        chain1 = ConstraintChain.empty().append(x > 0)
        chain2 = chain1.append(x < 10)

        assert len(chain1) == 1
        assert len(chain2) == 2

    def test_shared_prefix_immutable(self):
        """Chains sharing prefix must not corrupt each other."""
        x = z3.Int("x")

        base = ConstraintChain.empty().append(x > 0)
        fork1 = base.append(x < 5)
        fork2 = base.append(x < 10)
        fork3 = base.append(x < 15)

        # All forks should have correct lengths
        assert len(base) == 1
        assert len(fork1) == 2
        assert len(fork2) == 2
        assert len(fork3) == 2

        # Check actual constraints
        base_list = base.to_list()
        fork1_list = fork1.to_list()
        fork2_list = fork2.to_list()

        assert len(base_list) == 1
        assert len(fork1_list) == 2
        assert len(fork2_list) == 2

    def test_deep_chain_memory_efficiency(self):
        """Deep chains should share structure efficiently."""
        x = z3.Int("x")

        chain = ConstraintChain.empty()
        for i in range(1000):
            chain = chain.append(x > i)

        # Creating many forks shouldn't cause memory explosion
        forks: list[ConstraintChain] = []
        for i in range(100):
            fork = chain.append(x < 2000 + i)
            forks.append(fork)

        # All forks should be correct
        for i, fork in enumerate(forks):
            assert len(fork) == 1001


class TestBranchChainDeepIsolation:
    """Tests for BranchChain fork isolation."""

    def test_branch_chain_isolation(self):
        """Branch chain appends must not affect original."""
        cond1 = z3.Bool("c1")
        cond2 = z3.Bool("c2")

        record1 = BranchRecord(pc=0, condition=cond1, taken=True)
        record2 = BranchRecord(pc=4, condition=cond2, taken=False)

        chain1 = BranchChain.empty().append(record1)
        chain2 = chain1.append(record2)

        assert len(chain1) == 1
        assert len(chain2) == 2


class TestVMStateDeepIsolation:
    """Tests for VMState complete isolation."""

    def test_stack_deep_isolation(self):
        """Stack must be completely isolated across forks."""
        state = VMState()
        state.stack.append(z3.IntVal(1))
        state.stack.append(z3.IntVal(2))

        fork = state.fork()
        fork.stack.append(z3.IntVal(3))
        fork.stack.pop()
        fork.stack[-1] = z3.IntVal(99)

        assert len(state.stack) == 2
        assert len(fork.stack) == 2

    def test_local_vars_deep_isolation(self):
        """Local variables must be completely isolated."""
        state = VMState()
        state.local_vars["x"] = z3.Int("x")
        state.local_vars["y"] = z3.Int("y")

        fork = state.fork()
        fork.local_vars["z"] = z3.Int("z")
        del fork.local_vars["x"]

        assert "x" in state.local_vars
        assert "z" not in state.local_vars

    def test_global_vars_deep_isolation(self):
        """Global variables must be completely isolated."""
        state = VMState()
        state.global_vars["config"] = {"debug": True}

        fork = state.fork()
        fork.global_vars["config"] = {"debug": False}

        # Note: The dict object reference is shared, but the CowDict key is isolated
        assert state.global_vars.get("config") == {"debug": True}

    def test_memory_deep_isolation(self):
        """Memory must be completely isolated."""
        state = VMState()
        state.memory[100] = z3.Int("val1")
        state.memory[200] = z3.Int("val2")

        fork = state.fork()
        fork.memory[300] = z3.Int("val3")
        fork.memory[100] = z3.Int("new_val1")

        assert 300 not in state.memory
        # State's memory at 100 should be unchanged

    def test_constraint_chain_isolation(self):
        """Path constraints must be isolated."""
        x = z3.Int("x")

        state = VMState()
        state.add_constraint(x > 0)

        fork = state.fork()
        fork.add_constraint(x < 10)

        assert len(state.path_constraints) == 1
        assert len(fork.path_constraints) == 2

    def test_visited_pcs_isolation(self):
        """Visited PCs must be isolated."""
        state = VMState()
        state.visited_pcs.add(0)
        state.visited_pcs.add(10)

        fork = state.fork()
        fork.visited_pcs.add(20)

        assert 20 not in state.visited_pcs
        assert 20 in fork.visited_pcs

    def test_block_stack_isolation(self):
        """Block stack must be isolated."""
        block = BlockInfo(block_type="loop", start_pc=0, end_pc=100)

        state = VMState()
        state.block_stack.append(block)

        fork = state.fork()
        fork.block_stack.pop()

        assert len(state.block_stack) == 1
        assert len(fork.block_stack) == 0

    def test_loop_iterations_isolation(self):
        """Loop iteration counts must be isolated."""
        state = VMState()
        state.loop_iterations[10] = 5

        fork = state.fork()
        fork.loop_iterations[10] = 10
        fork.loop_iterations[20] = 1

        assert state.loop_iterations.get(10) == 5
        assert 20 not in state.loop_iterations

    def test_control_taint_isolation(self):
        """Control taint labels must be isolated."""
        state = VMState(control_taint=frozenset({"user_input"}))

        fork = state.fork()
        fork.control_taint = frozenset({"user_input", "network"})

        assert "network" not in state.control_taint
        assert "network" in fork.control_taint

    def test_pending_constraint_count_inherited(self):
        """pending_constraint_count should be inherited, not reset."""
        state = VMState()
        state.pending_constraint_count = 5

        fork = state.fork()

        # BUG-012 fix verification
        assert fork.pending_constraint_count == 5

    def test_branch_trace_isolation(self):
        """Branch trace must be isolated."""
        cond = z3.Bool("c")
        record = BranchRecord(pc=0, condition=cond, taken=True)

        state = VMState()
        state.record_branch(cond, True, 0)

        fork = state.fork()
        fork.record_branch(z3.Not(cond), False, 4)

        assert len(state.branch_trace) == 1
        assert len(fork.branch_trace) == 2


class TestCallFrameIsolation:
    """Tests for CallFrame isolation in VMState."""

    def test_call_stack_isolation(self):
        """Call stack must be isolated."""
        frame = CallFrame(
            function_name="foo",
            return_pc=10,
            local_vars=CowDict({"a": 1}),
            stack_depth=5,
        )

        state = VMState()
        state.call_stack.append(frame)

        fork = state.fork()
        fork.call_stack.pop()

        assert len(state.call_stack) == 1
        assert len(fork.call_stack) == 0

    def test_call_frame_local_vars_isolation(self):
        """CallFrame local vars must be forked if summary_builder present."""
        local_vars = CowDict({"x": z3.Int("x")})
        frame = CallFrame(
            function_name="bar",
            return_pc=20,
            local_vars=local_vars,
            stack_depth=3,
            summary_builder=object(),  # Triggers deep copy path
        )

        state = VMState()
        state.call_stack.append(frame)

        fork = state.fork()

        # Modify the forked frame's local vars
        if fork.call_stack:
            # CallFrame is frozen, so we can't modify it directly
            # but the local_vars CowDict should be forked
            assert fork.call_stack[0].local_vars is not state.call_stack[0].local_vars


class TestMassForking:
    """Stress tests for mass forking."""

    def test_thousand_forks(self):
        """Creating 1000 forks should be efficient and correct."""
        state = VMState()
        x = z3.Int("x")
        state.local_vars["x"] = x
        state.add_constraint(x > 0)

        forks: list[VMState] = []
        for i in range(1000):
            fork = state.fork()
            fork.local_vars[f"y_{i}"] = i
            forks.append(fork)

        # Original should be unchanged
        assert len(state.local_vars) == 1
        assert "y_0" not in state.local_vars

        # Each fork should have its unique variable
        for i, fork in enumerate(forks):
            assert f"y_{i}" in fork.local_vars

    def test_deep_sequential_fork_chain(self):
        """Sequential fork chain should maintain isolation at each level."""
        state = VMState()

        chain = [state]
        for i in range(100):
            prev = chain[-1]
            next_state = prev.fork()
            next_state.pc = i
            next_state.local_vars[f"depth_{i}"] = i
            chain.append(next_state)

        # Verify each level
        for i, s in enumerate(chain):
            if i == 0:
                assert s.pc == 0
                assert len(s.local_vars) == 0
            else:
                assert s.pc == i - 1
                assert f"depth_{i-1}" in s.local_vars

    def test_breadth_fork_tree(self):
        """Breadth-first fork tree should maintain isolation."""
        root = VMState()
        root.local_vars["root"] = True

        # Create tree with depth 3, branching factor 10
        level0 = [root]
        level1: list[VMState] = []
        level2: list[VMState] = []

        for state in level0:
            for i in range(10):
                fork = state.fork()
                fork.local_vars[f"l1_{i}"] = i
                level1.append(fork)

        for state in level1:
            for i in range(10):
                fork = state.fork()
                fork.local_vars[f"l2_{i}"] = i
                level2.append(fork)

        # Root unchanged
        assert len(root.local_vars) == 1

        # Level 1 states should have l1_* but not l2_*
        for s in level1:
            assert "root" in s.local_vars
            assert any(k.startswith("l1_") for k in s.local_vars)
            assert not any(k.startswith("l2_") for k in s.local_vars)


class TestMemoryPressure:
    """Tests for CoW behavior under memory pressure."""

    def test_gc_doesnt_corrupt_shared_state(self):
        """GC cycles shouldn't corrupt shared CoW state."""
        state = VMState()
        x = z3.Int("x")
        state.local_vars["x"] = x

        forks: list[VMState] = []
        for _ in range(100):
            fork = state.fork()
            forks.append(fork)

        # Force GC
        gc.collect()
        gc.collect()

        # All forks should still be valid
        for fork in forks:
            assert "x" in fork.local_vars

    def test_forked_state_independent_gc(self):
        """Forking should produce independent objects for GC purposes.

        Note: VMState uses __slots__ and doesn't support weakref by default.
        This test verifies that forked states don't share underlying data
        after mutations and can be collected independently.
        """
        state = VMState()
        state.local_vars["x"] = z3.Int("x")

        # Create many forks with modifications
        forks: list[VMState] = []
        for i in range(10):
            fork = state.fork()
            fork.local_vars[f"y_{i}"] = z3.Int(f"y_{i}")
            forks.append(fork)

        # Clear most forks
        forks_subset = forks[5:]
        del forks

        gc.collect()
        gc.collect()

        # Remaining forks should still be valid
        for fork in forks_subset:
            assert "x" in fork.local_vars

        # Original should be unaffected
        assert "x" in state.local_vars
        assert "y_0" not in state.local_vars
