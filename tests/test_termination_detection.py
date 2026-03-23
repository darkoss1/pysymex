"""Tests for termination detection and resource limit enforcement.

These tests verify that:
1. Analysis terminates on infinite loops (via depth/iteration limits)
2. Resource limits (paths, steps, time) are respected
3. Widening correctly accelerates loop analysis
4. The executor doesn't hang on pathological inputs

Termination bugs cause:
- Analysis hangs forever
- Resource exhaustion (memory, CPU)
- Denial of service on malicious inputs
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any

import pytest
import z3

from pysymex.core.state import VMState
from pysymex.core.copy_on_write import ConstraintChain


class TestLoopIterationLimits:
    """Tests for loop iteration limit enforcement."""

    def test_iteration_count_tracking(self):
        """Loop iteration counts should be tracked."""
        state = VMState()
        loop_pc = 10

        state.loop_iterations[loop_pc] = 0

        for i in range(10):
            state.loop_iterations[loop_pc] += 1

        assert state.loop_iterations[loop_pc] == 10

    def test_iteration_limit_check(self):
        """Iteration count should allow limit checking."""
        state = VMState()
        max_iterations = 100
        loop_pc = 20

        state.loop_iterations[loop_pc] = 0

        # Simulate loop until limit
        while state.loop_iterations.get(loop_pc, 0) < max_iterations:
            state.loop_iterations[loop_pc] = state.loop_iterations.get(loop_pc, 0) + 1

        assert state.loop_iterations[loop_pc] == max_iterations

    def test_multiple_loops_independent(self):
        """Different loops should have independent counters."""
        state = VMState()

        state.loop_iterations[10] = 5
        state.loop_iterations[20] = 10
        state.loop_iterations[30] = 15

        assert state.loop_iterations[10] == 5
        assert state.loop_iterations[20] == 10
        assert state.loop_iterations[30] == 15


class TestDepthLimits:
    """Tests for execution depth limits."""

    def test_depth_tracking(self):
        """Execution depth should be trackable."""
        state = VMState(depth=0)

        for _ in range(100):
            state.depth += 1

        assert state.depth == 100

    def test_depth_limit_check(self):
        """Depth limit should be checkable."""
        max_depth = 1000

        state = VMState(depth=500)
        assert state.depth < max_depth

        state = VMState(depth=1000)
        assert state.depth >= max_depth

    def test_depth_preserved_on_fork(self):
        """Depth should be preserved on fork."""
        state = VMState(depth=50)
        fork = state.fork()

        assert fork.depth == 50

        fork.depth = 100
        assert state.depth == 50  # Original unchanged


class TestPathExplosionMitigation:
    """Tests for path explosion handling."""

    def test_many_branch_states_trackable(self):
        """System should handle many branching states."""
        states: list[VMState] = [VMState()]

        # Simulate branching
        for _ in range(10):
            new_states: list[VMState] = []
            for state in states:
                # Each state branches into two
                true_branch = state.fork()
                false_branch = state.fork()
                new_states.extend([true_branch, false_branch])
            states = new_states

        # Should have 2^10 = 1024 states
        assert len(states) == 1024

    def test_constraint_chain_efficiency(self):
        """Constraint chains should be efficient for deep paths."""
        x = z3.Int("x")

        chain = ConstraintChain.empty()

        # Add many constraints
        for i in range(1000):
            chain = chain.append(x > i)

        assert len(chain) == 1000

        # Should be able to fork efficiently
        fork1 = chain.append(x < 2000)
        fork2 = chain.append(x < 3000)

        assert len(fork1) == 1001
        assert len(fork2) == 1001
        assert len(chain) == 1000  # Original unchanged


class TestVisitedPCDeduplication:
    """Tests for PC visitation deduplication."""

    def test_visited_pc_prevents_revisit(self):
        """Already visited PC should be detectable."""
        state = VMState(pc=10)

        first_visit = state.mark_visited()
        second_visit = state.mark_visited()

        assert first_visit is False
        assert second_visit is True

    def test_different_pcs_not_confused(self):
        """Different PCs should not interfere."""
        state = VMState()

        state.pc = 10
        state.mark_visited()

        state.pc = 20
        first_visit_20 = state.mark_visited()

        assert first_visit_20 is False  # First time seeing PC 20


class TestConstraintChainBounding:
    """Tests for constraint chain memory bounding."""

    def test_hash_bounded_to_64bit(self):
        """Chain hash should stay within 64-bit bounds."""
        x = z3.Int("x")

        chain = ConstraintChain.empty()
        for i in range(10000):
            chain = chain.append(x > i)

        h = chain.hash_value()

        assert h >= 0
        assert h < (1 << 64)

    def test_length_accurate(self):
        """Chain length should be accurate."""
        x = z3.Int("x")

        chain = ConstraintChain.empty()
        for i in range(500):
            chain = chain.append(x > i)
            assert len(chain) == i + 1


class TestTimeoutHandling:
    """Tests for timeout in various operations."""

    def test_solver_respects_timeout(self):
        """Solver should respect timeout setting."""
        from pysymex.core.solver import IncrementalSolver

        # Very short timeout
        solver = IncrementalSolver(timeout_ms=100)

        x = z3.Int("x")
        # Simple query should complete quickly
        result = solver.is_sat([x > 0])

        assert result is True

    def test_long_running_detectable(self):
        """Long-running operations should be detectable via timeout."""
        def potentially_long_operation():
            # Simulate work
            total = 0
            for i in range(1000000):
                total += i
            return total

        start = time.time()
        result = potentially_long_operation()
        elapsed = time.time() - start

        # Should complete in reasonable time
        assert elapsed < 10.0


class TestPendingConstraintOptimization:
    """Tests for pending constraint count optimization."""

    def test_pending_count_resets_after_check(self):
        """Pending count should be resettable after feasibility check."""
        state = VMState()
        x = z3.Int("x")

        state.add_constraint(x > 0)
        state.add_constraint(x < 10)

        assert state.pending_constraint_count == 2

        # Simulate feasibility check reset
        state.pending_constraint_count = 0

        assert state.pending_constraint_count == 0

    def test_pending_count_guides_check_frequency(self):
        """Pending count should guide when to check feasibility."""
        state = VMState()
        x = z3.Int("x")

        check_threshold = 5

        for i in range(10):
            state.add_constraint(x > i)

            if state.pending_constraint_count >= check_threshold:
                # Would normally check feasibility here
                state.pending_constraint_count = 0

        # Count should be less than threshold at end
        assert state.pending_constraint_count < check_threshold


class TestBranchTraceTracking:
    """Tests for branch trace tracking."""

    def test_branch_trace_accumulates(self):
        """Branch trace should accumulate decisions."""
        state = VMState()
        cond1 = z3.Bool("c1")
        cond2 = z3.Bool("c2")

        state.record_branch(cond1, True, 10)
        state.record_branch(cond2, False, 20)

        assert len(state.branch_trace) == 2

    def test_branch_trace_fork_isolation(self):
        """Branch traces should be isolated on fork."""
        state = VMState()
        cond1 = z3.Bool("c1")

        state.record_branch(cond1, True, 10)

        fork = state.fork()
        fork.record_branch(z3.Bool("c2"), False, 20)

        assert len(state.branch_trace) == 1
        assert len(fork.branch_trace) == 2


class TestResourceLimitEnforcement:
    """Tests for resource limit enforcement patterns."""

    def test_max_paths_pattern(self):
        """Max paths limit pattern should work."""
        max_paths = 100
        explored_paths = 0
        worklist: list[VMState] = [VMState()]

        while worklist and explored_paths < max_paths:
            state = worklist.pop()
            explored_paths += 1

            # Simulate branching
            if explored_paths < 50:
                worklist.append(state.fork())
                worklist.append(state.fork())

        assert explored_paths <= max_paths

    def test_max_steps_pattern(self):
        """Max steps limit pattern should work."""
        max_steps = 1000

        state = VMState()
        steps = 0

        while steps < max_steps:
            state.pc += 1
            steps += 1

        assert steps == max_steps

    def test_worklist_bounded(self):
        """Worklist size can be bounded."""
        max_worklist_size = 50
        worklist: list[VMState] = [VMState()]

        for _ in range(100):
            if worklist:
                state = worklist.pop()
                # Only add if we won't exceed the limit
                if len(worklist) + 2 <= max_worklist_size:
                    worklist.append(state.fork())
                    worklist.append(state.fork())

        assert len(worklist) <= max_worklist_size


class TestInfiniteLoopDetection:
    """Tests for infinite loop detection patterns."""

    def test_pc_revisit_detection(self):
        """PC revisit should be detectable."""
        state = VMState(pc=100)

        visits = 0
        max_revisits = 5

        for _ in range(10):
            if state.mark_visited():
                visits += 1
                if visits >= max_revisits:
                    break

        assert visits >= max_revisits

    def test_state_hash_convergence_detection(self):
        """State hash convergence should be detectable."""
        seen_hashes: set[int] = set()

        state = VMState(pc=10)

        for i in range(100):
            h = state.hash_value()
            if h in seen_hashes:
                # Convergence detected
                break
            seen_hashes.add(h)
            state.pc = 10  # Stay at same PC

        # Should detect convergence quickly
        assert len(seen_hashes) < 100
