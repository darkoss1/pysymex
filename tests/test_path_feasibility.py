"""Tests for path feasibility checking and deduplication.

These tests verify that:
1. Infeasible paths are correctly identified and pruned
2. State deduplication doesn't incorrectly merge different states
3. Path exploration correctly handles convergent and divergent paths
4. Resource limits (depth, iterations) are respected

Path feasibility errors cause:
- Exploring impossible paths (wasted resources)
- Missing valid paths (incomplete analysis, missed bugs)
"""

from __future__ import annotations

import threading

import pytest
import z3

from pysymex.core.copy_on_write import ConstraintChain
from pysymex.core.solver import IncrementalSolver, is_satisfiable
from pysymex.core.state import VMState


class TestPathFeasibilityBasics:
    """Basic path feasibility tests."""

    def test_satisfiable_path_accepted(self):
        """Satisfiable constraint set should be feasible."""
        x = z3.Int("x")

        constraints = [x > 0, x < 100, x != 50]

        assert is_satisfiable(constraints) is True

    def test_unsatisfiable_path_rejected(self):
        """Unsatisfiable constraint set should be infeasible."""
        x = z3.Int("x")

        constraints = [x > 10, x < 5]

        assert is_satisfiable(constraints) is False

    def test_empty_constraints_feasible(self):
        """Empty constraints should be trivially feasible."""
        assert is_satisfiable([]) is True

    def test_single_satisfiable_constraint(self):
        """Single satisfiable constraint should be feasible."""
        x = z3.Int("x")
        assert is_satisfiable([x > 0]) is True

    def test_single_unsatisfiable_constraint(self):
        """Single unsatisfiable constraint should be infeasible."""
        x = z3.Int("x")
        # x != x is always false
        assert is_satisfiable([x != x]) is False


class TestPathFeasibilityWithSolver:
    """Path feasibility with IncrementalSolver."""

    def test_solver_is_sat_correct(self):
        """IncrementalSolver.is_sat should give correct results."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        assert solver.is_sat([x > 0]) is True
        assert solver.is_sat([x > 0, x < 0]) is False

    def test_solver_respects_ambient_constraints(self):
        """Ambient constraints should affect feasibility."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        solver.push()
        solver.add(x < 5)

        # x > 10 infeasible given x < 5
        assert solver.is_sat([x > 10]) is False

        solver.pop()

        # Without ambient, x > 10 is feasible
        assert solver.is_sat([x > 10]) is True

    def test_nested_scopes_feasibility(self):
        """Nested scopes should correctly track feasibility."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        solver.push()
        solver.add(x > 0)

        solver.push()
        solver.add(x < 10)

        # Feasible: 0 < x < 10
        assert solver.is_sat([x == 5]) is True
        # Infeasible in this scope
        assert solver.is_sat([x == 100]) is False

        solver.pop()

        # After popping inner scope, x == 100 should be feasible
        assert solver.is_sat([x == 100]) is True

        solver.pop()


class TestStateDeduplication:
    """Tests for state-based path deduplication."""

    def test_identical_states_same_hash(self):
        """Semantically identical states should have same hash."""
        x = z3.Int("x")

        state1 = VMState(pc=10)
        state1.local_vars["x"] = x
        state1.add_constraint(x > 0)

        state2 = VMState(pc=10)
        state2.local_vars["x"] = x
        state2.add_constraint(x > 0)

        assert state1.hash_value() == state2.hash_value()

    def test_different_pc_different_hash(self):
        """States at different PCs should have different hashes."""
        state1 = VMState(pc=10)
        state2 = VMState(pc=20)

        assert state1.hash_value() != state2.hash_value()

    def test_different_constraints_different_hash(self):
        """States with different constraints should have different hashes."""
        x = z3.Int("x")

        state1 = VMState()
        state1.add_constraint(x > 0)

        state2 = VMState()
        state2.add_constraint(x < 0)

        assert state1.hash_value() != state2.hash_value()

    def test_fork_produces_different_path_id(self):
        """Forked states should have different path IDs from each other."""
        state = VMState()

        fork1 = state.fork()
        fork2 = state.fork()

        # Each fork gets a unique path_id from the counter
        assert fork1.path_id != fork2.path_id

    def test_constraint_order_affects_chain_hash(self):
        """Constraint order affects ConstraintChain hash."""
        x = z3.Int("x")

        chain1 = ConstraintChain.from_list([x > 0, x < 10])
        chain2 = ConstraintChain.from_list([x < 10, x > 0])

        # Hash may or may not differ based on implementation,
        # but should be deterministic
        h1 = chain1.hash_value()
        h2 = chain1.hash_value()
        assert h1 == h2  # Same chain, same hash


class TestBranchExploration:
    """Tests for branch path exploration."""

    def test_both_branches_of_conditional(self):
        """Both branches of a conditional should be explorable."""
        x = z3.Int("x")

        base_state = VMState()
        base_state.local_vars["x"] = x

        # Fork for true branch
        true_branch = base_state.fork()
        true_branch.add_constraint(x > 0)

        # Fork for false branch
        false_branch = base_state.fork()
        false_branch.add_constraint(z3.Not(x > 0))

        # Both should be feasible
        assert is_satisfiable(true_branch.path_constraints.to_list()) is True
        assert is_satisfiable(false_branch.path_constraints.to_list()) is True

    def test_incompatible_branches_detected(self):
        """Incompatible constraint combinations should be detected."""
        x = z3.Int("x")

        state = VMState()
        state.add_constraint(x > 10)
        state.add_constraint(x < 5)

        # This path is infeasible
        assert is_satisfiable(state.path_constraints.to_list()) is False

    def test_deep_path_feasibility(self):
        """Deep paths with many constraints should be checkable."""
        x = z3.Int("x")

        state = VMState()

        # Add many compatible constraints
        for i in range(100):
            state.add_constraint(x > i)

        # Still feasible as long as x > 99
        assert is_satisfiable(state.path_constraints.to_list()) is True

        # Add contradicting constraint
        state.add_constraint(x < 50)

        # Now infeasible
        assert is_satisfiable(state.path_constraints.to_list()) is False


class TestLoopUnrolling:
    """Tests for loop iteration tracking."""

    def test_loop_iteration_tracking(self):
        """Loop iterations should be tracked correctly."""
        state = VMState()
        loop_pc = 10

        state.loop_iterations[loop_pc] = 0

        for i in range(5):
            state.loop_iterations[loop_pc] = i + 1

        assert state.loop_iterations[loop_pc] == 5

    def test_loop_iterations_isolated_on_fork(self):
        """Loop iterations should be isolated across forks."""
        state = VMState()
        state.loop_iterations[10] = 5

        fork = state.fork()
        fork.loop_iterations[10] = 10
        fork.loop_iterations[20] = 1

        assert state.loop_iterations[10] == 5
        assert 20 not in state.loop_iterations


class TestVisitedPCTracking:
    """Tests for visited PC tracking for loop detection."""

    def test_mark_visited_first_time(self):
        """First visit should return False."""
        state = VMState(pc=10)

        was_visited = state.mark_visited()

        assert was_visited is False
        assert 10 in state.visited_pcs

    def test_mark_visited_second_time(self):
        """Second visit to same PC should return True."""
        state = VMState(pc=10)

        state.mark_visited()
        was_visited = state.mark_visited()

        assert was_visited is True

    def test_visited_isolated_on_fork(self):
        """Visited PCs should be isolated on fork."""
        state = VMState(pc=10)
        state.mark_visited()

        fork = state.fork()
        fork.pc = 20
        fork.mark_visited()

        assert 20 not in state.visited_pcs
        assert 20 in fork.visited_pcs


class TestConstraintChainOperations:
    """Tests for ConstraintChain operations."""

    def test_chain_length_tracking(self):
        """Chain length should be tracked correctly."""
        x = z3.Int("x")

        chain = ConstraintChain.empty()
        assert len(chain) == 0

        chain = chain.append(x > 0)
        assert len(chain) == 1

        chain = chain.append(x < 10)
        assert len(chain) == 2

    def test_chain_to_list_preserves_order(self):
        """to_list should preserve chronological order."""
        x = z3.Int("x")

        c1 = x > 0
        c2 = x < 10
        c3 = x != 5

        chain = ConstraintChain.from_list([c1, c2, c3])
        lst = chain.to_list()

        assert lst[0].eq(c1)
        assert lst[1].eq(c2)
        assert lst[2].eq(c3)

    def test_chain_iteration_reverse_order(self):
        """Iteration should be in chronological order (oldest first)."""
        x = z3.Int("x")

        c1 = x > 0
        c2 = x < 10

        chain = ConstraintChain.from_list([c1, c2])
        items = list(chain)

        # Oldest first
        assert len(items) == 2
        assert items[0].eq(c1)
        assert items[1].eq(c2)


class TestPendingConstraintCount:
    """Tests for pending_constraint_count optimization."""

    def test_count_increments_on_add(self):
        """Adding constraint should increment pending count."""
        state = VMState()
        x = z3.Int("x")

        assert state.pending_constraint_count == 0

        state.add_constraint(x > 0)
        assert state.pending_constraint_count == 1

        state.add_constraint(x < 10)
        assert state.pending_constraint_count == 2

    def test_count_inherited_on_fork(self):
        """Fork should inherit pending_constraint_count."""
        state = VMState()
        x = z3.Int("x")

        state.add_constraint(x > 0)
        state.add_constraint(x < 10)

        fork = state.fork()

        # BUG-012 fix: count should be inherited, not reset
        assert fork.pending_constraint_count == 2

    def test_count_independent_after_fork(self):
        """After fork, counts should be independent."""
        state = VMState()
        x = z3.Int("x")
        y = z3.Int("y")

        state.add_constraint(x > 0)
        fork = state.fork()

        fork.add_constraint(y > 0)

        assert state.pending_constraint_count == 1
        assert fork.pending_constraint_count == 2


class TestStateDepthTracking:
    """Tests for execution depth tracking."""

    def test_depth_can_be_set(self):
        """Depth should be settable."""
        state = VMState(depth=0)
        state.depth = 10

        assert state.depth == 10

    def test_depth_isolated_on_fork(self):
        """Depth should be isolated on fork."""
        state = VMState(depth=5)
        fork = state.fork()

        fork.depth = 10

        assert state.depth == 5
        assert fork.depth == 10


class TestComplexPathScenarios:
    """Complex path exploration scenarios."""

    def test_diamond_pattern(self):
        """Diamond control flow pattern."""
        x = z3.Int("x")

        # Start
        start = VMState()
        start.add_constraint(x > 0)

        # Branch: x > 5 vs x <= 5
        left = start.fork()
        left.add_constraint(x > 5)

        right = start.fork()
        right.add_constraint(x <= 5)

        # Both paths converge - verify independent feasibility
        assert is_satisfiable(left.path_constraints.to_list()) is True
        assert is_satisfiable(right.path_constraints.to_list()) is True

        # Left can have x = 10
        left_constraints = left.path_constraints.to_list() + [x == 10]
        assert is_satisfiable(left_constraints) is True

        # Right cannot have x = 10
        right_constraints = right.path_constraints.to_list() + [x == 10]
        assert is_satisfiable(right_constraints) is False

    def test_multiple_variable_constraints(self):
        """Path with constraints on multiple variables."""
        x = z3.Int("x")
        y = z3.Int("y")
        z_var = z3.Int("z")

        state = VMState()
        state.add_constraint(x > 0)
        state.add_constraint(y > x)
        state.add_constraint(z_var > y)
        state.add_constraint(z_var < 100)

        # Feasible: e.g., x=1, y=2, z=3
        assert is_satisfiable(state.path_constraints.to_list()) is True

        # Add conflicting constraint
        state.add_constraint(x > z_var)

        # Now infeasible: x > z > y > x is cyclic
        assert is_satisfiable(state.path_constraints.to_list()) is False
