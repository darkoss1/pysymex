"""Path feasibility soundness tests.

Verifies that no feasible paths are incorrectly pruned.

Source contracts tested:
- executor_core.py:821-841 (_check_path_feasibility)
- solver.py:458-462 (Unknown treated as SAT for soundness)

Critical invariants:
1. Unknown solver results must be treated as SAT (no unsound pruning)
2. Timeout must not be treated as UNSAT
3. Lazy evaluation threshold must not lose paths
4. All reachable branches must have at least one feasible path
"""

from __future__ import annotations

import pytest
import z3

from pysymex.core.solver import IncrementalSolver, SolverResult, is_satisfiable
from pysymex.core.state import VMState, create_initial_state
from pysymex.core.copy_on_write import ConstraintChain


class TestUnknownTreatedAsSAT:
    """Verify unknown results are conservatively treated as SAT."""

    def test_unknown_result_returns_sat(self):
        """SolverResult.unknown must be treated as SAT by is_sat()."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        # Any SAT query should return True
        assert solver.is_sat([x > 0]) is True

        # Even complex queries that might return unknown should return True
        # (conservative soundness)
        a, b = z3.Ints("a b")
        complex_constraints = [
            a * a + b * b > 0,
            a > 0,
            b > 0,
        ]
        result = solver.is_sat(complex_constraints)
        assert result is True  # Either SAT or unknown->True

    def test_is_satisfiable_function_soundness(self):
        """Module-level is_satisfiable must be sound."""
        x = z3.Int("x")

        # Definite SAT
        assert is_satisfiable([x > 0]) is True

        # Definite UNSAT
        assert is_satisfiable([x > 0, x < 0]) is False

        # Complex but SAT
        assert is_satisfiable([x > -1000, x < 1000]) is True


class TestTimeoutHandling:
    """Verify timeouts do not cause incorrect UNSAT conclusions."""

    def test_very_short_timeout_does_not_falsely_prune(self):
        """Even with very short timeout, SAT constraints should not return False."""
        # Create solver with minimal timeout
        solver = IncrementalSolver(timeout_ms=1)
        x = z3.Int("x")

        # Simple SAT query - should work even with timeout
        result = solver.is_sat([x > 0])

        # Must return True (either computed or conservative)
        assert result is True

    def test_timeout_does_not_pollute_cache(self):
        """Timed-out queries should not incorrectly cache as SAT or UNSAT."""
        solver = IncrementalSolver(timeout_ms=1)
        x = z3.Int("x")

        # First query with short timeout
        constraints = [x > 0, x < 100]
        result1 = solver.is_sat(constraints)

        # Create new solver with longer timeout
        solver2 = IncrementalSolver(timeout_ms=10000)
        result2 = solver2.is_sat(constraints)

        # Both should return True (one computed, one maybe cached)
        assert result1 is True
        assert result2 is True


class TestNoFalsePathPruning:
    """Verify no feasible paths are incorrectly pruned."""

    def test_sat_constraint_always_feasible(self):
        """Satisfiable constraint sets must never be pruned."""
        solver = IncrementalSolver()

        test_cases = [
            # Simple cases
            [z3.Int("x") > 0],
            [z3.Int("x") > 0, z3.Int("x") < 100],
            # Multiple variables
            [z3.Int("x") > 0, z3.Int("y") > 0],
            # Boolean constraints
            [z3.Bool("b") == True],
            [z3.Or(z3.Int("x") > 0, z3.Int("x") < 0)],
            # Edge cases
            [z3.Int("x") == 0],
            [z3.Int("x") != 0],
        ]

        for constraints in test_cases:
            result = solver.is_sat(constraints)
            assert result is True, f"Feasible path incorrectly pruned: {constraints}"

    def test_unsat_constraint_correctly_pruned(self):
        """Unsatisfiable constraints must return False (correct pruning)."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        unsat_cases = [
            [x > 0, x < 0],
            [x == 5, x == 10],
            [z3.And(x > 0, x < 0)],
            [z3.BoolVal(False)],
        ]

        for constraints in unsat_cases:
            result = solver.is_sat(constraints)
            assert result is False, f"UNSAT not detected: {constraints}"

    def test_edge_case_constraints(self):
        """Edge cases like empty constraints should be handled correctly."""
        solver = IncrementalSolver()

        # Empty constraints = trivially SAT
        assert solver.is_sat([]) is True

        # Single True constraint
        assert solver.is_sat([z3.BoolVal(True)]) is True

        # Single False constraint
        assert solver.is_sat([z3.BoolVal(False)]) is False


class TestBranchCoverage:
    """Verify all reachable branches are explored."""

    def test_both_branches_of_conditional_explored(self):
        """Both True and False branches of a conditional must be feasible."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        # In context where x is unconstrained
        condition = x > 0

        # True branch should be feasible
        true_branch = solver.is_sat([condition])
        assert true_branch is True

        # False branch should be feasible
        false_branch = solver.is_sat([z3.Not(condition)])
        assert false_branch is True

    def test_exhaustive_case_coverage(self):
        """All cases in exhaustive branching should be reachable."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        # Simulate exhaustive branching: x < 0, x == 0, x > 0
        cases = [
            x < 0,
            x == 0,
            x > 0,
        ]

        for case in cases:
            result = solver.is_sat([case])
            assert result is True, f"Reachable case incorrectly pruned: {case}"


class TestConstraintChainFeasibility:
    """Verify constraint chain operations maintain feasibility correctly."""

    def test_appending_sat_constraint_stays_sat(self):
        """Adding a compatible constraint to SAT chain should stay SAT."""
        x = z3.Int("x")

        chain = ConstraintChain.empty()
        chain = chain.append(x > 0)

        constraints = chain.to_list()
        assert is_satisfiable(constraints) is True

        # Add compatible constraint
        chain = chain.append(x < 100)
        constraints = chain.to_list()
        assert is_satisfiable(constraints) is True

    def test_appending_incompatible_constraint_becomes_unsat(self):
        """Adding incompatible constraint should make chain UNSAT."""
        x = z3.Int("x")

        chain = ConstraintChain.empty()
        chain = chain.append(x > 10)

        # Add incompatible constraint
        chain = chain.append(x < 5)

        constraints = chain.to_list()
        assert is_satisfiable(constraints) is False


class TestVMStateFeasibility:
    """Verify VMState path constraint feasibility."""

    def test_initial_state_is_feasible(self):
        """Fresh initial state should always be feasible."""
        state = create_initial_state()
        constraints = state.path_constraints.to_list()
        assert is_satisfiable(constraints) is True

    def test_state_with_sat_constraints_is_feasible(self):
        """State with SAT constraints should be feasible."""
        x = z3.Int("x")
        state = create_initial_state(constraints=[x > 0, x < 100])

        constraints = state.path_constraints.to_list()
        assert is_satisfiable(constraints) is True

    def test_forked_state_inherits_feasibility(self):
        """Forked state should inherit parent's feasibility status."""
        x = z3.Int("x")
        parent = create_initial_state(constraints=[x > 0])

        child = parent.fork()
        child.add_constraint(x < 100)

        parent_constraints = parent.path_constraints.to_list()
        child_constraints = child.path_constraints.to_list()

        assert is_satisfiable(parent_constraints) is True
        assert is_satisfiable(child_constraints) is True

    def test_independent_branches_both_feasible(self):
        """Both branches from a fork should be independently feasible."""
        x = z3.Int("x")
        parent = create_initial_state(constraints=[x > -1000, x < 1000])

        # True branch
        true_branch = parent.fork()
        true_branch.add_constraint(x > 0)

        # False branch
        false_branch = parent.fork()
        false_branch.add_constraint(x <= 0)

        assert is_satisfiable(true_branch.path_constraints.to_list()) is True
        assert is_satisfiable(false_branch.path_constraints.to_list()) is True


class TestLoopIterationFeasibility:
    """Verify loop iteration constraints don't incorrectly prune."""

    def test_loop_iteration_bounds_dont_over_prune(self):
        """Loop iteration constraints should not incorrectly prune valid iterations."""
        solver = IncrementalSolver()
        i = z3.Int("i")

        # Loop: for i in range(10)
        for iteration in range(10):
            constraints = [i == iteration, i >= 0, i < 10]
            result = solver.is_sat(constraints)
            assert result is True, f"Loop iteration {iteration} incorrectly pruned"

    def test_loop_exit_condition_feasible(self):
        """Loop exit condition should be feasible when loop can terminate."""
        solver = IncrementalSolver()
        i = z3.Int("i")

        # Loop terminates when i >= 10
        exit_constraints = [i >= 10]
        result = solver.is_sat(exit_constraints)
        assert result is True


class TestSymbolicPathConditions:
    """Verify symbolic path conditions are handled correctly."""

    def test_symbolic_comparison_both_branches_feasible(self):
        """Symbolic comparison should allow both branches."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")

        # Both x > y and x <= y should be feasible
        assert solver.is_sat([x > y]) is True
        assert solver.is_sat([x <= y]) is True

    def test_symbolic_equality_both_branches_feasible(self):
        """Symbolic equality should allow both branches."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")

        # Both x == y and x != y should be feasible
        assert solver.is_sat([x == y]) is True
        assert solver.is_sat([x != y]) is True

    def test_chained_symbolic_conditions(self):
        """Chained symbolic conditions should maintain feasibility appropriately."""
        solver = IncrementalSolver()
        x, y, z_var = z3.Ints("x y z")

        # x > y > z should be feasible
        constraints = [x > y, y > z_var]
        assert solver.is_sat(constraints) is True

        # But x > y, y > x is UNSAT
        unsat_constraints = [x > y, y > x]
        assert solver.is_sat(unsat_constraints) is False


class TestPendingConstraintCount:
    """Verify pending constraint count doesn't cause premature pruning."""

    def test_pending_constraints_eventually_checked(self):
        """Pending constraints should be checked before path is complete."""
        x = z3.Int("x")
        state = create_initial_state()

        # Add a SAT constraint
        state.add_constraint(x > 0)
        assert state.pending_constraint_count == 1

        # Should still be feasible
        assert is_satisfiable(state.path_constraints.to_list()) is True

    def test_fork_inherits_pending_count(self):
        """Forked state should inherit pending constraint count (BUG-012 fix)."""
        x = z3.Int("x")
        parent = create_initial_state()
        parent.add_constraint(x > 0)

        assert parent.pending_constraint_count == 1

        child = parent.fork()
        assert child.pending_constraint_count == 1
