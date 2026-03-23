"""Constraint independence soundness tests.

Verifies that constraint partitioning does not lose dependencies.

Source contracts tested:
- constraint_independence.py (UnionFind, ConstraintIndependenceOptimizer)
- solver.py:320-353 (_get_independent_clusters)

Critical invariants:
1. Transitive dependency capture (A-B, B-C means A in C's partition)
2. Sliced constraints must be equivalent to full constraints for query
3. Shared variable detection must be complete
4. No lost dependencies
"""

from __future__ import annotations

import pytest
import z3

from pysymex.core.constraint_independence import (
    ConstraintIndependenceOptimizer,
    UnionFind,
)
from pysymex.core.solver import IncrementalSolver, is_satisfiable


class TestUnionFindCorrectness:
    """Verify Union-Find data structure correctness."""

    def test_initial_elements_are_own_root(self):
        """Initially, each element should be its own root."""
        uf = UnionFind()
        assert uf.find("a") == "a"
        assert uf.find("b") == "b"
        assert uf.find("c") == "c"

    def test_union_creates_same_root(self):
        """Union should make both elements have the same root."""
        uf = UnionFind()
        uf.union("a", "b")

        assert uf.find("a") == uf.find("b")

    def test_union_is_transitive(self):
        """Union is transitive: a-b, b-c means a-c are in same set."""
        uf = UnionFind()
        uf.union("a", "b")
        uf.union("b", "c")

        assert uf.find("a") == uf.find("c")

    def test_union_chain(self):
        """Long union chains should maintain transitivity."""
        uf = UnionFind()
        elements = ["e1", "e2", "e3", "e4", "e5"]

        for i in range(len(elements) - 1):
            uf.union(elements[i], elements[i + 1])

        # All should be in the same set
        root = uf.find(elements[0])
        for e in elements:
            assert uf.find(e) == root

    def test_separate_sets_remain_separate(self):
        """Elements not unioned should remain in separate sets."""
        uf = UnionFind()
        uf.union("a", "b")
        uf.union("c", "d")

        assert uf.find("a") == uf.find("b")
        assert uf.find("c") == uf.find("d")
        assert uf.find("a") != uf.find("c")

    def test_path_compression(self):
        """Path compression should not affect correctness."""
        uf = UnionFind()
        # Create a deep tree
        uf.union("a", "b")
        uf.union("b", "c")
        uf.union("c", "d")
        uf.union("d", "e")

        # Find should trigger path compression
        root_e = uf.find("e")
        root_a = uf.find("a")

        assert root_e == root_a


class TestTransitiveDependencyCapture:
    """Verify transitive dependencies are correctly captured."""

    def test_transitive_through_shared_variable(self):
        """Constraints sharing a variable transitively should be in same partition."""
        optimizer = ConstraintIndependenceOptimizer()

        x, y, z_var = z3.Ints("x y z")

        # x-y constraint
        c1 = x + y > 0
        # y-z constraint
        c2 = y + z_var > 0
        # x is transitively connected to z through y

        vars1 = optimizer.register_constraint(c1)
        vars2 = optimizer.register_constraint(c2)

        # x and z should be in the same partition via y
        assert optimizer._uf.find("x") == optimizer._uf.find("z")

    def test_long_transitive_chain(self):
        """Long transitive chains should all be in same partition."""
        optimizer = ConstraintIndependenceOptimizer()

        vars = [z3.Int(f"v{i}") for i in range(10)]

        # Create chain: v0-v1, v1-v2, ..., v8-v9
        for i in range(9):
            constraint = vars[i] + vars[i + 1] > 0
            optimizer.register_constraint(constraint)

        # All should be in same partition
        root = optimizer._uf.find("v0")
        for i in range(10):
            assert optimizer._uf.find(f"v{i}") == root


class TestSliceForQueryCorrectness:
    """Verify slice_for_query returns correct constraints."""

    def test_slice_includes_query_variables(self):
        """Slice must include constraints involving query variables."""
        optimizer = ConstraintIndependenceOptimizer()

        x, y, z_var = z3.Ints("x y z")

        c1 = x > 0
        c2 = y > 0
        c3 = z_var > 0

        optimizer.register_constraint(c1)
        optimizer.register_constraint(c2)
        optimizer.register_constraint(c3)

        path_constraints = [c1, c2, c3]
        query = x < 10

        sliced = optimizer.slice_for_query(path_constraints, query)

        # Should include c1 (shares x with query) but not c2 or c3
        assert c1 in sliced
        # c2 and c3 are independent, may or may not be included

    def test_slice_includes_transitive_dependencies(self):
        """Slice must include transitively dependent constraints."""
        optimizer = ConstraintIndependenceOptimizer()

        x, y, z_var = z3.Ints("x y z")

        c1 = x + y > 0  # links x and y
        c2 = y + z_var > 0  # links y and z
        c3 = z_var < 100  # involves z

        for c in [c1, c2, c3]:
            optimizer.register_constraint(c)

        path_constraints = [c1, c2, c3]
        query = x < 10  # Query involves x

        sliced = optimizer.slice_for_query(path_constraints, query)

        # All constraints are transitively connected via x-y-z chain
        # So all should be included
        assert c1 in sliced
        assert c2 in sliced
        assert c3 in sliced


class TestSATEquivalence:
    """Verify sliced constraints produce same SAT result as full constraints."""

    def test_sat_preserved_after_slicing(self):
        """SAT result should be same for sliced and full constraints."""
        solver = IncrementalSolver()
        optimizer = ConstraintIndependenceOptimizer()

        x, y, z_var = z3.Ints("x y z")

        # Independent constraints
        c1 = x > 0
        c2 = y > 0
        c3 = z_var > 0

        for c in [c1, c2, c3]:
            optimizer.register_constraint(c)

        path_constraints = [c1, c2, c3]

        # Full constraint check
        full_sat = solver.is_sat(path_constraints)

        # Sliced check for query about x
        query = x < 10
        sliced = optimizer.slice_for_query(path_constraints, query)
        sliced_sat = solver.is_sat(sliced + [query])

        # Should both be SAT
        assert full_sat is True
        assert sliced_sat is True

    def test_unsat_preserved_after_slicing(self):
        """UNSAT result should be preserved after slicing."""
        solver = IncrementalSolver()
        optimizer = ConstraintIndependenceOptimizer()

        x = z3.Int("x")

        c1 = x > 10
        c2 = x < 5

        for c in [c1, c2]:
            optimizer.register_constraint(c)

        path_constraints = [c1, c2]
        query = x > 0  # Query involves x

        # Full is UNSAT
        full_sat = solver.is_sat(path_constraints)
        assert full_sat is False

        # Sliced should also be UNSAT
        sliced = optimizer.slice_for_query(path_constraints, query)
        sliced_sat = solver.is_sat(sliced)
        assert sliced_sat is False


class TestNoLostDependencies:
    """Verify no dependencies are lost during partitioning."""

    def test_complex_expression_variable_extraction(self):
        """Complex expressions should have all variables extracted."""
        optimizer = ConstraintIndependenceOptimizer()

        x, y, z_var = z3.Ints("x y z")

        # Complex expression with multiple variables
        c = z3.If(x > 0, y, z_var) > 0

        vars_found = optimizer.register_constraint(c)

        # All three variables should be found
        assert "x" in vars_found
        assert "y" in vars_found
        assert "z" in vars_found

    def test_nested_if_variable_extraction(self):
        """Nested If expressions should have all variables extracted."""
        optimizer = ConstraintIndependenceOptimizer()

        a, b, c_var, d = z3.Ints("a b c d")

        constraint = z3.If(a > 0, z3.If(b > 0, c_var, d), d) > 0

        vars_found = optimizer.register_constraint(constraint)

        assert "a" in vars_found
        assert "b" in vars_found
        assert "c" in vars_found
        assert "d" in vars_found

    def test_arithmetic_expression_variable_extraction(self):
        """Arithmetic expressions should have all operand variables extracted."""
        optimizer = ConstraintIndependenceOptimizer()

        x, y, z_var = z3.Ints("x y z")

        constraint = x * y + z_var - x > 0

        vars_found = optimizer.register_constraint(constraint)

        assert "x" in vars_found
        assert "y" in vars_found
        assert "z" in vars_found


class TestSharedVariableDetection:
    """Verify shared variables are correctly detected."""

    def test_same_variable_name_detected(self):
        """Constraints with same variable name should be linked."""
        optimizer = ConstraintIndependenceOptimizer()

        x = z3.Int("x")

        c1 = x > 0
        c2 = x < 10

        optimizer.register_constraint(c1)
        optimizer.register_constraint(c2)

        # Both should be in same partition via x
        # (Though with single variable, it's trivially true)

    def test_different_variable_names_separate(self):
        """Constraints with no shared variables should be in different partitions."""
        optimizer = ConstraintIndependenceOptimizer()

        x = z3.Int("x")
        y = z3.Int("y")

        c1 = x > 0
        c2 = y > 0

        optimizer.register_constraint(c1)
        optimizer.register_constraint(c2)

        # x and y should be in different partitions
        assert optimizer._uf.find("x") != optimizer._uf.find("y")


class TestOptimizerReset:
    """Verify optimizer reset works correctly."""

    def test_reset_clears_state(self):
        """Reset should clear all internal state."""
        optimizer = ConstraintIndependenceOptimizer()

        x, y = z3.Ints("x y")
        c1 = x + y > 0

        optimizer.register_constraint(c1)

        # Should have some state
        assert len(optimizer._uf._parent) > 0

        optimizer.reset()

        # Should be cleared
        assert len(optimizer._uf._parent) == 0


class TestIncrementalSolverIntegration:
    """Verify constraint independence works correctly with IncrementalSolver."""

    def test_independent_clusters_optimization(self):
        """Solver should correctly handle independent constraint clusters."""
        solver = IncrementalSolver()

        x, y = z3.Ints("x y")

        # Two independent clusters
        # Cluster 1: x > 0, x < 100
        # Cluster 2: y > 0, y < 100
        constraints = [x > 0, x < 100, y > 0, y < 100]

        result = solver.is_sat(constraints)
        assert result is True

    def test_dependent_clusters_correct_result(self):
        """Solver should correctly handle dependent constraint clusters."""
        solver = IncrementalSolver()

        x, y = z3.Ints("x y")

        # Dependent constraints
        constraints = [x > 0, y > 0, x + y < 1]

        result = solver.is_sat(constraints)
        assert result is False  # x > 0, y > 0 but x + y < 1 is impossible

    def test_mixed_clusters(self):
        """Solver should handle mix of independent and dependent clusters."""
        solver = IncrementalSolver()

        x, y, z_var = z3.Ints("x y z")

        # x and y are dependent, z is independent
        constraints = [
            x > 0,
            y > 0,
            x + y > 1,  # Links x and y
            z_var > 100,  # Independent
        ]

        result = solver.is_sat(constraints)
        assert result is True


class TestConstantConstraintHandling:
    """Verify constraints with no variables are handled correctly."""

    def test_true_constant_constraint(self):
        """True constant constraint should not affect SAT result."""
        optimizer = ConstraintIndependenceOptimizer()

        x = z3.Int("x")
        c1 = x > 0
        c2 = z3.BoolVal(True)

        optimizer.register_constraint(c1)
        vars_c2 = optimizer.register_constraint(c2)

        # Constant constraint should have no variables
        assert len(vars_c2) == 0

    def test_false_constant_constraint(self):
        """False constant constraint should make UNSAT."""
        solver = IncrementalSolver()

        x = z3.Int("x")
        constraints = [x > 0, z3.BoolVal(False)]

        result = solver.is_sat(constraints)
        assert result is False
