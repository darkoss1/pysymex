"""Tests for constraint chain soundness and hash collision resilience.

Invariant: Constraint chain hash collisions must not cause incorrect
solver cache hits. Two different constraint sets with the same hash
MUST still produce correct SAT/UNSAT results.

Violation impact: Cached wrong answer => missed bugs or phantom bugs.
"""

from __future__ import annotations

import z3
import pytest

from pysymex.core.copy_on_write import ConstraintChain
from pysymex.core.solver import is_satisfiable, get_model


class TestConstraintChainHashIntegrity:
    """Tests that constraint chain hashing doesn't cause soundness issues."""

    def test_hash_collision_does_not_corrupt_sat_result(self):
        """Even if two chains hash the same, solver returns correct result.

        Invariant: SAT(constraints) is determined by constraint semantics,
        not by hash-based cache lookup bugs.
        """
        x = z3.Int("x")

        # Build two semantically different constraint sets
        chain_sat = ConstraintChain.empty()
        chain_sat = chain_sat.append(x > 0)
        chain_sat = chain_sat.append(x < 100)

        chain_unsat = ConstraintChain.empty()
        chain_unsat = chain_unsat.append(x > 100)
        chain_unsat = chain_unsat.append(x < 0)  # Contradicts x > 100

        # Even if hashes collide, results must be correct
        sat_result = is_satisfiable(chain_sat.to_list())
        unsat_result = is_satisfiable(chain_unsat.to_list())

        assert sat_result is True, "SAT constraints incorrectly reported as UNSAT"
        assert unsat_result is False, "UNSAT constraints incorrectly reported as SAT"

    def test_append_order_affects_semantic_not_hash(self):
        """Same constraints in different append order must still be SAT-equivalent.

        Invariant: hash(Chain([A,B])) may differ from hash(Chain([B,A])) but
        SAT result must be identical for logically equivalent constraint sets.
        """
        x = z3.Int("x")

        c1 = x > 0
        c2 = x < 10
        c3 = x == 5

        # Order 1: c1, c2, c3
        chain1 = ConstraintChain.empty()
        for c in [c1, c2, c3]:
            chain1 = chain1.append(c)

        # Order 2: c3, c1, c2
        chain2 = ConstraintChain.empty()
        for c in [c3, c1, c2]:
            chain2 = chain2.append(c)

        result1 = is_satisfiable(chain1.to_list())
        result2 = is_satisfiable(chain2.to_list())

        assert result1 == result2, "Order should not affect SAT result"
        assert result1 is True, "x=5 satisfies all constraints"

    def test_incremental_append_preserves_semantics(self):
        """Incrementally building constraints must preserve all semantics.

        Invariant: Chain built incrementally is semantically equivalent to
        one built all at once.
        """
        x = z3.Int("x")
        y = z3.Int("y")

        constraints = [x > 0, y > 0, x + y < 100, x * y > 10]

        # Build incrementally
        chain = ConstraintChain.empty()
        for c in constraints:
            chain = chain.append(c)

        # Check SAT and get model
        assert is_satisfiable(chain.to_list()), "Should be SAT"

        model = get_model(chain.to_list())
        assert model is not None

        # Model must satisfy ALL constraints
        x_val = model.eval(x).as_long()
        y_val = model.eval(y).as_long()

        assert x_val > 0, "Model violates x > 0"
        assert y_val > 0, "Model violates y > 0"
        assert x_val + y_val < 100, "Model violates x + y < 100"
        assert x_val * y_val > 10, "Model violates x * y > 10"


class TestConstraintChainForking:
    """Tests for constraint chain fork semantics."""

    def test_fork_divergent_paths_independent(self):
        """Forked chains represent independent execution paths.

        Invariant: Adding constraints to a forked chain must not affect
        the original chain's SAT result.
        """
        x = z3.Int("x")

        # Base chain
        base = ConstraintChain.empty()
        base = base.append(x >= 0)
        base = base.append(x <= 100)

        # Fork and add contradictory constraint to fork
        forked = base.append(x < 0)  # This contradicts x >= 0

        # Base must still be SAT
        assert is_satisfiable(base.to_list()), "Base chain corrupted by fork"

        # Forked must be UNSAT
        assert not is_satisfiable(forked.to_list()), "Fork should be UNSAT"

    def test_multiple_forks_from_same_base(self):
        """Multiple forks from same base must be independent.

        Invariant: Fork isolation - each fork is a separate universe.
        """
        x = z3.Int("x")

        base = ConstraintChain.empty()
        base = base.append(x > 0)

        # Create 3 forks with different additional constraints
        fork_small = base.append(x < 10)
        fork_medium = base.append(x < 100)
        fork_large = base.append(x < 1000)

        # All should be SAT
        assert is_satisfiable(fork_small.to_list())
        assert is_satisfiable(fork_medium.to_list())
        assert is_satisfiable(fork_large.to_list())

        # Check models are within expected ranges
        m_small = get_model(fork_small.to_list())
        m_medium = get_model(fork_medium.to_list())
        m_large = get_model(fork_large.to_list())

        assert 0 < m_small.eval(x).as_long() < 10
        assert 0 < m_medium.eval(x).as_long() < 100
        assert 0 < m_large.eval(x).as_long() < 1000


class TestConstraintEquivalenceClasses:
    """Tests that semantically equivalent constraints are handled correctly."""

    def test_syntactically_different_but_equivalent(self):
        """Different syntax, same semantics must give same result.

        Invariant: x > 5 and NOT(x <= 5) are logically equivalent.
        """
        x = z3.Int("x")

        # Syntactically different
        c1 = x > 5
        c2 = z3.Not(x <= 5)

        chain1 = ConstraintChain.empty().append(c1).append(x < 10)
        chain2 = ConstraintChain.empty().append(c2).append(x < 10)

        # Must give same models (modulo solver nondeterminism)
        m1 = get_model(chain1.to_list())
        m2 = get_model(chain2.to_list())

        # Both models must satisfy both constraint sets
        x1 = m1.eval(x).as_long()
        x2 = m2.eval(x).as_long()

        assert 5 < x1 < 10, "Model 1 violates constraints"
        assert 5 < x2 < 10, "Model 2 violates constraints"

    def test_redundant_constraints_dont_affect_result(self):
        """Adding redundant constraints must not change SAT result.

        Invariant: SAT({A}) == SAT({A, A, A})
        """
        x = z3.Int("x")
        c = x == 42

        chain_single = ConstraintChain.empty().append(c)
        chain_triple = ConstraintChain.empty().append(c).append(c).append(c)

        r1 = is_satisfiable(chain_single.to_list())
        r2 = is_satisfiable(chain_triple.to_list())

        assert r1 == r2, "Redundant constraints changed result"

        m1 = get_model(chain_single.to_list())
        m2 = get_model(chain_triple.to_list())

        assert m1.eval(x).as_long() == m2.eval(x).as_long() == 42


class TestEdgeCaseConstraints:
    """Tests for constraint edge cases that could trigger bugs."""

    def test_empty_chain_is_satisfiable(self):
        """Empty constraint set is always SAT (tautology).

        Invariant: SAT({}) == True
        """
        chain = ConstraintChain.empty()
        assert is_satisfiable(chain.to_list()), "Empty constraints must be SAT"

    def test_single_false_is_unsat(self):
        """Single False constraint is UNSAT.

        Invariant: SAT({False}) == False
        """
        chain = ConstraintChain.empty().append(z3.BoolVal(False))
        assert not is_satisfiable(chain.to_list()), "False must be UNSAT"

    def test_single_true_is_sat(self):
        """Single True constraint is SAT.

        Invariant: SAT({True}) == True
        """
        chain = ConstraintChain.empty().append(z3.BoolVal(True))
        assert is_satisfiable(chain.to_list()), "True must be SAT"

    def test_very_long_chain_correctness(self):
        """Long constraint chains must still produce correct results.

        Invariant: Chain length doesn't affect correctness.
        """
        x = z3.Int("x")

        chain = ConstraintChain.empty()
        # Add 100 constraints that together force x into a small range
        for i in range(100):
            chain = chain.append(x > i)
        chain = chain.append(x < 150)

        assert is_satisfiable(chain.to_list())

        model = get_model(chain.to_list())
        x_val = model.eval(x).as_long()

        # x must satisfy all x > i for i in [0, 99] and x < 150
        assert x_val > 99, f"x={x_val} violates x > 99"
        assert x_val < 150, f"x={x_val} violates x < 150"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
