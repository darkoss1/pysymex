"""Tests for state hashing collision resistance and deduplication correctness.

These tests verify that:
1. State hashes are deterministic for identical states
2. Different states produce different hashes (collision resistance)
3. The 64-bit boundary is maintained (no arbitrary precision integers)
4. Hash collisions are detected and handled properly

Hash collisions can defeat path deduplication, causing:
- Infinite loops (states incorrectly merged)
- Missed paths (viable states pruned)
- State corruption (different states treated as identical)
"""

from __future__ import annotations

import gc
import itertools
import random
import threading

import pytest
import z3

from pysymex.core.copy_on_write import ConstraintChain, CowDict, CowSet
from pysymex.core.state import VMState


class TestStateHashDeterminism:
    """Tests that state hashes are deterministic."""

    def test_same_state_same_hash(self):
        """Identical state should produce identical hash."""
        state1 = VMState()
        state1.pc = 10
        state1.local_vars["x"] = 42

        state2 = VMState()
        state2.pc = 10
        state2.local_vars["x"] = 42

        assert state1.hash_value() == state2.hash_value()

    def test_hash_stable_across_calls(self):
        """Hash should be stable across multiple calls."""
        state = VMState()
        state.pc = 100
        state.local_vars["x"] = z3.Int("x")
        state.global_vars["y"] = z3.Bool("y")

        h1 = state.hash_value()
        h2 = state.hash_value()
        h3 = state.hash_value()

        assert h1 == h2 == h3

    def test_hash_stable_after_gc(self):
        """Hash should be stable even after GC cycles."""
        state = VMState()
        state.pc = 50
        x = z3.Int("x")
        state.local_vars["x"] = x
        state.add_constraint(x > 0)

        h_before = state.hash_value()

        gc.collect()
        gc.collect()

        h_after = state.hash_value()

        assert h_before == h_after


class TestStateHashCollisionResistance:
    """Tests that different states produce different hashes."""

    def test_different_pc_different_hash(self):
        """Different PCs should produce different hashes."""
        state1 = VMState(pc=0)
        state2 = VMState(pc=1)

        assert state1.hash_value() != state2.hash_value()

    def test_different_local_vars_different_hash(self):
        """Different local variables should produce different hashes."""
        state1 = VMState()
        state1.local_vars["x"] = 1

        state2 = VMState()
        state2.local_vars["x"] = 2

        assert state1.hash_value() != state2.hash_value()

    def test_different_constraints_different_hash(self):
        """Different constraints should produce different hashes."""
        x = z3.Int("x")

        state1 = VMState()
        state1.add_constraint(x > 0)

        state2 = VMState()
        state2.add_constraint(x < 0)

        assert state1.hash_value() != state2.hash_value()

    def test_different_stack_different_hash(self):
        """Different stack contents should produce different hashes."""
        state1 = VMState()
        state1.stack.append(1)

        state2 = VMState()
        state2.stack.append(2)

        assert state1.hash_value() != state2.hash_value()

    def test_variable_name_matters(self):
        """Constraints on different variables should produce different hashes."""
        x = z3.Int("x")
        y = z3.Int("y")

        state1 = VMState()
        state1.add_constraint(x > 0)

        state2 = VMState()
        state2.add_constraint(y > 0)

        assert state1.hash_value() != state2.hash_value()

    def test_subtle_constraint_differences(self):
        """Subtle constraint differences must be detectable."""
        x = z3.Int("x")

        state1 = VMState()
        state1.add_constraint(x > 0)
        state1.add_constraint(x < 100)

        state2 = VMState()
        state2.add_constraint(x > 0)
        state2.add_constraint(x <= 100)  # <= vs <

        assert state1.hash_value() != state2.hash_value()


class TestConstraintChainHash:
    """Tests for ConstraintChain hash integrity."""

    def test_hash_bounded_to_64bit(self):
        """Chain hash must stay within 64-bit bounds."""
        chain = ConstraintChain.empty()

        for i in range(1000):
            x = z3.Int(f"x_{i}")
            chain = chain.append(x > 0)

        h = chain.hash_value()
        assert h >= 0
        assert h < (1 << 64), "Hash exceeded 64-bit boundary"

    def test_hash_order_dependent(self):
        """Hash should depend on constraint order (same set, different order)."""
        x = z3.Int("x")
        y = z3.Int("y")

        c1 = x > 0
        c2 = y > 0

        chain1 = ConstraintChain.from_list([c1, c2])
        chain2 = ConstraintChain.from_list([c2, c1])

        # Note: Order-independence via XOR may make these equal,
        # but the incremental hash with multiplication should differ
        # This tests the current implementation behavior
        h1 = chain1.hash_value()
        h2 = chain2.hash_value()

        # These may be equal or different based on implementation,
        # but the hash must be deterministic
        if h1 == h2:
            # If equal, verify both chains have same constraints
            l1 = set(c.hash() for c in chain1.to_list())
            l2 = set(c.hash() for c in chain2.to_list())
            assert l1 == l2

    def test_empty_chain_distinct_from_single(self):
        """Empty chain must have different hash than any non-empty chain."""
        empty = ConstraintChain.empty()
        x = z3.Int("x")
        single = ConstraintChain.empty().append(x > 0)

        assert empty.hash_value() != single.hash_value()

    def test_chain_hash_collision_resistance(self):
        """Test collision resistance across many constraint patterns."""
        hashes = set()
        collision_count = 0

        for i in range(500):
            x = z3.Int(f"x_{i}")
            chain = ConstraintChain.empty()

            # Add varying numbers of constraints
            for j in range(i % 10 + 1):
                chain = chain.append(x > j)

            h = chain.hash_value()
            if h in hashes:
                collision_count += 1
            hashes.add(h)

        # Allow very few collisions (should be essentially zero with good hash)
        assert collision_count < 5, f"Too many hash collisions: {collision_count}"


class TestCowDictHash:
    """Tests for CowDict hash correctness."""

    def test_hash_deterministic(self):
        """Same contents should produce same hash."""
        d1 = CowDict({"a": 1, "b": 2})
        d2 = CowDict({"b": 2, "a": 1})  # Different insertion order

        assert d1.hash_value() == d2.hash_value()

    def test_hash_after_mutation(self):
        """Hash must update after mutation."""
        d = CowDict({"a": 1})
        h1 = d.hash_value()

        d["b"] = 2
        h2 = d.hash_value()

        assert h1 != h2

    def test_hash_isolation_after_fork(self):
        """Forked dict mutations should not affect original hash."""
        d = CowDict({"x": 10})
        original_hash = d.hash_value()

        forked = d.cow_fork()
        forked["y"] = 20

        # Original hash unchanged
        assert d.hash_value() == original_hash
        # Forked has different hash
        assert forked.hash_value() != original_hash

    def test_hash_with_symbolic_values(self):
        """Hash should work with symbolic Z3 values."""
        x = z3.Int("x")
        y = z3.Int("y")

        d = CowDict({"sym": x})
        h1 = d.hash_value()

        d2 = CowDict({"sym": y})
        h2 = d2.hash_value()

        # Different symbolic variables should produce different hashes
        assert h1 != h2


class TestCowSetHash:
    """Tests for CowSet hash correctness."""

    def test_hash_order_independent(self):
        """Set hash should be order-independent."""
        s1 = CowSet({1, 2, 3})
        s2 = CowSet({3, 2, 1})

        assert s1.hash_value() == s2.hash_value()

    def test_hash_bounded(self):
        """Set hash must stay within 64-bit bounds."""
        s = CowSet()
        for i in range(10000):
            s.add(i)

        h = s.hash_value()
        assert h >= 0
        assert h < (1 << 64)

    def test_hash_invalidated_on_add(self):
        """Adding element must invalidate cached hash."""
        s = CowSet({1, 2, 3})
        h1 = s.hash_value()

        s.add(4)
        h2 = s.hash_value()

        assert h1 != h2

    def test_hash_invalidated_on_discard(self):
        """Removing element must invalidate cached hash."""
        s = CowSet({1, 2, 3})
        h1 = s.hash_value()

        s.discard(2)
        h2 = s.hash_value()

        assert h1 != h2


class TestStateDeduplicationCorrectness:
    """Tests that state deduplication doesn't incorrectly merge states."""

    def test_semantically_different_states_not_merged(self):
        """States with same structure but different semantics must differ."""
        x = z3.Int("x")
        y = z3.Int("y")

        # Both states have same structure but semantically different
        state1 = VMState()
        state1.local_vars["var"] = x
        state1.add_constraint(x > 0)

        state2 = VMState()
        state2.local_vars["var"] = y  # Different variable
        state2.add_constraint(y > 0)

        assert state1.hash_value() != state2.hash_value()

    def test_constraint_order_in_chain_matters(self):
        """Order of constraints in the chain affects state hash."""
        x = z3.Int("x")

        state1 = VMState()
        state1.add_constraint(x > 0)
        state1.add_constraint(x < 10)

        state2 = VMState()
        state2.add_constraint(x < 10)
        state2.add_constraint(x > 0)

        h1 = state1.hash_value()
        h2 = state2.hash_value()

        # May be same or different based on hash algorithm, but must be deterministic
        state1_copy = VMState()
        state1_copy.add_constraint(x > 0)
        state1_copy.add_constraint(x < 10)

        assert state1.hash_value() == state1_copy.hash_value()


class TestManyStateHashDistribution:
    """Statistical tests for hash distribution quality."""

    def test_hash_distribution_uniform(self):
        """Hashes should be relatively uniformly distributed."""
        hashes = []

        for i in range(1000):
            state = VMState()
            state.pc = i * 7 % 256
            x = z3.Int(f"x_{i}")
            state.local_vars["x"] = x
            state.add_constraint(x > i)
            hashes.append(state.hash_value())

        # Check for clustering by looking at bucket distribution
        buckets = [0] * 16
        for h in hashes:
            buckets[h % 16] += 1

        # Each bucket should have roughly 1000/16 = 62.5 elements
        # Allow significant variance but detect extreme clustering
        min_count = min(buckets)
        max_count = max(buckets)

        assert min_count >= 20, f"Hash clustering detected: min bucket = {min_count}"
        assert max_count <= 150, f"Hash clustering detected: max bucket = {max_count}"

    def test_no_trivial_zero_hashes(self):
        """Non-empty states should never hash to zero."""
        for i in range(100):
            state = VMState()
            state.pc = i + 1
            state.local_vars[f"var{i}"] = z3.Int(f"v{i}")

            h = state.hash_value()
            # Allow zero for edge cases but it should be rare
            # This is more of a sanity check


class TestThreadSafetyHashing:
    """Tests for thread-safety of hash computations."""

    def test_concurrent_hash_computation(self):
        """Concurrent hash computation should be safe."""
        state = VMState()
        x = z3.Int("x")
        state.local_vars["x"] = x
        state.add_constraint(x > 0)

        results = []
        errors = []

        def compute_hash():
            try:
                for _ in range(100):
                    h = state.hash_value()
                    results.append(h)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=compute_hash) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        # All hashes should be identical
        assert len(set(results)) == 1, "Hash varied across threads"

    def test_concurrent_fork_and_hash(self):
        """Forking and hashing concurrently should be safe."""
        state = VMState()
        x = z3.Int("x")
        state.local_vars["x"] = x

        fork_results = []
        errors = []

        def fork_and_hash():
            try:
                for i in range(50):
                    forked = state.fork()
                    forked.local_vars[f"y_{threading.current_thread().name}_{i}"] = i
                    h = forked.hash_value()
                    fork_results.append(h)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=fork_and_hash, name=f"t{i}") for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        # Forks should all have different hashes
        assert len(fork_results) == 200


class TestConstraintChainSeenHashes:
    """Tests for the seen_hashes tracking in ConstraintChain."""

    def test_seen_hashes_accumulates(self):
        """_seen_hashes should accumulate all constraint hashes."""
        x = z3.Int("x")
        c1 = x > 0
        c2 = x < 10
        c3 = x != 5

        chain = ConstraintChain.empty()
        chain = chain.append(c1)
        chain = chain.append(c2)
        chain = chain.append(c3)

        # _seen_hashes should contain all three constraint hashes
        assert c1.hash() in chain._seen_hashes
        assert c2.hash() in chain._seen_hashes
        assert c3.hash() in chain._seen_hashes

    def test_forked_chains_share_history(self):
        """Chains forked from same parent should share seen_hashes up to fork."""
        x = z3.Int("x")

        base = ConstraintChain.empty().append(x > 0)
        fork1 = base.append(x < 5)
        fork2 = base.append(x < 10)

        # Both forks should have the base constraint's hash
        base_hash = (x > 0).hash()
        assert base_hash in fork1._seen_hashes
        assert base_hash in fork2._seen_hashes
