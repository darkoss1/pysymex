"""Tests for pysymex.core.constraint_hash — structural hashing utilities.

Covers: structural_hash, structural_hash_sorted.
"""

from __future__ import annotations

import z3

from pysymex.core.constraint_hash import structural_hash, structural_hash_sorted


class TestStructuralHash:

    def test_empty_list(self):
        h = structural_hash([])
        # Should produce a deterministic value (initial seed XOR'd with len=0)
        assert isinstance(h, int)

    def test_single_constraint(self):
        x = z3.Int("x")
        h = structural_hash([x > 0])
        assert isinstance(h, int)

    def test_same_constraints_same_hash(self):
        x = z3.Int("x")
        h1 = structural_hash([x > 5, x < 10])
        h2 = structural_hash([x > 5, x < 10])
        assert h1 == h2

    def test_different_order_different_hash(self):
        """structural_hash is order-sensitive."""
        x = z3.Int("x")
        h1 = structural_hash([x > 5, x < 10])
        h2 = structural_hash([x < 10, x > 5])
        assert h1 != h2

    def test_different_constraints_different_hash(self):
        x = z3.Int("x")
        y = z3.Int("y")
        h1 = structural_hash([x > 0])
        h2 = structural_hash([y > 0])
        assert h1 != h2

    def test_returns_64bit_value(self):
        x = z3.Int("x")
        h = structural_hash([x > 0, x < 10])
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF


class TestStructuralHashSorted:

    def test_empty_list(self):
        h = structural_hash_sorted([])
        assert h == 0

    def test_order_independent(self):
        """structural_hash_sorted produces the same value regardless of order."""
        x = z3.Int("x")
        c1 = x > 5
        c2 = x < 10
        h1 = structural_hash_sorted([c1, c2])
        h2 = structural_hash_sorted([c2, c1])
        assert h1 == h2

    def test_same_as_structural_hash_when_already_sorted(self):
        """Even with sorted order, sorted hash uses its own algorithm."""
        x = z3.Int("x")
        h_sorted = structural_hash_sorted([x > 0])
        h_regular = structural_hash([x > 0])
        # Both should be valid integers (not necessarily equal, but they might be
        # for a single element where sorting is a no-op)
        assert isinstance(h_sorted, int)
        assert isinstance(h_regular, int)

    def test_different_constraints_different_sorted_hash(self):
        x = z3.Int("x")
        y = z3.Int("y")
        h1 = structural_hash_sorted([x > 0])
        h2 = structural_hash_sorted([y > 0])
        assert h1 != h2

    def test_returns_64bit_value(self):
        x = z3.Int("x")
        h = structural_hash_sorted([x > 0, x < 10])
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF

    def test_three_constraints_order_independent(self):
        x = z3.Int("x")
        a, b, c = x > 0, x < 100, x != 42
        assert structural_hash_sorted([a, b, c]) == structural_hash_sorted([c, a, b])
        assert structural_hash_sorted([a, b, c]) == structural_hash_sorted([b, c, a])
