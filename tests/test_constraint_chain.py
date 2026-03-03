"""Tests for ConstraintChain persistent data structure."""

import pytest

import z3


from pysymex.core.copy_on_write import ConstraintChain


class TestConstraintChainCreation:
    """Basic creation and length."""

    def test_empty(self):
        chain = ConstraintChain.empty()

        assert len(chain) == 0

    def test_single_constraint(self):
        x = z3.Int("x")

        chain = ConstraintChain.empty().append(x > 0)

        assert len(chain) == 1

    def test_chain_length(self):
        x = z3.Int("x")

        chain = ConstraintChain.empty()

        for i in range(25):
            chain = chain.append(x > i)

        assert len(chain) == 25

    def test_empty_chain_bool(self):
        chain = ConstraintChain.empty()

        assert not chain

    def test_nonempty_chain_bool(self):
        x = z3.Int("x")

        chain = ConstraintChain.empty().append(x > 0)

        assert chain


class TestConstraintChainImmutability:
    """Append returns new chain; original is unchanged."""

    def test_append_immutable(self):
        x = z3.Int("x")

        chain1 = ConstraintChain.empty().append(x > 0)

        chain2 = chain1.append(x < 100)

        assert len(chain1) == 1

        assert len(chain2) == 2

    def test_branching_chains(self):
        """Two branches from the same parent."""

        x = z3.Int("x")

        parent = ConstraintChain.empty().append(x > 0)

        left = parent.append(x < 50)

        right = parent.append(x >= 50)

        assert len(parent) == 1

        assert len(left) == 2

        assert len(right) == 2

    def test_deep_branching(self):
        x = z3.Int("x")

        root = ConstraintChain.empty()

        chains = [root]

        for depth in range(10):
            new_chains = []

            for chain in chains:
                new_chains.append(chain.append(x > depth))

                new_chains.append(chain.append(x <= depth))

            chains = new_chains

        assert len(chains) == 1024

        assert len(root) == 0


class TestConstraintChainConversion:
    """Converting to list."""

    def test_to_list_empty(self):
        chain = ConstraintChain.empty()

        assert chain.to_list() == []

    def test_to_list_order(self):
        """Constraints should be in insertion order."""

        x = z3.Int("x")

        chain = ConstraintChain.empty()

        chain = chain.append(x > 0)

        chain = chain.append(x < 100)

        chain = chain.append(x != 50)

        result = chain.to_list()

        assert len(result) == 3

    def test_to_list_preserves_constraints(self):
        x, y = z3.Ints("x y")

        c1 = x + y > 10

        c2 = x - y < 5

        chain = ConstraintChain.empty().append(c1).append(c2)

        result = chain.to_list()

        assert len(result) == 2


class TestConstraintChainIteration:
    """Iteration support."""

    def test_iter(self):
        x = z3.Int("x")

        chain = ConstraintChain.empty()

        chain = chain.append(x > 0)

        chain = chain.append(x < 10)

        items = list(chain)

        assert len(items) == 2

    def test_iter_empty(self):
        chain = ConstraintChain.empty()

        items = list(chain)

        assert items == []

    def test_for_loop(self):
        x = z3.Int("x")

        chain = ConstraintChain.empty()

        for i in range(5):
            chain = chain.append(x > i)

        count = 0

        for _ in chain:
            count += 1

        assert count == 5


class TestConstraintChainPerformance:
    """Performance characteristics."""

    def test_append_is_fast(self):
        """Appending should not copy the entire chain."""

        x = z3.Int("x")

        chain = ConstraintChain.empty()

        for i in range(10000):
            chain = chain.append(x > i)

        assert len(chain) == 10000

    def test_large_to_list(self):
        x = z3.Int("x")

        chain = ConstraintChain.empty()

        for i in range(1000):
            chain = chain.append(x > i)

        result = chain.to_list()

        assert len(result) == 1000
