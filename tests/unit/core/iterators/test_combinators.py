import pysymex.core.iterators.combinators
import z3
from pysymex.core.iterators.base import SymbolicRange

class TestSymbolicEnumerate:
    """Test suite for pysymex.core.iterators.combinators.SymbolicEnumerate."""
    def test_has_next(self) -> None:
        """Scenario: enumerate wrapping active iterator; expected has_next true."""
        it = pysymex.core.iterators.combinators.SymbolicEnumerate(SymbolicRange.from_args(0, 2))
        assert z3.is_true(z3.simplify(it.has_next()))

    def test_remaining_bound(self) -> None:
        """Scenario: enumerate bound delegates to inner iterator."""
        it = pysymex.core.iterators.combinators.SymbolicEnumerate(SymbolicRange.from_args(0, 3))
        assert it.remaining_bound() == 3

    def test_clone(self) -> None:
        """Scenario: clone keeps counter state."""
        it = pysymex.core.iterators.combinators.SymbolicEnumerate(SymbolicRange.from_args(0, 3), counter=2)
        assert it.clone().counter == 2

    def test_is_bounded(self) -> None:
        """Scenario: bounded inner iterator implies bounded enumerate."""
        it = pysymex.core.iterators.combinators.SymbolicEnumerate(SymbolicRange.from_args(0, 3))
        assert it.is_bounded is True


class TestSymbolicZip:
    """Test suite for pysymex.core.iterators.combinators.SymbolicZip."""
    def test_has_next(self) -> None:
        """Scenario: all inner iterators can continue; expected zip has_next true."""
        it = pysymex.core.iterators.combinators.SymbolicZip([SymbolicRange.from_args(0, 2), SymbolicRange.from_args(0, 2)])
        assert z3.is_true(z3.simplify(it.has_next()))

    def test_remaining_bound(self) -> None:
        """Scenario: zip bound is minimum of inner bounds."""
        it = pysymex.core.iterators.combinators.SymbolicZip([SymbolicRange.from_args(0, 5), SymbolicRange.from_args(0, 2)])
        assert it.remaining_bound() == 2

    def test_clone(self) -> None:
        """Scenario: clone returns distinct zip iterator object."""
        it = pysymex.core.iterators.combinators.SymbolicZip([SymbolicRange.from_args(0, 2)])
        assert it.clone() is not it

    def test_is_bounded(self) -> None:
        """Scenario: all bounded inners produce bounded zip."""
        it = pysymex.core.iterators.combinators.SymbolicZip([SymbolicRange.from_args(0, 2)])
        assert it.is_bounded is True


class TestSymbolicMap:
    """Test suite for pysymex.core.iterators.combinators.SymbolicMap."""
    def test_has_next(self) -> None:
        """Scenario: map delegates has_next to inner iterator."""
        it = pysymex.core.iterators.combinators.SymbolicMap(lambda x: x, SymbolicRange.from_args(0, 2))
        assert z3.is_true(z3.simplify(it.has_next()))

    def test_remaining_bound(self) -> None:
        """Scenario: map remaining bound equals inner bound."""
        it = pysymex.core.iterators.combinators.SymbolicMap(lambda x: x, SymbolicRange.from_args(0, 4))
        assert it.remaining_bound() == 4

    def test_clone(self) -> None:
        """Scenario: clone returns independent mapped iterator."""
        it = pysymex.core.iterators.combinators.SymbolicMap(lambda x: x, SymbolicRange.from_args(0, 2))
        assert it.clone() is not it

    def test_is_bounded(self) -> None:
        """Scenario: bounded inner yields bounded map iterator."""
        it = pysymex.core.iterators.combinators.SymbolicMap(lambda x: x, SymbolicRange.from_args(0, 2))
        assert it.is_bounded is True


class TestSymbolicFilter:
    """Test suite for pysymex.core.iterators.combinators.SymbolicFilter."""
    def test_has_next(self) -> None:
        """Scenario: filter has_next delegates to underlying iterator."""
        it = pysymex.core.iterators.combinators.SymbolicFilter(lambda x: True, SymbolicRange.from_args(0, 2))
        assert z3.is_true(z3.simplify(it.has_next()))

    def test_remaining_bound(self) -> None:
        """Scenario: filter remaining bound delegates to inner bound."""
        it = pysymex.core.iterators.combinators.SymbolicFilter(lambda x: True, SymbolicRange.from_args(0, 3))
        assert it.remaining_bound() == 3

    def test_clone(self) -> None:
        """Scenario: clone returns distinct filter iterator."""
        it = pysymex.core.iterators.combinators.SymbolicFilter(lambda x: True, SymbolicRange.from_args(0, 2))
        assert it.clone() is not it

    def test_is_bounded(self) -> None:
        """Scenario: bounded inner implies bounded filter iterator."""
        it = pysymex.core.iterators.combinators.SymbolicFilter(lambda x: True, SymbolicRange.from_args(0, 2))
        assert it.is_bounded is True


class TestSymbolicReversed:
    """Test suite for pysymex.core.iterators.combinators.SymbolicReversed."""
    def test_has_next(self) -> None:
        """Scenario: non-empty concrete sequence; reversed iterator has next."""
        it = pysymex.core.iterators.combinators.SymbolicReversed([1, 2])
        assert z3.is_true(z3.simplify(it.has_next()))

    def test_remaining_bound(self) -> None:
        """Scenario: reversed bound equals element count at start."""
        it = pysymex.core.iterators.combinators.SymbolicReversed([1, 2, 3])
        assert it.remaining_bound() == 3

    def test_clone(self) -> None:
        """Scenario: cloned reversed iterator preserves index."""
        it = pysymex.core.iterators.combinators.SymbolicReversed([1, 2, 3])
        assert it.clone().index == it.index

    def test_is_bounded(self) -> None:
        """Scenario: reversed iterator over finite sequence is bounded."""
        it = pysymex.core.iterators.combinators.SymbolicReversed([1, 2, 3])
        assert it.is_bounded is True


class TestSymbolicDictKeysIterator:
    """Test suite for pysymex.core.iterators.combinators.SymbolicDictKeysIterator."""
    def test_has_next(self) -> None:
        """Scenario: key iterator at index zero over one key; has_next true."""
        it = pysymex.core.iterators.combinators.SymbolicDictKeysIterator(["k"])
        assert z3.is_true(z3.simplify(it.has_next()))

    def test_remaining_bound(self) -> None:
        """Scenario: key iterator bound equals number of remaining keys."""
        it = pysymex.core.iterators.combinators.SymbolicDictKeysIterator(["k1", "k2"], index=1)
        assert it.remaining_bound() == 1

    def test_clone(self) -> None:
        """Scenario: clone preserves index position for key iterator."""
        it = pysymex.core.iterators.combinators.SymbolicDictKeysIterator(["k1"], index=1)
        assert it.clone().index == 1

    def test_is_bounded(self) -> None:
        """Scenario: key iterator is always finite and bounded."""
        it = pysymex.core.iterators.combinators.SymbolicDictKeysIterator([])
        assert it.is_bounded is True


class TestSymbolicDictItemsIterator:
    """Test suite for pysymex.core.iterators.combinators.SymbolicDictItemsIterator."""
    def test_has_next(self) -> None:
        """Scenario: item iterator with one pair has next initially."""
        it = pysymex.core.iterators.combinators.SymbolicDictItemsIterator([("k", 1)])
        assert z3.is_true(z3.simplify(it.has_next()))

    def test_remaining_bound(self) -> None:
        """Scenario: item iterator remaining bound after first index."""
        it = pysymex.core.iterators.combinators.SymbolicDictItemsIterator([("k1", 1), ("k2", 2)], index=1)
        assert it.remaining_bound() == 1

    def test_clone(self) -> None:
        """Scenario: clone preserves item iterator index state."""
        it = pysymex.core.iterators.combinators.SymbolicDictItemsIterator([("k", 1)], index=1)
        assert it.clone().index == 1

    def test_is_bounded(self) -> None:
        """Scenario: item iterator over finite list is bounded."""
        it = pysymex.core.iterators.combinators.SymbolicDictItemsIterator([])
        assert it.is_bounded is True


class TestLoopBounds:
    """Test suite for pysymex.core.iterators.combinators.LoopBounds."""
    def test_from_iterator(self) -> None:
        """Scenario: loop bounds from bounded range iterator; finite non-symbolic."""
        bounds = pysymex.core.iterators.combinators.LoopBounds.from_iterator(SymbolicRange.from_args(0, 3))
        assert (bounds.max_iterations, bounds.is_finite, bounds.is_symbolic) == (3, True, False)

    def test_from_range(self) -> None:
        """Scenario: loop bounds from range args; expected concrete max iteration count."""
        bounds = pysymex.core.iterators.combinators.LoopBounds.from_range(0, 4)
        assert bounds.max_iterations == 4

    def test_get_unroll_count(self) -> None:
        """Scenario: unroll count capped by provided maximum."""
        bounds = pysymex.core.iterators.combinators.LoopBounds(0, 12, True, False)
        assert bounds.get_unroll_count(max_unroll=5) == 5
