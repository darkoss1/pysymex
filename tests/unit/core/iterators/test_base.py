import pysymex.core.iterators.base
import z3

class TestIteratorState:
    """Test suite for pysymex.core.iterators.base.IteratorState."""
    def test_initialization(self) -> None:
        """Scenario: iterator states are declared; expected enum members exist."""
        assert pysymex.core.iterators.base.IteratorState.ACTIVE.name == "ACTIVE"


class TestIterationResult:
    """Test suite for pysymex.core.iterators.base.IterationResult."""
    def test_has_value(self) -> None:
        """Scenario: non-exhausted result; expected has_value to be true."""
        iterator = pysymex.core.iterators.base.SymbolicRange.from_args(0, 1)
        result = next(iterator)
        assert result.has_value is True


class TestSymbolicIterator:
    """Test suite for pysymex.core.iterators.base.SymbolicIterator."""
    def test_has_next(self) -> None:
        """Scenario: base behavior via concrete range; expected has_next true initially."""
        iterator = pysymex.core.iterators.base.SymbolicRange.from_args(0, 2)
        assert z3.is_true(z3.simplify(iterator.has_next()))

    def test_remaining_bound(self) -> None:
        """Scenario: base behavior via concrete range; expected finite remaining bound."""
        iterator = pysymex.core.iterators.base.SymbolicRange.from_args(0, 3)
        assert iterator.remaining_bound() == 3

    def test_clone(self) -> None:
        """Scenario: clone on concrete range; expected equivalent state copy."""
        iterator = pysymex.core.iterators.base.SymbolicRange.from_args(0, 3)
        cloned = iterator.clone()
        assert cloned.current == iterator.current

    def test_is_bounded(self) -> None:
        """Scenario: base behavior via range iterator; expected bounded iterator."""
        iterator = pysymex.core.iterators.base.SymbolicRange.from_args(0, 3)
        assert iterator.is_bounded is True


class TestSymbolicRange:
    """Test suite for pysymex.core.iterators.base.SymbolicRange."""
    def test_from_args(self) -> None:
        """Scenario: one-argument factory form; expected start zero and stop set."""
        rng = pysymex.core.iterators.base.SymbolicRange.from_args(5)
        assert (rng.start, rng.stop, rng.step) == (0, 5, 1)

    def test_has_next(self) -> None:
        """Scenario: positive step before stop; expected has_next true."""
        rng = pysymex.core.iterators.base.SymbolicRange.from_args(0, 2)
        assert z3.is_true(z3.simplify(rng.has_next()))

    def test_remaining_bound(self) -> None:
        """Scenario: range length computation; expected exact bound count."""
        rng = pysymex.core.iterators.base.SymbolicRange.from_args(1, 7, 2)
        assert rng.remaining_bound() == 3

    def test_clone(self) -> None:
        """Scenario: cloned range copies current position; expected same current."""
        rng = pysymex.core.iterators.base.SymbolicRange.from_args(0, 5)
        _ = next(rng)
        cloned = rng.clone()
        assert cloned.current == rng.current

    def test_is_bounded(self) -> None:
        """Scenario: range iterator boundedness; expected true."""
        rng = pysymex.core.iterators.base.SymbolicRange.from_args(0, 5)
        assert rng.is_bounded is True

    def test_length(self) -> None:
        """Scenario: length property for concrete arithmetic progression; expected count."""
        rng = pysymex.core.iterators.base.SymbolicRange.from_args(0, 10, 3)
        assert rng.length == 4


class TestSymbolicSequenceIterator:
    """Test suite for pysymex.core.iterators.base.SymbolicSequenceIterator."""
    def test_has_next(self) -> None:
        """Scenario: index inside concrete list bounds; expected has_next true."""
        iterator = pysymex.core.iterators.base.SymbolicSequenceIterator([1, 2, 3])
        assert z3.is_true(z3.simplify(iterator.has_next()))

    def test_remaining_bound(self) -> None:
        """Scenario: concrete list remaining bound at start; expected list length."""
        iterator = pysymex.core.iterators.base.SymbolicSequenceIterator([1, 2, 3])
        assert iterator.remaining_bound() == 3

    def test_clone(self) -> None:
        """Scenario: cloned sequence iterator preserves index and sequence."""
        iterator = pysymex.core.iterators.base.SymbolicSequenceIterator([1, 2, 3], index=1)
        cloned = iterator.clone()
        assert cloned.index == 1

    def test_is_bounded(self) -> None:
        """Scenario: sequence iterators over finite concrete data are bounded."""
        iterator = pysymex.core.iterators.base.SymbolicSequenceIterator([1, 2, 3])
        assert iterator.is_bounded is True
