import pysymex.core.memory.collections.mappings

class TestSymbolicDictOps:
    """Test suite for pysymex.core.memory.collections.mappings.SymbolicDictOps."""
    def test_length(self) -> None:
        """Scenario: concrete dict length; expected exact key count."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.length({"a": 1, "b": 2})
        assert result.value == 2

    def test_getitem(self) -> None:
        """Scenario: get existing concrete key; expected stored value."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.getitem({"k": 5}, "k")
        assert result.value == 5

    def test_setitem(self) -> None:
        """Scenario: set concrete key; expected modified dictionary snapshot."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.setitem({}, "x", 9)
        assert result.modified_collection == {"x": 9}

    def test_delitem(self) -> None:
        """Scenario: delete existing key; expected dictionary without deleted key."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.delitem({"x": 1}, "x")
        assert result.modified_collection == {}

    def test_get(self) -> None:
        """Scenario: get missing key with default; expected provided default value."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.get({}, "m", 7)
        assert result.value == 7

    def test_contains(self) -> None:
        """Scenario: key containment on concrete dict; expected true for present key."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.contains({"a": 1}, "a")
        assert result.value is True

    def test_pop(self) -> None:
        """Scenario: pop existing key; expected popped value and shrunk dictionary."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.pop({"a": 2}, "a")
        assert (result.value, result.modified_collection) == (2, {})

    def test_setdefault(self) -> None:
        """Scenario: setdefault for absent key; expected default insertion and returned value."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.setdefault({}, "k", 3)
        assert result.modified_collection == {"k": 3}

    def test_update(self) -> None:
        """Scenario: update concrete dict with another dict; expected merged mapping."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.update({"a": 1}, {"b": 2})
        assert result.modified_collection == {"a": 1, "b": 2}

    def test_keys(self) -> None:
        """Scenario: enumerate concrete dict keys; expected ordered keys list."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.keys({"x": 1, "y": 2})
        assert result.value == ["x", "y"]

    def test_values(self) -> None:
        """Scenario: enumerate concrete dict values; expected values list."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.values({"x": 1, "y": 2})
        assert result.value == [1, 2]

    def test_items(self) -> None:
        """Scenario: enumerate concrete dict items; expected key-value pair list."""
        result = pysymex.core.memory.collections.mappings.SymbolicDictOps.items({"x": 1})
        assert result.value == [("x", 1)]


class TestSymbolicSetOps:
    """Test suite for pysymex.core.memory.collections.mappings.SymbolicSetOps."""
    def test_length(self) -> None:
        """Scenario: concrete set cardinality; expected unique element count."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.length({1, 2, 2})
        assert result.value == 2

    def test_contains(self) -> None:
        """Scenario: concrete set membership; expected true for included value."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.contains({1, 2}, 2)
        assert result.value is True

    def test_add(self) -> None:
        """Scenario: add value to concrete set; expected element presence afterward."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.add({1}, 3)
        assert result.modified_collection == {1, 3}

    def test_remove(self) -> None:
        """Scenario: remove present value; expected set without removed element."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.remove({1, 2}, 1)
        assert result.modified_collection == {2}

    def test_discard(self) -> None:
        """Scenario: discard missing value; expected set unchanged."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.discard({1, 2}, 9)
        assert result.modified_collection == {1, 2}

    def test_pop(self) -> None:
        """Scenario: pop from non-empty concrete set; expected one existing element."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.pop({4})
        assert result.value == 4

    def test_union(self) -> None:
        """Scenario: union on concrete sets; expected all elements combined."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.union({1, 2}, {2, 3})
        assert result.value == {1, 2, 3}

    def test_intersection(self) -> None:
        """Scenario: intersection on concrete sets; expected common elements only."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.intersection({1, 2}, {2, 3})
        assert result.value == {2}

    def test_difference(self) -> None:
        """Scenario: difference on concrete sets; expected left-only elements."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.difference({1, 2}, {2, 3})
        assert result.value == {1}

    def test_symmetric_difference(self) -> None:
        """Scenario: symmetric difference; expected non-overlapping elements."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.symmetric_difference(
            {1, 2}, {2, 3}
        )
        assert result.value == {1, 3}

    def test_issubset(self) -> None:
        """Scenario: subset check; expected true for contained set."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.issubset({1}, {1, 2})
        assert result.value is True

    def test_issuperset(self) -> None:
        """Scenario: superset check; expected true for containing set."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.issuperset({1, 2}, {1})
        assert result.value is True

    def test_isdisjoint(self) -> None:
        """Scenario: disjointness check; expected true for non-overlapping sets."""
        result = pysymex.core.memory.collections.mappings.SymbolicSetOps.isdisjoint({1}, {2})
        assert result.value is True


class TestSymbolicTupleOps:
    """Test suite for pysymex.core.memory.collections.mappings.SymbolicTupleOps."""
    def test_length(self) -> None:
        """Scenario: concrete tuple length; expected exact element count."""
        result = pysymex.core.memory.collections.mappings.SymbolicTupleOps.length((1, 2, 3))
        assert result.value == 3

    def test_getitem(self) -> None:
        """Scenario: concrete tuple indexing; expected selected element."""
        result = pysymex.core.memory.collections.mappings.SymbolicTupleOps.getitem((7, 8), 1)
        assert result.value == 8

    def test_count(self) -> None:
        """Scenario: concrete tuple count; expected repetition count."""
        result = pysymex.core.memory.collections.mappings.SymbolicTupleOps.count((1, 2, 1), 1)
        assert result.value == 2

    def test_index(self) -> None:
        """Scenario: concrete tuple index lookup; expected first matching position."""
        result = pysymex.core.memory.collections.mappings.SymbolicTupleOps.index((3, 4, 5), 4)
        assert result.value == 1

    def test_slice(self) -> None:
        """Scenario: concrete tuple slicing; expected exact sliced tuple."""
        result = pysymex.core.memory.collections.mappings.SymbolicTupleOps.slice((1, 2, 3, 4), 1, 3)
        assert result.value == (2, 3)

    def test_concatenate(self) -> None:
        """Scenario: concatenate concrete tuples; expected appended tuple values."""
        result = pysymex.core.memory.collections.mappings.SymbolicTupleOps.concatenate((1, 2), (3,))
        assert result.value == (1, 2, 3)

    def test_contains(self) -> None:
        """Scenario: membership in concrete tuple; expected true for existing value."""
        result = pysymex.core.memory.collections.mappings.SymbolicTupleOps.contains((1, 2, 3), 3)
        assert result.value is True
