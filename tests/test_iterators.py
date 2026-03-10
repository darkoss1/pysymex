"""
Tests for pysymex Iterator Protocol - Phase 16

Comprehensive tests for:
- SymbolicRange: range iteration with symbolic bounds
- SymbolicSequenceIterator: list/tuple/string iteration
- SymbolicEnumerate: enumerate() iterator
- SymbolicZip: zip() iterator
- SymbolicMap: map() iterator
- SymbolicFilter: filter() iterator
- Loop bound analysis
"""

import z3

from pysymex.core.iterators import (
    LoopBounds,
    SymbolicDictItemsIterator,
    SymbolicDictKeysIterator,
    SymbolicEnumerate,
    SymbolicFilter,
    SymbolicRange,
    SymbolicSequenceIterator,
    collect_iterator,
    create_iterator,
    symbolic_enumerate,
    symbolic_filter,
    symbolic_map,
    symbolic_range,
    symbolic_reversed,
    symbolic_zip,
)
from pysymex.core.symbolic_types import SymbolicInt

# =============================================================================
# SymbolicRange Tests
# =============================================================================


class TestSymbolicRange:
    """Tests for SymbolicRange iterator."""

    def test_create_with_stop_only(self):
        """Test creating range with just stop."""
        r = SymbolicRange.from_args(5)
        assert r.start == 0
        assert r.stop == 5
        assert r.step == 1

    def test_create_with_start_stop(self):
        """Test creating range with start and stop."""
        r = SymbolicRange.from_args(2, 7)
        assert r.start == 2
        assert r.stop == 7
        assert r.step == 1

    def test_create_with_step(self):
        """Test creating range with step."""
        r = SymbolicRange.from_args(0, 10, 2)
        assert r.start == 0
        assert r.stop == 10
        assert r.step == 2

    def test_iterate_simple_range(self):
        """Test iterating over simple range."""
        r = SymbolicRange.from_args(3)
        values = []

        for _ in range(10):  # Safety limit
            result = next(r)
            if result.exhausted:
                break
            values.append(result.value.z3_int.as_long())
            r = result.iterator

        assert values == [0, 1, 2]

    def test_iterate_with_start(self):
        """Test iterating with non-zero start."""
        r = SymbolicRange.from_args(2, 5)
        values = []

        for _ in range(10):
            result = next(r)
            if result.exhausted:
                break
            values.append(result.value.z3_int.as_long())
            r = result.iterator

        assert values == [2, 3, 4]

    def test_iterate_with_step(self):
        """Test iterating with step > 1."""
        r = SymbolicRange.from_args(0, 10, 3)
        values = []

        for _ in range(10):
            result = next(r)
            if result.exhausted:
                break
            values.append(result.value.z3_int.as_long())
            r = result.iterator

        assert values == [0, 3, 6, 9]

    def test_negative_step(self):
        """Test range with negative step."""
        r = SymbolicRange.from_args(5, 0, -1)
        values = []

        for _ in range(10):
            result = next(r)
            if result.exhausted:
                break
            values.append(result.value.z3_int.as_long())
            r = result.iterator

        assert values == [5, 4, 3, 2, 1]

    def test_empty_range(self):
        """Test empty range."""
        r = SymbolicRange.from_args(5, 5)
        result = next(r)
        assert result.exhausted

    def test_has_next_concrete(self):
        """Test has_next for concrete range."""
        r = SymbolicRange.from_args(3)

        # Initially has elements
        assert z3.is_true(z3.simplify(r.has_next()))

        # After exhausting
        for _ in range(3):
            result = next(r)
            r = result.iterator

        assert z3.is_false(z3.simplify(r.has_next()))

    def test_remaining_bound_concrete(self):
        """Test remaining_bound for concrete range."""
        r = SymbolicRange.from_args(5)

        assert r.remaining_bound() == 5

        result = next(r)
        r = result.iterator

        assert r.remaining_bound() == 4

    def test_symbolic_stop(self):
        """Test range with symbolic stop."""
        n = z3.Int("n")
        r = SymbolicRange(start=0, stop=n, step=1)

        # has_next should be symbolic
        has_next = r.has_next()
        assert isinstance(has_next, z3.BoolRef)

        # Should be satisfiable when n > 0
        solver = z3.Solver()
        solver.add(n == 5)
        solver.add(has_next)
        assert solver.check() == z3.sat

    def test_length(self):
        """Test length calculation."""
        r = SymbolicRange.from_args(10)
        assert r.length == 10

        r2 = SymbolicRange.from_args(2, 8, 2)
        assert r2.length == 3  # [2, 4, 6]

    def test_clone(self):
        """Test cloning preserves state."""
        r = SymbolicRange.from_args(5)

        # Advance original
        result = next(r)
        r = result.iterator

        # Clone
        r2 = r.clone()

        # Both should have same current
        assert r.current == r2.current  # type: ignore[reportAttributeAccessIssue]

        # Advancing one shouldn't affect other
        result = next(r)
        r = result.iterator
        assert r.current != r2.current  # type: ignore[reportAttributeAccessIssue]

    def test_is_bounded(self):
        """Test is_bounded property."""
        r = SymbolicRange.from_args(10)
        assert r.is_bounded

        # Symbolic range is still bounded
        n = z3.Int("n")
        r2 = SymbolicRange(start=0, stop=n, step=1)
        assert r2.is_bounded


# =============================================================================
# SymbolicSequenceIterator Tests
# =============================================================================


class TestSymbolicSequenceIterator:
    """Tests for SymbolicSequenceIterator."""

    def test_iterate_list(self):
        """Test iterating over a list."""
        lst = [10, 20, 30]
        it = SymbolicSequenceIterator(sequence=lst)
        values = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            values.append(result.value)
            it = result.iterator

        assert values == [10, 20, 30]

    def test_iterate_tuple(self):
        """Test iterating over a tuple."""
        tpl = ("a", "b", "c")
        it = SymbolicSequenceIterator(sequence=tpl)
        values = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            values.append(result.value)
            it = result.iterator

        assert values == ["a", "b", "c"]

    def test_iterate_string(self):
        """Test iterating over a string."""
        s = "abc"
        it = SymbolicSequenceIterator(sequence=s)
        values = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            values.append(result.value)
            it = result.iterator

        assert values == ["a", "b", "c"]

    def test_empty_sequence(self):
        """Test iterating over empty sequence."""
        it = SymbolicSequenceIterator(sequence=[])
        result = next(it)
        assert result.exhausted

    def test_remaining_bound(self):
        """Test remaining_bound calculation."""
        lst = [1, 2, 3, 4, 5]
        it = SymbolicSequenceIterator(sequence=lst)

        assert it.remaining_bound() == 5

        result = next(it)
        it = result.iterator

        assert it.remaining_bound() == 4


# =============================================================================
# SymbolicEnumerate Tests
# =============================================================================


class TestSymbolicEnumerate:
    """Tests for SymbolicEnumerate iterator."""

    def test_enumerate_list(self):
        """Test enumerate over list."""
        lst = ["a", "b", "c"]
        it = symbolic_enumerate(lst)
        pairs = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            # Extract tuple elements
            idx = result.value.elements[0]
            val = result.value.elements[1]
            if isinstance(idx, SymbolicInt):
                idx = idx.z3_int.as_long()
            pairs.append((idx, val))
            it = result.iterator

        assert pairs == [(0, "a"), (1, "b"), (2, "c")]

    def test_enumerate_with_start(self):
        """Test enumerate with custom start."""
        lst = ["x", "y"]
        it = symbolic_enumerate(lst, start=10)
        pairs = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            idx = result.value.elements[0]
            val = result.value.elements[1]
            if isinstance(idx, SymbolicInt):
                idx = idx.z3_int.as_long()
            pairs.append((idx, val))
            it = result.iterator

        assert pairs == [(10, "x"), (11, "y")]

    def test_enumerate_empty(self):
        """Test enumerate over empty sequence."""
        it = symbolic_enumerate([])
        result = next(it)
        assert result.exhausted


# =============================================================================
# SymbolicZip Tests
# =============================================================================


class TestSymbolicZip:
    """Tests for SymbolicZip iterator."""

    def test_zip_two_lists(self):
        """Test zipping two lists."""
        a = [1, 2, 3]
        b = ["a", "b", "c"]
        it = symbolic_zip(a, b)
        pairs = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            elems = result.value.elements
            pairs.append((elems[0], elems[1]))
            it = result.iterator

        assert pairs == [(1, "a"), (2, "b"), (3, "c")]

    def test_zip_different_lengths(self):
        """Test zipping lists of different lengths."""
        a = [1, 2, 3, 4]
        b = ["x", "y"]
        it = symbolic_zip(a, b)
        pairs = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            elems = result.value.elements
            pairs.append((elems[0], elems[1]))
            it = result.iterator

        assert pairs == [(1, "x"), (2, "y")]  # Stops at shortest

    def test_zip_three_iterables(self):
        """Test zipping three iterables."""
        a = [1, 2]
        b = ["a", "b"]
        c = [True, False]
        it = symbolic_zip(a, b, c)
        tuples = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            elems = result.value.elements
            tuples.append((elems[0], elems[1], elems[2]))
            it = result.iterator

        assert tuples == [(1, "a", True), (2, "b", False)]

    def test_zip_empty(self):
        """Test zipping with empty iterable."""
        it = symbolic_zip([1, 2], [])
        result = next(it)
        assert result.exhausted

    def test_zip_remaining_bound(self):
        """Test remaining_bound is minimum."""
        a = [1, 2, 3, 4, 5]  # 5 elements
        b = [1, 2, 3]  # 3 elements
        it = symbolic_zip(a, b)

        assert it.remaining_bound() == 3  # Minimum


# =============================================================================
# SymbolicMap Tests
# =============================================================================


class TestSymbolicMap:
    """Tests for SymbolicMap iterator."""

    def test_map_double(self):
        """Test mapping with double function."""
        lst = [1, 2, 3]
        it = symbolic_map(lambda x: x * 2, lst)
        values = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            values.append(result.value)
            it = result.iterator

        assert values == [2, 4, 6]

    def test_map_to_string(self):
        """Test mapping to strings."""
        lst = [1, 2, 3]
        it = symbolic_map(str, lst)
        values = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            values.append(result.value)
            it = result.iterator

        assert values == ["1", "2", "3"]

    def test_map_empty(self):
        """Test mapping over empty."""
        it = symbolic_map(lambda x: x, [])
        result = next(it)
        assert result.exhausted


# =============================================================================
# SymbolicFilter Tests
# =============================================================================


class TestSymbolicFilter:
    """Tests for SymbolicFilter iterator."""

    def test_filter_even(self):
        """Test filtering for even numbers."""
        lst = [1, 2, 3, 4, 5, 6]
        it = symbolic_filter(lambda x: x % 2 == 0, lst)
        values = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            values.append(result.value)
            it = result.iterator

        assert values == [2, 4, 6]

    def test_filter_none_pass(self):
        """Test filter where nothing passes."""
        lst = [1, 3, 5]
        it = symbolic_filter(lambda x: x % 2 == 0, lst)
        result = next(it)
        assert result.exhausted

    def test_filter_all_pass(self):
        """Test filter where everything passes."""
        lst = [2, 4, 6]
        it = symbolic_filter(lambda x: x % 2 == 0, lst)
        values = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            values.append(result.value)
            it = result.iterator

        assert values == [2, 4, 6]


# =============================================================================
# SymbolicReversed Tests
# =============================================================================


class TestSymbolicReversed:
    """Tests for SymbolicReversed iterator."""

    def test_reversed_list(self):
        """Test reversing a list."""
        lst = [1, 2, 3]
        it = symbolic_reversed(lst)
        values = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            values.append(result.value)
            it = result.iterator

        assert values == [3, 2, 1]

    def test_reversed_string(self):
        """Test reversing a string."""
        s = "abc"
        it = symbolic_reversed(s)
        values = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            values.append(result.value)
            it = result.iterator

        assert values == ["c", "b", "a"]

    def test_reversed_empty(self):
        """Test reversing empty sequence."""
        it = symbolic_reversed([])
        result = next(it)
        assert result.exhausted


# =============================================================================
# Dict Iterator Tests
# =============================================================================


class TestDictIterators:
    """Tests for dict iterators."""

    def test_keys_iterator(self):
        """Test iterating over dict keys."""
        d = {"a": 1, "b": 2, "c": 3}
        it = SymbolicDictKeysIterator(keys=list(d.keys()))
        values = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            values.append(result.value)
            it = result.iterator

        assert set(values) == {"a", "b", "c"}

    def test_items_iterator(self):
        """Test iterating over dict items."""
        d = {"x": 10, "y": 20}
        it = SymbolicDictItemsIterator(items=list(d.items()))
        pairs = []

        for _ in range(10):
            result = next(it)
            if result.exhausted:
                break
            elems = result.value.elements
            pairs.append((elems[0], elems[1]))
            it = result.iterator

        assert set(pairs) == {("x", 10), ("y", 20)}


# =============================================================================
# LoopBounds Tests
# =============================================================================


class TestLoopBounds:
    """Tests for LoopBounds analysis."""

    def test_from_iterator_concrete(self):
        """Test bounds from concrete iterator."""
        r = SymbolicRange.from_args(10)
        bounds = LoopBounds.from_iterator(r)

        assert bounds.min_iterations == 0
        assert bounds.max_iterations == 10
        assert bounds.is_finite
        assert not bounds.is_symbolic

    def test_from_iterator_symbolic(self):
        """Test bounds from symbolic iterator."""
        n = z3.Int("n")
        r = SymbolicRange(start=0, stop=n, step=1)
        bounds = LoopBounds.from_iterator(r)

        assert bounds.min_iterations == 0
        assert bounds.is_finite
        assert bounds.is_symbolic

    def test_from_range_params(self):
        """Test bounds from range parameters."""
        bounds = LoopBounds.from_range(0, 5, 1)

        assert bounds.max_iterations == 5
        assert bounds.is_finite

    def test_unroll_count_concrete(self):
        """Test unroll count for concrete bounds."""
        bounds = LoopBounds.from_range(0, 10)

        assert bounds.get_unroll_count() == 10
        assert bounds.get_unroll_count(max_unroll=5) == 5

    def test_unroll_count_symbolic(self):
        """Test unroll count for symbolic bounds."""
        n = z3.Int("n")
        r = SymbolicRange(start=0, stop=n, step=1)
        bounds = LoopBounds.from_iterator(r)

        # Should return max_unroll for symbolic
        assert bounds.get_unroll_count(max_unroll=50) == 50


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestFactoryFunctions:
    """Tests for iterator factory functions."""

    def test_create_iterator_range(self):
        """Test create_iterator with range."""
        it = create_iterator(range(3))
        values, _ = collect_iterator(it)

        # Extract concrete values
        concrete = [v.z3_int.as_long() if isinstance(v, SymbolicInt) else v for v in values]
        assert concrete == [0, 1, 2]

    def test_create_iterator_list(self):
        """Test create_iterator with list."""
        it = create_iterator([1, 2, 3])
        values, _ = collect_iterator(it)

        assert values == [1, 2, 3]

    def test_create_iterator_dict(self):
        """Test create_iterator with dict."""
        d = {"a": 1, "b": 2}
        it = create_iterator(d)
        values, _ = collect_iterator(it)

        assert set(values) == {"a", "b"}

    def test_symbolic_range_factory(self):
        """Test symbolic_range factory."""
        r = symbolic_range(5)
        values, _ = collect_iterator(r)

        concrete = [v.z3_int.as_long() for v in values]
        assert concrete == [0, 1, 2, 3, 4]


# =============================================================================
# collect_iterator Tests
# =============================================================================


class TestCollectIterator:
    """Tests for collect_iterator function."""

    def test_collect_simple(self):
        """Test collecting from simple iterator."""
        it = SymbolicSequenceIterator(sequence=[1, 2, 3])
        values, constraints = collect_iterator(it)

        assert values == [1, 2, 3]
        assert len(constraints) == 4  # 3 values + 1 exhausted

    def test_collect_with_limit(self):
        """Test collecting with iteration limit."""
        it = SymbolicSequenceIterator(sequence=list(range(100)))
        values, _ = collect_iterator(it, max_iterations=10)

        assert len(values) == 10

    def test_collect_empty(self):
        """Test collecting from empty iterator."""
        it = SymbolicSequenceIterator(sequence=[])
        values, constraints = collect_iterator(it)

        assert values == []
        assert len(constraints) == 1  # Just the exhausted check


# =============================================================================
# Integration Tests
# =============================================================================


class TestIteratorIntegration:
    """Integration tests for iterators."""

    def test_nested_loops(self):
        """Test simulating nested loops."""
        outer = SymbolicRange.from_args(3)
        results = []

        for _ in range(10):
            outer_result = next(outer)
            if outer_result.exhausted:
                break

            i = outer_result.value.z3_int.as_long()
            inner = SymbolicRange.from_args(2)

            for _ in range(10):
                inner_result = next(inner)
                if inner_result.exhausted:
                    break

                j = inner_result.value.z3_int.as_long()
                results.append((i, j))
                inner = inner_result.iterator

            outer = outer_result.iterator

        expected = [(0, 0), (0, 1), (1, 0), (1, 1), (2, 0), (2, 1)]
        assert results == expected

    def test_enumerate_zip_combo(self):
        """Test combining enumerate and zip."""
        a = [10, 20, 30]
        b = ["x", "y", "z"]

        # enumerate(zip(a, b)) pattern
        zipped = symbolic_zip(a, b)
        enumed = SymbolicEnumerate(inner=zipped)

        results = []
        for _ in range(10):
            result = next(enumed)
            if result.exhausted:
                break

            # result.value is (idx, (a_val, b_val))
            outer = result.value.elements
            idx = outer[0]
            if isinstance(idx, SymbolicInt):
                idx = idx.z3_int.as_long()
            inner = outer[1].elements

            results.append((idx, inner[0], inner[1]))
            enumed = result.iterator

        assert results == [(0, 10, "x"), (1, 20, "y"), (2, 30, "z")]

    def test_map_filter_chain(self):
        """Test chaining map and filter."""
        lst = [1, 2, 3, 4, 5, 6]

        # filter(lambda x: x > 5, map(lambda x: x * 2, lst))
        mapped = symbolic_map(lambda x: x * 2, lst)
        filtered = SymbolicFilter(predicate=lambda x: x > 5, inner=mapped)

        values, _ = collect_iterator(filtered)

        assert values == [6, 8, 10, 12]  # 3*2, 4*2, 5*2, 6*2

    def test_symbolic_bounds_verification(self):
        """Test that symbolic bounds can be verified with Z3."""
        n = z3.Int("n")
        r = SymbolicRange(start=0, stop=n, step=1)

        solver = z3.Solver()

        # If n = 5, should iterate 5 times
        solver.add(n == 5)

        # Length should be 5
        length = r.length
        solver.add(length == 5)

        assert solver.check() == z3.sat

    def test_iterator_constraints_accumulate(self):
        """Test that constraints accumulate through iteration."""
        n = z3.Int("n")
        r = SymbolicRange(start=0, stop=n, step=1)

        values, constraints = collect_iterator(r, max_iterations=3)

        # Should have constraints from each iteration
        assert len(constraints) >= 1

        # All constraints should be Z3 expressions
        for c in constraints:
            assert isinstance(c, z3.BoolRef)


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests."""

    def test_single_element(self):
        """Test iterator with single element."""
        it = SymbolicSequenceIterator(sequence=[42])

        result = next(it)
        assert not result.exhausted
        assert result.value == 42

        result2 = next(result.iterator)
        assert result2.exhausted

    def test_large_range(self):
        """Test handling large ranges."""
        r = SymbolicRange.from_args(1000000)

        # Should handle without actually iterating
        assert r.length == 1000000
        assert r.remaining_bound() == 1000000

    def test_negative_range(self):
        """Test range that would be negative (empty)."""
        r = SymbolicRange.from_args(10, 5, 1)  # Start > stop with positive step

        result = next(r)
        assert result.exhausted

    def test_zero_step_handling(self):
        """Test range with zero step (invalid but handled)."""
        r = SymbolicRange(start=0, stop=10, step=0)

        # Should not iterate
        assert r.remaining_bound() == 0

    def test_iterator_reuse(self):
        """Test that iterators are immutable (clone on advance)."""
        r = SymbolicRange.from_args(3)

        # Save original
        original_current = r.current

        # Advance
        result = next(r)
        new_r = result.iterator

        # Original unchanged
        assert r.current == original_current
        # New iterator advanced
        assert new_r.current != original_current  # type: ignore[reportAttributeAccessIssue]
