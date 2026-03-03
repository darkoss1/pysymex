"""
Tests for pysymex Collection Theories - Phase 15

Comprehensive tests for:
- SymbolicListOps: append, extend, pop, insert, etc.
- SymbolicDictOps: get, set, delete, update, etc.
- SymbolicSetOps: add, union, intersection, etc.
- SymbolicTupleOps: indexing, slicing, count, etc.
- Integration with Z3 constraint solving
"""

import pytest

import z3


from pysymex.core.collections import (
    OpResult,
    SymbolicListOps,
    SymbolicDictOps,
    SymbolicSetOps,
    SymbolicTupleOps,
    SymbolicStringOps,
)

from pysymex.core.symbolic_types import (
    SymbolicInt,
    SymbolicBool,
    SymbolicString,
    SymbolicList,
    SymbolicDict,
    SymbolicSet,
    SymbolicTuple,
)

from pysymex.core.memory_model import SymbolicArray, SymbolicMap


class TestOpResult:
    """Tests for OpResult class."""

    def test_success_result(self):
        """Test successful operation result."""

        result = OpResult(value=42)

        assert result.success

        assert result.value == 42

        assert result.error is None

    def test_error_result(self):
        """Test error operation result."""

        result = OpResult(value=None, error="IndexError")

        assert not result.success

        assert result.error == "IndexError"

    def test_with_constraint(self):
        """Test adding constraints."""

        result = OpResult(value=42)

        result.with_constraint(z3.Int("x") > 0)

        assert len(result.constraints) == 1

    def test_modified_collection(self):
        """Test modified collection tracking."""

        lst = [1, 2, 3]

        result = OpResult(value=None, modified_collection=lst)

        assert result.modified_collection is lst


class TestSymbolicListOps:
    """Tests for SymbolicListOps class."""

    def test_length_concrete(self):
        """Test length of concrete list."""

        result = SymbolicListOps.length([1, 2, 3])

        assert result.value == 3

    def test_length_symbolic_array(self):
        """Test length of symbolic array."""

        arr = SymbolicArray("test")

        result = SymbolicListOps.length(arr)

        assert isinstance(result.value, z3.ArithRef)

    def test_getitem_concrete_list_concrete_index(self):
        """Test getting item from concrete list with concrete index."""

        result = SymbolicListOps.getitem([10, 20, 30], 1)

        assert result.value == 20

    def test_getitem_concrete_list_out_of_bounds(self):
        """Test out of bounds access."""

        result = SymbolicListOps.getitem([1, 2, 3], 10)

        assert not result.success

        assert "IndexError" in result.error

    def test_getitem_symbolic_array(self):
        """Test getting item from symbolic array."""

        arr = SymbolicArray("data")

        result = SymbolicListOps.getitem(arr, 0)

        assert result.success

        assert len(result.constraints) > 0

    def test_getitem_symbolic_index(self):
        """Test getting with symbolic index."""

        arr = SymbolicArray("data")

        idx = z3.Int("i")

        result = SymbolicListOps.getitem(arr, idx)

        assert result.success

    def test_setitem_concrete_list(self):
        """Test setting item in concrete list."""

        lst = [1, 2, 3]

        result = SymbolicListOps.setitem(lst, 1, 99)

        assert result.success

        assert lst[1] == 99

    def test_setitem_out_of_bounds(self):
        """Test setting out of bounds."""

        lst = [1, 2, 3]

        result = SymbolicListOps.setitem(lst, 10, 99)

        assert not result.success

    def test_setitem_symbolic_array(self):
        """Test setting in symbolic array."""

        arr = SymbolicArray("data")

        result = SymbolicListOps.setitem(arr, 0, 42)

        assert result.success

        assert result.modified_collection is not None

    def test_append_concrete_list(self):
        """Test appending to concrete list."""

        lst = [1, 2, 3]

        result = SymbolicListOps.append(lst, 4)

        assert result.success

        assert lst == [1, 2, 3, 4]

    def test_append_symbolic_array(self):
        """Test appending to symbolic array."""

        arr = SymbolicArray("data")

        result = SymbolicListOps.append(arr, z3.IntVal(42))

        assert result.success

        assert result.modified_collection is not None

    def test_extend_concrete_lists(self):
        """Test extending concrete lists."""

        lst = [1, 2]

        result = SymbolicListOps.extend(lst, [3, 4])

        assert result.success

        assert lst == [1, 2, 3, 4]

    def test_extend_symbolic_with_concrete(self):
        """Test extending symbolic with concrete."""

        arr = SymbolicArray("data")

        result = SymbolicListOps.extend(arr, [1, 2, 3])

        assert result.success

    def test_pop_last_concrete(self):
        """Test popping last element from concrete list."""

        lst = [1, 2, 3]

        result = SymbolicListOps.pop(lst)

        assert result.value == 3

        assert lst == [1, 2]

    def test_pop_at_index_concrete(self):
        """Test popping at index from concrete list."""

        lst = [1, 2, 3]

        result = SymbolicListOps.pop(lst, 0)

        assert result.value == 1

        assert lst == [2, 3]

    def test_pop_empty_list(self):
        """Test popping from empty list."""

        result = SymbolicListOps.pop([])

        assert not result.success

        assert "empty" in result.error.lower()

    def test_pop_symbolic_array(self):
        """Test popping from symbolic array."""

        arr = SymbolicArray("data")

        result = SymbolicListOps.pop(arr)

        assert result.success

        assert len(result.constraints) > 0

    def test_insert_concrete(self):
        """Test inserting into concrete list."""

        lst = [1, 3]

        result = SymbolicListOps.insert(lst, 1, 2)

        assert result.success

        assert lst == [1, 2, 3]

    def test_remove_concrete(self):
        """Test removing from concrete list."""

        lst = [1, 2, 3, 2]

        result = SymbolicListOps.remove(lst, 2)

        assert result.success

        assert lst == [1, 3, 2]

    def test_remove_not_found(self):
        """Test removing non-existent value."""

        lst = [1, 2, 3]

        result = SymbolicListOps.remove(lst, 99)

        assert not result.success

        assert "not in list" in result.error

    def test_index_concrete(self):
        """Test finding index in concrete list."""

        result = SymbolicListOps.index([10, 20, 30], 20)

        assert result.value == 1

    def test_index_not_found(self):
        """Test index for non-existent value."""

        result = SymbolicListOps.index([1, 2, 3], 99)

        assert not result.success

    def test_index_symbolic(self):
        """Test finding index in symbolic array."""

        arr = SymbolicArray("data")

        result = SymbolicListOps.index(arr, 42)

        assert result.success

        assert isinstance(result.value, SymbolicInt)

    def test_count_concrete(self):
        """Test counting in concrete list."""

        result = SymbolicListOps.count([1, 2, 2, 3, 2], 2)

        assert result.value == 3

    def test_count_symbolic(self):
        """Test counting in symbolic array."""

        arr = SymbolicArray("data")

        result = SymbolicListOps.count(arr, 5)

        assert result.success

        assert isinstance(result.value, SymbolicInt)

    def test_reverse_concrete(self):
        """Test reversing concrete list."""

        lst = [1, 2, 3]

        result = SymbolicListOps.reverse(lst)

        assert result.success

        assert lst == [3, 2, 1]

    def test_contains_concrete_true(self):
        """Test contains for present value."""

        result = SymbolicListOps.contains([1, 2, 3], 2)

        assert result.value is True

    def test_contains_concrete_false(self):
        """Test contains for absent value."""

        result = SymbolicListOps.contains([1, 2, 3], 99)

        assert result.value is False

    def test_contains_symbolic(self):
        """Test contains in symbolic array."""

        arr = SymbolicArray("data")

        result = SymbolicListOps.contains(arr, 42)

        assert result.success

        assert isinstance(result.value, SymbolicBool)

    def test_slice_concrete(self):
        """Test slicing concrete list."""

        result = SymbolicListOps.slice([1, 2, 3, 4, 5], 1, 4)

        assert result.value == [2, 3, 4]

    def test_slice_symbolic(self):
        """Test slicing symbolic array."""

        arr = SymbolicArray("data")

        result = SymbolicListOps.slice(arr, 1, 3)

        assert result.success

    def test_concatenate_concrete(self):
        """Test concatenating concrete lists."""

        result = SymbolicListOps.concatenate([1, 2], [3, 4])

        assert result.value == [1, 2, 3, 4]

    def test_concatenate_symbolic(self):
        """Test concatenating symbolic arrays."""

        arr1 = SymbolicArray("a")

        arr2 = SymbolicArray("b")

        result = SymbolicListOps.concatenate(arr1, arr2)

        assert result.success


class TestSymbolicDictOps:
    """Tests for SymbolicDictOps class."""

    def test_length_concrete(self):
        """Test length of concrete dict."""

        result = SymbolicDictOps.length({"a": 1, "b": 2})

        assert result.value == 2

    def test_getitem_concrete(self):
        """Test getting item from concrete dict."""

        result = SymbolicDictOps.getitem({"a": 1, "b": 2}, "a")

        assert result.value == 1

    def test_getitem_key_error(self):
        """Test getting non-existent key."""

        result = SymbolicDictOps.getitem({"a": 1}, "x")

        assert not result.success

        assert "KeyError" in result.error

    def test_getitem_symbolic_map(self):
        """Test getting from symbolic map."""

        m = SymbolicMap("data")

        m = m.set(z3.IntVal(1), z3.IntVal(100))

        result = SymbolicDictOps.getitem(m, 1)

        assert result.success

    def test_setitem_concrete(self):
        """Test setting item in concrete dict."""

        d = {"a": 1}

        result = SymbolicDictOps.setitem(d, "b", 2)

        assert result.success

        assert d == {"a": 1, "b": 2}

    def test_setitem_symbolic_map(self):
        """Test setting in symbolic map."""

        m = SymbolicMap("data")

        result = SymbolicDictOps.setitem(m, 1, 100)

        assert result.success

        assert result.modified_collection is not None

    def test_delitem_concrete(self):
        """Test deleting from concrete dict."""

        d = {"a": 1, "b": 2}

        result = SymbolicDictOps.delitem(d, "a")

        assert result.success

        assert d == {"b": 2}

    def test_delitem_key_error(self):
        """Test deleting non-existent key."""

        result = SymbolicDictOps.delitem({"a": 1}, "x")

        assert not result.success

    def test_get_existing(self):
        """Test get for existing key."""

        result = SymbolicDictOps.get({"a": 1}, "a", default=99)

        assert result.value == 1

    def test_get_missing_with_default(self):
        """Test get for missing key with default."""

        result = SymbolicDictOps.get({"a": 1}, "x", default=99)

        assert result.value == 99

    def test_get_symbolic_map_with_default(self):
        """Test get from symbolic map with default."""

        m = SymbolicMap("data")

        result = SymbolicDictOps.get(m, 1, default=z3.IntVal(-1))

        assert result.success

    def test_contains_concrete_true(self):
        """Test contains for existing key."""

        result = SymbolicDictOps.contains({"a": 1}, "a")

        assert result.value is True

    def test_contains_concrete_false(self):
        """Test contains for missing key."""

        result = SymbolicDictOps.contains({"a": 1}, "x")

        assert result.value is False

    def test_contains_symbolic_map(self):
        """Test contains in symbolic map."""

        m = SymbolicMap("data")

        m = m.set(z3.IntVal(1), z3.IntVal(100))

        result = SymbolicDictOps.contains(m, 1)

        assert result.success

    def test_pop_concrete(self):
        """Test popping from concrete dict."""

        d = {"a": 1, "b": 2}

        result = SymbolicDictOps.pop(d, "a")

        assert result.value == 1

        assert d == {"b": 2}

    def test_pop_with_default(self):
        """Test popping non-existent with default."""

        d = {"a": 1}

        result = SymbolicDictOps.pop(d, "x", default=99)

        assert result.value == 99

    def test_pop_key_error(self):
        """Test popping non-existent without default."""

        result = SymbolicDictOps.pop({"a": 1}, "x")

        assert not result.success

    def test_setdefault_existing(self):
        """Test setdefault for existing key."""

        d = {"a": 1}

        result = SymbolicDictOps.setdefault(d, "a", 99)

        assert result.value == 1

        assert d == {"a": 1}

    def test_setdefault_new(self):
        """Test setdefault for new key."""

        d = {"a": 1}

        result = SymbolicDictOps.setdefault(d, "b", 2)

        assert result.value == 2

        assert d == {"a": 1, "b": 2}

    def test_update_concrete(self):
        """Test updating concrete dict."""

        d = {"a": 1}

        result = SymbolicDictOps.update(d, {"b": 2, "c": 3})

        assert result.success

        assert d == {"a": 1, "b": 2, "c": 3}

    def test_update_symbolic_with_concrete(self):
        """Test updating symbolic map with concrete dict."""

        m = SymbolicMap("data")

        result = SymbolicDictOps.update(m, {1: 10, 2: 20})

        assert result.success

    def test_keys_concrete(self):
        """Test getting keys from concrete dict."""

        result = SymbolicDictOps.keys({"a": 1, "b": 2})

        assert set(result.value) == {"a", "b"}

    def test_values_concrete(self):
        """Test getting values from concrete dict."""

        result = SymbolicDictOps.values({"a": 1, "b": 2})

        assert set(result.value) == {1, 2}

    def test_items_concrete(self):
        """Test getting items from concrete dict."""

        result = SymbolicDictOps.items({"a": 1})

        assert result.value == [("a", 1)]


class TestSymbolicSetOps:
    """Tests for SymbolicSetOps class."""

    def test_length_concrete(self):
        """Test length of concrete set."""

        result = SymbolicSetOps.length({1, 2, 3})

        assert result.value == 3

    def test_contains_concrete_true(self):
        """Test contains for present value."""

        result = SymbolicSetOps.contains({1, 2, 3}, 2)

        assert result.value is True

    def test_contains_concrete_false(self):
        """Test contains for absent value."""

        result = SymbolicSetOps.contains({1, 2, 3}, 99)

        assert result.value is False

    def test_add_concrete(self):
        """Test adding to concrete set."""

        s = {1, 2}

        result = SymbolicSetOps.add(s, 3)

        assert result.success

        assert s == {1, 2, 3}

    def test_add_duplicate(self):
        """Test adding duplicate to set."""

        s = {1, 2}

        result = SymbolicSetOps.add(s, 2)

        assert result.success

        assert s == {1, 2}

    def test_remove_concrete(self):
        """Test removing from concrete set."""

        s = {1, 2, 3}

        result = SymbolicSetOps.remove(s, 2)

        assert result.success

        assert s == {1, 3}

    def test_remove_not_found(self):
        """Test removing non-existent value."""

        result = SymbolicSetOps.remove({1, 2}, 99)

        assert not result.success

    def test_discard_existing(self):
        """Test discarding existing value."""

        s = {1, 2, 3}

        result = SymbolicSetOps.discard(s, 2)

        assert result.success

        assert s == {1, 3}

    def test_discard_non_existing(self):
        """Test discarding non-existent value (no error)."""

        s = {1, 2}

        result = SymbolicSetOps.discard(s, 99)

        assert result.success

    def test_pop_concrete(self):
        """Test popping from concrete set."""

        s = {1}

        result = SymbolicSetOps.pop(s)

        assert result.value == 1

        assert s == set()

    def test_pop_empty(self):
        """Test popping from empty set."""

        result = SymbolicSetOps.pop(set())

        assert not result.success

    def test_union_concrete(self):
        """Test union of concrete sets."""

        result = SymbolicSetOps.union({1, 2}, {2, 3})

        assert result.value == {1, 2, 3}

    def test_intersection_concrete(self):
        """Test intersection of concrete sets."""

        result = SymbolicSetOps.intersection({1, 2, 3}, {2, 3, 4})

        assert result.value == {2, 3}

    def test_difference_concrete(self):
        """Test difference of concrete sets."""

        result = SymbolicSetOps.difference({1, 2, 3}, {2, 3})

        assert result.value == {1}

    def test_symmetric_difference_concrete(self):
        """Test symmetric difference of concrete sets."""

        result = SymbolicSetOps.symmetric_difference({1, 2, 3}, {2, 3, 4})

        assert result.value == {1, 4}

    def test_issubset_true(self):
        """Test issubset when true."""

        result = SymbolicSetOps.issubset({1, 2}, {1, 2, 3})

        assert result.value is True

    def test_issubset_false(self):
        """Test issubset when false."""

        result = SymbolicSetOps.issubset({1, 4}, {1, 2, 3})

        assert result.value is False

    def test_issuperset_true(self):
        """Test issuperset when true."""

        result = SymbolicSetOps.issuperset({1, 2, 3}, {1, 2})

        assert result.value is True

    def test_issuperset_false(self):
        """Test issuperset when false."""

        result = SymbolicSetOps.issuperset({1, 2}, {1, 2, 3})

        assert result.value is False

    def test_isdisjoint_true(self):
        """Test isdisjoint when true."""

        result = SymbolicSetOps.isdisjoint({1, 2}, {3, 4})

        assert result.value is True

    def test_isdisjoint_false(self):
        """Test isdisjoint when false."""

        result = SymbolicSetOps.isdisjoint({1, 2}, {2, 3})

        assert result.value is False


class TestSymbolicTupleOps:
    """Tests for SymbolicTupleOps class."""

    def test_length_concrete(self):
        """Test length of concrete tuple."""

        result = SymbolicTupleOps.length((1, 2, 3))

        assert result.value == 3

    def test_getitem_concrete(self):
        """Test getting item from concrete tuple."""

        result = SymbolicTupleOps.getitem((10, 20, 30), 1)

        assert result.value == 20

    def test_getitem_out_of_bounds(self):
        """Test out of bounds access."""

        result = SymbolicTupleOps.getitem((1, 2, 3), 10)

        assert not result.success

    def test_getitem_symbolic_index(self):
        """Test getting with symbolic index."""

        t = (10, 20, 30)

        idx = z3.Int("i")

        result = SymbolicTupleOps.getitem(t, idx)

        assert result.success

        assert len(result.constraints) > 0

    def test_count_concrete(self):
        """Test counting in concrete tuple."""

        result = SymbolicTupleOps.count((1, 2, 2, 3, 2), 2)

        assert result.value == 3

    def test_index_concrete(self):
        """Test finding index in concrete tuple."""

        result = SymbolicTupleOps.index((10, 20, 30), 20)

        assert result.value == 1

    def test_index_not_found(self):
        """Test index for non-existent value."""

        result = SymbolicTupleOps.index((1, 2, 3), 99)

        assert not result.success

    def test_slice_concrete(self):
        """Test slicing concrete tuple."""

        result = SymbolicTupleOps.slice((1, 2, 3, 4, 5), 1, 4)

        assert result.value == (2, 3, 4)

    def test_concatenate_concrete(self):
        """Test concatenating concrete tuples."""

        result = SymbolicTupleOps.concatenate((1, 2), (3, 4))

        assert result.value == (1, 2, 3, 4)

    def test_contains_concrete_true(self):
        """Test contains for present value."""

        result = SymbolicTupleOps.contains((1, 2, 3), 2)

        assert result.value is True

    def test_contains_concrete_false(self):
        """Test contains for absent value."""

        result = SymbolicTupleOps.contains((1, 2, 3), 99)

        assert result.value is False


class TestSymbolicStringOps:
    """Tests for SymbolicStringOps class."""

    def test_length_concrete(self):
        """Test length of concrete string."""

        result = SymbolicStringOps.length("hello")

        assert result.value == 5

    def test_contains_concrete_true(self):
        """Test contains for present substring."""

        result = SymbolicStringOps.contains("hello world", "world")

        assert result.value is True

    def test_contains_concrete_false(self):
        """Test contains for absent substring."""

        result = SymbolicStringOps.contains("hello", "world")

        assert result.value is False

    def test_concatenate_concrete(self):
        """Test concatenating concrete strings."""

        result = SymbolicStringOps.concatenate("hello", " world")

        assert result.value == "hello world"

    def test_startswith_true(self):
        """Test startswith when true."""

        result = SymbolicStringOps.startswith("hello world", "hello")

        assert result.value is True

    def test_startswith_false(self):
        """Test startswith when false."""

        result = SymbolicStringOps.startswith("hello world", "world")

        assert result.value is False

    def test_endswith_true(self):
        """Test endswith when true."""

        result = SymbolicStringOps.endswith("hello world", "world")

        assert result.value is True

    def test_endswith_false(self):
        """Test endswith when false."""

        result = SymbolicStringOps.endswith("hello world", "hello")

        assert result.value is False


class TestCollectionZ3Integration:
    """Integration tests verifying Z3 constraint generation."""

    def test_list_bounds_checking(self):
        """Test that list bounds constraints are satisfiable."""

        arr = SymbolicArray("data")

        solver = z3.Solver()

        solver.add(arr.length == 5)

        result = SymbolicListOps.getitem(arr, 2)

        for c in result.constraints:
            solver.add(c)

        assert solver.check() == z3.sat

    def test_list_out_of_bounds_unsat(self):
        """Test that out-of-bounds access is unsatisfiable."""

        arr = SymbolicArray("data")

        solver = z3.Solver()

        solver.add(arr.length == 3)

        result = SymbolicListOps.getitem(arr, 5)

        for c in result.constraints:
            solver.add(c)

        assert solver.check() == z3.unsat

    def test_symbolic_contains_constraint(self):
        """Test symbolic contains generates proper constraints."""

        arr = SymbolicArray("data")

        result = SymbolicListOps.contains(arr, 42)

        assert isinstance(result.value, SymbolicBool)

        assert len(result.constraints) > 0

    def test_dict_key_constraint(self):
        """Test dict access generates key existence constraint."""

        m = SymbolicMap("config")

        m = m.set(z3.IntVal(1), z3.IntVal(100))

        result = SymbolicDictOps.getitem(m, 1)

        assert len(result.constraints) > 0

        solver = z3.Solver()

        for c in result.constraints:
            solver.add(c)

        assert solver.check() == z3.sat

    def test_chained_list_operations(self):
        """Test chaining multiple list operations."""

        arr = SymbolicArray("data")

        r1 = SymbolicListOps.append(arr, z3.IntVal(1))

        arr = r1.modified_collection

        r2 = SymbolicListOps.append(arr, z3.IntVal(2))

        arr = r2.modified_collection

        r3 = SymbolicListOps.append(arr, z3.IntVal(3))

        arr = r3.modified_collection

        solver = z3.Solver()

        original_arr = SymbolicArray("data")

        solver.add(original_arr.length == 0)

        solver.add(arr.length == 3)

        assert solver.check() == z3.sat

    def test_set_operations_constraints(self):
        """Test set operations with symbolic sets."""

        s1_z3 = z3.EmptySet(z3.IntSort())

        s2_z3 = z3.EmptySet(z3.IntSort())

        s1 = SymbolicSet(s1_z3, z3.IntSort(), "s1")

        s2 = SymbolicSet(s2_z3, z3.IntSort(), "s2")

        s1 = s1.add(SymbolicInt(z3.IntVal(1)))

        s1 = s1.add(SymbolicInt(z3.IntVal(2)))

        s2 = s2.add(SymbolicInt(z3.IntVal(2)))

        s2 = s2.add(SymbolicInt(z3.IntVal(3)))

        result = SymbolicSetOps.union(s1, s2)

        union_set = result.value

        solver = z3.Solver()

        solver.add(z3.IsMember(z3.IntVal(1), union_set.z3_set))

        solver.add(z3.IsMember(z3.IntVal(2), union_set.z3_set))

        solver.add(z3.IsMember(z3.IntVal(3), union_set.z3_set))

        assert solver.check() == z3.sat


class TestEdgeCases:
    """Edge case and corner case tests."""

    def test_empty_list_operations(self):
        """Test operations on empty list."""

        assert not SymbolicListOps.pop([]).success

        assert not SymbolicListOps.getitem([], 0).success

    def test_empty_dict_operations(self):
        """Test operations on empty dict."""

        assert not SymbolicDictOps.getitem({}, "key").success

        assert not SymbolicDictOps.delitem({}, "key").success

    def test_empty_set_operations(self):
        """Test operations on empty set."""

        assert not SymbolicSetOps.pop(set()).success

        assert not SymbolicSetOps.remove(set(), 1).success

    def test_negative_index_handling(self):
        """Test negative index handling for lists."""

        lst = [1, 2, 3]

        result = SymbolicListOps.getitem(lst, -1)

        assert result.value == 3

    def test_large_collection_operations(self):
        """Test operations on large collections."""

        lst = list(range(1000))

        assert SymbolicListOps.length(lst).value == 1000

        assert SymbolicListOps.getitem(lst, 999).value == 999

        assert SymbolicListOps.count(lst, 500).value == 1

    def test_nested_collections(self):
        """Test operations with nested collections."""

        lst = [[1, 2], [3, 4], [5, 6]]

        result = SymbolicListOps.getitem(lst, 1)

        assert result.value == [3, 4]

        nested = result.value

        SymbolicListOps.append(nested, 99)

        assert lst[1] == [3, 4, 99]
