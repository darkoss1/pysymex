"""Tests for pysymex.core.havoc — HavocValue and utility functions.

Covers: HavocValue.havoc, is_havoc, has_havoc, union_taint,
HavocValue.__getitem__, __getattr__, __call__, __repr__.
"""

from __future__ import annotations

import z3
import pytest

from pysymex.core.havoc import HavocValue, has_havoc, is_havoc, union_taint
from pysymex.core.types import SymbolicValue


# ---------------------------------------------------------------------------
# HavocValue.havoc factory
# ---------------------------------------------------------------------------

class TestHavocFactory:

    def test_basic_creation(self):
        val, constraint = HavocValue.havoc("test")
        assert isinstance(val, HavocValue)
        assert isinstance(constraint, z3.BoolRef)

    def test_is_symbolic_value_subclass(self):
        val, _ = HavocValue.havoc("test")
        assert isinstance(val, SymbolicValue)

    def test_name_preserved(self):
        val, _ = HavocValue.havoc("my_havoc")
        assert val._name == "my_havoc"

    def test_type_constraint_satisfiable(self):
        """The type constraint should be satisfiable (at least one type tag true)."""
        _, constraint = HavocValue.havoc("test")
        s = z3.Solver()
        s.add(constraint)
        assert s.check() == z3.sat

    def test_type_constraint_at_most_one(self):
        """At most one type tag should be true at a time."""
        val, constraint = HavocValue.havoc("test")
        s = z3.Solver()
        s.add(constraint)
        # Force two type tags true simultaneously
        s.add(val.is_int)
        s.add(val.is_bool)
        assert s.check() == z3.unsat

    def test_no_taint_by_default(self):
        val, _ = HavocValue.havoc("test")
        assert val.taint_labels is None

    def test_taint_labels_set(self):
        val, _ = HavocValue.havoc("test", taint_labels={"user_input"})
        assert val.taint_labels == frozenset({"user_input"})

    def test_taint_labels_frozenset(self):
        val, _ = HavocValue.havoc("test", taint_labels=frozenset({"a", "b"}))
        assert val.taint_labels == frozenset({"a", "b"})

    def test_z3_variables_created(self):
        val, _ = HavocValue.havoc("h1")
        assert val.z3_int is not None
        assert val.z3_bool is not None
        assert val.z3_str is not None

    def test_is_havoc_flag(self):
        val, _ = HavocValue.havoc("test")
        assert val._is_havoc is True


# ---------------------------------------------------------------------------
# HavocValue dunder methods
# ---------------------------------------------------------------------------

class TestHavocDunders:

    def test_getitem_returns_havoc(self):
        val, _ = HavocValue.havoc("arr")
        result = val[0]
        assert isinstance(result, tuple)
        new_val, new_constraint = result
        assert isinstance(new_val, HavocValue)
        assert isinstance(new_constraint, z3.BoolRef)

    def test_getitem_propagates_taint(self):
        val, _ = HavocValue.havoc("arr", taint_labels={"tainted"})
        new_val, _ = val[0]
        assert new_val.taint_labels == frozenset({"tainted"})

    def test_call_returns_havoc(self):
        val, _ = HavocValue.havoc("func")
        result = val()
        assert isinstance(result, tuple)
        new_val, new_constraint = result
        assert isinstance(new_val, HavocValue)

    def test_call_propagates_taint(self):
        val, _ = HavocValue.havoc("func", taint_labels={"t1"})
        new_val, _ = val()
        assert new_val.taint_labels == frozenset({"t1"})

    def test_getattr_returns_havoc(self):
        val, _ = HavocValue.havoc("obj")
        result = val.some_attr
        assert isinstance(result, tuple)
        new_val, _ = result
        assert isinstance(new_val, HavocValue)

    def test_getattr_propagates_taint(self):
        val, _ = HavocValue.havoc("obj", taint_labels={"src"})
        new_val, _ = val.attr
        assert new_val.taint_labels == frozenset({"src"})

    def test_getattr_private_raises(self):
        """Accessing underscore attrs should raise AttributeError to prevent recursion."""
        val, _ = HavocValue.havoc("obj")
        with pytest.raises(AttributeError):
            _ = val._private_attr

    def test_repr(self):
        val, _ = HavocValue.havoc("my_name")
        assert repr(val) == "HavocValue(my_name)"


# ---------------------------------------------------------------------------
# is_havoc / has_havoc
# ---------------------------------------------------------------------------

class TestIsHavoc:

    def test_havoc_value_is_havoc(self):
        val, _ = HavocValue.havoc("test")
        assert is_havoc(val) is True

    def test_regular_symbolic_not_havoc(self):
        sv, _ = SymbolicValue.symbolic("x")
        assert is_havoc(sv) is False

    def test_int_not_havoc(self):
        assert is_havoc(42) is False

    def test_none_not_havoc(self):
        assert is_havoc(None) is False


class TestHasHavoc:

    def test_single_havoc(self):
        val, _ = HavocValue.havoc("test")
        assert has_havoc(val) is True

    def test_no_havoc(self):
        sv, _ = SymbolicValue.symbolic("x")
        assert has_havoc(sv) is False

    def test_mixed_havoc_and_regular(self):
        hv, _ = HavocValue.havoc("h")
        sv, _ = SymbolicValue.symbolic("x")
        assert has_havoc(sv, hv) is True

    def test_empty_args(self):
        assert has_havoc() is False

    def test_multiple_non_havoc(self):
        assert has_havoc(1, "hello", None) is False


# ---------------------------------------------------------------------------
# union_taint
# ---------------------------------------------------------------------------

class TestUnionTaint:

    def test_no_taint(self):
        sv, _ = SymbolicValue.symbolic("x")
        assert union_taint([sv]) is None

    def test_single_tainted(self):
        hv, _ = HavocValue.havoc("h", taint_labels={"a"})
        result = union_taint([hv])
        assert result == frozenset({"a"})

    def test_multiple_taints_merged(self):
        h1, _ = HavocValue.havoc("h1", taint_labels={"a"})
        h2, _ = HavocValue.havoc("h2", taint_labels={"b"})
        result = union_taint([h1, h2])
        assert result == frozenset({"a", "b"})

    def test_mixed_tainted_and_untainted(self):
        h1, _ = HavocValue.havoc("h1", taint_labels={"x"})
        sv, _ = SymbolicValue.symbolic("v")
        result = union_taint([h1, sv])
        assert result == frozenset({"x"})

    def test_empty_list(self):
        assert union_taint([]) is None

    def test_all_none_taint(self):
        assert union_taint([42, "hello"]) is None

    def test_overlapping_taints(self):
        h1, _ = HavocValue.havoc("h1", taint_labels={"a", "b"})
        h2, _ = HavocValue.havoc("h2", taint_labels={"b", "c"})
        result = union_taint([h1, h2])
        assert result == frozenset({"a", "b", "c"})
