# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false
"""Tests for pysymex.tracing.analyzer.helpers — parsing, formatting, extraction."""

from __future__ import annotations

from pysymex.tracing.analyzer.helpers import (
    as_dict,
    as_float,
    as_int,
    as_list,
    as_str,
    constraints_contain,
    float_field_at_least,
    float_field_at_most,
    float_field_in_range,
    has_stack_pop,
    int_field_at_least,
    int_field_at_most,
    int_field_in_range,
    list_contains,
    str_contains,
)


class TestHelperFunctions:
    """Tests for str_contains, list_contains, as_dict, etc."""

    def test_str_contains_true(self) -> None:
        """Returns True when substring found."""
        assert str_contains("hello world", "world") is True

    def test_str_contains_false(self) -> None:
        """Returns False when substring not found."""
        assert str_contains("hello", "world") is False

    def test_str_contains_none(self) -> None:
        """Returns False for None."""
        assert str_contains(None, "x") is False

    def test_list_contains_true(self) -> None:
        """Returns True when item found."""
        assert list_contains(["abc", "def"], "ab") is True

    def test_list_contains_false(self) -> None:
        """Returns False when item not found."""
        assert list_contains(["abc", "def"], "xyz") is False

    def test_list_contains_none(self) -> None:
        """Returns False for None."""
        assert list_contains(None, "x") is False

    def test_constraints_contain_true(self) -> None:
        """Finds substring in constraint smtlib field."""
        constraints: list[object] = [{"smtlib": "(> x 0)"}]
        assert constraints_contain(constraints, "x") is True

    def test_constraints_contain_false(self) -> None:
        """Returns False when not found."""
        constraints: list[object] = [{"smtlib": "(> y 0)"}]
        assert constraints_contain(constraints, "x") is False

    def test_constraints_contain_empty(self) -> None:
        """Returns False for empty list."""
        assert constraints_contain([], "x") is False

    def test_as_dict_returns_dict(self) -> None:
        """as_dict normalizes a dict."""
        result = as_dict({"a": 1})
        assert result is not None
        assert result["a"] == 1

    def test_as_dict_returns_none_for_non_dict(self) -> None:
        """as_dict returns None for non-dict."""
        assert as_dict([1, 2]) is None

    def test_as_list_returns_list(self) -> None:
        """as_list returns list for list."""
        result = as_list([1, 2])
        assert result == [1, 2]

    def test_as_list_returns_none_for_non_list(self) -> None:
        """as_list returns None for non-list."""
        assert as_list({"a": 1}) is None

    def test_as_str(self) -> None:
        """as_str returns str for str, None otherwise."""
        assert as_str("hello") == "hello"
        assert as_str(123) is None

    def test_as_int(self) -> None:
        """as_int returns int for int, None otherwise."""
        assert as_int(42) == 42
        assert as_int("42") is None

    def test_as_float(self) -> None:
        """as_float returns float for numeric, None otherwise."""
        assert as_float(3.14) == 3.14
        assert as_float(5) == 5.0
        assert as_float("x") is None

    def test_int_field_bounds_include_zero(self) -> None:
        """Integer field bound helpers treat zero as a present value."""
        event: dict[str, object] = {"seq": 0}
        assert int_field_at_least(event, "seq", 0) is True
        assert int_field_at_most(event, "seq", 0) is True
        assert int_field_in_range(event, "seq", 0, 0) is True

    def test_int_field_bounds_reject_missing(self) -> None:
        """Integer field bound helpers reject absent or non-integer values."""
        assert int_field_at_least({}, "seq", 0) is False
        assert int_field_at_most({"seq": "0"}, "seq", 0) is False

    def test_float_field_bounds_include_zero(self) -> None:
        """Float field bound helpers treat zero as a present value."""
        event: dict[str, object] = {"confidence": 0.0}
        assert float_field_at_least(event, "confidence", 0.0) is True
        assert float_field_at_most(event, "confidence", 0.0) is True
        assert float_field_in_range(event, "confidence", 0.0, 0.0) is True

    def test_float_field_bounds_reject_missing(self) -> None:
        """Float field bound helpers reject absent or non-numeric values."""
        assert float_field_at_least({}, "confidence", 0.0) is False
        assert float_field_at_most({"confidence": "0.0"}, "confidence", 0.0) is False

    def test_has_stack_pop_true(self) -> None:
        """has_stack_pop returns True when popped > 0."""
        event: dict[str, object] = {"stack_diff": {"popped": 2}}
        assert has_stack_pop(event) is True

    def test_has_stack_pop_false(self) -> None:
        """has_stack_pop returns False when no stack_diff."""
        assert has_stack_pop({}) is False
