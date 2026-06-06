"""Tests for pysymex.config helper factories and normalizers."""

from __future__ import annotations

import pysymex.config as mod


class TestIsObjectList:
    """Tests for is_object_list TypeGuard."""

    def test_list_returns_true(self) -> None:
        """A list returns True."""
        assert mod.is_object_list([1, 2, 3]) is True

    def test_tuple_returns_false(self) -> None:
        """A tuple is not a list."""
        assert mod.is_object_list((1, 2)) is False

    def test_string_returns_false(self) -> None:
        """A string is not a list."""
        assert mod.is_object_list("abc") is False


class TestIsObjectCollection:
    """Tests for is_object_collection TypeGuard."""

    def test_list_returns_true(self) -> None:
        """A list is a collection."""
        assert mod.is_object_collection([1]) is True

    def test_set_returns_true(self) -> None:
        """A set is a collection."""
        assert mod.is_object_collection({1, 2}) is True

    def test_tuple_returns_true(self) -> None:
        """A tuple is a collection."""
        assert mod.is_object_collection((1,)) is True

    def test_dict_returns_false(self) -> None:
        """A dict is not in the collection TypeGuard."""
        assert mod.is_object_collection({"a": 1}) is False

    def test_string_returns_false(self) -> None:
        """A string is not a collection."""
        assert mod.is_object_collection("abc") is False


class TestIsObjectDict:
    """Tests for is_object_dict TypeGuard."""

    def test_dict_returns_true(self) -> None:
        """A dict returns True."""
        assert mod.is_object_dict({"a": 1}) is True

    def test_list_returns_false(self) -> None:
        """A list is not a dict."""
        assert mod.is_object_dict([1, 2]) is False


class TestNormalizeObjectDict:
    """Tests for normalize_object_dict."""

    def test_valid_dict(self) -> None:
        """A dict with mixed keys is normalized to str keys."""
        result = mod.normalize_object_dict({1: "a", "b": 2})
        assert result == {"1": "a", "b": 2}

    def test_non_dict_returns_none(self) -> None:
        """Non-dict input returns None."""
        result = mod.normalize_object_dict([1, 2])
        assert result is None

    def test_empty_dict(self) -> None:
        """Empty dict normalizes to empty dict."""
        result = mod.normalize_object_dict({})
        assert result == {}


class TestNormalizeStringList:
    """Tests for normalize_string_list."""

    def test_valid_list(self) -> None:
        """A list of mixed types is stringified."""
        result = mod.normalize_string_list([1, "two", 3.0])
        assert result == ["1", "two", "3.0"]

    def test_non_list_returns_none(self) -> None:
        """Non-list input returns None."""
        result = mod.normalize_string_list("abc")
        assert result is None
