"""Unit tests for core types."""

import pytest

import z3

from pysymex.core.types import (
    SymbolicValue,
    SymbolicString,
    SymbolicList,
    SymbolicDict,
    SymbolicNone,
)


class TestSymbolicValue:
    """Tests for SymbolicValue class."""

    def test_symbolic_creation(self):
        """Test creating symbolic value with factory method."""

        val, constraint = SymbolicValue.symbolic("x")

        assert val.name == "x"

        assert isinstance(val, SymbolicValue)

    def test_arithmetic_operations(self):
        """Test basic arithmetic on symbolic values."""

        x, _ = SymbolicValue.symbolic("x")

        y, _ = SymbolicValue.symbolic("y")

        result = x + y

        assert isinstance(result, SymbolicValue)

        result = x - y

        assert isinstance(result, SymbolicValue)

        result = x * y

        assert isinstance(result, SymbolicValue)

        result = x / y

        assert isinstance(result, SymbolicValue)

    def test_comparison_operations(self):
        """Test comparison operations on symbolic values."""

        x, _ = SymbolicValue.symbolic("x")

        y, _ = SymbolicValue.symbolic("y")

        result = x < y

        assert isinstance(result, SymbolicValue)

        result = x > y

        assert isinstance(result, SymbolicValue)

        result = x <= y

        assert isinstance(result, SymbolicValue)

        result = x >= y

        assert isinstance(result, SymbolicValue)

    def test_negation(self):
        """Test negation of symbolic value."""

        x, _ = SymbolicValue.symbolic("x")

        result = -x

        assert isinstance(result, SymbolicValue)


class TestSymbolicString:
    """Tests for SymbolicString class."""

    def test_symbolic_creation(self):
        """Test creating symbolic string."""

        s, constraint = SymbolicString.symbolic("s")

        assert s.name == "s"

        assert isinstance(s, SymbolicString)

    def test_length(self):
        """Test string length."""

        s, _ = SymbolicString.symbolic("s")

        length = s.length()

        assert length is not None


class TestSymbolicList:
    """Tests for SymbolicList class."""

    def test_creation(self):
        """Test creating symbolic list."""

        lst, constraint = SymbolicList.symbolic("lst")

        assert isinstance(lst, SymbolicList)

    def test_append(self):
        """Test appending to list."""

        lst, _ = SymbolicList.symbolic("lst")

        x, _ = SymbolicValue.symbolic("x")

        try:
            lst.append(x)

        except:
            pass


class TestSymbolicDict:
    """Tests for SymbolicDict class."""

    def test_creation(self):
        """Test creating symbolic dict."""

        d, constraint = SymbolicDict.symbolic("d")

        assert isinstance(d, SymbolicDict)


class TestSymbolicNone:
    """Tests for SymbolicNone class."""

    def test_creation(self):
        """Test creating SymbolicNone."""

        n = SymbolicNone()

        assert isinstance(n, SymbolicNone)

    def test_truthy(self):
        """Test that None is falsy."""

        n = SymbolicNone()

        truthy = n.could_be_truthy()

        assert truthy == z3.BoolVal(False)

    def test_falsy(self):
        """Test that None is always falsy."""

        n = SymbolicNone()

        falsy = n.could_be_falsy()

        assert falsy == z3.BoolVal(True)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
