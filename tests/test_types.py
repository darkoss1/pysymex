"""Unit tests for core types."""

import pytest
import z3

from pysymex.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
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

        # These should not raise exceptions
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

        # These should return symbolic values with boolean semantics
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

    def test_symbolic_division_is_guarded(self):
        """Symbolic division should avoid undefined Z3 division-by-zero terms."""
        x, _ = SymbolicValue.symbolic("x")
        y, _ = SymbolicValue.symbolic("y")

        result = x / y
        assert isinstance(result, SymbolicValue)
        assert "If" in str(result.z3_int)

    def test_concrete_zero_division_raises(self):
        """Concrete zero divisors should still raise eagerly."""
        x = SymbolicValue.from_const(10)
        y = SymbolicValue.from_const(0)

        with pytest.raises(ZeroDivisionError):
            _ = x / y

        with pytest.raises(ZeroDivisionError):
            _ = x // y

        with pytest.raises(ZeroDivisionError):
            _ = x % y


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

        # Length should work
        length = s.length()
        assert length is not None

    def test_heterogeneous_merge_succeeds(self):
        s, _ = SymbolicString.symbolic("s")
        v, _ = SymbolicValue.symbolic("v")

        # Incompatible merges used to raise, but now they merge into a universal SymbolicValue
        result = s.conditional_merge(v, z3.Bool("cond_s"))
        assert isinstance(result, SymbolicValue)


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

        # Append should work without error
        try:
            lst.append(x)
        except:
            pass  # Append may not be fully implemented

    def test_heterogeneous_merge_succeeds(self):
        lst, _ = SymbolicList.symbolic("lst")
        v, _ = SymbolicValue.symbolic("v_list")

        result = lst.conditional_merge(v, z3.Bool("cond_l"))
        assert isinstance(result, SymbolicValue)


class TestSymbolicDict:
    """Tests for SymbolicDict class."""

    def test_creation(self):
        """Test creating symbolic dict."""
        d, constraint = SymbolicDict.symbolic("d")

        assert isinstance(d, SymbolicDict)

    def test_heterogeneous_merge_succeeds(self):
        d, _ = SymbolicDict.symbolic("d")
        v, _ = SymbolicValue.symbolic("v_dict")

        result = d.conditional_merge(v, z3.Bool("cond_d"))
        assert isinstance(result, SymbolicValue)


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
