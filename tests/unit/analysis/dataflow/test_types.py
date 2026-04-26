import pytest
from pysymex.analysis.dataflow.types import (
    Definition,
    Use,
    DefUseChain,
    Expression,
    NullState,
    NullInfo,
)


class TestDefinition:
    """Test suite for pysymex.analysis.dataflow.types.Definition."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        d = Definition("x", 1, 10, line=5)
        assert d.var_name == "x"
        assert d.block_id == 1
        assert d.pc == 10
        assert d.line == 5
        assert repr(d) == "Def(x@10)"


class TestUse:
    """Test suite for pysymex.analysis.dataflow.types.Use."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        u = Use("y", 2, 20, line=10)
        assert u.var_name == "y"
        assert u.block_id == 2
        assert u.pc == 20
        assert u.line == 10
        assert repr(u) == "Use(y@20)"


class TestDefUseChain:
    """Test suite for pysymex.analysis.dataflow.types.DefUseChain."""

    def test_add_use(self) -> None:
        """Test add_use behavior."""
        d = Definition("x", 1, 10)
        chain = DefUseChain(d)
        u1 = Use("x", 2, 20)
        u2 = Use("x", 3, 30)
        chain.add_use(u1)
        chain.add_use(u2)
        assert len(chain.uses) == 2
        assert u1 in chain.uses
        assert u2 in chain.uses

    def test_is_dead(self) -> None:
        """Test is_dead behavior."""
        d = Definition("x", 1, 10)
        chain = DefUseChain(d)
        assert chain.is_dead() is True
        chain.add_use(Use("x", 2, 20))
        assert chain.is_dead() is False


class TestExpression:
    """Test suite for pysymex.analysis.dataflow.types.Expression."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        expr1 = Expression("+", ("a", "b"))
        assert expr1.operator == "+"
        assert expr1.operands == ("a", "b")
        assert repr(expr1) == "(a + b)"

        expr2 = Expression("~", ("c",))
        assert repr(expr2) == "~(c)"


class TestNullState:
    """Test suite for pysymex.analysis.dataflow.types.NullState."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert NullState.DEFINITELY_NULL.name == "DEFINITELY_NULL"
        assert NullState.DEFINITELY_NOT_NULL.name == "DEFINITELY_NOT_NULL"


class TestNullInfo:
    """Test suite for pysymex.analysis.dataflow.types.NullInfo."""

    def test_copy(self) -> None:
        """Test copy behavior."""
        info1 = NullInfo({"x": NullState.DEFINITELY_NULL})
        info2 = info1.copy()
        assert info1 == info2
        info1.set_state("x", NullState.MAYBE_NULL)
        assert info1 != info2

    def test_get_state(self) -> None:
        """Test get_state behavior."""
        info = NullInfo({"x": NullState.DEFINITELY_NOT_NULL})
        assert info.get_state("x") == NullState.DEFINITELY_NOT_NULL
        assert info.get_state("unknown") == NullState.UNKNOWN

    def test_set_state(self) -> None:
        """Test set_state behavior."""
        info = NullInfo()
        info.set_state("x", NullState.MAYBE_NULL)
        assert info.get_state("x") == NullState.MAYBE_NULL

    def test_join(self) -> None:
        """Test join behavior."""
        i1 = NullInfo({"x": NullState.DEFINITELY_NULL, "y": NullState.DEFINITELY_NOT_NULL})
        i2 = NullInfo({"x": NullState.DEFINITELY_NULL, "y": NullState.DEFINITELY_NULL})
        i3 = i1.join(i2)
        assert i3.get_state("x") == NullState.DEFINITELY_NULL
        assert i3.get_state("y") == NullState.MAYBE_NULL

        i4 = NullInfo({"z": NullState.DEFINITELY_NULL})
        i5 = NullInfo({"z": NullState.UNKNOWN})
        assert i4.join(i5).get_state("z") == NullState.UNKNOWN
